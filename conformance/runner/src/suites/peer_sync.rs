//! The `peer-sync` suite (conformance/PROTOCOL.md section 5.1): the runner is the node's only peer
//! and serves it each corpus scenario through the node's own headers-first synchronization,
//! including the blocks Bitcoin Core rejects. The interop suite only ever gives a node valid
//! blocks, and the corpus suite gives it blocks one call at a time; neither reaches the code that
//! validates a downloaded batch, where an implementation can differ from its one-block path.
//!
//! For each scenario:
//!
//! 1. **Cases from Bitcoin Core.** The final chain is the one the interop suite uses (the tip of the
//!    last check, followed back to genesis). Every other recorded block whose parent is on that
//!    chain is a candidate. A fresh `bitcoind -regtest` with the scenario's options gets the final
//!    chain with `submitblock`; while each chain block is the tip, every candidate child of it is
//!    put to `getblocktemplate` in proposal mode, which runs every check Core applies to a block on
//!    its tip except proof of work. A candidate all of whose recorded byte variants get a reject
//!    reason is a case: a block on top of chain block `i` that Core rejects, so a node that has
//!    chain blocks 1 to `i` and receives it must still have chain block `i` as its tip. The other
//!    candidates are left out (counted in the details).
//! 2. **Serving.** The node command (`--sync-node`) starts with `{peer}` set to the runner's
//!    listener. The runner accepts the version 1 transport and BIP324 version 2 (a node may
//!    reconnect at any time), answers `version`, `ping` and `getheaders` (from the chain it has
//!    announced so far, then the current case's header), and serves the blocks it announced.
//!    Requested blocks go out in bursts: once the node has sent no `getdata` for [`QUIET`], all of
//!    them, back to back in chain order. The burst that holds a case's parent waits for the
//!    node's request of the case block (at most [`HOLD`]), and the case block goes last, so the
//!    two arrive together at the end of a run of blocks, as during initial block download.
//! 3. **Checks.** When every chain block up to the parent is delivered, and the case block too (or
//!    the node did not ask for it within [`REQUEST_WAIT`]), the runner sends `ping`, waits for the
//!    `pong`, and asks the node for its tip on standard input ([`Session::settled_tip`]).
//!
//! Each scenario runs in two modes:
//!
//! - **follow**: one node takes every case in chain order (the chain up to the parent announced
//!   with unsolicited `headers`, then the case header), then the rest of the chain: its tip must be
//!   the final tip, and after `{"op":"stop"}` its `stopped` line must name it and the node must exit
//!   with status 0. A failed check ends the node and the next check starts a fresh one, so one
//!   divergence does not hide the checks after it.
//! - **ibd**: a fresh node per case, whose peer offers the chain up to the parent and the case
//!   block as its best chain from the start, so the case block ends the node's initial block
//!   download. Some implementations validate initial block download in batches and only then
//!   (rbitcoin-org/rbitcoin#1537 accepted a block re-spending an output its parent had created and
//!   spent, after a merged write of the two was rejected and retried one block at a time).
//!   `--ibd-limit` bounds the cases per scenario (default 32, evenly spaced).

use crate::bitcoind::{free_ports, Bitcoind};
use crate::check::{shorten, Stats};
use crate::hex;
use crate::listen::{self, Event, Writer};
use crate::p2p::{self, Message};
use crate::process;
use crate::suites::{corpus, interop};
use crate::tx::{sha256d, write_compact_size};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SUITE: &str = "peer-sync";
/// How long the window of requests that holds a case's parent is held back waiting for the request
/// of the case block.
pub const HOLD: Duration = Duration::from_secs(2);
/// Requested blocks go out together once the node has sent no `getdata` for this long, so each
/// window of requests arrives as one burst.
pub const QUIET: Duration = Duration::from_millis(50);
/// How long the runner waits for the node to ask for a case block once every chain block below it
/// is delivered (a node does not ask for a block whose header it rejected).
pub const REQUEST_WAIT: Duration = Duration::from_secs(2);
/// How long the runner waits for the node to ask for a block it still needs.
pub const STALL: Duration = Duration::from_secs(120);
/// How long the node must send no `getdata` before the runner asks for its tip again.
pub const SETTLE: Duration = Duration::from_secs(1);
/// How often a node gets the same case block at most. Core asks again for a block that fails its
/// context-free checks as soon as it has it (a peer may have sent a damaged copy), for as long as
/// the block is on its best header chain; answering at once would keep it busy, and not answering
/// would use up its blocks-in-flight slots.
pub const CASE_RESEND: Duration = Duration::from_secs(1);
/// Consecutive node failures (no connection, no answer, crash) after which a scenario is abandoned.
const MAX_NODE_ERRORS: u32 = 3;

const MSG_BLOCK: u32 = 2;
const MSG_WITNESS_FLAG: u32 = 1 << 30;
const NODE_NETWORK: u64 = 1;
const NODE_WITNESS: u64 = 1 << 3;
const NODE_P2P_V2: u64 = 1 << 11;

pub const RULE_IBD_LIMIT: &str =
    "ibd mode: block left out of the evenly spaced sample of --ibd-limit cases per scenario (the follow mode still checks it)";
pub const RULE_STOP_AT: &str = "the --sync-node command has a {stop_at} placeholder; in this suite the runner says when to stop";

pub struct Config {
    pub bitcoind: PathBuf,
    pub node: String,
    pub corpus: Vec<PathBuf>,
    pub port_range: (u16, u16),
    pub node_timeout: Duration,
    pub keep_temp: bool,
    /// Cases per scenario that the ibd mode runs (each starts a fresh node); `None` runs all.
    pub ibd_limit: Option<usize>,
}

/// A block as served: its hash (raw order) and its bytes.
#[derive(Clone)]
struct Block {
    hash: [u8; 32],
    bytes: Vec<u8>,
}

impl Block {
    fn display(&self) -> String {
        hex::encode_reversed(&self.hash)
    }
}

/// A block Core rejects on top of chain block `parent`.
struct Case {
    parent: usize,
    block: Block,
    reason: String,
}

/// A block hash (raw order) and its recorded byte variants, in file order.
type Variants = ([u8; 32], Vec<Vec<u8>>);

/// What the corpus file holds: the final chain (index 0 is genesis, without bytes) with the byte
/// variants of each block, and the candidate children of chain blocks in file order.
struct Loaded {
    options: Value,
    chain: Vec<([u8; 32], Vec<Vec<u8>>)>,
    candidates: Vec<(usize, [u8; 32], Vec<Vec<u8>>)>,
    max_time: i64,
}

fn load(file: &Path) -> Result<Loaded, String> {
    let (_meta, events) = corpus::read_events(file)?;
    let base = file.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut options = json!({});
    let mut genesis = [0u8; 32];
    let mut tip = None;
    let mut order: Vec<[u8; 32]> = Vec::new();
    let mut variants: HashMap<[u8; 32], Vec<Vec<u8>>> = HashMap::new();
    for ev in &events {
        match ev["type"].as_str() {
            Some("reset") => {
                genesis = raw_hash(ev["genesis"].as_str().unwrap_or(""))?;
                options = ev.get("options").cloned().unwrap_or_else(|| json!({}));
            }
            Some("block") => {
                let bytes = corpus::block_bytes(ev, &base)?;
                let hash = sha256d(&bytes[..80]);
                let list = variants.entry(hash).or_default();
                if list.is_empty() {
                    order.push(hash);
                }
                if !list.contains(&bytes) {
                    list.push(bytes);
                }
            }
            Some("check") => tip = Some(raw_hash(ev["tip"].as_str().unwrap_or(""))?),
            _ => {}
        }
    }
    let tip = tip.ok_or("the scenario has no check")?;
    let mut chain = Vec::new();
    let mut max_time = 0i64;
    let mut cursor = tip;
    while cursor != genesis {
        let list = variants.get(&cursor).ok_or_else(|| {
            format!(
                "block {} of the final chain is not in the file",
                hex::encode_reversed(&cursor)
            )
        })?;
        let header = &list[0][..80];
        max_time = max_time.max(u32::from_le_bytes(header[68..72].try_into().unwrap()) as i64);
        chain.push((cursor, list.clone()));
        cursor = header[4..36].try_into().unwrap();
        if chain.len() > 10_000_000 {
            return Err("final chain does not reach genesis".into());
        }
    }
    chain.push((genesis, Vec::new()));
    chain.reverse();
    let position: HashMap<[u8; 32], usize> = chain
        .iter()
        .enumerate()
        .map(|(i, (h, _))| (*h, i))
        .collect();
    let candidates = order
        .iter()
        .filter(|h| !position.contains_key(*h))
        .filter_map(|h| {
            let list = &variants[h];
            let parent: [u8; 32] = list[0][4..36].try_into().unwrap();
            position.get(&parent).map(|&p| (p, *h, list.clone()))
        })
        .collect();
    Ok(Loaded {
        options,
        chain,
        candidates,
        max_time,
    })
}

fn raw_hash(display: &str) -> Result<[u8; 32], String> {
    let mut h = hex::decode32(display)?;
    h.reverse();
    Ok(h)
}

/// The scenario after classification: the final chain with the variant Core accepted, the cases
/// in chain order, and what was left out.
struct Scenario {
    name: String,
    options: Value,
    chain: Vec<Block>,
    cases: Vec<Case>,
    valid_siblings: usize,
    unclassified: Vec<String>,
}

/// Step 1: Core's verdict on every candidate, from a fresh bitcoind holding the final chain.
fn classify(cfg: &Config, name: &str, loaded: Loaded, root: &Path) -> Result<Scenario, String> {
    let extra = interop::bitcoind_args(&loaded.options)?;
    let ports = free_ports(cfg.port_range, 2, &[])?;
    let mut core = Bitcoind::start(
        &cfg.bitcoind,
        &root.join("bitcoind"),
        ports[0],
        ports[1],
        false,
        &extra,
    )?;
    let mut by_parent: BTreeMap<usize, Vec<Variants>> = BTreeMap::new();
    for (parent, hash, list) in loaded.candidates {
        by_parent.entry(parent).or_default().push((hash, list));
    }
    let mut chain = vec![Block {
        hash: loaded.chain[0].0,
        bytes: Vec::new(),
    }];
    let mut cases = Vec::new();
    let mut valid_siblings = 0;
    let mut unclassified = Vec::new();
    for (height, (hash, list)) in loaded.chain.iter().enumerate() {
        if height > 0 {
            let mut accepted = None;
            let mut last = String::new();
            for bytes in list {
                match core.rpc("submitblock", json!([hex::encode(bytes)])) {
                    Ok(Value::Null) => {
                        accepted = Some(bytes.clone());
                        break;
                    }
                    Ok(other) => last = other.to_string(),
                    Err(e) => last = e,
                }
            }
            let bytes = accepted.ok_or_else(|| {
                format!("bitcoind rejected block {height} of the final chain: {last}")
            })?;
            chain.push(Block { hash: *hash, bytes });
        }
        for (child, list) in by_parent.remove(&height).unwrap_or_default() {
            let mut reasons = Vec::new();
            let mut valid = false;
            let mut other = None;
            for bytes in &list {
                let proposal =
                    json!([{"mode": "proposal", "data": hex::encode(bytes), "rules": ["segwit"]}]);
                match core.rpc("getblocktemplate", proposal) {
                    Ok(Value::Null) => valid = true,
                    Ok(Value::String(s))
                        if !s.starts_with("duplicate") && !s.starts_with("inconclusive") =>
                    {
                        reasons.push((s, bytes.clone()))
                    }
                    Ok(v) => other = Some(v.to_string()),
                    Err(e) => other = Some(e),
                }
            }
            if valid {
                valid_siblings += 1;
            } else if let (Some((reason, bytes)), None) = (reasons.first(), &other) {
                cases.push(Case {
                    parent: height,
                    block: Block {
                        hash: child,
                        bytes: bytes.clone(),
                    },
                    reason: reason.clone(),
                });
            } else {
                unclassified.push(format!(
                    "{}: {}",
                    hex::encode_reversed(&child),
                    other.unwrap_or_default()
                ));
            }
        }
    }
    core.stop();
    Ok(Scenario {
        name: name.to_string(),
        options: loaded.options,
        chain,
        cases,
        valid_siblings,
        unclassified,
    })
}

/// One run of the node command and the runner's side of its connection.
struct Session<'a> {
    sc: &'a Scenario,
    timeout: Duration,
    rx: Receiver<Event>,
    stop_accept: Arc<AtomicBool>,
    child: process::Group,
    stdin: Option<ChildStdin>,
    conn: Option<(u64, Writer, &'static str)>,
    ready: bool,
    connections: u64,
    transports: BTreeSet<&'static str>,
    chain_pos: HashMap<[u8; 32], usize>,
    /// The chain is announced up to this index.
    upto: usize,
    /// Requests for chain blocks received so far. Requests for a case block do not count: Core
    /// asks again and again for a block it dropped as mutated, which changes nothing.
    requests: u64,
    /// Every tip answer must be confirmed by a second one (see [`Session::settled_tip`]).
    confirm: bool,
    /// The case whose header was announced last.
    current: Option<usize>,
    /// The connection and case of the last case header sent.
    x_pushed: Option<(u64, usize)>,
    /// Every case whose header was announced (served on request).
    announced: HashMap<[u8; 32], usize>,
    delivered: std::collections::HashSet<[u8; 32]>,
    /// Chain blocks 1 to `delivered_prefix` are all delivered.
    delivered_prefix: usize,
    /// Requested blocks not sent yet, in request order.
    queue: Vec<[u8; 32]>,
    last_getdata: Instant,
    /// While the current case's parent is undelivered: its height, and since when a block held
    /// for the final burst has been queued.
    hold: Option<(usize, Option<Instant>)>,
    /// Chain blocks requested and not sent yet, and the most there have been at once: the node's
    /// download window as seen from here.
    outstanding: std::collections::HashSet<[u8; 32]>,
    window: usize,
    last_activity: Instant,
    /// When [`Session::pump`] last looked for a stopped process in the node's group.
    stop_check: Instant,
    pong: Option<(u64, bool)>,
    answers: HashMap<u64, Value>,
    next_query: u64,
    stopped: Option<Value>,
    node_error: Option<String>,
    problems: Vec<String>,
    stderr_path: PathBuf,
    /// When each case block was last sent, and the requests for one sent less than
    /// [`CASE_RESEND`] ago.
    case_sent: HashMap<[u8; 32], Instant>,
    deferred: Vec<[u8; 32]>,
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl<'a> Session<'a> {
    /// Starts the node. With `initial`, the runner offers the chain up to that case's parent and
    /// the case block from the start, so the case block ends the node's initial synchronization.
    fn start(
        cfg: &Config,
        sc: &'a Scenario,
        dir: &Path,
        initial: Option<usize>,
    ) -> Result<Session<'a>, String> {
        let node_dir = dir.join("node");
        std::fs::create_dir_all(&node_dir)
            .map_err(|e| format!("cannot create {}: {e}", node_dir.display()))?;
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| format!("cannot listen: {e}"))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let (tx, rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
        let stop_accept = Arc::new(AtomicBool::new(false));
        {
            let tx = tx.clone();
            let stop = stop_accept.clone();
            let magic = p2p::network("regtest").unwrap().magic;
            std::thread::spawn(move || listen::accept_loop(listener, magic, tx, stop));
        }
        let command = cfg
            .node
            .replace("{network}", "regtest")
            .replace("{datadir}", &node_dir.display().to_string())
            .replace("{peer}", &format!("127.0.0.1:{port}"))
            .replace("{options}", &shell_quote(&sc.options.to_string()));
        let stderr_path = dir.join("node-stderr.log");
        let stderr = std::fs::File::create(&stderr_path)
            .map_err(|e| format!("cannot create {}: {e}", stderr_path.display()))?;
        let mut child = process::spawn(
            process::shell(&command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(stderr),
        )
        .map_err(|e| format!("cannot start the node: {e}"))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stdin = child.stdin.take();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        if tx.send(Event::NodeLine(l)).is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(Event::NodeEof);
        });
        let chain_pos = sc
            .chain
            .iter()
            .enumerate()
            .map(|(i, b)| (b.hash, i))
            .collect();
        let mut s = Session {
            sc,
            timeout: cfg.node_timeout,
            rx,
            stop_accept,
            child,
            stdin,
            conn: None,
            ready: false,
            connections: 0,
            transports: BTreeSet::new(),
            chain_pos,
            upto: 0,
            requests: 0,
            confirm: initial.is_some(),
            current: None,
            x_pushed: None,
            announced: HashMap::new(),
            delivered: Default::default(),
            delivered_prefix: 0,
            queue: Vec::new(),
            last_getdata: Instant::now(),
            hold: None,
            outstanding: Default::default(),
            window: 1,
            last_activity: Instant::now(),
            stop_check: Instant::now(),
            pong: None,
            answers: HashMap::new(),
            next_query: 0,
            stopped: None,
            node_error: None,
            problems: Vec::new(),
            stderr_path,
            case_sent: HashMap::new(),
            deferred: Vec::new(),
        };
        if let Some(c) = initial {
            let parent = sc.cases[c].parent;
            s.upto = parent;
            s.current = Some(c);
            s.announced.insert(sc.cases[c].block.hash, c);
            if parent >= 1 {
                s.hold = Some((parent, None));
            }
        }
        let deadline = Instant::now() + s.timeout;
        while !s.ready {
            if Instant::now() >= deadline {
                return Err(s.with_stderr(format!(
                    "the node did not connect and complete the version handshake within {} s",
                    s.timeout.as_secs()
                )));
            }
            s.pump(Duration::from_millis(200))?;
        }
        Ok(s)
    }

    fn with_stderr(&self, message: String) -> String {
        let text = std::fs::read_to_string(&self.stderr_path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let tail = lines[lines.len().saturating_sub(3)..].join(" | ");
        if tail.is_empty() {
            message
        } else {
            format!("{message} (node stderr: {})", shorten(&tail, 300))
        }
    }

    /// Sends the queued blocks when it is time, back to back, chain blocks in chain order and the
    /// case block last: everything at once when the current case block is requested; otherwise
    /// once the node has sent no `getdata` for [`QUIET`]. While the case's parent is undelivered,
    /// the blocks that would make up the node's last download window before the case block (from
    /// [`Session::window`] blocks below it) wait for the case block's request, or for [`HOLD`], so
    /// the parent and the case block end a burst as long as the node's window.
    fn flush(&mut self) -> Result<(), String> {
        if self.queue.is_empty() {
            return Ok(());
        }
        let case = self.current.map(|c| self.sc.cases[c].block.hash);
        let mut send: Vec<[u8; 32]> = if case.is_some_and(|h| self.queue.contains(&h)) {
            std::mem::take(&mut self.queue)
        } else {
            let quiet = self.last_getdata.elapsed() >= QUIET;
            let from = self
                .hold
                .map(|(parent, _)| (parent + 2).saturating_sub(self.window).clamp(1, parent));
            let chain_pos = &self.chain_pos;
            let held =
                |h: &[u8; 32]| from.is_some_and(|f| chain_pos.get(h).is_some_and(|&p| p >= f));
            let any_held = self.queue.iter().any(held);
            let release = match &mut self.hold {
                Some((_, since)) if any_held => {
                    since.get_or_insert_with(Instant::now).elapsed() >= HOLD
                }
                _ => false,
            };
            if !quiet && !release {
                return Ok(());
            }
            let (out, keep): (Vec<[u8; 32]>, Vec<[u8; 32]>) = std::mem::take(&mut self.queue)
                .into_iter()
                .partition(|h| release || (quiet && !held(h)));
            self.queue = keep;
            out
        };
        let chain_pos = &self.chain_pos;
        send.sort_by_key(|h| chain_pos.get(h).copied().unwrap_or(usize::MAX));
        for h in send {
            self.send_block(&h)?;
        }
        if self
            .hold
            .is_some_and(|(parent, _)| self.delivered.contains(&self.sc.chain[parent].hash))
        {
            self.hold = None;
        }
        Ok(())
    }

    /// Handles at most one event, waiting up to `wait`, and the timers.
    fn pump(&mut self, wait: Duration) -> Result<(), String> {
        self.flush()?;
        if !self.deferred.is_empty() {
            let due: Vec<[u8; 32]> = self
                .deferred
                .iter()
                .copied()
                .filter(|h| {
                    self.case_sent
                        .get(h)
                        .is_none_or(|t| t.elapsed() >= CASE_RESEND)
                })
                .collect();
            self.deferred.retain(|h| !due.contains(h));
            for h in due {
                self.send_block(&h)?;
            }
        }
        let limit = if self.queue.is_empty() { 50 } else { 5 };
        match self.rx.recv_timeout(wait.min(Duration::from_millis(limit))) {
            Ok(Event::Connected(id, writer, transport)) => {
                if let Some((_, old, _)) = self.conn.take() {
                    old.close();
                }
                self.conn = Some((id, writer, transport));
                self.ready = false;
                self.connections += 1;
                self.transports.insert(transport);
            }
            Ok(Event::Message(id, m)) => {
                if self.conn.as_ref().is_some_and(|c| c.0 == id) {
                    self.on_message(m)?;
                }
            }
            Ok(Event::Closed(id, _why)) => {
                if self.conn.as_ref().is_some_and(|c| c.0 == id) {
                    self.conn = None;
                    self.ready = false;
                    // A pending barrier is met: the node dropped the connection after the blocks.
                    if let Some((_, seen)) = &mut self.pong {
                        *seen = true;
                    }
                }
            }
            Ok(Event::NodeLine(line)) => self.on_line(line),
            Ok(Event::NodeEof) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("internal: event channel closed".into())
            }
        }
        if let Some(e) = &self.node_error {
            return Err(format!("the node reported an error: {e}"));
        }
        if self.stopped.is_none() {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(self.with_stderr(format!("the node exited ({status})")));
            }
        }
        if self.stop_check.elapsed() >= process::STOP_CHECK {
            self.stop_check = Instant::now();
            if let Some(stop) = process::stopped(&self.child) {
                // Ended here, since a stopped node cannot act on the EOF `Session::end` waits on.
                process::end(&mut self.child);
                return Err(self.with_stderr(format!("the node command {stop}")));
            }
        }
        Ok(())
    }

    fn on_line(&mut self, line: String) {
        if !line.starts_with('{') {
            return;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => match v["event"].as_str() {
                Some("tip") => {
                    if let Some(id) = v["id"].as_u64() {
                        self.answers.insert(id, v);
                    }
                }
                Some("stopped") => self.stopped = Some(v),
                Some("error") => self.node_error = Some(shorten(&line, 300)),
                Some(e) if e.starts_with("x_") => {}
                _ => self
                    .problems
                    .push(format!("unexpected line: {}", shorten(&line, 200))),
            },
            Err(_) => self.problems.push(format!(
                "line starting with {{ is not JSON: {}",
                shorten(&line, 200)
            )),
        }
    }

    fn send(&mut self, command: &str, payload: &[u8]) -> Result<(), String> {
        if let Some((_, writer, _)) = &mut self.conn {
            if writer.send(command, payload).is_err() {
                // The reader thread reports the closed connection.
                writer.close();
            }
        }
        Ok(())
    }

    fn on_message(&mut self, m: Message) -> Result<(), String> {
        match m.command.as_str() {
            "version" => {
                let v2 = self.conn.as_ref().is_some_and(|c| c.2 == "v2");
                let services = NODE_NETWORK | NODE_WITNESS | if v2 { NODE_P2P_V2 } else { 0 };
                let height = self.upto + usize::from(self.current.is_some());
                let version = p2p::version_payload(services, height as i32);
                self.send("version", &version)?;
                self.send("verack", &[])?;
            }
            "verack" => self.ready = true,
            "ping" => self.send("pong", &m.payload)?,
            "pong" => {
                if let Some((nonce, seen)) = &mut self.pong {
                    if m.payload.len() == 8
                        && u64::from_le_bytes(m.payload[..8].try_into().unwrap()) == *nonce
                    {
                        *seen = true;
                    }
                }
            }
            "getheaders" => self.on_getheaders(&m.payload)?,
            "getdata" => self.on_getdata(&m.payload)?,
            _ => {}
        }
        Ok(())
    }

    /// Answers from the announced chain, as a node answers from its active chain: the headers after
    /// the first locator entry it knows (genesis if none), at most 2,000, up to the stop hash. When
    /// the answer reaches the announced end, the current case's header ends it, so the case block
    /// is the tip of the peer's best chain. A header Core rejects goes in a `headers` message of
    /// its own instead, after the answer, so that a node refusing a whole message for one bad
    /// header still gets the chain.
    fn on_getheaders(&mut self, payload: &[u8]) -> Result<(), String> {
        let Some((locator, stop)) = decode_getheaders(payload) else {
            return Ok(());
        };
        let fork = locator
            .iter()
            .find_map(|h| self.chain_pos.get(h).copied().filter(|&p| p <= self.upto))
            .unwrap_or(0);
        let mut headers: Vec<&[u8]> = Vec::new();
        let mut reached_end = fork == self.upto;
        for k in fork + 1..=self.upto {
            if headers.len() == p2p::MAX_HEADERS_RESULTS {
                break;
            }
            let b = &self.sc.chain[k];
            headers.push(&b.bytes[..80]);
            if k == self.upto {
                reached_end = true;
            }
            if b.hash == stop {
                break;
            }
        }
        let mut separate = false;
        let id = self.conn.as_ref().map(|c| c.0);
        if let (true, Some(c), Some(id)) = (reached_end, self.current, id) {
            let case = &self.sc.cases[c];
            if case.parent == self.upto && headers.len() < p2p::MAX_HEADERS_RESULTS {
                if header_rule(&case.reason) {
                    separate = true;
                } else {
                    headers.push(&case.block.bytes[..80]);
                    self.x_pushed = Some((id, c));
                }
            }
        }
        let message = encode_headers(&headers);
        self.send("headers", &message)?;
        if separate {
            self.push_case_header()?;
        }
        Ok(())
    }

    /// Sends the current case's header unless this connection already has it.
    fn push_case_header(&mut self) -> Result<(), String> {
        let (Some(c), Some(id)) = (self.current, self.conn.as_ref().map(|c| c.0)) else {
            return Ok(());
        };
        let sc: &'a Scenario = self.sc;
        if !self.ready || sc.cases[c].parent != self.upto || self.x_pushed == Some((id, c)) {
            return Ok(());
        }
        self.x_pushed = Some((id, c));
        self.send(
            "headers",
            &encode_headers(&[&sc.cases[c].block.bytes[..80]]),
        )
    }

    fn on_getdata(&mut self, payload: &[u8]) -> Result<(), String> {
        let Some(items) = decode_inv(payload) else {
            return Ok(());
        };
        let mut missing = Vec::new();
        for (kind, hash) in items {
            if kind & !MSG_WITNESS_FLAG != MSG_BLOCK {
                missing.push((kind, hash));
                continue;
            }
            self.last_activity = Instant::now();
            self.last_getdata = Instant::now();
            if self.chain_pos.contains_key(&hash) {
                self.requests += 1;
                self.outstanding.insert(hash);
                self.window = self.window.max(self.outstanding.len());
            }
            if self.lookup(&hash).is_none() {
                missing.push((kind, hash));
            } else if !self.queue.contains(&hash) {
                self.queue.push(hash);
            }
        }
        if !missing.is_empty() {
            let mut p = Vec::new();
            write_compact_size(&mut p, missing.len() as u64);
            for (kind, hash) in missing {
                p.extend_from_slice(&kind.to_le_bytes());
                p.extend_from_slice(&hash);
            }
            self.send("notfound", &p)?;
        }
        Ok(())
    }

    /// The bytes of an announced chain block or case block.
    fn lookup(&self, hash: &[u8; 32]) -> Option<&'a [u8]> {
        let sc: &'a Scenario = self.sc;
        if let Some(&k) = self.chain_pos.get(hash) {
            return (k >= 1 && k <= self.upto).then(|| sc.chain[k].bytes.as_slice());
        }
        self.announced
            .get(hash)
            .map(|&c| sc.cases[c].block.bytes.as_slice())
    }

    fn send_block(&mut self, hash: &[u8; 32]) -> Result<(), String> {
        let Some(bytes) = self.lookup(hash) else {
            return Ok(());
        };
        if !self.chain_pos.contains_key(hash) {
            if self
                .case_sent
                .get(hash)
                .is_some_and(|t| t.elapsed() < CASE_RESEND)
            {
                if !self.deferred.contains(hash) {
                    self.deferred.push(*hash);
                }
                return Ok(());
            }
            self.case_sent.insert(*hash, Instant::now());
        }
        self.send("block", bytes)?;
        self.delivered.insert(*hash);
        self.outstanding.remove(hash);
        self.last_activity = Instant::now();
        while self.delivered_prefix < self.upto
            && self
                .delivered
                .contains(&self.sc.chain[self.delivered_prefix + 1].hash)
        {
            self.delivered_prefix += 1;
        }
        Ok(())
    }

    /// Announces the chain up to `to` with unsolicited `headers` messages.
    fn extend(&mut self, to: usize) -> Result<(), String> {
        if to <= self.upto {
            return Ok(());
        }
        let from = self.upto + 1;
        self.upto = to;
        self.current = None;
        while self.delivered_prefix < self.upto
            && self
                .delivered
                .contains(&self.sc.chain[self.delivered_prefix + 1].hash)
        {
            self.delivered_prefix += 1;
        }
        let sc: &'a Scenario = self.sc;
        for chunk in sc.chain[from..=to].chunks(p2p::MAX_HEADERS_RESULTS) {
            let headers: Vec<&[u8]> = chunk.iter().map(|b| &b.bytes[..80]).collect();
            self.send("headers", &encode_headers(&headers))?;
        }
        Ok(())
    }

    /// Announces case `c` in a `headers` message of its own. When its parent has not been delivered,
    /// the window of requests that holds the parent is held back until the node asks for the case
    /// block (see [`Session::flush`]).
    fn announce(&mut self, c: usize) -> Result<(), String> {
        let sc: &'a Scenario = self.sc;
        let case = &sc.cases[c];
        self.current = Some(c);
        self.announced.insert(case.block.hash, c);
        if case.parent >= 1 && !self.delivered.contains(&sc.chain[case.parent].hash) {
            self.hold = Some((case.parent, None));
        }
        self.push_case_header()
    }

    /// Waits until chain blocks 1 to `upto` are delivered, and the case block too when `case` is
    /// given (or the node has not asked for it within [`REQUEST_WAIT`]).
    fn wait_delivered(&mut self, case: Option<&[u8; 32]>) -> Result<(), String> {
        let mut complete_since: Option<Instant> = None;
        self.last_activity = Instant::now();
        loop {
            if self.delivered_prefix >= self.upto {
                let since = *complete_since.get_or_insert_with(Instant::now);
                match case {
                    None => return Ok(()),
                    Some(h) if self.delivered.contains(h) => return Ok(()),
                    Some(_) if since.elapsed() >= REQUEST_WAIT => return Ok(()),
                    Some(_) => {}
                }
            }
            if self.last_activity.elapsed() >= STALL {
                let missing = self.delivered_prefix + 1;
                return Err(self.with_stderr(format!(
                    "no block requested for {} s; chain block {missing} ({}) of {} not delivered{}",
                    STALL.as_secs(),
                    shorten(&self.sc.chain[missing].display(), 16),
                    self.upto,
                    if self.conn.is_none() {
                        ", and the node is not connected"
                    } else {
                        ""
                    }
                )));
            }
            self.pump(Duration::from_millis(50))?;
        }
    }

    /// `ping` and the matching `pong`: every message sent before it was read. A connection the
    /// node closes meets the barrier too.
    fn barrier(&mut self) -> Result<(), String> {
        if !self.ready {
            return Ok(());
        }
        let nonce = u64::from_le_bytes(
            sha256d(&format!("{:?}{}", Instant::now(), self.next_query).into_bytes())[..8]
                .try_into()
                .unwrap(),
        );
        self.pong = Some((nonce, false));
        self.send("ping", &nonce.to_le_bytes())?;
        let deadline = Instant::now() + self.timeout;
        while !self.pong.is_some_and(|p| p.1) {
            if Instant::now() >= deadline {
                return Err(format!("no pong within {} s", self.timeout.as_secs()));
            }
            self.pump(Duration::from_millis(50))?;
        }
        self.pong = None;
        Ok(())
    }

    fn write_line(&mut self, line: &str) -> Result<(), String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or("the node's standard input is closed")?;
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|_| stdin.flush())
            .map_err(|e| format!("cannot write to the node's standard input: {e}"))
    }

    /// Asks the node for its tip: (hash, height).
    fn query_tip(&mut self) -> Result<(String, i64), String> {
        self.next_query += 1;
        let id = self.next_query;
        self.write_line(&json!({"op": "tip", "id": id}).to_string())?;
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(v) = self.answers.remove(&id) {
                return match (v["tip"].as_str(), v["height"].as_i64()) {
                    (Some(t), Some(h)) => Ok((t.to_string(), h)),
                    _ => Err(format!("tip answer without tip and height: {v}")),
                };
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "no answer to tip request {id} within {} s",
                    self.timeout.as_secs()
                ));
            }
            self.pump(Duration::from_millis(50))?;
        }
    }

    /// The id of the node's connection once its handshake is complete.
    fn link(&self) -> Option<u64> {
        self.conn.as_ref().filter(|_| self.ready).map(|c| c.0)
    }

    /// The node's tip once it has settled. After the barrier the runner asks for the tip. An answer
    /// other than `want` (and, with `confirm`, any answer) is taken only when the next answer,
    /// asked after the node has requested no chain block for [`SETTLE`] on one open connection, is
    /// the same with no chain block requested and no connection opened or closed in between; until
    /// then the runner keeps serving, so a node that drops blocks it already had and fetches them
    /// again, or drops the runner and connects again, is judged on where it ends.
    fn settled_tip(
        &mut self,
        want: &str,
        want_height: i64,
        confirm: bool,
    ) -> Result<(String, i64), String> {
        let deadline = Instant::now() + self.timeout;
        let mut previous: Option<(String, i64, u64, Option<u64>)> = None;
        loop {
            self.barrier()?;
            let answer = self.query_tip()?;
            let (requests, link) = (self.requests, self.link());
            if previous.as_ref().is_some_and(|p| {
                p.0 == answer.0 && p.1 == answer.1 && p.2 == requests && p.3 == link
            }) && link.is_some()
            {
                return Ok(answer);
            }
            if !confirm && previous.is_none() && answer.0 == want && answer.1 == want_height {
                return Ok(answer);
            }
            if Instant::now() >= deadline {
                return Ok(answer);
            }
            previous = Some((answer.0, answer.1, requests, link));
            // Quiet: no chain block requested for SETTLE on one open connection, and none left to
            // send.
            let mut quiet_since = Instant::now();
            let mut seen = (self.requests, self.link());
            while quiet_since.elapsed() < SETTLE && Instant::now() < deadline {
                self.pump(Duration::from_millis(50))?;
                let queued = self.queue.iter().any(|h| self.chain_pos.contains_key(h));
                let now = (self.requests, self.link());
                if now != seen || now.1.is_none() || queued {
                    seen = now;
                    quiet_since = Instant::now();
                }
            }
        }
    }

    /// Runs one case: Ok(None) when the tip is the parent, Ok(Some(mismatch)) otherwise. The
    /// case of a session started with `initial` is already announced.
    fn run_case(&mut self, c: usize) -> Result<Option<String>, String> {
        let sc: &'a Scenario = self.sc;
        let case = &sc.cases[c];
        if self.current != Some(c) {
            self.extend(case.parent)?;
            self.announce(c)?;
        }
        self.wait_delivered(Some(&case.block.hash))?;
        let want = &sc.chain[case.parent];
        let (tip, height) = self.settled_tip(&want.display(), case.parent as i64, self.confirm)?;
        Ok(
            (tip != want.display() || height != case.parent as i64).then(|| {
                format!(
                    "tip {} height {height}, expected {} height {} (the block was {}, Core: {}){}",
                    short(&tip),
                    short(&want.display()),
                    case.parent,
                    if self.delivered.contains(&case.block.hash) {
                        "delivered"
                    } else {
                        "announced, never requested"
                    },
                    case.reason,
                    if tip == case.block.display() {
                        "; the tip is the rejected block"
                    } else {
                        ""
                    }
                )
            }),
        )
    }

    /// The end: the whole chain, the final tip, then `stop`.
    fn finish(&mut self) -> Result<Option<String>, String> {
        let n = self.sc.chain.len() - 1;
        self.extend(n)?;
        self.current = None;
        self.wait_delivered(None)?;
        let want = self.sc.chain[n].display();
        let (tip, height) = self.settled_tip(&want, n as i64, self.confirm)?;
        if tip != want || height != n as i64 {
            return Ok(Some(format!(
                "tip {} height {height}, expected the final tip {} height {n}",
                short(&tip),
                short(&want)
            )));
        }
        self.write_line(&json!({"op": "stop"}).to_string())?;
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.stopped.is_none() {
            if Instant::now() >= deadline {
                return Err("no stopped line within 60 s of the stop request".into());
            }
            self.pump(Duration::from_millis(50))?;
        }
        let stopped = self.stopped.clone().unwrap();
        let status = wait_exit(&mut self.child, Duration::from_secs(60));
        let mut problems = Vec::new();
        if stopped["tip"].as_str() != Some(want.as_str())
            || stopped["height"].as_i64() != Some(n as i64)
        {
            problems.push(format!(
                "stopped line {stopped}, expected tip {want} height {n}"
            ));
        }
        match status {
            Some(s) if s.success() => {}
            Some(s) => problems.push(format!("the node exited with {s} after its stopped line")),
            None => problems.push("the node did not exit within 60 s of its stopped line".into()),
        }
        problems.append(&mut self.problems);
        Ok((!problems.is_empty()).then(|| problems.join("; ")))
    }

    /// Ends the node: standard input closed; then, after 10 seconds, whatever is left of its
    /// process group ([`process::end`]). Ending it again does nothing.
    fn end(&mut self) {
        self.stdin = None;
        let _ = wait_exit(&mut self.child, Duration::from_secs(10));
        process::end(&mut self.child);
        if let Some((_, w, _)) = self.conn.take() {
            w.close();
        }
        self.stop_accept.store(true, Ordering::Relaxed);
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.end();
    }
}

fn wait_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => return None,
        }
    }
}

/// Core's reasons for a header it rejects (`CheckBlockHeader`, `ContextualCheckBlockHeader`).
fn header_rule(reason: &str) -> bool {
    [
        "high-hash",
        "bad-diffbits",
        "time-too-old",
        "time-too-new",
        "time-timewarp-attack",
        "bad-version",
        "bad-prevblk",
        "checkpoint",
    ]
    .iter()
    .any(|p| reason.starts_with(p))
}

fn short(hash: &str) -> String {
    if hash.len() == 64 {
        format!("{}..{}", &hash[..8], &hash[56..])
    } else {
        hash.to_string()
    }
}

fn encode_headers(headers: &[&[u8]]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + headers.len() * 81);
    write_compact_size(&mut p, headers.len() as u64);
    for h in headers {
        p.extend_from_slice(&h[..80]);
        p.push(0);
    }
    p
}

fn decode_getheaders(payload: &[u8]) -> Option<(Vec<[u8; 32]>, [u8; 32])> {
    let mut pos = 4;
    let n = p2p::read_compact_size(payload, &mut pos).ok()? as usize;
    if n > 101 || payload.len() != pos + 32 * n + 32 {
        return None;
    }
    let locator = (0..n)
        .map(|i| {
            payload[pos + 32 * i..pos + 32 * (i + 1)]
                .try_into()
                .unwrap()
        })
        .collect();
    let stop = payload[pos + 32 * n..].try_into().unwrap();
    Some((locator, stop))
}

fn decode_inv(payload: &[u8]) -> Option<Vec<(u32, [u8; 32])>> {
    let mut pos = 0;
    let n = p2p::read_compact_size(payload, &mut pos).ok()? as usize;
    if n > 50_000 || payload.len() != pos + 36 * n {
        return None;
    }
    Some(
        (0..n)
            .map(|i| {
                let at = pos + 36 * i;
                (
                    u32::from_le_bytes(payload[at..at + 4].try_into().unwrap()),
                    payload[at + 4..at + 36].try_into().unwrap(),
                )
            })
            .collect(),
    )
}

/// Counts of one mode (follow or ibd) of one scenario.
#[derive(Default)]
struct ModeResult {
    cases: u64,
    passed: u64,
    failed: u64,
    not_run: u64,
    nodes: u64,
}

impl ModeResult {
    fn text(&self) -> String {
        let mut t = format!("{}/{}", self.passed, self.cases);
        if self.not_run > 0 {
            t.push_str(&format!(" ({} not run)", self.not_run));
        }
        t
    }
}

/// What every check of one scenario shares.
struct Scope<'a> {
    cfg: &'a Config,
    sc: &'a Scenario,
    root: &'a Path,
    verbose: bool,
}

/// Runs `checks` in order, each a case index or `None` for the final tip. `fresh` starts a new node
/// for every check (the ibd mode); otherwise one node runs them all, and a failed check ends it so
/// the next check starts a new one (the follow mode).
fn run_checks(
    scope: &Scope,
    mode: &str,
    checks: &[Option<usize>],
    fresh: bool,
    stats: &mut Stats,
    transports: &mut BTreeSet<&'static str>,
) -> ModeResult {
    let Scope {
        cfg,
        sc,
        root,
        verbose,
    } = *scope;
    let mut r = ModeResult::default();
    let mut session: Option<Session> = None;
    let mut node_errors = 0u32;
    // Ends the node; its directory goes unless one of its checks failed or --keep-temp.
    let close = |session: &mut Option<Session>, failed: bool, nodes: u64| {
        if let Some(mut s) = session.take() {
            s.end();
            if !failed && !cfg.keep_temp {
                let _ = std::fs::remove_dir_all(root.join(format!("{mode}-{nodes}")));
            }
        }
    };
    for (i, check) in checks.iter().enumerate() {
        if node_errors >= MAX_NODE_ERRORS {
            r.not_run = (checks.len() - i) as u64;
            stats.fail(
                SUITE,
                verbose,
                &format!("{} {mode} not run", sc.name),
                &format!(
                    "{} checks not run after {MAX_NODE_ERRORS} node failures in a row",
                    r.not_run
                ),
            );
            break;
        }
        let loc = match check {
            Some(c) => format!("{} {mode} {}", sc.name, sc.cases[*c].block.display()),
            None => format!("{} {mode} final tip", sc.name),
        };
        if session.is_none() {
            r.nodes += 1;
            let dir = root.join(format!("{mode}-{}", r.nodes));
            match Session::start(cfg, sc, &dir, check.filter(|_| fresh)) {
                Ok(s) => session = Some(s),
                Err(e) => {
                    node_errors += 1;
                    r.cases += 1;
                    r.failed += 1;
                    stats.fail(SUITE, verbose, &loc, &e);
                    continue;
                }
            }
        }
        let s = session.as_mut().unwrap();
        let outcome = match check {
            Some(c) => s.run_case(*c),
            None => s.finish(),
        };
        transports.extend(s.transports.iter().copied());
        r.cases += 1;
        let failed = match outcome {
            Ok(None) => {
                node_errors = 0;
                r.passed += 1;
                stats.pass();
                false
            }
            Ok(Some(mismatch)) => {
                node_errors = 0;
                stats.fail(SUITE, verbose, &loc, &mismatch);
                true
            }
            Err(e) => {
                node_errors += 1;
                stats.fail(SUITE, verbose, &loc, &e);
                true
            }
        };
        if failed {
            r.failed += 1;
        }
        if failed || fresh {
            close(&mut session, failed, r.nodes);
        }
    }
    close(&mut session, false, r.nodes);
    r
}

/// At most `limit` of `n` indices, evenly spaced, first and last included.
fn sample(n: usize, limit: Option<usize>) -> Vec<usize> {
    match limit {
        Some(k) if k < n => {
            if k == 0 {
                return Vec::new();
            }
            if k == 1 {
                return vec![0];
            }
            let mut out: Vec<usize> = (0..k).map(|i| i * (n - 1) / (k - 1)).collect();
            out.dedup();
            out
        }
        _ => (0..n).collect(),
    }
}

pub fn run(stats: &mut Stats, verbose: bool, cfg: &Config) -> Result<(), String> {
    if !cfg.bitcoind.is_file() {
        return Err(format!(
            "--bitcoind {} is not a file",
            cfg.bitcoind.display()
        ));
    }
    if cfg.node.contains("{stop_at}") {
        return Err(RULE_STOP_AT.into());
    }
    let files = corpus::corpus_files(&cfg.corpus)?;
    if files.is_empty() {
        stats.details.push("peer-sync: no corpus files".into());
        return Ok(());
    }
    stats.details.push(format!(
        "{:<34} {:>6} {:>6} {:>13} {:>13} {:>5} {:>8}  {}",
        "peer-sync scenario", "height", "cases", "follow", "ibd", "nodes", "time", "detail"
    ));
    let base = std::env::temp_dir().join(format!("bcs-peer-sync-{}", std::process::id()));
    let mut totals = (ModeResult::default(), ModeResult::default());
    for (i, file) in files.iter().enumerate() {
        let started = Instant::now();
        let name = file
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_end_matches(".jsonl.gz")
            .to_string();
        let root = base.join(format!("{i:03}-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        eprintln!("peer-sync: {name} ({} of {})", i + 1, files.len());
        let line =
            |height: &str, cases: &str, follow: &str, ibd: &str, nodes: &str, detail: &str| {
                format!(
                    "{:<34} {:>6} {:>6} {:>13} {:>13} {:>5} {:>7.1}s  {}",
                    shorten(&name, 34),
                    height,
                    cases,
                    follow,
                    ibd,
                    nodes,
                    started.elapsed().as_secs_f64(),
                    detail
                )
            };
        let loaded = match load(file) {
            Ok(l) => l,
            Err(e) => {
                stats.fail(SUITE, verbose, &format!("{name} setup"), &e);
                stats
                    .details
                    .push(line("-", "-", "-", "-", "-", &format!("ERROR {e}")));
                continue;
            }
        };
        if loaded.options.as_object().is_some_and(|o| !o.is_empty())
            && !cfg.node.contains("{options}")
        {
            stats.rule(interop::RULE_NEEDS_OPTIONS, 1);
            stats.details.push(line(
                "-",
                "-",
                "-",
                "-",
                "-",
                &format!("excluded: options {}", loaded.options),
            ));
            continue;
        }
        if loaded.max_time > p2p::unix_now() + 7200 {
            stats.rule(interop::RULE_FUTURE_BLOCKS, 1);
            stats.details.push(line(
                "-",
                "-",
                "-",
                "-",
                "-",
                "excluded: blocks dated in the future",
            ));
            continue;
        }
        let height = (loaded.chain.len() - 1).to_string();
        let sc = match classify(cfg, &name, loaded, &root.join("classify")) {
            Ok(sc) => sc,
            Err(e) => {
                stats.fail(SUITE, verbose, &format!("{name} setup"), &e);
                stats.details.push(line(
                    &height,
                    "-",
                    "-",
                    "-",
                    "-",
                    &format!("ERROR {e} (files kept in {})", root.display()),
                ));
                continue;
            }
        };
        if verbose {
            let mut reasons: BTreeMap<&str, u64> = BTreeMap::new();
            for c in &sc.cases {
                *reasons.entry(c.reason.as_str()).or_default() += 1;
            }
            println!(
                "CASES    [{SUITE}] {name}: {} blocks Core rejects ({}), {} valid siblings left out, {} not classified",
                sc.cases.len(),
                reasons.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "),
                sc.valid_siblings,
                sc.unclassified.len()
            );
            for u in &sc.unclassified {
                println!("         not classified: {u}");
            }
        }
        let mut transports = BTreeSet::new();
        let follow_checks: Vec<Option<usize>> =
            (0..sc.cases.len()).map(Some).chain([None]).collect();
        let scope = Scope {
            cfg,
            sc: &sc,
            root: &root,
            verbose,
        };
        let follow = run_checks(
            &scope,
            "follow",
            &follow_checks,
            false,
            stats,
            &mut transports,
        );
        let picked = sample(sc.cases.len(), cfg.ibd_limit);
        let ibd_checks: Vec<Option<usize>> = picked.iter().map(|&c| Some(c)).collect();
        let ibd = run_checks(&scope, "ibd", &ibd_checks, true, stats, &mut transports);
        let left_out = (sc.cases.len() - picked.len()) as u64;
        if left_out > 0 {
            stats.rule(RULE_IBD_LIMIT, left_out);
        }
        let mut detail = format!(
            "transport {}, {} valid siblings left out",
            if transports.is_empty() {
                "none".to_string()
            } else {
                transports.iter().copied().collect::<Vec<_>>().join("+")
            },
            sc.valid_siblings
        );
        if left_out > 0 {
            detail.push_str(&format!(
                ", ibd sample {} of {}",
                picked.len(),
                sc.cases.len()
            ));
        }
        if !sc.unclassified.is_empty() {
            detail.push_str(&format!(", {} not classified", sc.unclassified.len()));
        }
        if follow.failed + ibd.failed + follow.not_run + ibd.not_run > 0 {
            detail.push_str(&format!(" (files kept in {})", root.display()));
        } else if !cfg.keep_temp {
            let _ = std::fs::remove_dir_all(&root);
        }
        stats.details.push(line(
            &height,
            &sc.cases.len().to_string(),
            &follow.text(),
            &ibd.text(),
            &(follow.nodes + ibd.nodes).to_string(),
            &detail,
        ));
        for (t, r) in [(&mut totals.0, &follow), (&mut totals.1, &ibd)] {
            t.cases += r.cases;
            t.passed += r.passed;
            t.failed += r.failed;
            t.not_run += r.not_run;
            t.nodes += r.nodes;
        }
    }
    stats.details.push(format!(
        "peer-sync total: follow {} passed, ibd {} passed, {} nodes started",
        totals.0.text(),
        totals.1.text(),
        totals.0.nodes + totals.1.nodes
    ));
    let _ = std::fs::remove_dir(&base);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getheaders_and_inv_payloads() {
        let mut p = 70016u32.to_le_bytes().to_vec();
        p.push(2);
        p.extend_from_slice(&[1u8; 32]);
        p.extend_from_slice(&[2u8; 32]);
        p.extend_from_slice(&[0u8; 32]);
        let (locator, stop) = decode_getheaders(&p).unwrap();
        assert_eq!(locator, vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(stop, [0u8; 32]);
        assert!(decode_getheaders(&p[..p.len() - 1]).is_none());

        let mut inv = vec![2u8];
        inv.extend_from_slice(&(MSG_BLOCK | MSG_WITNESS_FLAG).to_le_bytes());
        inv.extend_from_slice(&[3u8; 32]);
        inv.extend_from_slice(&1u32.to_le_bytes());
        inv.extend_from_slice(&[4u8; 32]);
        assert_eq!(
            decode_inv(&inv).unwrap(),
            vec![(MSG_BLOCK | MSG_WITNESS_FLAG, [3u8; 32]), (1, [4u8; 32])]
        );
        assert!(decode_inv(&inv[..40]).is_none());
    }

    #[test]
    fn evenly_spaced_sample() {
        assert_eq!(sample(5, None), vec![0, 1, 2, 3, 4]);
        assert_eq!(sample(5, Some(10)), vec![0, 1, 2, 3, 4]);
        assert_eq!(sample(10, Some(4)), vec![0, 3, 6, 9]);
        assert_eq!(sample(10, Some(1)), vec![0]);
        assert!(sample(10, Some(0)).is_empty());
        assert_eq!(sample(2577, Some(32)).len(), 32);
    }

    #[test]
    fn headers_message() {
        let h = [7u8; 80];
        let m = encode_headers(&[&h, &h]);
        assert_eq!(m.len(), 1 + 2 * 81);
        assert_eq!(m[0], 2);
        assert_eq!(m[81], 0);
        assert_eq!(p2p::decode_headers(&m).unwrap(), vec![h, h]);
    }
}
