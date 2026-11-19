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
//!    candidates are left out (counted in the details). A final-chain block recorded with other
//!    bytes too (a duplicated transaction, a changed witness) has each of them put to proposal
//!    mode before it is submitted; those Core rejects are its damaged copies.
//! 2. **Serving.** The node command (`--sync-node`) starts with `{peer}` set to the runner's
//!    listener. The runner accepts the version 1 transport and BIP324 version 2 (a node may
//!    reconnect at any time), answers `version`, `ping` and `getheaders` (from the chain it has
//!    announced so far, then the current case's header), and serves the blocks it announced.
//!    A chain block with damaged copies is answered with them first, one per request, and only
//!    then with the block itself, so a node that marks the hash invalid on a damaged copy, or
//!    accepts one, never gets the chain.
//!    Requested blocks go out in bursts: once the node has sent no `getdata` for [`QUIET`], all of
//!    them, back to back in chain order. The burst that holds a case's parent waits for the
//!    node's request of the case block (at most [`HOLD`]), and the case block goes last, so the
//!    two arrive together at the end of a run of blocks, as during initial block download.
//! 3. **Checks.** When every chain block up to the parent is delivered, and the case block too, the
//!    runner sends `ping`, waits for the `pong`, and asks the node for its tip on standard input
//!    ([`Session::settled_tip`]). While the node is not connected the runner waits for it to come
//!    back and serves the case then. Only a case whose header breaks a rule may pass without its
//!    block: one the node was sent on an open connection and did not ask for within
//!    [`REQUEST_WAIT`]. Any other case fails when the node, after answering a tip request, still
//!    does not ask for the block within [`REQUEST_WAIT`]. The details count the case blocks
//!    delivered.
//!
//! Each scenario runs in two modes:
//!
//! - **follow**: one node takes every case in chain order (the chain up to the parent announced
//!   with unsolicited `headers`, then the case header), then the rest of the chain: its tip must be
//!   the final tip, and after `{"op":"stop"}` its `stopped` line must name it and the node must exit
//!   with status 0. The line's `hash_serialized_3`, when present, must equal what the classifying
//!   bitcoind reported at the final tip; a line without it is counted at level 2, as in the interop
//!   suite. Before the chain is extended past a parent, the node is asked for its tip once more,
//!   which must still be the parent. A failed check ends the node and the next check starts a
//!   fresh one, so one divergence does not hide the checks after it.
//! - **ibd**: a fresh node per case, whose peer offers the chain up to the parent and the case
//!   block as its best chain from the start, so the case block ends the node's initial block
//!   download. Some implementations validate initial block download in batches and only then
//!   (rbitcoin-org/rbitcoin#1537 accepted a block re-spending an output its parent had created and
//!   spent, after a merged write of the two was rejected and retried one block at a time).
//!   `--ibd-limit` bounds the cases per scenario (default 32, evenly spaced).

use crate::bitcoind::{free_ports, Bitcoind};
use crate::check::{short_hash, shorten, Stats};
use crate::hex;
use crate::listen::{self, Event, SendError, Writer};
use crate::p2p::{self, Message};
use crate::process;
use crate::suites::{corpus, interop};
use crate::tx::{sha256d, write_compact_size};
use crate::work::U256;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
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

/// Other bytes recorded for a final-chain block, which Core rejects: what a peer that damaged
/// the block in transit would send.
struct Damaged {
    bytes: Vec<u8>,
    reason: String,
}

/// A block Core rejects on top of chain block `parent`.
struct Case {
    parent: usize,
    block: Block,
    reason: String,
}

impl Case {
    /// Whether a node must ask for the block: its header breaks none of Core's header rules, so
    /// only the block shows what is wrong. Proposal mode skips proof of work, which is therefore
    /// checked here.
    fn requestable(&self) -> bool {
        !header_rule(&self.reason) && pow_ok(&self.block.bytes[..80])
    }
}

/// Core's `CheckProofOfWork` on a regtest header, whose bits Core has already checked.
fn pow_ok(header: &[u8]) -> bool {
    let bits = u32::from_le_bytes(header[72..76].try_into().unwrap());
    U256::from_compact(bits)
        .is_some_and(|t| !t.is_zero() && U256::from_le_bytes(&sha256d(&header[..80])) <= t)
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

/// The scenario after classification: the final chain with the variant Core accepted, Core's
/// `hash_serialized_3` at its tip, the cases in chain order, and what was left out.
struct Scenario {
    name: String,
    options: Value,
    chain: Vec<Block>,
    utxo_hash: String,
    cases: Vec<Case>,
    /// Damaged copies of chain blocks, by height, in file order.
    damaged: HashMap<usize, Vec<Damaged>>,
    /// Other bytes of chain blocks that are not served: larger than a P2P message, or not a
    /// block Core can decode (Core drops such a message and keeps waiting for the block).
    damaged_left_out: usize,
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
    let mut damaged = HashMap::new();
    let mut damaged_left_out = 0;
    let mut valid_siblings = 0;
    let mut unclassified = Vec::new();
    for (height, (hash, list)) in loaded.chain.iter().enumerate() {
        if height > 0 {
            // Proposed while the parent is the tip and before any copy is submitted: a rejected
            // submission can leave the header known, and a proposal of a known hash is answered
            // `duplicate-inconclusive`.
            let mut copies = Vec::new();
            for bytes in list.iter().filter(|_| list.len() > 1) {
                let proposal =
                    json!([{"mode": "proposal", "data": hex::encode(bytes), "rules": ["segwit"]}]);
                match core.rpc("getblocktemplate", proposal) {
                    Ok(Value::Null) => {}
                    Ok(Value::String(reason))
                        if !reason.starts_with("duplicate")
                            && !reason.starts_with("inconclusive")
                            && bytes.len() <= p2p::MAX_MESSAGE_LENGTH =>
                    {
                        copies.push(Damaged {
                            bytes: bytes.clone(),
                            reason,
                        })
                    }
                    _ => damaged_left_out += 1,
                }
            }
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
            copies.retain(|d| d.bytes != bytes);
            if !copies.is_empty() {
                damaged.insert(height, copies);
            }
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
    let tip = chain[chain.len() - 1].display();
    let utxo = core.rpc("gettxoutsetinfo", json!(["hash_serialized_3"]))?;
    if utxo["bestblock"].as_str() != Some(tip.as_str()) {
        return Err(format!(
            "bitcoind's tip is {} after loading, the scenario's final tip is {tip}",
            utxo["bestblock"]
        ));
    }
    let utxo_hash = utxo["hash_serialized_3"]
        .as_str()
        .ok_or_else(|| format!("gettxoutsetinfo answered {utxo}"))?
        .to_string();
    core.stop();
    Ok(Scenario {
        name: name.to_string(),
        options: loaded.options,
        chain,
        utxo_hash,
        cases,
        damaged,
        damaged_left_out,
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
    /// The `stop` request has been written.
    stop_sent: bool,
    /// The node closed its standard output, and every line of it has been handled.
    stdout_closed: bool,
    /// Set by [`Session::finish`] once the stopped line names the final tip: whether it carried
    /// `hash_serialized_3`.
    utxo_reported: Option<bool>,
    node_error: Option<String>,
    problems: Vec<String>,
    stderr_path: PathBuf,
    /// When each case block was last sent, and the requests for one sent less than
    /// [`CASE_RESEND`] ago.
    case_sent: HashMap<[u8; 32], Instant>,
    deferred: Vec<[u8; 32]>,
    /// Damaged copies sent so far, by chain height.
    damaged_sent: HashMap<usize, usize>,
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
            for line in process::output_lines(stdout) {
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
        let mut s = Session::new(
            sc,
            cfg.node_timeout,
            rx,
            stop_accept,
            child,
            stdin,
            stderr_path,
        );
        if let Some(c) = initial {
            let parent = sc.cases[c].parent;
            s.confirm = true;
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

    /// A session with nothing announced yet, for a node already started.
    fn new(
        sc: &'a Scenario,
        timeout: Duration,
        rx: Receiver<Event>,
        stop_accept: Arc<AtomicBool>,
        child: process::Group,
        stdin: Option<ChildStdin>,
        stderr_path: PathBuf,
    ) -> Session<'a> {
        let chain_pos = sc
            .chain
            .iter()
            .enumerate()
            .map(|(i, b)| (b.hash, i))
            .collect();
        Session {
            sc,
            timeout,
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
            confirm: false,
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
            stop_sent: false,
            stdout_closed: false,
            utxo_reported: None,
            node_error: None,
            problems: Vec::new(),
            stderr_path,
            case_sent: HashMap::new(),
            deferred: Vec::new(),
            damaged_sent: HashMap::new(),
        }
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
                    self.drop_connection();
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
                    self.drop_connection();
                }
            }
            Ok(Event::NodeLine(line)) => self.on_line(line),
            Ok(Event::NodeEof) => self.stdout_closed = true,
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
                // After `stop`, the stopped line can still be queued behind other events, so the
                // exit is an error only once the output is all read. Output a leftover process
                // keeps open is left to the stop request's deadline.
                if !self.stop_sent || self.stdout_closed {
                    return Err(self.with_stderr(format!("the node exited ({status})")));
                }
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

    /// The node's connection is gone. Its requests went with it (a node asks again on its next
    /// connection), and a pending barrier is met: the node dropped the connection after the blocks.
    fn drop_connection(&mut self) {
        self.ready = false;
        self.queue.clear();
        self.deferred.clear();
        self.outstanding.clear();
        if let Some((_, seen)) = &mut self.pong {
            *seen = true;
        }
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

    /// Writes a message to the node's connection. Returns whether it was written: without a
    /// connection, or when the write fails, nothing is sent. A node that takes no byte of it for
    /// the timeout, or is stopped, is an error, since [`Session::pump`] does not run meanwhile.
    fn send(&mut self, command: &str, payload: &[u8]) -> Result<bool, String> {
        let (Some((_, writer, _)), child) = (&mut self.conn, &mut self.child) else {
            return Ok(false);
        };
        let timeout = self.timeout;
        let sent = writer.send(command, payload, |idle| {
            if let Some(stop) = process::stopped(child) {
                // As in `Session::pump`: a stopped node cannot act on the EOF `Session::end`
                // waits on.
                process::end(child);
                return Err(format!("the node command {stop}"));
            }
            if idle >= timeout {
                return Err(format!(
                    "the node read none of a `{command}` message for {} s",
                    timeout.as_secs()
                ));
            }
            Ok(())
        });
        match sent {
            Ok(()) => Ok(true),
            Err(SendError::Closed) => {
                // The reader thread reports the closed connection.
                writer.close();
                Ok(false)
            }
            Err(SendError::Stalled(e)) => Err(self.with_stderr(e)),
        }
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
            "ping" => {
                self.send("pong", &m.payload)?;
            }
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
        let mut pushed = None;
        let id = self.conn.as_ref().map(|c| c.0);
        if let (true, Some(c), Some(id)) = (reached_end, self.current, id) {
            let case = &self.sc.cases[c];
            if case.parent == self.upto && headers.len() < p2p::MAX_HEADERS_RESULTS {
                if header_rule(&case.reason) {
                    separate = true;
                } else {
                    headers.push(&case.block.bytes[..80]);
                    pushed = Some((id, c));
                }
            }
        }
        let message = encode_headers(&headers);
        if self.send("headers", &message)? && pushed.is_some() {
            self.x_pushed = pushed;
        }
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
        if self.send(
            "headers",
            &encode_headers(&[&sc.cases[c].block.bytes[..80]]),
        )? {
            self.x_pushed = Some((id, c));
        }
        Ok(())
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

    /// Sends a requested block. A chain block that has damaged copies not sent yet gets the next
    /// of them instead: the request is answered, and the block is not delivered.
    fn send_block(&mut self, hash: &[u8; 32]) -> Result<(), String> {
        let Some(bytes) = self.lookup(hash) else {
            return Ok(());
        };
        let sc: &'a Scenario = self.sc;
        if let Some((k, copies)) = self
            .chain_pos
            .get(hash)
            .and_then(|k| sc.damaged.get(k).map(|c| (*k, c)))
        {
            let sent = self.damaged_sent.get(&k).copied().unwrap_or(0);
            if let Some(copy) = copies.get(sent) {
                if self.send("block", &copy.bytes)? {
                    self.damaged_sent.insert(k, sent + 1);
                    self.outstanding.remove(hash);
                    self.last_activity = Instant::now();
                }
                return Ok(());
            }
        }
        let case = !self.chain_pos.contains_key(hash);
        if case
            && self
                .case_sent
                .get(hash)
                .is_some_and(|t| t.elapsed() < CASE_RESEND)
        {
            if !self.deferred.contains(hash) {
                self.deferred.push(*hash);
            }
            return Ok(());
        }
        if !self.send("block", bytes)? {
            return Ok(());
        }
        if case {
            self.case_sent.insert(*hash, Instant::now());
        }
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

    /// Waits until chain blocks 1 to `upto` are delivered, and the block of case `case` too when
    /// given. The node may give up on the case block only on an open connection that was sent
    /// its header, after [`REQUEST_WAIT`]; a requestable one ([`Case::requestable`]) also gets
    /// a tip request, so that a node that asks for blocks only once it has processed the ones
    /// before is not cut short, and [`REQUEST_WAIT`] more. While the node is not connected, the
    /// runner waits for it to connect again (up to [`STALL`]).
    fn wait_delivered(&mut self, case: Option<usize>) -> Result<(), String> {
        let sc: &'a Scenario = self.sc;
        // The connection the case header went out on, and since when it has been open with
        // nothing left to send but the case block.
        let mut waiting: Option<(u64, Instant)> = None;
        let mut asked = false;
        self.last_activity = Instant::now();
        loop {
            if self.delivered_prefix >= self.upto {
                let Some(c) = case else { return Ok(()) };
                let block = &sc.cases[c].block.hash;
                if self.delivered.contains(block) {
                    return Ok(());
                }
                let link = self.link().filter(|&id| self.x_pushed == Some((id, c)));
                let pending = self.queue.contains(block) || self.deferred.contains(block);
                match (link, waiting) {
                    (Some(id), Some((on, since)))
                        if id == on && !pending && since.elapsed() >= REQUEST_WAIT =>
                    {
                        if !sc.cases[c].requestable() || asked {
                            return Ok(());
                        }
                        asked = true;
                        self.barrier()?;
                        self.query_tip()?;
                        waiting = None;
                        continue;
                    }
                    (Some(id), Some((on, _))) if id == on && !pending => {}
                    (Some(id), _) => waiting = Some((id, Instant::now())),
                    (None, _) => waiting = None,
                }
            }
            if self.last_activity.elapsed() >= STALL {
                let missing = match (self.delivered_prefix < self.upto, case) {
                    (true, _) | (false, None) => {
                        let k = self.delivered_prefix + 1;
                        format!(
                            "chain block {k} ({}) of {}{}",
                            shorten(&sc.chain[k].display(), 16),
                            self.upto,
                            self.damaged_note(k)
                        )
                    }
                    (false, Some(c)) => format!(
                        "the block ({}) on chain block {}, whose header {}",
                        sc.cases[c].reason,
                        self.upto,
                        if self.link().is_some_and(|id| self.x_pushed == Some((id, c))) {
                            "went out on this connection"
                        } else {
                            "has not gone out on this connection"
                        }
                    ),
                };
                return Err(self.with_stderr(format!(
                    "no block requested for {} s; {missing} not delivered{}",
                    STALL.as_secs(),
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

    /// Says which damaged copies of chain block `k` went out, if any did. A node that accepted one,
    /// or marked the block invalid for it, does not ask for the block again.
    fn damaged_note(&self, k: usize) -> String {
        let sent = self.damaged_sent.get(&k).copied().unwrap_or(0);
        if sent == 0 {
            return String::new();
        }
        let reasons: Vec<&str> = self.sc.damaged[&k][..sent]
            .iter()
            .map(|d| d.reason.as_str())
            .collect();
        format!(
            ", after {sent} damaged {} of it (Core: {}): the node accepted a damaged copy or \
             marked the block invalid for one",
            if sent == 1 { "copy" } else { "copies" },
            reasons.join(", ")
        )
    }

    /// `ping` and the matching `pong`: every message sent before it was read. Returns the
    /// connection the `pong` came on; `None` when there was no connection or the node closed it,
    /// which meets the barrier too.
    fn barrier(&mut self) -> Result<Option<u64>, String> {
        let Some(id) = self.link() else {
            return Ok(None);
        };
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
        Ok((self.link() == Some(id)).then_some(id))
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

    /// The node's tip once it has settled. After the barrier the runner asks for the tip. A first
    /// answer of `want` is taken when the `pong` before it came on the connection still open
    /// after it, and `confirm` is not set. Any other answer is taken only when the next answer,
    /// asked after the node has requested no chain block for [`SETTLE`] on one open connection, is
    /// the same with no chain block requested and no connection opened or closed in between; until
    /// then the runner keeps serving, so a node that drops blocks it already had and fetches them
    /// again, or drops the runner and connects again, is judged on where it ends. A tip that has
    /// not settled by the `--node-timeout` deadline is an error.
    fn settled_tip(
        &mut self,
        want: &str,
        want_height: i64,
        confirm: bool,
    ) -> Result<(String, i64), String> {
        let deadline = Instant::now() + self.timeout;
        let mut previous: Option<(String, i64, u64, Option<u64>)> = None;
        loop {
            let pong = self.barrier()?;
            let answer = self.query_tip()?;
            let (requests, link) = (self.requests, self.link());
            if previous.as_ref().is_some_and(|p| {
                p.0 == answer.0 && p.1 == answer.1 && p.2 == requests && p.3 == link
            }) && link.is_some()
            {
                return Ok(answer);
            }
            if !confirm
                && previous.is_none()
                && pong.is_some()
                && pong == link
                && answer.0 == want
                && answer.1 == want_height
            {
                return Ok(answer);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the tip did not settle within {} s; the last answer was {} height {}{}",
                    self.timeout.as_secs(),
                    short_hash(&answer.0),
                    answer.1,
                    if link.is_none() {
                        ", with the node not connected"
                    } else {
                        ""
                    }
                ));
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

    /// Runs one case: Ok(None) when the tip is the parent and the block was delivered (unless
    /// the node need not ask for it, see [`Case::requestable`]), Ok(Some(mismatch)) otherwise.
    /// The case of a session started with `initial` is already announced. With `recheck` (the
    /// last case on its parent before the chain is extended), an unconfirmed tip is asked for
    /// once more, so a node that answered before it had processed the case block, and then
    /// accepted it, is not hidden by the chain that follows.
    fn run_case(&mut self, c: usize, recheck: bool) -> Result<Option<String>, String> {
        let sc: &'a Scenario = self.sc;
        let case = &sc.cases[c];
        if self.current != Some(c) {
            self.extend(case.parent)?;
            self.announce(c)?;
        }
        self.wait_delivered(Some(c))?;
        let want = sc.chain[case.parent].display();
        let height = case.parent as i64;
        let delivered = self.delivered.contains(&case.block.hash);
        let block = if delivered {
            "delivered"
        } else {
            "announced, never requested"
        };
        let (tip, h) = self.settled_tip(&want, height, self.confirm)?;
        if tip != want || h != height {
            return Ok(Some(format!(
                "tip {} height {h}, expected {} height {height} (the block was {block}, Core: {}){}",
                short_hash(&tip),
                short_hash(&want),
                case.reason,
                self.tip_note(&tip)
            )));
        }
        if !delivered && case.requestable() {
            return Ok(Some(format!(
                "the node never asked for the block (Core: {}), whose header breaks no header rule",
                case.reason
            )));
        }
        if recheck && !self.confirm {
            self.barrier()?;
            let (again, h) = self.query_tip()?;
            if again != want || h != height {
                return Ok(Some(format!(
                    "tip {} height {h} when asked again, after {} height {height} (Core: {}){}",
                    short_hash(&again),
                    short_hash(&want),
                    case.reason,
                    self.tip_note(&again)
                )));
            }
        }
        Ok(None)
    }

    /// Names the case block a reported tip is, if it is one.
    fn tip_note(&self, tip: &str) -> String {
        let sc: &'a Scenario = self.sc;
        self.announced
            .iter()
            .find(|(h, _)| hex::encode_reversed(h.as_slice()) == tip)
            .map(|(_, &c)| {
                format!(
                    "; the tip is the rejected block {} (Core: {})",
                    short_hash(tip),
                    sc.cases[c].reason
                )
            })
            .unwrap_or_default()
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
                short_hash(&tip),
                short_hash(&want)
            )));
        }
        self.write_line(&json!({"op": "stop"}).to_string())?;
        self.stop_sent = true;
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.stopped.is_none() {
            if Instant::now() >= deadline {
                return Err("no stopped line within 60 s of the stop request".into());
            }
            self.pump(Duration::from_millis(50))?;
        }
        let stopped = self.stopped.clone().unwrap();
        let status = wait_exit(&mut self.child, Duration::from_secs(60));
        let (mut problems, utxo_reported) =
            check_stopped(&stopped, &want, n as i64, &self.sc.utxo_hash);
        self.utxo_reported = utxo_reported;
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

/// Compares a `stopped` line with the final tip and Core's `hash_serialized_3` there. Also returns
/// whether the line carried the hash, or `None` when its tip is wrong and the hash means nothing.
fn check_stopped(
    stopped: &Value,
    tip: &str,
    height: i64,
    utxo_hash: &str,
) -> (Vec<String>, Option<bool>) {
    if stopped["tip"].as_str() != Some(tip) || stopped["height"].as_i64() != Some(height) {
        return (
            vec![format!(
                "stopped line {stopped}, expected tip {tip} height {height}"
            )],
            None,
        );
    }
    match stopped.get("hash_serialized_3") {
        // PROTOCOL.md section 5: optional for a node that keeps no UTXO set.
        None | Some(Value::Null) => (Vec::new(), Some(false)),
        Some(h) if h.as_str() == Some(utxo_hash) => (Vec::new(), Some(true)),
        Some(h) => (
            vec![format!(
                "stopped line hash_serialized_3 {h}, bitcoind {utxo_hash}"
            )],
            Some(true),
        ),
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
    /// Passed cases whose block reached the node. The others passed without it because their
    /// header breaks a rule, so the node had no reason to ask for the block.
    delivered: u64,
    /// The final tip passed without `hash_serialized_3` (level 2).
    utxo_unreported: bool,
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
            Some(c) => {
                let parent = sc.cases[*c].parent;
                let recheck = checks
                    .get(i + 1)
                    .is_none_or(|next| next.is_none_or(|n| sc.cases[n].parent != parent));
                s.run_case(*c, recheck)
            }
            None => s.finish(),
        };
        transports.extend(s.transports.iter().copied());
        r.cases += 1;
        let failed = match outcome {
            Ok(None) => {
                node_errors = 0;
                r.passed += 1;
                if let Some(c) = check {
                    if s.delivered.contains(&sc.cases[*c].block.hash) {
                        r.delivered += 1;
                    }
                }
                stats.pass();
                // As in the interop suite, level 2 is judged only on a final tip that passed.
                if let Some(reported) = s.utxo_reported.take() {
                    stats.l2_checked += 1;
                    if !reported {
                        stats.l2_mismatches += 1;
                        r.utxo_unreported = true;
                        if verbose {
                            println!("LEVEL2   [{SUITE}] {loc}: hash_serialized_3 not reported");
                        }
                    }
                }
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
    crate::bitcoind::check_version(&cfg.bitcoind)?;
    if cfg.node.contains("{stop_at}") {
        return Err(RULE_STOP_AT.into());
    }
    let files = corpus::corpus_files(&cfg.corpus)?;
    if files.is_empty() {
        let where_: Vec<String> = cfg.corpus.iter().map(|p| p.display().to_string()).collect();
        return Err(format!(
            "no corpus files (*.jsonl.gz) in {}",
            where_.join(", ")
        ));
    }
    stats.details.push(format!(
        "{:<34} {:>6} {:>6} {:>13} {:>13} {:>5} {:>8}  {}",
        "peer-sync scenario", "height", "cases", "follow", "ibd", "nodes", "time", "detail"
    ));
    let base = std::env::temp_dir().join(format!("bcs-peer-sync-{}", std::process::id()));
    let mut totals = (ModeResult::default(), ModeResult::default());
    for (i, file) in files.iter().enumerate() {
        let started = Instant::now();
        let name = corpus::file_name(file);
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
                // A file that cannot be loaded is a corpus defect, not the node's: no
                // `--known-failures` entry waives it.
                stats.cases += 1;
                stats.failed += 1;
                if verbose {
                    println!("FAIL     [{SUITE}] {name} setup: {e}");
                }
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
                "CASES    [{SUITE}] {name}: {} blocks Core rejects ({}), {} valid siblings left out, {} not classified, {} damaged copies of chain blocks ({} other copies left out)",
                sc.cases.len(),
                reasons.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "),
                sc.valid_siblings,
                sc.unclassified.len(),
                sc.damaged.values().map(Vec::len).sum::<usize>(),
                sc.damaged_left_out
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
            "blocks delivered: follow {}, ibd {}; transport {}, {} valid siblings left out",
            follow.delivered,
            ibd.delivered,
            if transports.is_empty() {
                "none".to_string()
            } else {
                transports.iter().copied().collect::<Vec<_>>().join("+")
            },
            sc.valid_siblings
        );
        let damaged: usize = sc.damaged.values().map(Vec::len).sum();
        if damaged > 0 {
            detail.push_str(&format!(", {damaged} damaged copies sent first"));
        }
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
        if follow.utxo_unreported {
            detail.push_str(", UTXO hash not reported (level 2)");
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
            t.delivered += r.delivered;
        }
    }
    stats.details.push(format!(
        "peer-sync total: follow {} passed ({} case blocks delivered), ibd {} passed ({} case blocks delivered), {} nodes started",
        totals.0.text(),
        totals.0.delivered,
        totals.1.text(),
        totals.1.delivered,
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
    fn stopped_line_utxo_hash() {
        let tip = "11".repeat(32);
        let core = "22".repeat(32);
        let line = |v: Value| check_stopped(&v, &tip, 5, &core);
        assert_eq!(
            line(json!({"tip": tip, "height": 5, "hash_serialized_3": core})),
            (vec![], Some(true))
        );
        let (problems, reported) =
            line(json!({"tip": tip, "height": 5, "hash_serialized_3": "00".repeat(32)}));
        assert_eq!(reported, Some(true));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("hash_serialized_3"), "{}", problems[0]);
        assert_eq!(
            line(json!({"tip": tip, "height": 5})),
            (vec![], Some(false))
        );
        assert_eq!(
            line(json!({"tip": tip, "height": 5, "hash_serialized_3": null})),
            (vec![], Some(false))
        );
        let (problems, reported) =
            line(json!({"tip": core, "height": 5, "hash_serialized_3": core}));
        assert_eq!((problems.len(), reported), (1, None));
        let (problems, reported) =
            line(json!({"tip": tip, "height": 4, "hash_serialized_3": core}));
        assert_eq!((problems.len(), reported), (1, None));
    }

    const REGTEST_GENESIS: &str =
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    /// A header on regtest genesis whose proof of work is valid, or invalid when `valid` is false.
    fn header_on_genesis(valid: bool) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[..4].copy_from_slice(&4u32.to_le_bytes());
        h[4..36].copy_from_slice(&raw_hash(REGTEST_GENESIS).unwrap());
        h[68..72].copy_from_slice(&1_296_688_700u32.to_le_bytes());
        h[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
        for nonce in 0u32.. {
            h[76..80].copy_from_slice(&nonce.to_le_bytes());
            if pow_ok(&h) == valid {
                return h;
            }
        }
        unreachable!()
    }

    #[test]
    fn requestable_cases() {
        assert!(pow_ok(&header_on_genesis(true)));
        assert!(!pow_ok(&header_on_genesis(false)));
        let case = |valid: bool, reason: &str| Case {
            parent: 0,
            block: Block {
                hash: sha256d(&header_on_genesis(valid)),
                bytes: header_on_genesis(valid).to_vec(),
            },
            reason: reason.into(),
        };
        assert!(case(true, "bad-txns-inputs-missingorspent").requestable());
        assert!(!case(true, "bad-diffbits").requestable());
        // Proposal mode does not check proof of work, so Core names a later rule.
        assert!(!case(false, "bad-txns-inputs-missingorspent").requestable());
    }

    /// A node that completes the handshake, answers `ping`, and reports regtest genesis as its
    /// tip. With `ask` it requests every header it is sent; with `never` it requests nothing.
    /// `retry` is `ask` that requests each block once more when it first gets it, as a node does
    /// after dropping a damaged copy. `junk` is `ask` that also writes a line that is not UTF-8
    /// before each answer. `deaf` asks
    /// for more than the connection holds (20 `getdata` messages of 50,000 transactions, each
    /// answered with a `notfound` as large) and stops reading; `deaf-stop` then stops itself.
    const FAKE_NODE: &str = r#"
import hashlib, json, os, signal, socket, struct, sys, threading
host, port = sys.argv[1].rsplit(":", 1)
mode, genesis = sys.argv[2], sys.argv[3]
magic = bytes.fromhex("fabfb5da")
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
s = socket.create_connection((host, int(port)))
lock = threading.Lock()
seen = set()
def send(cmd, p):
    with lock:
        s.sendall(magic + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(p)) + dsha(p)[:4] + p)
def exact(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise EOFError
        b += c
    return b
def reader():
    try:
        while True:
            h = exact(24)
            cmd = h[4:16].rstrip(b"\0").decode()
            p = exact(struct.unpack("<I", h[16:20])[0])
            if cmd == "version":
                send("verack", b"")
                if mode.startswith("deaf"):
                    inv = b"\xfd" + struct.pack("<H", 50000) + (struct.pack("<I", 1) + bytes(32)) * 50000
                    for _ in range(20): send("getdata", inv)
                    if mode == "deaf-stop": os.kill(os.getpid(), signal.SIGSTOP)
                    return
            elif cmd == "ping": send("pong", p)
            elif cmd == "headers" and mode in ("ask", "junk", "retry") and p[0]:
                send("getdata", bytes([p[0]]) + b"".join(
                    struct.pack("<I", 0x40000002) + dsha(p[1 + 81 * i:81 + 81 * i]) for i in range(p[0])))
            elif cmd == "block" and mode == "retry" and dsha(p[:80]) not in seen:
                seen.add(dsha(p[:80]))
                send("getdata", b"\x01" + struct.pack("<I", 0x40000002) + dsha(p[:80]))
    except (EOFError, OSError):
        pass
threading.Thread(target=reader, daemon=True).start()
send("version", struct.pack("<iQq", 70016, 8, 0) + bytes(52) + struct.pack("<Q", 1) + b"\0" + struct.pack("<ib", 0, 0))
for line in sys.stdin:
    if json.loads(line)["op"] == "tip":
        if mode == "junk":
            sys.stdout.buffer.write(b"\xff not UTF-8\n")
        print(json.dumps({"event": "tip", "id": json.loads(line)["id"], "tip": genesis, "height": 0}), flush=True)
"#;

    /// Runs one follow-mode case on regtest genesis against [`FAKE_NODE`]: the verdict and
    /// whether the case block was delivered. `None` without `python3`.
    fn fake_node_case(mode: &str, reason: &str) -> Option<(Option<String>, bool)> {
        fake_node_run(mode, reason, Duration::from_secs(30)).map(|r| r.unwrap())
    }

    /// A fresh directory holding [`FAKE_NODE`], and a configuration that runs it in `mode`.
    /// `None` without `python3`.
    fn fake_node_cfg(name: &str, mode: &str, node_timeout: Duration) -> Option<(PathBuf, Config)> {
        if process::spawn(process::shell("python3 -c ''").stdin(Stdio::null()))
            .ok()
            .and_then(|mut c| c.wait().ok())
            .is_none_or(|s| !s.success())
        {
            eprintln!("skipped: no python3");
            return None;
        }
        let dir =
            std::env::temp_dir().join(format!("bcs-peer-sync-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake_node.py");
        std::fs::write(&script, FAKE_NODE).unwrap();
        let cfg = Config {
            bitcoind: PathBuf::new(),
            node: format!(
                "python3 -I {} {{peer}} {mode} {REGTEST_GENESIS}",
                script.display()
            ),
            corpus: Vec::new(),
            port_range: (0, 0),
            node_timeout,
            keep_temp: false,
            ibd_limit: None,
        };
        Some((dir, cfg))
    }

    /// [`fake_node_case`] with the given `--node-timeout`, and an error of the session returned.
    fn fake_node_run(
        mode: &str,
        reason: &str,
        node_timeout: Duration,
    ) -> Option<Result<(Option<String>, bool), String>> {
        let (dir, cfg) = fake_node_cfg(&format!("{mode}-{reason}"), mode, node_timeout)?;
        let header = header_on_genesis(true);
        let mut bytes = header.to_vec();
        bytes.push(0);
        let sc = Scenario {
            name: "test".into(),
            options: json!({}),
            chain: vec![Block {
                hash: raw_hash(REGTEST_GENESIS).unwrap(),
                bytes: Vec::new(),
            }],
            utxo_hash: String::new(),
            cases: vec![Case {
                parent: 0,
                block: Block {
                    hash: sha256d(&header),
                    bytes,
                },
                reason: reason.into(),
            }],
            damaged: HashMap::new(),
            damaged_left_out: 0,
            valid_siblings: 0,
            unclassified: Vec::new(),
        };
        let result = Session::start(&cfg, &sc, &dir, None).and_then(|mut s| {
            let verdict = s.run_case(0, true)?;
            Ok((verdict, s.delivered.contains(&sc.cases[0].block.hash)))
        });
        let _ = std::fs::remove_dir_all(&dir);
        Some(result)
    }

    /// A node that stops reading its connection fails the case at `--node-timeout`, instead of
    /// holding the runner in the write.
    #[test]
    fn a_node_that_stops_reading_times_out() {
        let started = Instant::now();
        if let Some(result) = fake_node_run("deaf", "bad-txns-nonfinal", Duration::from_secs(2)) {
            let e = result.expect_err("a node that stopped reading passed");
            assert!(
                e.contains("read none of a `notfound` message for 2 s"),
                "{e}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "{:?}",
                started.elapsed()
            );
        }
    }

    /// A node stopped while the runner waits for it to read is found by the stopped-process
    /// check, well before `--node-timeout`.
    #[test]
    fn a_node_stopped_while_the_runner_writes_fails() {
        let started = Instant::now();
        if let Some(result) =
            fake_node_run("deaf-stop", "bad-txns-nonfinal", Duration::from_secs(60))
        {
            let e = result.expect_err("a stopped node passed");
            assert!(e.contains("the node command was stopped"), "{e}");
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "{:?}",
                started.elapsed()
            );
        }
    }

    /// A chain block with a damaged copy: the node's first request gets the copy, its second the
    /// block, which only then counts as delivered.
    #[test]
    fn damaged_copy_goes_before_the_block() {
        let Some((dir, cfg)) = fake_node_cfg("damaged", "retry", Duration::from_secs(30)) else {
            return;
        };
        let header = header_on_genesis(true);
        let mut bytes = header.to_vec();
        bytes.push(0);
        let mut copy = bytes.clone();
        copy.push(0);
        let mut sc = genesis_only();
        sc.chain.push(Block {
            hash: sha256d(&header),
            bytes: bytes.clone(),
        });
        sc.damaged.insert(
            1,
            vec![Damaged {
                bytes: copy,
                reason: "bad-txnmrklroot".into(),
            }],
        );
        let result = Session::start(&cfg, &sc, &dir, None).and_then(|mut s| {
            s.extend(1)?;
            s.wait_delivered(None)?;
            Ok((
                s.damaged_sent.get(&1).copied(),
                s.requests,
                s.damaged_note(1),
            ))
        });
        let _ = std::fs::remove_dir_all(&dir);
        let (sent, requests, note) = result.unwrap();
        assert_eq!(sent, Some(1));
        assert_eq!(requests, 2);
        assert!(
            note.contains("after 1 damaged copy of it (Core: bad-txnmrklroot)"),
            "{note}"
        );
    }

    #[test]
    fn case_block_requested_and_delivered_passes() {
        if let Some((verdict, delivered)) = fake_node_case("ask", "bad-txns-nonfinal") {
            assert_eq!(verdict, None);
            assert!(delivered);
        }
    }

    /// A line that is not UTF-8 does not stop the runner reading the answers after it.
    #[test]
    fn a_line_that_is_not_utf8_is_skipped() {
        if let Some((verdict, delivered)) = fake_node_case("junk", "bad-txns-nonfinal") {
            assert_eq!(verdict, None);
            assert!(delivered);
        }
    }

    #[test]
    fn case_block_never_requested_fails() {
        if let Some((verdict, delivered)) = fake_node_case("never", "bad-txns-nonfinal") {
            assert!(!delivered);
            let verdict = verdict.expect("a node that never asked for the block passed");
            assert!(verdict.contains("never asked for the block"), "{verdict}");
        }
    }

    #[test]
    fn header_rule_case_passes_without_the_block() {
        if let Some((verdict, delivered)) = fake_node_case("never", "bad-diffbits") {
            assert_eq!(verdict, None);
            assert!(!delivered);
        }
    }

    fn genesis_only() -> Scenario {
        Scenario {
            name: "test".into(),
            options: json!({}),
            chain: vec![Block {
                hash: raw_hash(REGTEST_GENESIS).unwrap(),
                bytes: Vec::new(),
            }],
            utxo_hash: String::new(),
            cases: Vec::new(),
            damaged: HashMap::new(),
            damaged_left_out: 0,
            valid_siblings: 0,
            unclassified: Vec::new(),
        }
    }

    /// A session whose node has already exited with `code`, with `events` queued in order. The
    /// node's output stays open until the returned sender is dropped.
    fn exited_session(
        sc: &Scenario,
        code: i32,
        events: Vec<Event>,
    ) -> (Session<'_>, Sender<Event>) {
        let mut child =
            process::spawn(process::shell(&format!("exit {code}")).stdin(Stdio::null())).unwrap();
        child.wait().unwrap();
        let (tx, rx) = mpsc::channel();
        for e in events {
            tx.send(e).unwrap();
        }
        let stop_accept = Arc::new(AtomicBool::new(false));
        let s = Session::new(
            sc,
            Duration::from_secs(30),
            rx,
            stop_accept,
            child,
            None,
            PathBuf::new(),
        );
        (s, tx)
    }

    fn closed() -> Event {
        Event::Closed(1, "closed by the peer".into())
    }

    #[test]
    fn stopped_line_queued_after_exit_is_read() {
        let sc = genesis_only();
        let stopped = json!({"event": "stopped", "tip": REGTEST_GENESIS, "height": 0});
        let (mut s, _tx) = exited_session(
            &sc,
            0,
            vec![
                closed(),
                Event::NodeLine(stopped.to_string()),
                Event::NodeEof,
            ],
        );
        s.stop_sent = true;
        while s.stopped.is_none() {
            s.pump(Duration::from_millis(50)).unwrap();
        }
        assert_eq!(s.stopped, Some(stopped));
    }

    #[test]
    fn exit_without_stopped_line_fails_once_output_is_read() {
        let sc = genesis_only();
        let tip = json!({"event": "tip", "id": 1, "tip": REGTEST_GENESIS, "height": 0});
        let (mut s, _tx) = exited_session(
            &sc,
            0,
            vec![closed(), Event::NodeLine(tip.to_string()), Event::NodeEof],
        );
        s.stop_sent = true;
        s.pump(Duration::from_millis(50)).unwrap();
        s.pump(Duration::from_millis(50)).unwrap();
        assert!(s.answers.contains_key(&1));
        let e = s.pump(Duration::from_millis(50)).unwrap_err();
        assert!(e.contains("the node exited (exit status: 0)"), "{e}");
    }

    #[test]
    fn exit_before_stop_fails_at_once() {
        let sc = genesis_only();
        let tip = json!({"event": "tip", "id": 1, "tip": REGTEST_GENESIS, "height": 0});
        let (mut s, _tx) = exited_session(&sc, 3, vec![closed(), Event::NodeLine(tip.to_string())]);
        let e = s.pump(Duration::from_millis(50)).unwrap_err();
        assert!(e.contains("the node exited (exit status: 3)"), "{e}");
        assert!(!s.answers.contains_key(&1));
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
