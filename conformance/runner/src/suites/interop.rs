//! The `interop` suite (conformance/PROTOCOL.md section 5): the implementation runs as a live node
//! and synchronizes from a regtest Bitcoin Core node over the version 1 peer-to-peer protocol, or
//! with `--v2transport` over BIP324 version 2 if the node chooses to.
//!
//! For each chain the runner starts a fresh `bitcoind -regtest` (temporary data directory, free
//! ports, `-debug=net`, no whitelist, `-listen=1`, `-v2transport=0`, or `-v2transport=1` with
//! `--v2transport`), loads the chain, runs the node command with `{network}`, `{datadir}`, `{peer}`
//! and `{stop_at}` substituted, waits for its `stopped` line and compares tip and height with
//! `bitcoind` (`getbestblockhash`, `getblockcount`). `hash_serialized_3` is compared with
//! `gettxoutsetinfo` when the node reports it; a node that keeps no UTXO set may leave it out,
//! which is counted at level 2 (it fails the run only with `--fail-on-level2`). Chains:
//!
//! - `generate-300`: 300 blocks from `generatetodescriptor 300 "raw(51)"`;
//! - one per corpus scenario: the blocks of the scenario's final active chain (the tip of its last
//!   check), submitted in height order with `submitblock`, with `bitcoind` started with
//!   `-testactivationheight=name@height` and `-test=bip94` from the scenario's `reset` options.
//!   When a block hash has several recorded byte variants (mutated copies), they are tried in
//!   file order until `bitcoind` accepts one.
//!
//! `{options}` in the node command (PROTOCOL.md section 5) becomes the scenario's `reset` options as
//! a single shell-quoted JSON object (the `options` of `chain_reset`). A `Misbehaving` line in
//! bitcoind's debug log fails the chain. The transport of the node's connections, from the same
//! log, is shown with each chain.

use crate::bitcoind::{free_ports, Bitcoind};
use crate::check::Stats;
use crate::hex;
use crate::p2p::unix_now;
use crate::suites::corpus;
use crate::tx::sha256d;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const RULE_FUTURE_BLOCKS: &str =
    "scenario's final chain has blocks dated more than 2 hours after the current time (a live node uses its real clock)";
pub const RULE_NEEDS_OPTIONS: &str =
    "scenario needs consensus options (its reset options) and the node command has no {options} placeholder";

pub struct Config {
    pub bitcoind: PathBuf,
    pub node: String,
    pub corpus: Vec<PathBuf>,
    pub port_range: (u16, u16),
    pub node_timeout: Duration,
    pub keep_temp: bool,
    pub v2transport: bool,
}

enum Load {
    Generate(u32),
    Corpus { file: PathBuf },
}

struct Chain {
    name: String,
    options: Value,
    load: Load,
}

/// The blocks of a scenario's final active chain, in height order, each with its byte variants
/// in file order; plus the scenario's reset options and final tip.
struct FinalChain {
    tip: String,
    blocks: Vec<Vec<Vec<u8>>>,
    max_time: i64,
}

fn final_chain(file: &Path) -> Result<FinalChain, String> {
    let (_meta, events) = corpus::read_events(file)?;
    let base = file.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut genesis = String::new();
    let mut tip = String::new();
    let mut variants: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    for ev in &events {
        match ev["type"].as_str() {
            Some("reset") => genesis = ev["genesis"].as_str().unwrap_or("").to_string(),
            Some("block") => {
                let bytes = corpus::block_bytes(ev, &base)?;
                let hash = hex::encode_reversed(&sha256d(&bytes[..80]));
                let list = variants.entry(hash).or_default();
                if !list.contains(&bytes) {
                    list.push(bytes);
                }
            }
            Some("check") => tip = ev["tip"].as_str().unwrap_or("").to_string(),
            _ => {}
        }
    }
    if tip.is_empty() {
        return Err("the scenario has no check".into());
    }
    let mut chain = Vec::new();
    let mut max_time = 0i64;
    let mut cursor = tip.clone();
    while cursor != genesis {
        let list = variants
            .get(&cursor)
            .ok_or_else(|| format!("block {cursor} of the final chain is not in the file"))?;
        let header = &list[0][..80];
        max_time = max_time.max(u32::from_le_bytes(header[68..72].try_into().unwrap()) as i64);
        cursor = hex::encode_reversed(&header[4..36]);
        chain.push(list.clone());
        if chain.len() > 10_000_000 {
            return Err("final chain does not reach genesis".into());
        }
    }
    chain.reverse();
    Ok(FinalChain {
        tip,
        blocks: chain,
        max_time,
    })
}

pub fn bitcoind_args(options: &Value) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let Some(obj) = options.as_object() else {
        return Err("options is not an object".into());
    };
    for (key, value) in obj {
        match key.as_str() {
            "testactivationheight" => {
                for (name, height) in value
                    .as_object()
                    .ok_or("testactivationheight is not an object")?
                {
                    let h = height
                        .as_i64()
                        .ok_or("activation height is not an integer")?;
                    args.push(format!("-testactivationheight={name}@{h}"));
                }
            }
            "test" => {
                for t in value.as_array().ok_or("test is not an array")? {
                    args.push(format!(
                        "-test={}",
                        t.as_str().ok_or("test option is not a string")?
                    ));
                }
            }
            other => return Err(format!("option {other} has no bitcoind equivalent here")),
        }
    }
    Ok(args)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// What the node reported.
struct NodeOutcome {
    stopped: Option<Value>,
    last_progress: Option<Value>,
    problems: Vec<String>,
    exit: Option<std::process::ExitStatus>,
}

fn run_node(command: &str, stderr_path: &Path, timeout: Duration) -> Result<NodeOutcome, String> {
    let stderr = std::fs::File::create(stderr_path)
        .map_err(|e| format!("cannot create {}: {e}", stderr_path.display()))?;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("cannot start the node: {e}"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut out = NodeOutcome {
        stopped: None,
        last_progress: None,
        problems: Vec::new(),
        exit: None,
    };
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            out.problems
                .push(format!("no stopped line within {} s", timeout.as_secs()));
            break;
        }
        match rx.recv_timeout(left.min(Duration::from_millis(500))) {
            Ok(Ok(line)) => {
                if !line.starts_with('{') {
                    continue;
                }
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) => match v["event"].as_str() {
                        Some("stopped") => {
                            out.stopped = Some(v);
                            break;
                        }
                        Some("tip") => out.last_progress = Some(v),
                        // PROTOCOL.md section 5: `x_` events are implementation extensions.
                        Some(event) if event.starts_with("x_") => {}
                        Some("error") => out.problems.push(format!(
                            "node reported an error: {}",
                            crate::check::shorten(&line, 200)
                        )),
                        _ => out.problems.push(format!(
                            "unexpected line: {}",
                            crate::check::shorten(&line, 200)
                        )),
                    },
                    Err(_) => out.problems.push(format!(
                        "line starting with {{ is not JSON: {}",
                        crate::check::shorten(&line, 200)
                    )),
                }
            }
            Ok(Err(e)) => {
                out.problems
                    .push(format!("cannot read the node's output: {e}"));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(status)) = child.try_wait() {
                    // Drain what is left, then stop waiting.
                    while let Ok(Ok(line)) = rx.recv_timeout(Duration::from_millis(200)) {
                        if let Ok(v) = serde_json::from_str::<Value>(&line) {
                            if v["event"] == "stopped" {
                                out.stopped = Some(v);
                            }
                        }
                    }
                    out.exit = Some(status);
                    if out.stopped.is_none() {
                        out.problems
                            .push(format!("the node exited ({status}) without a stopped line"));
                    }
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait().ok();
                out.exit = status;
                if out.stopped.is_none() {
                    out.problems.push(format!(
                        "the node closed its output without a stopped line{}",
                        status.map(|s| format!(" ({s})")).unwrap_or_default()
                    ));
                }
                break;
            }
        }
    }
    // After `stopped` the node must exit with status 0.
    if out.exit.is_none() {
        let grace =
            Instant::now() + Duration::from_secs(if out.stopped.is_some() { 30 } else { 0 });
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    out.exit = Some(status);
                    break;
                }
                _ if Instant::now() >= grace => {
                    let _ = child.kill();
                    let _ = child.wait();
                    if out.stopped.is_some() {
                        out.problems
                            .push("the node did not exit after its stopped line".into());
                    }
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
    if out.stopped.is_some() {
        if let Some(status) = out.exit {
            if !status.success() {
                out.problems.push(format!(
                    "the node exited with {status} after its stopped line"
                ));
            }
        }
    }
    Ok(out)
}

fn stderr_tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(5)..].join(" | ")
}

/// How a chain ended.
enum ChainOutcome {
    /// A stated rule excludes the chain.
    Excluded(&'static str),
    /// The node ran; no problem means it matched `bitcoind`. `utxo_reported` is `Some(false)` when
    /// the node stopped without `hash_serialized_3` (level 2), `None` when it never stopped.
    Done {
        problems: Vec<String>,
        utxo_reported: Option<bool>,
    },
}

fn run_chain(
    cfg: &Config,
    chain: &Chain,
    root: &Path,
    details: &mut Vec<String>,
) -> Result<ChainOutcome, String> {
    let started = Instant::now();
    let mut final_chain = None;
    if chain.options.as_object().is_some_and(|o| !o.is_empty()) && !cfg.node.contains("{options}") {
        return Ok(ChainOutcome::Excluded(RULE_NEEDS_OPTIONS));
    }
    if let Load::Corpus { file } = &chain.load {
        let fc = final_chain_checked(file)?;
        if fc.max_time > unix_now() + 7200 {
            return Ok(ChainOutcome::Excluded(RULE_FUTURE_BLOCKS));
        }
        final_chain = Some(fc);
    }
    let extra = bitcoind_args(&chain.options)?;
    let ports = free_ports(cfg.port_range, 2, &[])?;
    let core_dir = root.join("bitcoind");
    let node_dir = root.join("node");
    std::fs::create_dir_all(&node_dir)
        .map_err(|e| format!("cannot create {}: {e}", node_dir.display()))?;
    let mut core = Bitcoind::start(
        &cfg.bitcoind,
        &core_dir,
        ports[0],
        ports[1],
        cfg.v2transport,
        &extra,
    )?;

    match &chain.load {
        Load::Generate(n) => {
            core.rpc("generatetodescriptor", json!([n, "raw(51)"]))?;
        }
        Load::Corpus { .. } => {
            let fc = final_chain.as_ref().unwrap();
            for (height, variants) in fc.blocks.iter().enumerate() {
                let mut accepted = false;
                let mut last = String::new();
                for bytes in variants {
                    match core.rpc("submitblock", json!([hex::encode(bytes)])) {
                        Ok(Value::Null) => {
                            accepted = true;
                            break;
                        }
                        Ok(Value::String(s)) if s == "duplicate" => {
                            accepted = true;
                            break;
                        }
                        Ok(other) => last = other.to_string(),
                        Err(e) => last = e,
                    }
                }
                if !accepted {
                    return Err(format!(
                        "bitcoind rejected block {} of the final chain: {last}",
                        height + 1
                    ));
                }
            }
            let best = core.rpc("getbestblockhash", json!([]))?;
            if best.as_str() != Some(fc.tip.as_str()) {
                return Err(format!(
                    "bitcoind's tip is {best} after loading, the scenario's final tip is {}",
                    fc.tip
                ));
            }
        }
    }
    let tip = core
        .rpc("getbestblockhash", json!([]))?
        .as_str()
        .unwrap_or("")
        .to_string();
    let height = core.rpc("getblockcount", json!([]))?.as_i64().unwrap_or(-1);
    let utxo = core.rpc("gettxoutsetinfo", json!(["hash_serialized_3"]))?;
    let utxo_hash = utxo["hash_serialized_3"].as_str().unwrap_or("").to_string();

    let command = cfg
        .node
        .replace("{network}", "regtest")
        .replace("{datadir}", &node_dir.display().to_string())
        .replace("{peer}", &format!("127.0.0.1:{}", core.p2p_port))
        .replace("{stop_at}", &tip)
        .replace("{options}", &shell_quote(&chain.options.to_string()));
    let stderr_path = root.join("node-stderr.log");
    let outcome = run_node(&command, &stderr_path, cfg.node_timeout)?;
    core.stop();

    let mut problems = outcome.problems.clone();
    // Any misbehaviour bitcoind saw from the node fails the chain, even if the sync completed.
    let debug_log = core_dir.join("regtest/debug.log");
    let log = std::fs::read_to_string(&debug_log).unwrap_or_default();
    let misbehaving: Vec<&str> = log.lines().filter(|l| l.contains("Misbehaving")).collect();
    if !misbehaving.is_empty() {
        problems.push(format!(
            "bitcoind logged {} Misbehaving line(s), first: {}",
            misbehaving.len(),
            misbehaving[0].trim()
        ));
    }
    let transport = transports(&log);
    let mut utxo_reported = None;
    match &outcome.stopped {
        Some(v) => {
            if v["tip"].as_str() != Some(tip.as_str()) {
                problems.push(format!("node tip {}, bitcoind {tip}", v["tip"]));
            }
            if v["height"].as_i64() != Some(height) {
                problems.push(format!("node height {}, bitcoind {height}", v["height"]));
            }
            match v.get("hash_serialized_3") {
                // PROTOCOL.md section 5: optional for a node that keeps no UTXO set.
                None | Some(Value::Null) => utxo_reported = Some(false),
                Some(h) => {
                    utxo_reported = Some(true);
                    if h.as_str() != Some(utxo_hash.as_str()) {
                        problems.push(format!("node hash_serialized_3 {h}, bitcoind {utxo_hash}"));
                    }
                }
            }
        }
        None => {
            if let Some(p) = &outcome.last_progress {
                problems.push(format!("last progress line: {p}"));
            }
            let tail = stderr_tail(&stderr_path);
            if !tail.is_empty() {
                problems.push(format!("node stderr: {tail}"));
            }
        }
    }
    details.push(format!(
        "{:<44} {:>7} {:>8} {:>7.1}s  {}",
        crate::check::shorten(&chain.name, 44),
        height,
        if problems.is_empty() {
            "match"
        } else {
            "MISMATCH"
        },
        started.elapsed().as_secs_f64(),
        if problems.is_empty() {
            format!(
                "tip {}, transport {transport}{}",
                &tip[..16],
                if utxo_reported == Some(false) {
                    ", UTXO hash not reported (level 2)"
                } else {
                    ""
                }
            )
        } else {
            format!("{} (transport {transport})", problems.join("; "))
        }
    ));
    Ok(ChainOutcome::Done {
        problems,
        utxo_reported,
    })
}

/// The transports of the node's connections, from bitcoind's `-debug=net` lines
/// `New inbound peer connected: transport: v2, ...`, joined with `+`; `none` without a connection.
fn transports(log: &str) -> String {
    let seen: BTreeSet<&str> = log
        .lines()
        .filter_map(|l| l.split("peer connected: transport: ").nth(1))
        .map(|rest| rest.split(',').next().unwrap_or("").trim())
        .collect();
    if seen.is_empty() {
        "none".into()
    } else {
        seen.into_iter().collect::<Vec<_>>().join("+")
    }
}

fn final_chain_checked(file: &Path) -> Result<FinalChain, String> {
    final_chain(file).map_err(|e| format!("{}: {e}", file.display()))
}

pub fn run(stats: &mut Stats, verbose: bool, cfg: &Config) -> Result<(), String> {
    const SUITE: &str = "interop";
    if !cfg.bitcoind.is_file() {
        return Err(format!(
            "--bitcoind {} is not a file",
            cfg.bitcoind.display()
        ));
    }
    let mut chains = vec![Chain {
        name: "generate-300".into(),
        options: json!({}),
        load: Load::Generate(300),
    }];
    let files = corpus::corpus_files(&cfg.corpus)?;
    for file in &files {
        let (_meta, events) = corpus::read_events(file)?;
        let options = events
            .iter()
            .find(|e| e["type"] == "reset")
            .and_then(|e| e.get("options").cloned())
            .unwrap_or_else(|| json!({}));
        let name = file
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_end_matches(".jsonl.gz")
            .to_string();
        chains.push(Chain {
            name,
            options,
            load: Load::Corpus { file: file.clone() },
        });
    }
    if files.is_empty() {
        stats
            .details
            .push("interop: no corpus files, only the generated chain is used".into());
    }
    stats.details.push(format!(
        "{:<44} {:>7} {:>8} {:>8}  {}",
        "interop chain", "height", "result", "time", "detail"
    ));
    let base = std::env::temp_dir().join(format!("bcs-interop-{}", std::process::id()));
    for (i, chain) in chains.iter().enumerate() {
        let root = base.join(format!("{i:03}-{}", chain.name));
        let _ = std::fs::remove_dir_all(&root);
        let loc = format!("chain {}", chain.name);
        eprintln!("interop: {} ({} of {})", chain.name, i + 1, chains.len());
        let outcome = run_chain(cfg, chain, &root, &mut stats.details);
        if let Ok(ChainOutcome::Done {
            utxo_reported: Some(reported),
            ..
        }) = &outcome
        {
            stats.l2_checked += 1;
            if !reported {
                stats.l2_mismatches += 1;
            }
        }
        match outcome {
            Ok(ChainOutcome::Excluded(rule)) => {
                stats.rule(rule, 1);
                stats.details.push(format!(
                    "{:<44} {:>7} {:>8} {:>8}  {}",
                    crate::check::shorten(&chain.name, 44),
                    "-",
                    "excluded",
                    "",
                    if chain.options.as_object().is_some_and(|o| !o.is_empty()) {
                        format!("options {}", chain.options)
                    } else {
                        String::new()
                    }
                ));
                let _ = std::fs::remove_dir_all(&root);
            }
            Ok(ChainOutcome::Done { problems, .. }) if problems.is_empty() => {
                stats.pass();
                if !cfg.keep_temp {
                    let _ = std::fs::remove_dir_all(&root);
                }
            }
            Ok(ChainOutcome::Done { problems, .. }) => {
                stats.fail(
                    SUITE,
                    verbose,
                    &loc,
                    &format!("{} (files kept in {})", problems.join("; "), root.display()),
                );
            }
            Err(e) => {
                stats.details.push(format!(
                    "{:<44} {:>7} {:>8}  {e}",
                    crate::check::shorten(&chain.name, 44),
                    "-",
                    "ERROR"
                ));
                stats.fail(
                    SUITE,
                    verbose,
                    &loc,
                    &format!("{e} (files kept in {})", root.display()),
                );
            }
        }
    }
    let _ = std::fs::remove_dir(&base);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transports_come_from_bitcoind_connection_lines() {
        let log = "2026-11-09T03:09:33Z [net] New inbound peer connected: transport: v2, version: 70016, peer=0\n\
                   2026-11-09T03:09:34Z [net] New inbound peer connected: transport: v1, version: 70016, peer=1\n\
                   2026-11-09T03:09:34Z [net] New inbound peer connected: transport: v2, version: 70016, peer=2\n";
        assert_eq!(transports(log), "v1+v2");
        assert_eq!(transports("no connections\n"), "none");
    }

    #[test]
    fn options_become_bitcoind_arguments() {
        let args = bitcoind_args(
            &json!({"testactivationheight": {"segwit": 165, "csv": 432}, "test": ["bip94"]}),
        )
        .unwrap();
        // Object keys come in sorted order.
        assert_eq!(
            args,
            vec![
                "-test=bip94",
                "-testactivationheight=csv@432",
                "-testactivationheight=segwit@165"
            ]
        );
        assert!(bitcoind_args(&json!({})).unwrap().is_empty());
        assert!(bitcoind_args(&json!({"signetchallenge": "51"})).is_err());
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote(r#"{"a":1}"#), r#"'{"a":1}'"#);
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
