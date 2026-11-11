//! `bcs-conformance`: runs the bitcoin-consensus-spec conformance suites against any harness that
//! speaks conformance/PROTOCOL.md, and derives the flag-complete expectations of Core's script
//! vectors from the Bitcoin Core oracle.
//!
//! The runner deliberately does not depend on the reference implementation it is used to test.

mod amount;
mod bitcoind;
mod check;
mod derived;
mod flags;
mod harness;
mod hex;
mod known;
mod p2p;
mod script;
mod suites;
mod taproot;
mod tx;
mod work;

use check::{Ctx, Stats};
use harness::Harness;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use suites::{Mode, Paths, SUITES};

const USAGE: &str = "\
bcs-conformance: conformance runner for the bitcoin-consensus-spec

USAGE:
  bcs-conformance [run] --impl \"<harness command>\" [OPTIONS]
  bcs-conformance <suite> [OPTIONS]                 (same as --suite <suite>)
  bcs-conformance derive --oracle \"<oracle-core-harness command>\" [--out DIR] [OPTIONS]
  bcs-conformance suites

RUN OPTIONS:
  --impl CMD          Shell command that starts the harness (run through sh -c)
  --suite LIST        Comma separated suites to run (default: every suite marked default in
                      `bcs-conformance suites`; headers-live and interop only run when named)
  --exclude LIST      Suites to leave out of the run
  --raw               Check only the expectations the original vector files state for
                      consensus-only flags, instead of the derived expectations
  --verbose           Print every failure and level 2 mismatch with its row, flags and values
  --fail-on-level2    Also exit non-zero when error identifiers or corpus UTXO hashes differ
  --known-failures FILE
                      Checks the implementation is known to fail, one \"<suite> <location>\" per
                      line (# starts a comment line). A failure the file names is counted as
                      known, not failed; an entry that names no failure, in a suite that ran,
                      fails the run
  --vectors DIR       Vector directory (default: conformance/vectors)
  --derived DIR       Derived vector directory (default: <vectors>/derived)
  --timeout SECS      Seconds to wait for each harness response (default: 120)

CORPUS OPTIONS:
  --corpus PATH       Corpus file or directory, repeatable (default: <vectors>/blocks)
  --restart-shortcut  Skip restart events whose options equal the ones in force (CORPUS.md 4)

HEADERS-LIVE OPTIONS:
  --peer HOST[:PORT]  Peer to download headers from; a name may resolve to several addresses
  --network NAME      main, testnet3, testnet4, signet or regtest (default: main)
  --peer-timeout SECS Seconds to wait for each headers message (default: 120)

INTEROP OPTIONS:
  --bitcoind PATH     The bitcoind binary to run next to the node
  --node CMD          Node command template with {network} {datadir} {peer} {stop_at}
                      (and the extension {options}, see conformance/README.md)
  --port-range LO-HI  Ports for bitcoind (default: 29000-29999; ports in use are skipped)
  --node-timeout SECS Seconds to wait for the node's stopped line (default: 600)
  --keep-temp         Keep the temporary data directories of passing chains too

DERIVE OPTIONS:
  --oracle CMD        Shell command that starts oracle-core-harness
  --out DIR           Output directory (default: <vectors>/derived)
  --suite LIST        Script suites to derive (default: all four)
  --vectors DIR, --timeout SECS as above (cross-check failures are always printed)

Exit status: 0 when every check passed at level 1 (level 0 for the corpus), 1 otherwise,
2 for usage errors. Checks that need an operation the harness does not list are failures unless
their suite is excluded.
";

struct Options {
    command: String,
    harness: Option<String>,
    out: Option<PathBuf>,
    suites: Option<Vec<String>>,
    exclude: Vec<String>,
    raw: bool,
    verbose: bool,
    fail_on_level2: bool,
    known_failures: Option<PathBuf>,
    vectors: Option<PathBuf>,
    derived: Option<PathBuf>,
    timeout: Duration,
    corpus: Vec<PathBuf>,
    restart_shortcut: bool,
    peer: Option<String>,
    network: String,
    peer_timeout: Duration,
    bitcoind: Option<PathBuf>,
    node: Option<String>,
    port_range: (u16, u16),
    node_timeout: Duration,
    keep_temp: bool,
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("bcs-conformance: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn list(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        command: "run".into(),
        harness: None,
        out: None,
        suites: None,
        exclude: Vec::new(),
        raw: false,
        verbose: false,
        fail_on_level2: false,
        known_failures: None,
        vectors: None,
        derived: None,
        timeout: Duration::from_secs(120),
        corpus: Vec::new(),
        restart_shortcut: false,
        peer: None,
        network: "main".into(),
        peer_timeout: Duration::from_secs(120),
        bitcoind: None,
        node: None,
        port_range: (29000, 29999),
        node_timeout: Duration::from_secs(600),
        keep_temp: false,
    };
    let mut i = 0;
    if let Some(first) = args.first() {
        if !first.starts_with('-') {
            if suites::suite(first).is_some() {
                o.suites = Some(vec![first.clone()]);
            } else {
                o.command = first.clone();
            }
            i = 1;
        }
    }
    let value = |i: &mut usize, name: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("{name} needs a value"))
    };
    let secs = |v: String, name: &str| -> Result<Duration, String> {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("{name} takes whole seconds"))?;
        Ok(Duration::from_secs(n.max(1)))
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--impl" | "--oracle" => o.harness = Some(value(&mut i, a)?),
            "--out" => o.out = Some(PathBuf::from(value(&mut i, a)?)),
            "--suite" | "--suites" => {
                let v = value(&mut i, a)?;
                o.suites.get_or_insert_with(Vec::new).extend(list(&v));
            }
            "--exclude" => {
                let v = value(&mut i, a)?;
                o.exclude.extend(list(&v));
            }
            "--raw" => o.raw = true,
            "--verbose" | "-v" => o.verbose = true,
            "--fail-on-level2" => o.fail_on_level2 = true,
            "--known-failures" => o.known_failures = Some(PathBuf::from(value(&mut i, a)?)),
            "--vectors" => o.vectors = Some(PathBuf::from(value(&mut i, a)?)),
            "--derived" => o.derived = Some(PathBuf::from(value(&mut i, a)?)),
            "--timeout" => o.timeout = secs(value(&mut i, a)?, a)?,
            "--corpus" => o.corpus.push(PathBuf::from(value(&mut i, a)?)),
            "--restart-shortcut" => o.restart_shortcut = true,
            "--peer" => o.peer = Some(value(&mut i, a)?),
            "--network" => o.network = value(&mut i, a)?,
            "--peer-timeout" => o.peer_timeout = secs(value(&mut i, a)?, a)?,
            "--bitcoind" => o.bitcoind = Some(PathBuf::from(value(&mut i, a)?)),
            "--node" => o.node = Some(value(&mut i, a)?),
            "--port-range" => {
                let v = value(&mut i, a)?;
                let (lo, hi) = v.split_once('-').ok_or("--port-range takes LO-HI")?;
                let lo: u16 = lo.parse().map_err(|_| "bad --port-range")?;
                let hi: u16 = hi.parse().map_err(|_| "bad --port-range")?;
                if lo == 0 || hi < lo {
                    return Err("bad --port-range".into());
                }
                o.port_range = (lo, hi);
            }
            "--node-timeout" => o.node_timeout = secs(value(&mut i, a)?, a)?,
            "--keep-temp" => o.keep_temp = true,
            "--help" | "-h" => o.command = "help".into(),
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    Ok(o)
}

fn default_vectors() -> PathBuf {
    let candidates = [
        PathBuf::from("conformance/vectors"),
        PathBuf::from("vectors"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors"),
    ];
    for c in &candidates {
        if c.join("core/script_tests.json").is_file() {
            return c.clone();
        }
    }
    candidates[0].clone()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(o) => o,
        Err(e) => return usage_error(&e),
    };
    match opts.command.as_str() {
        "help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        "suites" => {
            for s in SUITES {
                println!(
                    "{:<14} {:<8} {}",
                    s.name,
                    if s.default { "default" } else { "named" },
                    s.what
                );
            }
            ExitCode::SUCCESS
        }
        "run" => cmd_run(&opts),
        "derive" => cmd_derive(&opts),
        other => usage_error(&format!("unknown command {other}")),
    }
}

fn paths(opts: &Options) -> Paths {
    let vectors = opts.vectors.clone().unwrap_or_else(default_vectors);
    let derived = opts
        .derived
        .clone()
        .unwrap_or_else(|| vectors.join("derived"));
    Paths { vectors, derived }
}

/// The suites to run: `--suite` (or every default suite), minus `--exclude`.
fn selected_suites(
    opts: &Options,
    allowed: &[&'static str],
    defaults: &[&'static str],
) -> Result<Vec<&'static str>, String> {
    let check = |s: &String| -> Result<&'static str, String> {
        allowed
            .iter()
            .find(|a| **a == s.as_str())
            .copied()
            .ok_or_else(|| format!("unknown suite {s} (expected one of {})", allowed.join(", ")))
    };
    let mut chosen: Vec<&'static str> = match &opts.suites {
        None => defaults.to_vec(),
        Some(list) => list.iter().map(check).collect::<Result<_, _>>()?,
    };
    for e in &opts.exclude {
        let e = check(e)?;
        chosen.retain(|s| *s != e);
    }
    let mut seen = Vec::new();
    chosen.retain(|s| {
        let new = !seen.contains(s);
        seen.push(s);
        new
    });
    Ok(chosen)
}

fn start(opts: &Options, what: &str) -> Result<Harness, String> {
    let cmd = opts
        .harness
        .as_deref()
        .ok_or_else(|| format!("{what} is required"))?;
    let h = Harness::start(cmd, opts.timeout)?;
    println!(
        "harness: {} {} (spec {}), ops: {}",
        h.info.name,
        h.info.version,
        h.info.spec_version,
        h.info.ops.join(", ")
    );
    Ok(h)
}

fn suite_ops(suite: &str) -> &'static [&'static str] {
    match suite {
        "script-tests" | "script-assets" => &["script_verify"],
        "tx-valid" | "tx-invalid" => &["script_verify", "tx_check"],
        "sighash" => &["sighash_legacy", "tx_check"],
        "bip341" => &[
            "sighash_taproot",
            "script_verify",
            "taproot_commitment_verify",
        ],
        "bip340" => &["schnorr_verify"],
        "custom" => &[
            "script_verify",
            "tx_check",
            "sighash_legacy",
            "sighash_taproot",
            "taproot_commitment_verify",
            "schnorr_verify",
        ],
        "corpus" => &[
            "chain_reset",
            "chain_process_block",
            "chain_process_headers",
            "chain_invalidate",
            "chain_tip",
        ],
        "headers-live" => &["chain_reset", "chain_process_headers"],
        _ => &[],
    }
}

fn corpus_paths(opts: &Options, paths: &Paths) -> Vec<PathBuf> {
    if opts.corpus.is_empty() {
        vec![paths.vectors.join("blocks")]
    } else {
        opts.corpus.clone()
    }
}

fn cmd_run(opts: &Options) -> ExitCode {
    let all: Vec<&'static str> = SUITES.iter().map(|s| s.name).collect();
    let defaults: Vec<&'static str> = SUITES
        .iter()
        .filter(|s| s.default)
        .map(|s| s.name)
        .collect();
    let selected = match selected_suites(opts, &all, &defaults) {
        Ok(s) => s,
        Err(e) => return usage_error(&e),
    };
    if selected.is_empty() {
        return usage_error("no suite selected");
    }
    if let Some(path) = &opts.known_failures {
        if let Err(e) = known::load(path, &all) {
            return usage_error(&e);
        }
    }
    if selected.contains(&"headers-live") && opts.peer.is_none() {
        return usage_error("headers-live needs --peer HOST[:PORT]");
    }
    if selected.contains(&"interop") && (opts.bitcoind.is_none() || opts.node.is_none()) {
        return usage_error("interop needs --bitcoind PATH and --node \"<command template>\"");
    }
    let needs_harness = selected
        .iter()
        .any(|s| suites::suite(s).is_some_and(|i| i.needs_harness));
    let mut harness = if needs_harness {
        match start(opts, "--impl") {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("bcs-conformance: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let paths = paths(opts);
    let mode = if opts.raw { Mode::Raw } else { Mode::Derived };
    if selected.iter().any(|s| suites::script_source(s).is_some()) {
        println!(
            "mode: {}  vectors: {}{}",
            if opts.raw {
                "raw (original vector expectations, consensus flags only)"
            } else {
                "derived (all 64 consensus flag combinations)"
            },
            paths.vectors.display(),
            if opts.raw {
                String::new()
            } else {
                format!("  derived: {}", paths.derived.display())
            }
        );
    }
    let mut results: Vec<(&str, Stats, Duration)> = Vec::new();
    for suite in selected {
        let started = Instant::now();
        if suite == "interop" {
            let cfg = suites::interop::Config {
                bitcoind: opts.bitcoind.clone().unwrap(),
                node: opts.node.clone().unwrap(),
                corpus: corpus_paths(opts, &paths),
                port_range: opts.port_range,
                node_timeout: opts.node_timeout,
                keep_temp: opts.keep_temp,
            };
            let mut stats = Stats::default();
            if let Err(e) = suites::interop::run(&mut stats, opts.verbose, &cfg) {
                stats.error = Some(e);
            }
            results.push((suite, stats, started.elapsed()));
            continue;
        }
        let harness = harness.as_mut().expect("started above");
        let ops = suite_ops(suite);
        if !ops.iter().any(|op| harness.supports(op)) {
            let stats = Stats {
                error: Some(format!("not supported (needs {})", ops.join(" or "))),
                ..Default::default()
            };
            results.push((suite, stats, started.elapsed()));
            continue;
        }
        let mut ctx = Ctx::new(harness, suite, opts.verbose);
        let outcome = match suite {
            "sighash" => suites::sighash::run(&mut ctx, &paths.vectors),
            "bip341" => suites::bip341::run(&mut ctx, &paths.vectors),
            "bip340" => suites::bip340::run(&mut ctx, &paths.vectors),
            "custom" => suites::custom::run(&mut ctx, &paths.vectors),
            "corpus" => {
                suites::corpus::run(&mut ctx, &corpus_paths(opts, &paths), opts.restart_shortcut)
            }
            "headers-live" => {
                let cfg = suites::headers_live::Config {
                    peer: opts.peer.clone().unwrap(),
                    network: opts.network.clone(),
                    response_timeout: opts.peer_timeout,
                    max_reconnects: 8,
                };
                suites::headers_live::run(&mut ctx, &cfg)
            }
            _ => suites::run_script_suite(&mut ctx, &paths, mode),
        };
        let mut stats = ctx.stats;
        if let Err(e) = outcome {
            stats.error = Some(e);
        }
        results.push((suite, stats, started.elapsed()));
    }
    let restarts = harness.as_ref().map_or(0, |h| h.restarts());
    drop(harness);
    let failed = print_report(&results, if opts.raw { "raw" } else { "derived" });
    if restarts > 0 {
        println!("note: the harness died and was restarted {restarts} time(s)");
    }
    let l2 = results.iter().map(|r| r.1.l2_mismatches).sum::<u64>();
    if failed || (opts.fail_on_level2 && l2 > 0) {
        if !opts.verbose {
            println!("run with --verbose to see every failure");
        }
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Prints the per-suite table and each suite's detail lines. Returns true when any suite failed
/// at level 1 (level 0 for the corpus), could not run, has checks the harness does not support,
/// or when a `--known-failures` entry of a suite that ran named no failure.
fn print_report(results: &[(&str, Stats, Duration)], mode: &str) -> bool {
    println!();
    println!(
        "{:<14} {:<8} {:>9} {:>9} {:>8} {:>8} {:>11} {:>8} {:>8}",
        "suite", "mode", "cases", "passed", "failed", "level2", "l2-checked", "unsupp.", "time"
    );
    let mut any_failure = false;
    for (suite, s, t) in results {
        let mode = if matches!(
            *suite,
            "script-tests" | "tx-valid" | "tx-invalid" | "script-assets"
        ) || mode == "core"
        {
            mode
        } else {
            "-"
        };
        if let Some(e) = &s.error {
            if s.cases == 0 {
                println!("{suite:<14} {mode:<8} {e}");
                any_failure = true;
                continue;
            }
        }
        println!(
            "{:<14} {:<8} {:>9} {:>9} {:>8} {:>8} {:>11} {:>8} {:>7.1}s",
            suite,
            mode,
            s.cases,
            s.passed,
            s.failed,
            s.l2_mismatches,
            s.l2_checked,
            s.unsupported,
            t.as_secs_f64()
        );
        if let Some(e) = &s.error {
            println!("{:<14} error: {e}", "");
            any_failure = true;
        }
        if s.failed > 0 || s.unsupported > 0 {
            any_failure = true;
        }
    }
    let rules: Vec<_> = results.iter().filter(|r| !r.1.rules.is_empty()).collect();
    if !rules.is_empty() {
        println!();
        println!("rows without a check in this mode (stated rules, counted):");
        for (suite, s, _) in rules {
            for (rule, n) in &s.rules {
                println!("  {suite}: {n} x {rule}");
            }
        }
    }
    for (_, s, _) in results {
        if !s.details.is_empty() {
            println!();
            for line in &s.details {
                println!("{line}");
            }
        }
    }
    let ran: Vec<&str> = results.iter().map(|r| r.0).collect();
    if let Some((path, stale)) = known::stale(&ran) {
        let counts: Vec<String> = results
            .iter()
            .filter(|r| r.1.known > 0)
            .map(|r| format!("{} {}", r.0, r.1.known))
            .collect();
        println!();
        println!(
            "known failures ({}): {}",
            path.display(),
            if counts.is_empty() {
                "none failed".to_string()
            } else {
                format!("{} (counted in cases, not in failed)", counts.join(", "))
            }
        );
        for s in &stale {
            println!(
                "STALE    [{}] {}: {}:{} names no failure of this run; remove it",
                s.suite,
                s.location,
                path.display(),
                s.line
            );
        }
        if !stale.is_empty() {
            any_failure = true;
        }
    }
    println!();
    println!(
        "{}",
        if any_failure {
            "RESULT: FAIL"
        } else {
            "RESULT: PASS"
        }
    );
    any_failure
}

fn cmd_derive(opts: &Options) -> ExitCode {
    let script_suites: Vec<&'static str> = suites::SCRIPT_SOURCES.iter().map(|s| s.0).collect();
    let selected = match selected_suites(opts, &script_suites, &script_suites) {
        Ok(s) => s,
        Err(e) => return usage_error(&e),
    };
    let mut oracle = match start(opts, "--oracle") {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bcs-conformance: {e}");
            return ExitCode::FAILURE;
        }
    };
    let paths = paths(opts);
    let out = opts.out.clone().unwrap_or_else(|| paths.derived.clone());
    let info = Value::Object(oracle.info.raw.clone());
    let provenance = json!({
        "core_version": info.get("core_version").cloned().unwrap_or(Value::Null),
        "core_commit": info.get("core_commit").cloned().unwrap_or(Value::Null),
        "oracle": info,
        "generator": format!("bcs-conformance {} derive", env!("CARGO_PKG_VERSION")),
    });
    let mut files = Vec::new();
    let mut results = Vec::new();
    for &suite in &selected {
        let started = Instant::now();
        eprintln!("deriving {suite} ...");
        // Cross-check failures are runner or oracle bugs: always print them.
        let mut ctx = Ctx::new(&mut oracle, suite, true);
        let outcome = suites::derive_suite(&mut ctx, &paths, &provenance);
        let mut stats = ctx.stats;
        match outcome {
            Ok(file) => {
                eprintln!(
                    "  {} queries x 64 combinations, cross-check {} passed / {} failed / {} level 2 mismatches",
                    file.script_count(),
                    stats.passed,
                    stats.failed,
                    stats.l2_mismatches
                );
                files.push((suites::script_source(suite).unwrap().1, file));
            }
            Err(e) => stats.error = Some(e),
        }
        results.push((suite, stats, started.elapsed()));
    }

    // Replay of Core's own unit tests with their original flags, when the oracle offers the
    // extension that accepts policy flags. It proves that the runner builds every row exactly as
    // Core's tests do, including rows whose expectations need policy flags.
    let has_replay = oracle
        .info
        .raw
        .get("extensions")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|e| e.as_str() == Some(suites::CORE_REPLAY_OP)));
    let mut replay = Vec::new();
    if has_replay {
        for suite in selected.iter().copied().filter(|s| *s != "script-assets") {
            let started = Instant::now();
            eprintln!("replaying Core's {suite} unit test with its original flags ...");
            let mut ctx = Ctx::new(&mut oracle, suite, true);
            let outcome = suites::replay_core(&mut ctx, &paths);
            let mut stats = ctx.stats;
            if let Err(e) = outcome {
                stats.error = Some(e);
            }
            replay.push((suite, stats, started.elapsed()));
        }
    } else {
        eprintln!(
            "note: the oracle does not offer {}; Core's unit tests were not replayed with policy flags",
            suites::CORE_REPLAY_OP
        );
    }
    drop(oracle);
    println!("\ncross-check of the oracle's answers against the original vector expectations:");
    let mut failed = print_report(&results, "raw");
    if !replay.is_empty() {
        println!(
            "\nreplay of Core's unit tests with the rows' original flags (policy flags included):"
        );
        failed |= print_report(&replay, "core");
    }
    let l2 = results
        .iter()
        .chain(replay.iter())
        .map(|r| r.1.l2_mismatches)
        .sum::<u64>();
    if failed || l2 > 0 {
        eprintln!("bcs-conformance: the cross-check failed; no derived file was written");
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("bcs-conformance: cannot create {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    for (name, file) in files {
        let path = out.join(name);
        let text = match file.to_text() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("bcs-conformance: {name}: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = std::fs::write(&path, &text) {
            eprintln!("bcs-conformance: cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!(
            "wrote {} ({} bytes, {} entries)",
            path.display(),
            text.len(),
            file.script_count()
        );
    }
    ExitCode::SUCCESS
}
