//! `bcs-conformance`: runs the bitcoin-consensus-spec conformance suites against any harness that
//! speaks conformance/PROTOCOL.md, and derives the flag-complete expectations of Core's script
//! vectors from the Bitcoin Core oracle.
//!
//! The runner deliberately does not depend on the reference implementation it is used to test.

mod amount;
mod check;
mod derived;
mod flags;
mod harness;
mod hex;
mod script;
mod suites;
mod taproot;
mod tx;

use check::{Ctx, Stats};
use harness::Harness;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use suites::{Mode, Paths, PLANNED, SUITES};

const USAGE: &str = "\
bcs-conformance: conformance runner for the bitcoin-consensus-spec

USAGE:
  bcs-conformance [run] --impl \"<harness command>\" [OPTIONS]
  bcs-conformance derive --oracle \"<oracle-core-harness command>\" [--out DIR] [OPTIONS]
  bcs-conformance suites
  bcs-conformance corpus | headers-live | interop      (not implemented yet)

RUN OPTIONS:
  --impl CMD          Shell command that starts the harness (run through sh -c)
  --suite LIST        Comma separated suites to run (default: all; see `bcs-conformance suites`)
  --raw               Check only the expectations the original vector files state for
                      consensus-only flags, instead of the derived expectations
  --verbose           Print every failure and level 2 mismatch with its row, flags and values
  --fail-on-level2    Also exit non-zero when error identifiers differ (level 2)
  --vectors DIR       Vector directory (default: conformance/vectors)
  --derived DIR       Derived vector directory (default: <vectors>/derived)
  --timeout SECS      Seconds to wait for each harness response (default: 120)

DERIVE OPTIONS:
  --oracle CMD        Shell command that starts oracle-core-harness
  --out DIR           Output directory (default: <vectors>/derived)
  --suite LIST        Script suites to derive (default: all four)
  --vectors DIR, --timeout SECS as above (cross-check failures are always printed)

Exit status: 0 when every check passed at level 1, 1 otherwise, 2 for usage errors.
";

struct Options {
    command: String,
    harness: Option<String>,
    out: Option<PathBuf>,
    suites: Option<Vec<String>>,
    raw: bool,
    verbose: bool,
    fail_on_level2: bool,
    vectors: Option<PathBuf>,
    derived: Option<PathBuf>,
    timeout: Duration,
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("bcs-conformance: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        command: "run".into(),
        harness: None,
        out: None,
        suites: None,
        raw: false,
        verbose: false,
        fail_on_level2: false,
        vectors: None,
        derived: None,
        timeout: Duration::from_secs(120),
    };
    let mut i = 0;
    if let Some(first) = args.first() {
        if !first.starts_with('-') {
            o.command = first.clone();
            i = 1;
        }
    }
    let value = |i: &mut usize, name: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("{name} needs a value"))
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--impl" => o.harness = Some(value(&mut i, a)?),
            "--oracle" => o.harness = Some(value(&mut i, a)?),
            "--out" => o.out = Some(PathBuf::from(value(&mut i, a)?)),
            "--suite" | "--suites" => {
                let list = value(&mut i, a)?;
                let mut v: Vec<String> = o.suites.take().unwrap_or_default();
                v.extend(
                    list.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
                o.suites = Some(v);
            }
            "--raw" => o.raw = true,
            "--verbose" | "-v" => o.verbose = true,
            "--fail-on-level2" => o.fail_on_level2 = true,
            "--vectors" => o.vectors = Some(PathBuf::from(value(&mut i, a)?)),
            "--derived" => o.derived = Some(PathBuf::from(value(&mut i, a)?)),
            "--timeout" => {
                let secs: u64 = value(&mut i, a)?
                    .parse()
                    .map_err(|_| "--timeout takes whole seconds".to_string())?;
                o.timeout = Duration::from_secs(secs.max(1));
            }
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
            for (name, what) in SUITES {
                println!("{name:<14} {what}");
            }
            for (name, what) in PLANNED {
                println!("{name:<14} {what} (not implemented yet)");
            }
            ExitCode::SUCCESS
        }
        "run" => cmd_run(&opts),
        "derive" => cmd_derive(&opts),
        planned if PLANNED.iter().any(|(n, _)| *n == planned) => {
            let what = PLANNED.iter().find(|(n, _)| *n == planned).unwrap().1;
            eprintln!("bcs-conformance: the {planned} suite ({what}) is not implemented yet");
            ExitCode::from(2)
        }
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

fn selected_suites(opts: &Options, allowed: &[&'static str]) -> Result<Vec<&'static str>, String> {
    match &opts.suites {
        None => Ok(allowed.to_vec()),
        Some(list) => list
            .iter()
            .map(|s| {
                if PLANNED.iter().any(|(n, _)| n == s) {
                    return Err(format!("the {s} suite is not implemented yet"));
                }
                allowed
                    .iter()
                    .find(|a| **a == s.as_str())
                    .copied()
                    .ok_or_else(|| {
                        format!("unknown suite {s} (expected one of {})", allowed.join(", "))
                    })
            })
            .collect(),
    }
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
        _ => &[],
    }
}

fn cmd_run(opts: &Options) -> ExitCode {
    let all: Vec<&'static str> = SUITES.iter().map(|s| s.0).collect();
    let selected = match selected_suites(opts, &all) {
        Ok(s) => s,
        Err(e) => return usage_error(&e),
    };
    let mut harness = match start(opts, "--impl") {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bcs-conformance: {e}");
            return ExitCode::FAILURE;
        }
    };
    let paths = paths(opts);
    let mode = if opts.raw { Mode::Raw } else { Mode::Derived };
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
    let mut results: Vec<(&str, Stats, Duration)> = Vec::new();
    for suite in selected {
        let started = Instant::now();
        let ops = suite_ops(suite);
        if !ops.iter().any(|op| harness.supports(op)) {
            let stats = Stats {
                error: Some(format!("not supported (needs {})", ops.join(" or "))),
                ..Default::default()
            };
            results.push((suite, stats, started.elapsed()));
            continue;
        }
        let mut ctx = Ctx::new(&mut harness, suite, opts.verbose);
        let outcome = match suite {
            "sighash" => suites::sighash::run(&mut ctx, &paths.vectors),
            "bip341" => suites::bip341::run(&mut ctx, &paths.vectors),
            "bip340" => suites::bip340::run(&mut ctx, &paths.vectors),
            _ => suites::run_script_suite(&mut ctx, &paths, mode),
        };
        let mut stats = ctx.stats;
        if let Err(e) = outcome {
            stats.error = Some(e);
        }
        results.push((suite, stats, started.elapsed()));
    }
    let restarts = harness.restarts();
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

/// Prints the per-suite table. Returns true when any suite failed at level 1 or errored.
fn print_report(results: &[(&str, Stats, Duration)], mode: &str) -> bool {
    println!();
    println!(
        "{:<14} {:<8} {:>9} {:>9} {:>8} {:>8} {:>11} {:>8} {:>8}",
        "suite", "mode", "cases", "passed", "failed", "level2", "l2-checked", "unsupp.", "time"
    );
    let mut any_failure = false;
    for (suite, s, t) in results {
        let mode = if matches!(*suite, "sighash" | "bip341" | "bip340") {
            "-"
        } else {
            mode
        };
        if let Some(e) = &s.error {
            if s.cases == 0 {
                println!("{suite:<14} {mode:<8} {e}");
                if !e.starts_with("not supported") {
                    any_failure = true;
                }
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
        if s.failed > 0 {
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
    let selected = match selected_suites(opts, &script_suites) {
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
