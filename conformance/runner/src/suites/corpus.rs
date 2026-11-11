//! The `corpus` suite: replays the block scenarios of conformance/CORPUS.md.
//!
//! Each `*.jsonl.gz` file is replayed exactly as CORPUS.md section 4 says:
//!
//! - `reset` becomes `chain_reset` (the returned genesis must equal the event's `genesis`);
//! - `block`, `headers` and `invalidate` become `chain_process_block` (with `now`, `via` and
//!   `requested` when present), `chain_process_headers` (with `now` and `via`) and
//!   `chain_invalidate` (with `hash` and `now`);
//! - `restart` becomes `chain_reset` with the new options followed by every `block`, `headers` and
//!   `invalidate` request sent since the last `reset`, again (responses not scored). With
//!   `--restart-shortcut`, a restart whose options equal the ones in force sends nothing;
//! - `check` becomes `chain_tip` (level 0), `chain_tips` when the check carries `tips` (level 1),
//!   and `utxo_hash` when it carries `utxo` (level 2).
//!
//! Level 0 at normative checks is required. Non-normative level 0 checks, level 1 and level 2 are
//! reported separately. A harness error (`ok: false`, a crash) or a corrupt file is a failure.
//! `--known-failures` names a level 0 failure as `<file> check <n>` and a file's errors as
//! `<file> errors`.

use crate::check::{shorten, Ctx};
use crate::hex;
use crate::tx::sha256d;
use flate2::read::MultiGzDecoder;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const FORMAT: &str = "bcs-block-corpus";
pub const FORMAT_VERSION: u64 = 1;

/// How many events before a diverging check are shown with `--verbose`.
const DIAGNOSTIC_EVENTS: usize = 40;
/// How many further mismatches per file and level are printed with `--verbose`.
const MAX_MISMATCH_LINES: usize = 20;

/// Every `*.jsonl.gz` file in the given directories (sorted by name) and every file given
/// directly.
pub fn corpus_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| format!("cannot read {}: {e}", p.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|f| f.to_string_lossy().ends_with(".jsonl.gz"))
                .collect();
            found.sort();
            files.extend(found);
        } else if p.is_file() {
            files.push(p.clone());
        } else {
            return Err(format!("{} does not exist", p.display()));
        }
    }
    Ok(files)
}

/// Reads one corpus file: the `meta` event and every following event.
pub fn read_events(path: &Path) -> Result<(Value, Vec<Value>), String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let reader = BufReader::new(MultiGzDecoder::new(file));
    let mut lines = reader.lines();
    let first = lines
        .next()
        .ok_or_else(|| format!("{}: empty file", path.display()))?
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let meta: Value =
        serde_json::from_str(&first).map_err(|e| format!("{}: line 1: {e}", path.display()))?;
    if meta["type"] != "meta" {
        return Err(format!(
            "{}: the first line is not a meta event",
            path.display()
        ));
    }
    if meta["format"] != FORMAT || meta["format_version"].as_u64() != Some(FORMAT_VERSION) {
        return Err(format!(
            "{}: unsupported format {} version {} (this runner reads {FORMAT} version {FORMAT_VERSION})",
            path.display(),
            meta["format"],
            meta["format_version"]
        ));
    }
    let mut events = Vec::new();
    for (i, line) in lines.enumerate() {
        let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(
            serde_json::from_str(&line)
                .map_err(|e| format!("{}: line {}: {e}", path.display(), i + 2))?,
        );
    }
    Ok((meta, events))
}

/// The serialized block of a `block` event: its `hex`, or the bytes of its blob (checked against
/// `sha256` and `size`). The block hash is checked against `hash`.
pub fn block_bytes(ev: &Value, base: &Path) -> Result<Vec<u8>, String> {
    let bytes = if let Some(h) = ev["hex"].as_str() {
        hex::decode(h)?
    } else if let Some(blob) = ev["blob"].as_str() {
        let path = base.join(blob);
        let file = std::fs::File::open(&path)
            .map_err(|e| format!("cannot open blob {}: {e}", path.display()))?;
        let mut bytes = Vec::new();
        MultiGzDecoder::new(file)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read blob {}: {e}", path.display()))?;
        if let Some(size) = ev["size"].as_u64() {
            if bytes.len() as u64 != size {
                return Err(format!(
                    "blob {blob} has {} bytes, the event says {size}",
                    bytes.len()
                ));
            }
        }
        if let Some(sha) = ev["sha256"].as_str() {
            if hex::encode(&Sha256::digest(&bytes)) != sha {
                return Err(format!("blob {blob} does not match its sha256"));
            }
        }
        bytes
    } else {
        return Err("block event without hex or blob".into());
    };
    if bytes.len() < 80 {
        return Err("block shorter than a header".into());
    }
    if let Some(hash) = ev["hash"].as_str() {
        let got = hex::encode_reversed(&sha256d(&bytes[..80]));
        if got != hash {
            return Err(format!("block hash is {got}, the event says {hash}"));
        }
    }
    Ok(bytes)
}

/// Request fields (without braces) of a map.
fn body(fields: Map<String, Value>) -> String {
    let s = Value::Object(fields).to_string();
    s[1..s.len() - 1].to_string()
}

/// The protocol request of a `block`, `headers` or `invalidate` event: (op, fields).
pub fn event_request(ev: &Value, base: &Path) -> Result<(&'static str, String), String> {
    let mut f = Map::new();
    let now = ev["now"].as_i64().ok_or("event without integer now")?;
    match ev["type"].as_str() {
        Some("block") => {
            f.insert("block".into(), json!(hex::encode(&block_bytes(ev, base)?)));
            f.insert("now".into(), json!(now));
            if let Some(via) = ev.get("via") {
                f.insert("via".into(), via.clone());
            }
            if let Some(requested) = ev.get("requested") {
                f.insert("requested".into(), requested.clone());
            }
            Ok(("chain_process_block", body(f)))
        }
        Some("headers") => {
            let headers = ev["headers"]
                .as_array()
                .ok_or("headers event without headers")?;
            f.insert("headers".into(), Value::Array(headers.clone()));
            f.insert("now".into(), json!(now));
            if let Some(via) = ev.get("via") {
                f.insert("via".into(), via.clone());
            }
            Ok(("chain_process_headers", body(f)))
        }
        Some("invalidate") => {
            f.insert("hash".into(), ev["hash"].clone());
            f.insert("now".into(), json!(now));
            Ok(("chain_invalidate", body(f)))
        }
        other => Err(format!("not a chain event: {other:?}")),
    }
}

/// Results of one file.
#[derive(Default)]
pub struct FileResult {
    pub name: String,
    pub events: u64,
    pub checks: u64,
    pub normative: u64,
    pub l0_fail: u64,
    /// Normative checks that failed as `--known-failures` says (not in `l0_fail`).
    pub l0_known: u64,
    pub l0_other: u64,
    pub l0_other_fail: u64,
    pub l1: u64,
    pub l1_fail: u64,
    pub l2: u64,
    pub l2_fail: u64,
    pub restarts: u64,
    pub restarts_skipped: u64,
    pub redelivered: u64,
    pub errors: Vec<String>,
    pub outcomes: BTreeMap<String, u64>,
    pub seconds: f64,
}

fn short(hash: &str) -> String {
    if hash.len() == 64 {
        format!("{}..{}", &hash[..8], &hash[56..])
    } else {
        hash.to_string()
    }
}

fn tip_text(v: &Value) -> String {
    match (v["tip"].as_str(), v["height"].as_i64()) {
        (Some(t), Some(h)) => format!("{} height {h}", short(t)),
        _ => "(no tip)".to_string(),
    }
}

/// One line describing an event and the harness's answer, for divergence reports.
fn describe_event(idx: usize, ev: &Value, answer: &Result<Map<String, Value>, String>) -> String {
    let t = ev["type"].as_str().unwrap_or("?");
    let mut s = format!("event {idx} (line {}) {t}", idx + 2);
    match t {
        "block" => {
            s.push_str(&format!(" {}", short(ev["hash"].as_str().unwrap_or("?"))));
            if let Some(via) = ev["via"].as_str() {
                s.push_str(&format!(" via {via}"));
            }
            if let Some(r) = ev["requested"].as_bool() {
                s.push_str(&format!(" requested={r}"));
            }
        }
        "headers" => {
            let n = ev["headers"].as_array().map_or(0, |a| a.len());
            s.push_str(&format!(" ({n} headers)"));
            if let Some(via) = ev["via"].as_str() {
                s.push_str(&format!(" via {via}"));
            }
        }
        "invalidate" => s.push_str(&format!(" {}", short(ev["hash"].as_str().unwrap_or("?")))),
        _ => {}
    }
    if let Some(now) = ev["now"].as_i64() {
        s.push_str(&format!(" now {now}"));
    }
    match answer {
        Err(e) => s.push_str(&format!(" -> ERROR {e}")),
        Ok(a) => {
            let a = Value::Object(a.clone());
            if let Some(r) = a["result"].as_str() {
                s.push_str(&format!(" -> {r}"));
            } else {
                s.push_str(" ->");
            }
            if let Some(reason) = a["reason"].as_str() {
                s.push_str(&format!(" ({reason})"));
            }
            if let Some(i) = a["index"].as_i64() {
                s.push_str(&format!(" at index {i}"));
            }
            if a.get("tip").is_some() {
                s.push_str(&format!(", tip {}", tip_text(&a)));
            }
            if let Some(b) = a["best_header"].as_str() {
                s.push_str(&format!(", best header {}", short(b)));
            }
        }
    }
    s
}

type Triple = (String, i64, String);

fn tips_set(v: &Value) -> BTreeSet<Triple> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|t| {
                    (
                        t["hash"].as_str().unwrap_or("").to_string(),
                        t["height"].as_i64().unwrap_or(-1),
                        t["status"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Replays one file through the harness.
pub fn replay_file(ctx: &mut Ctx, path: &Path, restart_shortcut: bool) -> FileResult {
    let started = Instant::now();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let name = name.trim_end_matches(".jsonl.gz").to_string();
    let mut r = FileResult {
        name: name.clone(),
        ..Default::default()
    };
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let (_meta, events) = match read_events(path) {
        Ok(x) => x,
        Err(e) => {
            r.errors.push(e);
            return r;
        }
    };
    r.events = events.len() as u64;

    let mut network: Option<Value> = None;
    let mut options = Value::Object(Map::new());
    let mut prefix: Vec<&Value> = Vec::new();
    let mut recent: Vec<String> = Vec::new();
    let mut diverged = false;
    let mut printed = [0usize; 3];

    let call = |ctx: &mut Ctx, op: &str, fields: &str| -> Result<Map<String, Value>, String> {
        ctx.harness.call(op, fields).map_err(|e| e.to_string())
    };

    for (idx, ev) in events.iter().enumerate() {
        if r.errors.len() > 20 {
            r.errors.push("too many errors, replay stopped".into());
            break;
        }
        let kind = ev["type"].as_str().unwrap_or("");
        match kind {
            "reset" => {
                let opts = ev.get("options").cloned().unwrap_or_else(|| json!({}));
                let mut f = Map::new();
                f.insert("network".into(), ev["network"].clone());
                f.insert("options".into(), opts.clone());
                match call(ctx, "chain_reset", &body(f)) {
                    Ok(a) => {
                        if let (Some(want), Some(got)) = (
                            ev["genesis"].as_str(),
                            a.get("genesis").and_then(Value::as_str),
                        ) {
                            if want != got {
                                r.errors.push(format!("event {idx}: chain_reset returned genesis {got}, expected {want}"));
                            }
                        }
                    }
                    Err(e) => r.errors.push(format!("event {idx} chain_reset: {e}")),
                }
                network = Some(ev["network"].clone());
                options = opts;
                prefix.clear();
                recent.clear();
            }
            "restart" => {
                r.restarts += 1;
                let new_options = ev.get("options").cloned().unwrap_or_else(|| json!({}));
                if restart_shortcut && new_options == options {
                    r.restarts_skipped += 1;
                    if ctx.verbose {
                        recent.push(format!(
                            "event {idx} restart (same options, skipped by the shortcut)"
                        ));
                    }
                    continue;
                }
                let Some(net) = network.clone() else {
                    r.errors
                        .push(format!("event {idx}: restart before any reset"));
                    continue;
                };
                options = new_options;
                let mut f = Map::new();
                f.insert("network".into(), net);
                f.insert("options".into(), options.clone());
                if let Err(e) = call(ctx, "chain_reset", &body(f)) {
                    r.errors
                        .push(format!("event {idx} restart chain_reset: {e}"));
                    continue;
                }
                for pev in &prefix {
                    let answer =
                        event_request(pev, &base).and_then(|(op, fields)| call(ctx, op, &fields));
                    r.redelivered += 1;
                    if let Err(e) = answer {
                        r.errors
                            .push(format!("event {idx} (re-delivery after restart): {e}"));
                    }
                }
                if ctx.verbose {
                    let tip = call(ctx, "chain_tip", "")
                        .map(|a| tip_text(&Value::Object(a)))
                        .unwrap_or_else(|e| e);
                    recent.push(format!(
                        "event {idx} restart with options {options} ({} events re-delivered), tip after: {tip}",
                        prefix.len()
                    ));
                }
            }
            "block" | "headers" | "invalidate" => {
                let answer =
                    event_request(ev, &base).and_then(|(op, fields)| call(ctx, op, &fields));
                match &answer {
                    Ok(a) => {
                        let outcome = a.get("result").and_then(Value::as_str).unwrap_or("ok");
                        *r.outcomes.entry(format!("{kind}:{outcome}")).or_default() += 1;
                    }
                    Err(e) => r.errors.push(format!("event {idx} {kind}: {e}")),
                }
                if ctx.verbose {
                    recent.push(describe_event(idx, ev, &answer));
                    if recent.len() > DIAGNOSTIC_EVENTS {
                        recent.remove(0);
                    }
                }
                prefix.push(ev);
            }
            "check" => {
                r.checks += 1;
                let normative = ev["normative"].as_bool().unwrap_or(true);
                let n = ev["n"].as_i64().unwrap_or(-1);
                let label = ev["label"].as_str().unwrap_or("");
                let want = format!(
                    "{} height {}",
                    short(ev["tip"].as_str().unwrap_or("?")),
                    ev["height"]
                );
                let loc = format!(
                    "{name} check {n} (event {idx}, line {}{}{})",
                    idx + 2,
                    if label.is_empty() { "" } else { ", " },
                    label
                );
                // Level 0.
                let got = call(ctx, "chain_tip", "");
                let matched = match &got {
                    Ok(a) => {
                        a.get("tip").and_then(Value::as_str) == ev["tip"].as_str()
                            && a.get("height").and_then(Value::as_i64) == ev["height"].as_i64()
                    }
                    Err(_) => false,
                };
                if let Err(e) = &got {
                    r.errors.push(format!("{loc}: chain_tip: {e}"));
                }
                let got_text = match &got {
                    Ok(a) => tip_text(&Value::Object(a.clone())),
                    Err(e) => format!("error: {e}"),
                };
                if normative {
                    r.normative += 1;
                    if !matched && crate::known::take("corpus", &loc) {
                        r.l0_known += 1;
                        if ctx.verbose {
                            println!(
                                "KNOWN    [corpus] {loc}: expected tip {want}, got {got_text}"
                            );
                        }
                    } else if !matched {
                        r.l0_fail += 1;
                        if ctx.verbose && !diverged {
                            println!(
                                "DIVERGE  [corpus] {loc}: expected tip {want}, got {got_text}"
                            );
                            if recent.is_empty() {
                                println!("         (no event since the previous check)");
                            } else {
                                println!("         events since the previous check (last {DIAGNOSTIC_EVENTS} at most):");
                                for line in &recent {
                                    println!("           {line}");
                                }
                            }
                        } else if ctx.verbose {
                            if printed[0] < MAX_MISMATCH_LINES {
                                println!(
                                    "FAIL     [corpus] {loc}: expected tip {want}, got {got_text}"
                                );
                            }
                            printed[0] += 1;
                        }
                        diverged = true;
                    }
                } else {
                    r.l0_other += 1;
                    if !matched {
                        r.l0_other_fail += 1;
                        if ctx.verbose {
                            let why = ev["why"].as_str().unwrap_or("");
                            println!("NONNORM  [corpus] {loc}: expected tip {want}, got {got_text} (not normative: {why})");
                        }
                    }
                }
                // Level 1.
                if ev.get("tips").is_some() {
                    r.l1 += 1;
                    match call(ctx, "chain_tips", "") {
                        Ok(a) => {
                            let want = tips_set(&ev["tips"]);
                            let got = tips_set(a.get("tips").unwrap_or(&Value::Null));
                            if want != got {
                                r.l1_fail += 1;
                                if ctx.verbose && printed[1] < MAX_MISMATCH_LINES {
                                    printed[1] += 1;
                                    let missing: Vec<_> = want.difference(&got).take(4).collect();
                                    let extra: Vec<_> = got.difference(&want).take(4).collect();
                                    println!(
                                        "LEVEL1   [corpus] {loc}: chain tips differ ({} expected, {} got); missing {:?}, unexpected {:?}",
                                        want.len(),
                                        got.len(),
                                        missing,
                                        extra
                                    );
                                }
                            }
                        }
                        Err(e) => r.errors.push(format!("{loc}: chain_tips: {e}")),
                    }
                }
                // Level 2.
                if let Some(utxo) = ev.get("utxo") {
                    r.l2 += 1;
                    match call(ctx, "utxo_hash", "") {
                        Ok(a) => {
                            let ok = a.get("hash_serialized_3") == utxo.get("hash_serialized_3")
                                && a.get("txouts").and_then(Value::as_i64)
                                    == utxo["txouts"].as_i64();
                            if !ok {
                                r.l2_fail += 1;
                                if ctx.verbose && printed[2] < MAX_MISMATCH_LINES {
                                    printed[2] += 1;
                                    println!(
                                        "LEVEL2   [corpus] {loc}: expected utxo {} ({} txouts), got {} ({} txouts)",
                                        utxo["hash_serialized_3"].as_str().unwrap_or("?"),
                                        utxo["txouts"],
                                        a.get("hash_serialized_3").and_then(Value::as_str).unwrap_or("?"),
                                        a.get("txouts").unwrap_or(&Value::Null)
                                    );
                                }
                            }
                        }
                        Err(e) => r.errors.push(format!("{loc}: utxo_hash: {e}")),
                    }
                }
                recent.clear();
            }
            "meta" => r.errors.push(format!("event {idx}: a second meta event")),
            other => r
                .errors
                .push(format!("event {idx}: unknown event type {other:?}")),
        }
    }
    if ctx.verbose && printed[0] > MAX_MISMATCH_LINES {
        println!(
            "         [corpus] {name}: {} more level 0 mismatches not shown",
            printed[0] - MAX_MISMATCH_LINES
        );
    }
    r.seconds = started.elapsed().as_secs_f64();
    r
}

/// Runs the suite over every corpus file.
pub fn run(ctx: &mut Ctx, paths: &[PathBuf], restart_shortcut: bool) -> Result<(), String> {
    let files = corpus_files(paths)?;
    if files.is_empty() {
        let where_ = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        ctx.stats.details.push(format!(
            "no corpus files (*.jsonl.gz) in {where_}: nothing to replay"
        ));
        return Ok(());
    }
    let ops = [
        "chain_reset",
        "chain_process_block",
        "chain_process_headers",
        "chain_invalidate",
        "chain_tip",
    ];
    let missing: Vec<&str> = ops.iter().copied().filter(|op| !ctx.supports(op)).collect();
    if !missing.is_empty() {
        return Err(format!("the harness does not list {}", missing.join(", ")));
    }
    ctx.stats.details.push(format!(
        "{:<44} {:>7} {:>11} {:>11} {:>9} {:>9} {:>6} {:>8}",
        "corpus file", "checks", "L0 normat.", "L0 other", "L1 tips", "L2 utxo", "errors", "time"
    ));
    let mut totals = FileResult::default();
    for file in &files {
        let fr = replay_file(ctx, file, restart_shortcut);
        let frac = |pass: u64, all: u64| format!("{}/{}", pass, all);
        ctx.stats.details.push(format!(
            "{:<44} {:>7} {:>11} {:>11} {:>9} {:>9} {:>6} {:>7.1}s",
            shorten(&fr.name, 44),
            fr.checks,
            frac(fr.normative - fr.l0_fail - fr.l0_known, fr.normative),
            frac(fr.l0_other - fr.l0_other_fail, fr.l0_other),
            frac(fr.l1 - fr.l1_fail, fr.l1),
            frac(fr.l2 - fr.l2_fail, fr.l2),
            fr.errors.len(),
            fr.seconds
        ));
        for e in fr.errors.iter().take(5) {
            ctx.stats.details.push(format!("    error: {e}"));
            if ctx.verbose {
                println!("ERROR    [corpus] {}: {e}", fr.name);
            }
        }
        // Scoring: every normative check is a case; an error fails the file once.
        ctx.stats.cases += fr.normative;
        ctx.stats.passed += fr.normative - fr.l0_fail - fr.l0_known;
        ctx.stats.failed += fr.l0_fail;
        ctx.stats.known += fr.l0_known;
        if !fr.errors.is_empty() {
            ctx.stats.cases += 1;
            if crate::known::take("corpus", &format!("{} errors", fr.name)) {
                ctx.stats.known += 1;
            } else {
                ctx.stats.failed += 1;
            }
        }
        ctx.stats.l2_checked += fr.l2;
        ctx.stats.l2_mismatches += fr.l2_fail;
        totals.checks += fr.checks;
        totals.normative += fr.normative;
        totals.l0_fail += fr.l0_fail;
        totals.l0_known += fr.l0_known;
        totals.l0_other += fr.l0_other;
        totals.l0_other_fail += fr.l0_other_fail;
        totals.l1 += fr.l1;
        totals.l1_fail += fr.l1_fail;
        totals.l2 += fr.l2;
        totals.l2_fail += fr.l2_fail;
        totals.restarts += fr.restarts;
        totals.restarts_skipped += fr.restarts_skipped;
        totals.redelivered += fr.redelivered;
        totals.events += fr.events;
        for (k, v) in fr.outcomes {
            *totals.outcomes.entry(k).or_default() += v;
        }
    }
    ctx.stats.details.push(format!(
        "{:<44} {:>7} {:>11} {:>11} {:>9} {:>9}",
        format!("total ({} files, {} events)", files.len(), totals.events),
        totals.checks,
        format!(
            "{}/{}",
            totals.normative - totals.l0_fail - totals.l0_known,
            totals.normative
        ),
        format!(
            "{}/{}",
            totals.l0_other - totals.l0_other_fail,
            totals.l0_other
        ),
        format!("{}/{}", totals.l1 - totals.l1_fail, totals.l1),
        format!("{}/{}", totals.l2 - totals.l2_fail, totals.l2),
    ));
    ctx.stats.details.push(format!(
        "restarts: {} ({} skipped by the shortcut, {} events re-delivered); harness outcomes (diagnostic): {}",
        totals.restarts,
        totals.restarts_skipped,
        totals.redelivered,
        totals.outcomes.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ")
    ));
    if totals.l0_other_fail > 0 || totals.l1_fail > 0 {
        ctx.stats.details.push(
            "non-normative level 0 checks and level 1 (chain tips) are reported only; they never fail the run".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_requests() {
        let genesis_block = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
        let ev = json!({"type": "block", "hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                        "hex": genesis_block, "now": 5, "via": "p2p", "requested": false});
        let (op, body) = event_request(&ev, Path::new(".")).unwrap();
        assert_eq!(op, "chain_process_block");
        let v: Value = serde_json::from_str(&format!("{{{body}}}")).unwrap();
        assert_eq!(
            v,
            json!({"block": genesis_block, "now": 5, "via": "p2p", "requested": false})
        );
        // A wrong hash is a corrupt file.
        let mut bad = ev.clone();
        bad["hash"] = json!("00".repeat(32));
        assert!(event_request(&bad, Path::new(".")).is_err());
        let ev = json!({"type": "invalidate", "hash": "ab", "now": 7});
        assert_eq!(
            event_request(&ev, Path::new(".")).unwrap(),
            ("chain_invalidate", r#""hash":"ab","now":7"#.to_string())
        );
    }
}
