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
//! - `check` becomes `chain_tip` (level 0, which compares `chainwork` too when the check carries
//!   it), `chain_tips` when the check carries `tips` (level 1),
//!   and `utxo_hash` when it carries `utxo` (level 2). A harness that does not list `chain_tips`,
//!   or `utxo_hash` (an implementation that keeps no UTXO set, PROTOCOL.md section 4.13), is not
//!   asked; each such check counts at its level as not compared, and so as failed. A call that
//!   fails is an error and fails the comparison too.
//!
//! Level 0 at normative checks is required, and so is level 1 with `--fail-on-tips`. Non-normative
//! level 0 checks, level 1 without that flag and level 2 are reported separately. A harness error
//! (`ok: false`, a crash) or a corrupt file is a failure. `--known-failures` names a level 0
//! failure as `<file> check <n>`, a tip set that differs as `<file> check <n> tips` and a file's
//! errors as `<file> errors from event <n>`, `<n>` being the event whose replay recorded the first
//! one.

use crate::check::{short_hash, shorten, Ctx};
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
/// directly. Two files with the same name (`file_name`) are refused, the same file selected twice
/// too: failures and `--known-failures` entries name a file by that name alone.
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
    let mut seen: BTreeMap<String, &PathBuf> = BTreeMap::new();
    for f in &files {
        let name = file_name(f);
        if let Some(first) = seen.insert(name.clone(), f) {
            return Err(format!(
                "{} and {} are both named {name}: failures and --known-failures entries \
                 name a corpus file by its name alone",
                first.display(),
                f.display()
            ));
        }
    }
    Ok(files)
}

/// The name a corpus file's failures and `--known-failures` entries use: its file name without
/// `.jsonl.gz`.
pub fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default()
        .trim_end_matches(".jsonl.gz")
        .to_string()
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
    check_counts(&meta, &events).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((meta, events))
}

/// Compares the meta event's `counts` with the events read. A file cut short at a line boundary
/// still decompresses and parses; only the counts written when it was recorded show that events
/// are missing. A file without `counts` is not checked (CORPUS.md does not require it).
fn check_counts(meta: &Value, events: &[Value]) -> Result<(), String> {
    let Some(counts) = meta.get("counts") else {
        return Ok(());
    };
    let counts = counts.as_object().ok_or("meta counts is not an object")?;
    let of_type = |t: &str| events.iter().filter(|e| e["type"] == t).count();
    let mut wrong = Vec::new();
    for (key, want) in counts {
        let got = match key.as_str() {
            "events" => events.len(),
            "blocks" => of_type("block"),
            "headers" => of_type("headers"),
            "invalidate" => of_type("invalidate"),
            "restart" => of_type("restart"),
            "checks" => of_type("check"),
            "normative_checks" => events
                .iter()
                .filter(|e| e["type"] == "check" && e["normative"].as_bool().unwrap_or(true))
                .count(),
            _ => continue,
        };
        let want = want
            .as_u64()
            .ok_or_else(|| format!("meta counts.{key} is not a count"))?;
        if got as u64 != want {
            wrong.push(format!("{got} {key}, meta says {want}"));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the file does not hold the events it was recorded with: {}",
            wrong.join("; ")
        ))
    }
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
    /// Level 1 checks. A `chain_tips` call that failed is an error and a tip set that differs.
    pub l1: u64,
    pub l1_fail: u64,
    /// Tip sets that differ as `--known-failures` says (not in `l1_fail`).
    pub l1_known: u64,
    /// Level 1 checks not compared because the harness does not list `chain_tips` (also counted
    /// in `l1_fail`).
    pub l1_uncompared: u64,
    /// Level 2 checks. A `utxo_hash` call that failed is an error and a mismatch.
    pub l2: u64,
    pub l2_fail: u64,
    /// Level 2 checks not compared because the harness does not list `utxo_hash` (also counted
    /// in `l2_fail`).
    pub l2_uncompared: u64,
    pub restarts: u64,
    pub restarts_skipped: u64,
    pub redelivered: u64,
    pub errors: Vec<String>,
    /// The 0-based index of the event whose replay recorded the first error; none for a file
    /// that could not be read.
    pub first_error_event: Option<usize>,
    pub outcomes: BTreeMap<String, u64>,
    pub seconds: f64,
}

impl FileResult {
    /// Records `idx` as the event of the first error when this is the first time there is one.
    /// Called once each event's replay is over.
    fn note_first_error(&mut self, idx: usize) {
        if self.first_error_event.is_none() && !self.errors.is_empty() {
            self.first_error_event = Some(idx);
        }
    }

    /// How `--known-failures` names this file's errors.
    pub fn errors_location(&self) -> String {
        match self.first_error_event {
            Some(idx) => format!("{} errors from event {idx}", self.name),
            None => format!("{} errors", self.name),
        }
    }

    /// Whether `--known-failures` waives this file's errors, given `take` for the corpus suite:
    /// an entry names them by the event of the first one, or as `<file> errors` wherever they
    /// start. A file that could not be read is a corpus defect, not the harness's: no entry
    /// waives it.
    pub fn errors_waived(&self, take: &mut dyn FnMut(&str) -> bool) -> bool {
        self.first_error_event.is_some()
            && (take(&self.errors_location()) || take(&format!("{} errors", self.name)))
    }
}

fn tip_text(v: &Value) -> String {
    match (v["tip"].as_str(), v["height"].as_i64()) {
        (Some(t), Some(h)) => format!("{} height {h}", short_hash(t)),
        _ => "(no tip)".to_string(),
    }
}

/// One line describing an event and the harness's answer, for divergence reports.
fn describe_event(idx: usize, ev: &Value, answer: &Result<Map<String, Value>, String>) -> String {
    let t = ev["type"].as_str().unwrap_or("?");
    let mut s = format!("event {idx} (line {}) {t}", idx + 2);
    match t {
        "block" => {
            s.push_str(&format!(
                " {}",
                short_hash(ev["hash"].as_str().unwrap_or("?"))
            ));
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
        "invalidate" => s.push_str(&format!(
            " {}",
            short_hash(ev["hash"].as_str().unwrap_or("?"))
        )),
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
                s.push_str(&format!(", best header {}", short_hash(b)));
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

/// Replays one file through the harness. `fail_on_tips` only changes how a tip set that differs
/// is printed; `run` decides whether it fails.
pub fn replay_file(
    ctx: &mut Ctx,
    path: &Path,
    restart_shortcut: bool,
    fail_on_tips: bool,
) -> FileResult {
    let started = Instant::now();
    let name = file_name(path);
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
        // Here and not after the match: its arms can `continue`.
        if let Some(prev) = idx.checked_sub(1) {
            r.note_first_error(prev);
        }
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
                        if let Some(want) = ev["genesis"].as_str() {
                            match a.get("genesis").and_then(Value::as_str) {
                                Some(got) if got == want => {}
                                Some(got) => r.errors.push(format!(
                                    "event {idx}: chain_reset returned genesis {got}, expected {want}"
                                )),
                                None => r.errors.push(format!(
                                    "event {idx}: chain_reset returned no genesis, expected {want}"
                                )),
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
                    short_hash(ev["tip"].as_str().unwrap_or("?")),
                    ev["height"]
                );
                let at = format!(
                    "(event {idx}, line {}{}{})",
                    idx + 2,
                    if label.is_empty() { "" } else { ", " },
                    label
                );
                let loc = format!("{name} check {n} {at}");
                // Level 0, with the chain work when the check carries it.
                let want_work = ev.get("chainwork").and_then(Value::as_str);
                let got = call(ctx, "chain_tip", "");
                let got_work = got
                    .as_ref()
                    .ok()
                    .and_then(|a| a.get("chainwork"))
                    .and_then(Value::as_str);
                let matched = match &got {
                    Ok(a) => {
                        a.get("tip").and_then(Value::as_str) == ev["tip"].as_str()
                            && a.get("height").and_then(Value::as_i64) == ev["height"].as_i64()
                            && want_work
                                .is_none_or(|w| got_work.is_some_and(|g| g.eq_ignore_ascii_case(w)))
                    }
                    Err(_) => false,
                };
                if let Err(e) = &got {
                    r.errors.push(format!("{loc}: chain_tip: {e}"));
                }
                let mut got_text = match &got {
                    Ok(a) => tip_text(&Value::Object(a.clone())),
                    Err(e) => format!("error: {e}"),
                };
                if let (Some(w), Ok(_)) = (want_work, &got) {
                    // After the tips, so that the line keeps the form mutation/run.py reads.
                    got_text += &format!(
                        "; chainwork expected {w}, got {}",
                        got_work.unwrap_or("(none)")
                    );
                }
                if normative {
                    r.normative += 1;
                    if !matched && crate::known::take("corpus", &format!("{name} check {n}")) {
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
                    if !ctx.supports("chain_tips") {
                        // Level 1 is optional (CORPUS.md section 4).
                        r.l1_fail += 1;
                        r.l1_uncompared += 1;
                    } else {
                        let want = tips_set(&ev["tips"]);
                        let got = call(ctx, "chain_tips", "")
                            .map(|a| tips_set(a.get("tips").unwrap_or(&Value::Null)));
                        if let Err(e) = &got {
                            r.errors.push(format!("{loc}: chain_tips: {e}"));
                        }
                        if got.as_ref() != Ok(&want) {
                            // Taken without --fail-on-tips too, so one list serves runs
                            // with and without it.
                            let known =
                                crate::known::take("corpus", &format!("{name} check {n} tips"));
                            let tag = if known {
                                r.l1_known += 1;
                                "KNOWN"
                            } else {
                                r.l1_fail += 1;
                                if fail_on_tips {
                                    "FAIL"
                                } else {
                                    "LEVEL1"
                                }
                            };
                            if ctx.verbose && (known || printed[1] < MAX_MISMATCH_LINES) {
                                if !known {
                                    printed[1] += 1;
                                }
                                let what = match &got {
                                    Ok(got) => {
                                        let missing: Vec<_> =
                                            want.difference(got).take(4).collect();
                                        let extra: Vec<_> = got.difference(&want).take(4).collect();
                                        format!(
                                            "chain tips differ ({} expected, {} got); missing {:?}, unexpected {:?}",
                                            want.len(),
                                            got.len(),
                                            missing,
                                            extra
                                        )
                                    }
                                    Err(e) => format!("chain_tips failed: {e}"),
                                };
                                println!("{tag:<8} [corpus] {name} check {n} tips {at}: {what}");
                            }
                        }
                    }
                }
                // Level 2.
                if let Some(utxo) = ev.get("utxo") {
                    r.l2 += 1;
                    if !ctx.supports("utxo_hash") {
                        // PROTOCOL.md section 4.13: optional for an implementation that keeps no
                        // UTXO set.
                        r.l2_fail += 1;
                        r.l2_uncompared += 1;
                    } else {
                        match call(ctx, "utxo_hash", "") {
                            Ok(a) => {
                                let ok = a.get("hash_serialized_3")
                                    == utxo.get("hash_serialized_3")
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
                            Err(e) => {
                                // A mismatch too: with --fail-on-level2, an entry waiving the
                                // file's errors must not leave the hash unchecked.
                                r.l2_fail += 1;
                                r.errors.push(format!("{loc}: utxo_hash: {e}"));
                            }
                        }
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
    if let Some(last) = events.len().checked_sub(1) {
        r.note_first_error(last);
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

/// Runs the suite over every corpus file. With `fail_on_tips`, every tip set compared is a check.
pub fn run(
    ctx: &mut Ctx,
    paths: &[PathBuf],
    restart_shortcut: bool,
    fail_on_tips: bool,
) -> Result<(), String> {
    let files = corpus_files(paths)?;
    if files.is_empty() {
        let where_ = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("no corpus files (*.jsonl.gz) in {where_}"));
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
        let fr = replay_file(ctx, file, restart_shortcut, fail_on_tips);
        let frac = |pass: u64, all: u64| format!("{}/{}", pass, all);
        ctx.stats.details.push(format!(
            "{:<44} {:>7} {:>11} {:>11} {:>9} {:>9} {:>6} {:>7.1}s",
            shorten(&fr.name, 44),
            fr.checks,
            frac(fr.normative - fr.l0_fail - fr.l0_known, fr.normative),
            frac(fr.l0_other - fr.l0_other_fail, fr.l0_other),
            frac(fr.l1 - fr.l1_fail - fr.l1_known, fr.l1),
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
        if fail_on_tips {
            ctx.stats.cases += fr.l1;
            ctx.stats.passed += fr.l1 - fr.l1_fail - fr.l1_known;
            ctx.stats.failed += fr.l1_fail;
            ctx.stats.known += fr.l1_known;
        }
        if !fr.errors.is_empty() {
            ctx.stats.cases += 1;
            let loc = fr.errors_location();
            let known = fr.errors_waived(&mut |name| crate::known::take("corpus", name));
            if known {
                ctx.stats.known += 1;
            } else {
                ctx.stats.failed += 1;
            }
            if ctx.verbose {
                println!(
                    "{:<8} [corpus] {loc}: {} errors, the first: {}",
                    if known { "KNOWN" } else { "FAIL" },
                    fr.errors.len(),
                    fr.errors[0]
                );
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
        totals.l1_known += fr.l1_known;
        totals.l1_uncompared += fr.l1_uncompared;
        totals.l2 += fr.l2;
        totals.l2_fail += fr.l2_fail;
        totals.l2_uncompared += fr.l2_uncompared;
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
        format!(
            "{}/{}",
            totals.l1 - totals.l1_fail - totals.l1_known,
            totals.l1
        ),
        format!("{}/{}", totals.l2 - totals.l2_fail, totals.l2),
    ));
    ctx.stats.details.push(format!(
        "restarts: {} ({} skipped by the shortcut, {} events re-delivered); harness outcomes (diagnostic): {}",
        totals.restarts,
        totals.restarts_skipped,
        totals.redelivered,
        totals.outcomes.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ")
    ));
    if totals.l1_uncompared > 0 {
        ctx.stats.details.push(format!(
            "level 1: {} chain tip sets not compared (the harness does not list chain_tips)",
            totals.l1_uncompared
        ));
    }
    if totals.l2_uncompared > 0 {
        ctx.stats.details.push(format!(
            "level 2: {} UTXO set hashes not compared (the harness does not list utxo_hash, PROTOCOL.md section 4.13)",
            totals.l2_uncompared
        ));
    }
    if totals.l0_other_fail > 0 {
        ctx.stats
            .details
            .push("non-normative level 0 checks are reported only; they never fail the run".into());
    }
    if !fail_on_tips && totals.l1_fail > 0 {
        ctx.stats.details.push(
            "level 1 (chain tips) is reported only; it fails the run with --fail-on-tips".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Harness;
    use std::io::Write;
    use std::time::Duration;

    /// A harness that refuses a `chain_reset` whose options carry `"refuse":true`, answers
    /// `chain_tip` with tip `t` at height 0 with chain work 2 and `chain_tips` with that tip alone,
    /// and fails every other chain op (`utxo_hash` too) as internal.
    const STUB: &str = r#"while IFS= read -r line; do
  id=${line#*'"id":'}; id=${id%%[,\}]*}
  case "$line" in
    *'"op":"info"'*) printf '{"id":%s,"ok":true,"name":"stub","version":"0","spec_version":"0","ops":["info","chain_reset","chain_process_block","chain_process_headers","chain_invalidate","chain_tip","chain_tips","utxo_hash"]}\n' "$id";;
    *'"refuse":true'*) printf '{"id":%s,"ok":false,"error":"bad_request","message":"refused"}\n' "$id";;
    *'"op":"chain_reset"'*) printf '{"id":%s,"ok":true}\n' "$id";;
    *'"op":"chain_tip"'*) printf '{"id":%s,"ok":true,"tip":"t","height":0,"chainwork":"02"}\n' "$id";;
    *'"op":"chain_tips"'*) printf '{"id":%s,"ok":true,"tips":[{"hash":"t","height":0,"status":"active"}]}\n' "$id";;
    *) printf '{"id":%s,"ok":false,"error":"internal","message":"stub"}\n' "$id";;
  esac
done"#;

    fn replay(name: &str, events: &[Value]) -> FileResult {
        with_file(name, events, |ctx, path| {
            replay_file(ctx, path, false, false)
        })
    }

    /// Writes `events` as corpus file `name` and calls `f` with the stub harness and the file.
    fn with_file<T>(name: &str, events: &[Value], f: impl FnOnce(&mut Ctx, &Path) -> T) -> T {
        with_stub(name, events, STUB, f)
    }

    /// `STUB` with `from` replaced by `to`, which must change it.
    fn stub_with(from: &str, to: &str) -> String {
        assert!(STUB.contains(from), "{from}");
        STUB.replace(from, to)
    }

    /// As `with_file`, with the harness script `script`.
    fn with_stub<T>(
        name: &str,
        events: &[Value],
        script: &str,
        f: impl FnOnce(&mut Ctx, &Path) -> T,
    ) -> T {
        // One directory per call: tests run in parallel and each removes its own at the end.
        let dir =
            std::env::temp_dir().join(format!("bcs-corpus-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join(format!("{name}.sh"));
        std::fs::write(&stub, script).unwrap();
        let path = dir.join(format!("{name}.jsonl.gz"));
        let mut gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::fast(),
        );
        writeln!(
            gz,
            "{}",
            json!({"type": "meta", "format": FORMAT, "format_version": FORMAT_VERSION})
        )
        .unwrap();
        for ev in events {
            writeln!(gz, "{ev}").unwrap();
        }
        gz.finish().unwrap();
        let mut harness =
            Harness::start(&format!("sh '{}'", stub.display()), Duration::from_secs(10)).unwrap();
        let mut ctx = Ctx::new(&mut harness, "corpus", false);
        let r = f(&mut ctx, &path);
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    #[test]
    fn tip_sets_are_checks_only_with_fail_on_tips() {
        let tips = |status: &str| json!([{"hash": "t", "height": 0, "status": status}]);
        let events = [
            json!({"type": "reset", "network": "regtest"}),
            json!({"type": "check", "n": 1, "tip": "t", "height": 0, "tips": tips("active")}),
            json!({"type": "check", "n": 2, "tip": "t", "height": 0, "tips": tips("invalid")}),
        ];
        let stats = |name: &str, fail_on_tips: bool| {
            with_file(name, &events, |ctx, path| {
                run(ctx, &[path.to_path_buf()], false, fail_on_tips).unwrap();
                std::mem::take(&mut ctx.stats)
            })
        };

        let reported = stats("tips-reported", false);
        assert_eq!(
            (reported.cases, reported.passed, reported.failed),
            (2, 2, 0)
        );
        assert!(
            reported.details.iter().any(|d| d.contains("1/2")),
            "{:?}",
            reported.details
        );
        assert!(reported
            .details
            .iter()
            .any(|d| d.contains("--fail-on-tips")));

        let enforced = stats("tips-enforced", true);
        assert_eq!(
            (enforced.cases, enforced.passed, enforced.failed),
            (4, 3, 1)
        );
        assert!(!enforced
            .details
            .iter()
            .any(|d| d.contains("--fail-on-tips")));
    }

    #[test]
    fn files_that_share_a_name_are_refused() {
        let dir =
            std::env::temp_dir().join(format!("bcs-corpus-test-{}-names", std::process::id()));
        for sub in ["one", "two", "three"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for f in [
            "one/shared.jsonl.gz",
            "two/shared.jsonl.gz",
            "three/other.jsonl.gz",
        ] {
            std::fs::write(dir.join(f), b"").unwrap();
        }
        let files =
            |paths: &[&str]| corpus_files(&paths.iter().map(|p| dir.join(p)).collect::<Vec<_>>());
        // An entry `corpus shared check 1` would waive check 1 of whichever file failed it.
        let e = files(&["one", "two"]).unwrap_err();
        assert!(e.contains("are both named shared"), "{e}");
        assert!(
            e.contains(&dir.join("one/shared.jsonl.gz").display().to_string()),
            "{e}"
        );
        assert!(
            e.contains(&dir.join("two/shared.jsonl.gz").display().to_string()),
            "{e}"
        );
        assert!(files(&["one/shared.jsonl.gz", "two"]).is_err());
        // The same file selected twice would leave its second replay unwaived.
        assert!(files(&["one", "one/shared.jsonl.gz"]).is_err());
        assert_eq!(files(&["one", "three"]).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_check_with_chainwork_needs_that_work() {
        let reset = json!({"type": "reset", "network": "regtest"});
        let check = |work: Option<&str>| {
            let mut c = json!({"type": "check", "n": 1, "tip": "t", "height": 0});
            if let Some(w) = work {
                c["chainwork"] = json!(w);
            }
            c
        };
        let fails = |name: &str, work: Option<&str>| {
            let r = replay(name, &[reset.clone(), check(work)]);
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            r.l0_fail
        };
        assert_eq!(fails("work-absent", None), 0);
        assert_eq!(fails("work-same", Some("02")), 0);
        assert_eq!(fails("work-differs", Some("04")), 1);
    }

    #[test]
    fn a_tip_that_is_not_hex_fails_its_check() {
        // 64 bytes, with a two-byte character across byte 8.
        let tip = format!("{}é{}", "a".repeat(7), "a".repeat(55));
        assert_eq!(tip.len(), 64);
        let script = stub_with(
            r#""tip":"t","height""#,
            &format!(r#""tip":"{tip}","height""#),
        );
        let events = [
            json!({"type": "reset", "network": "regtest"}),
            json!({"type": "check", "n": 1, "tip": "t", "height": 0}),
        ];
        let r = with_stub("tip-not-hex", &events, &script, |ctx, path| {
            replay_file(ctx, path, false, false)
        });
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.l0_fail, 1);
    }

    #[test]
    fn chain_reset_must_return_the_events_genesis() {
        let events = [
            json!({"type": "reset", "network": "regtest", "genesis": "g"}),
            json!({"type": "check", "n": 1, "tip": "t", "height": 0}),
        ];
        let errors = |name: &str, answer: Option<&str>| {
            let script = match answer {
                None => STUB.to_string(),
                Some(g) => stub_with(
                    r#""op":"chain_reset"'*) printf '{"id":%s,"ok":true}"#,
                    &format!(
                        r#""op":"chain_reset"'*) printf '{{"id":%s,"ok":true,"genesis":"{g}"}}"#
                    ),
                ),
            };
            with_stub(name, &events, &script, |ctx, path| {
                replay_file(ctx, path, false, false)
            })
            .errors
        };
        assert_eq!(errors("genesis-same", Some("g")), Vec::<String>::new());
        assert_eq!(
            errors("genesis-differs", Some("h")),
            ["event 0: chain_reset returned genesis h, expected g"]
        );
        assert_eq!(
            errors("genesis-absent", None),
            ["event 0: chain_reset returned no genesis, expected g"]
        );
    }

    #[test]
    fn errors_are_named_from_the_first_event_that_recorded_one() {
        let reset = json!({"type": "reset", "network": "regtest"});
        let check = |n: u64| json!({"type": "check", "n": n, "tip": "t", "height": 0});
        let refused_restart = json!({"type": "restart", "options": {"refuse": true}});
        let invalidate = json!({"type": "invalidate", "hash": "ab", "now": 7});

        let clean = replay("clean", &[reset.clone(), check(1)]);
        assert!(clean.errors.is_empty());
        assert_eq!(clean.first_error_event, None);

        // A restart whose chain_reset is refused ends its event with `continue`.
        let r = replay(
            "late",
            &[reset.clone(), check(1), refused_restart.clone(), check(2)],
        );
        assert_eq!(r.first_error_event, Some(2), "{:?}", r.errors);
        assert_eq!(r.errors_location(), "late errors from event 2");
        let waived = |r: &FileResult, list: &str| {
            let mut k = crate::known::Known::parse(Path::new("k"), list, &["corpus"]).unwrap();
            r.errors_waived(&mut |name| k.take("corpus", name))
        };
        assert!(waived(&r, "corpus late errors"));
        assert!(waived(&r, "corpus late errors from event 2"));
        assert!(!waived(&r, "corpus late errors from event 1"));
        assert!(!waived(&r, "corpus late"));

        // An error before the refused restart moves the location, so an entry for the
        // restart no longer covers the file.
        let r = replay(
            "early",
            &[reset, invalidate, check(1), refused_restart, check(2)],
        );
        assert_eq!(r.first_error_event, Some(1), "{:?}", r.errors);
        assert_eq!(r.errors.len(), 2);
        assert!(!waived(&r, "corpus early errors from event 3"));
        assert!(waived(&r, "corpus early errors"));

        // The last event recording the first error.
        let r = replay(
            "last",
            &[json!({"type": "reset", "network": "regtest", "options": {"refuse": true}})],
        );
        assert_eq!(r.errors_location(), "last errors from event 0");
    }

    /// A reset and one normative check with a tip set (that the stub's `chain_tips` matches) and a
    /// UTXO hash.
    fn tips_and_utxo_check() -> [Value; 2] {
        [
            json!({"type": "reset", "network": "regtest"}),
            json!({"type": "check", "n": 1, "tip": "t", "height": 0,
                   "tips": [{"hash": "t", "height": 0, "status": "active"}],
                   "utxo": {"hash_serialized_3": "ab", "txouts": 1}}),
        ]
    }

    #[test]
    fn a_failed_chain_tips_or_utxo_hash_call_fails_its_level() {
        // The stub fails utxo_hash already; this makes chain_tips fail too.
        let script = stub_with(r#"*'"op":"chain_tips"'*)"#, r#"*'"op":"no_such_op"'*)"#);
        let (r, stats) = with_stub(
            "failed-calls",
            &tips_and_utxo_check(),
            &script,
            |ctx, path| {
                let r = replay_file(ctx, path, false, false);
                run(ctx, &[path.to_path_buf()], false, false).unwrap();
                (r, std::mem::take(&mut ctx.stats))
            },
        );
        assert_eq!(r.errors.len(), 2, "{:?}", r.errors);
        assert_eq!((r.l1, r.l1_fail, r.l1_uncompared), (1, 1, 0));
        assert_eq!((r.l2, r.l2_fail, r.l2_uncompared), (1, 1, 0));
        // So --fail-on-level2 fails the run even when an entry waives the file's errors.
        assert_eq!((stats.l2_checked, stats.l2_mismatches), (1, 1));
        // The file's row: name, checks, L0 normative, L0 other, L1, L2, errors, time.
        let row = stats
            .details
            .iter()
            .find(|d| d.starts_with("failed-calls"))
            .unwrap();
        let cols: Vec<&str> = row.split_whitespace().collect();
        assert_eq!(cols[4..7], ["0/1", "0/1", "2"], "{row}");
    }

    #[test]
    fn a_harness_without_chain_tips_or_utxo_hash_is_not_asked() {
        // The stub still answers both, so a call made regardless would pass its level.
        let script = stub_with(r#","chain_tips","utxo_hash"]"#, "]");
        let events = tips_and_utxo_check();
        let r = with_stub("unlisted", &events, &script, |ctx, path| {
            replay_file(ctx, path, false, false)
        });
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!((r.l0_fail, r.normative), (0, 1));
        assert_eq!((r.l1, r.l1_fail, r.l1_uncompared), (1, 1, 1));
        assert_eq!((r.l2, r.l2_fail, r.l2_uncompared), (1, 1, 1));

        let stats = |name: &str, fail_on_tips: bool| {
            with_stub(name, &events, &script, |ctx, path| {
                run(ctx, &[path.to_path_buf()], false, fail_on_tips).unwrap();
                std::mem::take(&mut ctx.stats)
            })
        };
        // Level 1 is reported only, so the file passes.
        let reported = stats("unlisted-reported", false);
        assert_eq!(
            (reported.cases, reported.passed, reported.failed),
            (1, 1, 0)
        );
        assert!(
            reported
                .details
                .iter()
                .any(|d| d.starts_with("level 1: 1 chain tip sets not compared")),
            "{:?}",
            reported.details
        );
        // Tip sets that cannot be compared cannot pass when they are enforced.
        let enforced = stats("unlisted-enforced", true);
        assert_eq!(
            (enforced.cases, enforced.passed, enforced.failed),
            (2, 1, 1)
        );
    }

    #[test]
    fn a_file_cut_short_fails_its_meta_counts() {
        let meta = |counts: Value| json!({"type": "meta", "counts": counts});
        let events = [
            json!({"type": "reset"}),
            json!({"type": "block"}),
            json!({"type": "check", "normative": true}),
            json!({"type": "check", "normative": false}),
        ];
        let full = json!({"events": 4, "blocks": 1, "headers": 0, "invalidate": 0,
                          "restart": 0, "checks": 2, "normative_checks": 1});
        assert_eq!(check_counts(&meta(full.clone()), &events), Ok(()));
        // Recorded before CORPUS.md listed counts, or written by hand.
        assert_eq!(check_counts(&json!({"type": "meta"}), &events), Ok(()));

        let e = check_counts(&meta(full.clone()), &events[..1]).unwrap_err();
        assert!(e.contains("1 events, meta says 4"), "{e}");
        assert!(e.contains("0 checks, meta says 2"), "{e}");
        assert!(check_counts(&meta(full), &[]).is_err());
        assert!(check_counts(&meta(json!({"events": "4"})), &events).is_err());
        assert!(check_counts(&meta(json!([4])), &events).is_err());
    }

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
