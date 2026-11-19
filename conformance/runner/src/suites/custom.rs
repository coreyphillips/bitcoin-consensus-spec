//! The `custom` suite: targeted cases in `conformance/vectors/custom/*.jsonl`. The `pow`, `signet`
//! and `params` suites run `conformance/vectors/<suite>/*.jsonl` the same way, and `block-connect`
//! runs `conformance/vectors/block-connect/*.jsonl.gz` (whole blocks, so compressed).
//!
//! Each line is `{"name": ..., "request": <a PROTOCOL.md request without id>, "expect": <response
//! fields>}`. The request is sent as it is. Every expected field must match the response:
//! `script_error` and `reason` at level 2, every other field (`valid`, `sighash`, ...) at level 1.
//! A valid `script_verify` answer without `script_error` counts as `OK`.

use crate::check::{shorten, Ctx};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// The files of `dir` whose name ends in `.<ext>`. `vectors/signet` holds `*.jsonl` cases and a
/// `*.jsonl.gz` corpus scenario, so one extension never matches the other.
pub fn files(dir: &Path, ext: &str) -> Result<Vec<PathBuf>, String> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let suffix = format!(".{ext}");
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().ends_with(&suffix)))
        .collect();
    out.sort();
    Ok(out)
}

struct Case {
    /// `<file> line <n>`: the name `--known-failures` uses, which `loc` extends with the case's.
    name: String,
    loc: String,
    op: String,
    body: String,
    expect: Map<String, Value>,
}

fn load(path: &Path) -> Result<Vec<Case>, String> {
    let cannot = |e: std::io::Error| format!("cannot read {}: {e}", path.display());
    let text = if path.extension().is_some_and(|x| x == "gz") {
        let mut text = String::new();
        let file = std::fs::File::open(path).map_err(cannot)?;
        std::io::Read::read_to_string(&mut flate2::read::MultiGzDecoder::new(file), &mut text)
            .map_err(cannot)?;
        text
    } else {
        std::fs::read_to_string(path).map_err(cannot)?
    };
    let file = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut cases = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let bad = |m: &str| format!("{} line {}: {m}", path.display(), i + 1);
        let v: Value = serde_json::from_str(line).map_err(|e| bad(&e.to_string()))?;
        let name = v["name"].as_str().unwrap_or("").to_string();
        let mut request = v["request"]
            .as_object()
            .cloned()
            .ok_or_else(|| bad("request is not an object"))?;
        let op = request
            .remove("op")
            .and_then(|o| o.as_str().map(str::to_string))
            .ok_or_else(|| bad("request has no op"))?;
        if request.contains_key("id") {
            return Err(bad("request must not have an id"));
        }
        let expect = v["expect"]
            .as_object()
            .cloned()
            .ok_or_else(|| bad("expect is not an object"))?;
        let s = Value::Object(request).to_string();
        let check = format!("{file} line {}", i + 1);
        cases.push(Case {
            loc: format!("{check} ({name})"),
            name: check,
            op,
            body: s[1..s.len() - 1].to_string(),
            expect,
        });
    }
    Ok(cases)
}

pub fn run(ctx: &mut Ctx, vectors: &Path, subdir: &str) -> Result<(), String> {
    let ext = if subdir == "block-connect" { "jsonl.gz" } else { "jsonl" };
    let dir = vectors.join(subdir);
    let paths = files(&dir, ext)?;
    if paths.is_empty() {
        return Err(format!("no *.{ext} files in {}", dir.display()));
    }
    let mut cases = Vec::new();
    for p in &paths {
        cases.extend(load(p)?);
    }
    if !cases.iter().any(|c| ctx.supports(&c.op)) {
        return Err("the harness supports none of this suite's operations".into());
    }
    for case in &cases {
        if !ctx.supports(&case.op) {
            ctx.unsupported(1);
            continue;
        }
        let got = match ctx.harness.call(&case.op, &case.body) {
            Ok(g) => g,
            Err(e) => {
                ctx.call_failed_as(&case.name, &case.loc, &e);
                continue;
            }
        };
        let field = |k: &str| -> Value {
            match (k, got.get(k)) {
                ("script_error", None) if got.get("valid") == Some(&Value::Bool(true)) => {
                    Value::String("OK".into())
                }
                (_, Some(v)) => v.clone(),
                (_, None) => Value::Null,
            }
        };
        let level1: Vec<String> = case
            .expect
            .iter()
            .filter(|(k, _)| *k != "script_error" && *k != "reason")
            // A missing field fails even where null is expected (`signet_challenge`).
            .filter(|(k, v)| !got.contains_key(*k) || field(k) != **v)
            .map(|(k, v)| match got.get(k) {
                Some(g) => format!("{k}: expected {v}, got {g}"),
                None => format!("{k}: expected {v}, got no such field"),
            })
            .collect();
        if !level1.is_empty() {
            ctx.fail_as(&case.name, &case.loc, &shorten(&level1.join("; "), 400));
            continue;
        }
        let level2: Vec<(&String, &Value)> = case
            .expect
            .iter()
            .filter(|(k, _)| *k == "script_error" || *k == "reason")
            .collect();
        if level2.is_empty() {
            ctx.pass();
        } else {
            let want: Vec<String> = level2
                .iter()
                .map(|(k, v)| format!("{k} {}", v.as_str().unwrap_or("?")))
                .collect();
            let have: Vec<String> = level2
                .iter()
                .map(|(k, _)| format!("{k} {}", field(k).as_str().unwrap_or("(none)")))
                .collect();
            ctx.pass_l2(&case.loc, &want.join(", "), &have.join(", "));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_case_is_named_by_its_whole_file_name() {
        let dir = std::env::temp_dir().join(format!("bcs-custom-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("variant (A).jsonl");
        let case = r#"{"name": "x: (y)", "request": {"op": "tx_check"}, "expect": {}}"#;
        std::fs::write(&path, format!("{case}\n")).unwrap();
        let cases = load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(cases[0].name, "variant (A).jsonl line 1");
        assert_eq!(cases[0].loc, "variant (A).jsonl line 1 (x: (y))");
    }
}
