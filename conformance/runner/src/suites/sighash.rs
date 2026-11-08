//! sighash.json, as `sighash_from_data` in src/test/sighash_tests.cpp reads it.
//!
//! Row format: `[raw_tx, script_code, input_index, hash_type, expected_hash]`; single-element rows
//! are comments. The hash type is a signed 32-bit integer and the expected hash is in display
//! order (`uint256::GetHex`). Core also requires `CheckTransaction` to pass for every transaction,
//! so each row is two checks: `sighash_legacy` and `tx_check`.

use crate::check::{shorten, Ctx};
use crate::hex;
use serde_json::Value;
use std::path::Path;

pub fn run(ctx: &mut Ctx, vectors: &Path) -> Result<(), String> {
    let path = vectors.join("core/sighash.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let rows: Vec<Value> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if !ctx.supports("sighash_legacy") && !ctx.supports("tx_check") {
        return Err("the harness supports none of this suite's operations".into());
    }
    for (idx, row) in rows.iter().enumerate() {
        let bad = |m: &str| format!("{} row {idx}: {m}", path.display());
        let cells = row.as_array().ok_or_else(|| bad("row is not an array"))?;
        if cells.is_empty() {
            return Err(bad("bad test"));
        }
        if cells.len() == 1 {
            continue; // comment
        }
        let (Some(raw_tx), Some(script), Some(index), Some(hash_type), Some(expected)) = (
            cells.first().and_then(Value::as_str),
            cells.get(1).and_then(Value::as_str),
            cells.get(2).and_then(Value::as_i64),
            cells.get(3).and_then(Value::as_i64),
            cells.get(4).and_then(Value::as_str),
        ) else {
            return Err(bad("bad test"));
        };
        let hash_type =
            i32::try_from(hash_type).map_err(|_| bad("hash type is not a 32-bit integer"))?;
        let tx = hex::try_parse_hex(raw_tx).ok_or_else(|| bad("transaction is not hex"))?;
        let script = hex::try_parse_hex(script).ok_or_else(|| bad("script is not hex"))?;
        let loc = |what: &str| format!("row {idx} {what}: {}", shorten(&row.to_string(), 200));

        if ctx.supports("sighash_legacy") {
            let body = format!(
                "\"tx\":\"{}\",\"script_code\":\"{}\",\"index\":{index},\"hash_type\":{hash_type}",
                hex::encode(&tx),
                hex::encode(&script)
            );
            let want = hex::decode32(expected).map_err(|e| bad(&e))?;
            let want_raw = hex::encode_reversed(&want);
            match ctx.harness.call("sighash_legacy", &body) {
                Err(e) => ctx.call_failed(&loc("sighash_legacy"), &e),
                Ok(f) => match f.get("sighash").and_then(Value::as_str) {
                    Some(got) if got == want_raw => ctx.pass(),
                    Some(got) => ctx.fail(
                        &loc("sighash_legacy"),
                        &format!("expected {want_raw} (raw order), got {got}"),
                    ),
                    None => ctx.fail(&loc("sighash_legacy"), "response has no sighash"),
                },
            }
        } else {
            ctx.unsupported(1);
        }

        if ctx.supports("tx_check") {
            match ctx.tx_check(&tx) {
                Err(e) => ctx.call_failed(&loc("tx_check"), &e),
                Ok(r) if r.valid => ctx.pass(),
                Ok(r) => ctx.fail(
                    &loc("tx_check"),
                    &format!("expected valid, got {}", r.describe()),
                ),
            }
        } else {
            ctx.unsupported(1);
        }
    }
    Ok(())
}
