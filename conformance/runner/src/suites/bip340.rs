//! BIP340 test-vectors.csv: the `verification result` column.
//!
//! Columns: index, secret key, public key, aux_rand, message, signature, verification result,
//! comment. Every row is checked, including those without a secret key: `schnorr_verify` of the
//! public key, message and signature must return the listed result.

use crate::check::Ctx;
use crate::hex;
use serde_json::Value;
use std::path::Path;

pub fn run(ctx: &mut Ctx, vectors: &Path) -> Result<(), String> {
    let path = vectors.join("bip340/test-vectors.csv");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !ctx.supports("schnorr_verify") {
        return Err("the harness does not support schnorr_verify".into());
    }
    let mut lines = text.lines();
    let header = lines.next().ok_or("empty CSV")?;
    if !header
        .starts_with("index,secret key,public key,aux_rand,message,signature,verification result")
    {
        return Err(format!("unexpected CSV header: {header}"));
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.splitn(8, ',').collect();
        if cols.len() < 7 {
            return Err(format!("malformed CSV row: {line}"));
        }
        let expected = match cols[6] {
            "TRUE" => true,
            "FALSE" => false,
            other => {
                return Err(format!(
                    "unknown verification result {other} in row {}",
                    cols[0]
                ))
            }
        };
        let pubkey = hex::decode(cols[2])?;
        let msg = hex::decode(cols[4])?;
        let sig = hex::decode(cols[5])?;
        let comment = cols.get(7).copied().unwrap_or("");
        let loc = format!("row {} ({comment})", cols[0]);
        let body = format!(
            "\"pubkey\":\"{}\",\"msg\":\"{}\",\"sig\":\"{}\"",
            hex::encode(&pubkey),
            hex::encode(&msg),
            hex::encode(&sig)
        );
        match ctx.harness.call("schnorr_verify", &body) {
            Err(e) => ctx.call_failed(&loc, &e),
            Ok(f) => match f.get("valid").and_then(Value::as_bool) {
                Some(v) if v == expected => ctx.pass(),
                Some(v) => ctx.fail(&loc, &format!("expected {expected}, got {v}")),
                None => ctx.fail(&loc, "response has no boolean valid"),
            },
        }
    }
    Ok(())
}
