//! BIP341 wallet test vectors (bip341_wallet_vectors.json).
//!
//! - keyPathSpending: for every listed input, `sighash_taproot` of the unsigned transaction (key
//!   path, no annex) must equal `intermediary.sigHash` (raw order, as Core's
//!   `bip341_keypath_test_vectors` compares it), and that input of `auxiliary.fullySignedTx` must
//!   pass `script_verify` with P2SH, WITNESS and TAPROOT.
//! - scriptPubKey: every `expected.scriptPathControlBlocks[i]` must pass
//!   `taproot_commitment_verify` for leaf `i` of the script tree (leaves are numbered by their
//!   `id`) against `intermediary.tweakedPubkey`.

use crate::check::{Ctx, ScriptQuery, SpentOutput};
use crate::flags;
use crate::hex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

fn s<'a>(v: &'a Value, what: &str) -> Result<&'a str, String> {
    v.as_str().ok_or_else(|| format!("{what} is not a string"))
}

fn collect_leaves(tree: &Value, out: &mut BTreeMap<u64, Vec<u8>>) -> Result<(), String> {
    match tree {
        Value::Null => Ok(()),
        Value::Array(branches) => branches.iter().try_for_each(|b| collect_leaves(b, out)),
        Value::Object(leaf) => {
            let id = leaf
                .get("id")
                .and_then(Value::as_u64)
                .ok_or("leaf without id")?;
            let script = hex::decode(s(&leaf["script"], "leaf script")?)?;
            out.insert(id, script);
            Ok(())
        }
        _ => Err("malformed scriptTree".into()),
    }
}

pub fn run(ctx: &mut Ctx, vectors: &Path) -> Result<(), String> {
    let path = vectors.join("core/bip341_wallet_vectors.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let ops = [
        "sighash_taproot",
        "script_verify",
        "taproot_commitment_verify",
    ];
    if !ops.iter().any(|op| ctx.supports(op)) {
        return Err("the harness supports none of this suite's operations".into());
    }

    for (vi, vec) in v["keyPathSpending"]
        .as_array()
        .ok_or("no keyPathSpending")?
        .iter()
        .enumerate()
    {
        let unsigned = hex::decode(s(&vec["given"]["rawUnsignedTx"], "rawUnsignedTx")?)?;
        let signed = hex::decode(s(&vec["auxiliary"]["fullySignedTx"], "fullySignedTx")?)?;
        let spent: Vec<SpentOutput> = vec["given"]["utxosSpent"]
            .as_array()
            .ok_or("no utxosSpent")?
            .iter()
            .map(|u| {
                Ok(SpentOutput {
                    amount: u["amountSats"]
                        .as_i64()
                        .ok_or("amountSats is not an integer")?,
                    script_pubkey: hex::decode(s(&u["scriptPubKey"], "scriptPubKey")?)?,
                })
            })
            .collect::<Result<_, String>>()?;
        for input in vec["inputSpending"].as_array().ok_or("no inputSpending")? {
            let index = input["given"]["txinIndex"].as_u64().ok_or("txinIndex")? as u32;
            let hash_type = input["given"]["hashType"].as_u64().ok_or("hashType")?;
            let expected = s(&input["intermediary"]["sigHash"], "sigHash")?.to_string();
            let loc = |what: &str| {
                format!("keyPathSpending[{vi}] input {index} hashType {hash_type} {what}")
            };

            if ctx.supports("sighash_taproot") {
                let q = ScriptQuery::new(unsigned.clone(), index, spent.clone());
                let body = format!("{},\"hash_type\":{hash_type}", q.base_body());
                match ctx.harness.call("sighash_taproot", &body) {
                    Err(e) => ctx.call_failed(&loc("sighash_taproot"), &e),
                    Ok(f) => {
                        let valid = f.get("valid").and_then(Value::as_bool);
                        let got = f.get("sighash").and_then(Value::as_str);
                        match (valid, got) {
                            (Some(true), Some(g)) if g == expected => ctx.pass(),
                            (Some(true), Some(g)) => ctx.fail(
                                &loc("sighash_taproot"),
                                &format!("expected {expected}, got {g}"),
                            ),
                            _ => ctx.fail(
                                &loc("sighash_taproot"),
                                &format!("expected {expected}, got {f:?}"),
                            ),
                        }
                    }
                }
            } else {
                ctx.unsupported(1);
            }

            if ctx.supports("script_verify") {
                let q = ScriptQuery::new(signed.clone(), index, spent.clone());
                let f = flags::P2SH | flags::WITNESS | flags::TAPROOT;
                let got = ctx.script(&q, f);
                ctx.expect_script(
                    &|| loc("script_verify of fullySignedTx flags P2SH,WITNESS,TAPROOT"),
                    got,
                    true,
                    Some("OK"),
                );
            } else {
                ctx.unsupported(1);
            }
        }
    }

    for (vi, vec) in v["scriptPubKey"]
        .as_array()
        .ok_or("no scriptPubKey")?
        .iter()
        .enumerate()
    {
        let Some(blocks) = vec["expected"]["scriptPathControlBlocks"].as_array() else {
            continue; // key path only
        };
        let mut leaves = BTreeMap::new();
        collect_leaves(&vec["given"]["scriptTree"], &mut leaves)?;
        let output_key = s(&vec["intermediary"]["tweakedPubkey"], "tweakedPubkey")?;
        for (i, cb) in blocks.iter().enumerate() {
            let control = s(cb, "control block")?;
            let script = leaves
                .get(&(i as u64))
                .ok_or_else(|| format!("scriptPubKey[{vi}]: no leaf with id {i}"))?;
            let loc = format!("scriptPubKey[{vi}] control block {i}");
            if !ctx.supports("taproot_commitment_verify") {
                ctx.unsupported(1);
                continue;
            }
            let body = format!(
                "\"control_block\":\"{}\",\"script\":\"{}\",\"output_key\":\"{}\"",
                hex::encode(&hex::decode(control)?),
                hex::encode(script),
                hex::encode(&hex::decode(output_key)?)
            );
            match ctx.harness.call("taproot_commitment_verify", &body) {
                Err(e) => ctx.call_failed(&loc, &e),
                Ok(f) => match f.get("valid").and_then(Value::as_bool) {
                    Some(true) => ctx.pass(),
                    Some(false) => ctx.fail(&loc, "expected valid, got invalid"),
                    None => ctx.fail(&loc, "response has no boolean valid"),
                },
            }
        }
    }
    Ok(())
}
