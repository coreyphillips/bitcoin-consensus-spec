//! script_assets_test.json (qa-assets), as `AssetTest` in src/test/script_assets_tests.cpp reads
//! it.
//!
//! Each case has a transaction (serialized without witnesses), its spent outputs (serialized
//! `CTxOut`s), the input index, the flags it was generated with, an optional `final` marker, and a
//! `success` and/or `failure` scriptSig plus witness for that input.
//!
//! Over Core's 64 consensus flag combinations: the success witness is valid under every
//! combination that is a subset of the case's flags, or under every combination when the case is
//! `final`; the failure witness is invalid under every combination that is a superset of the
//! case's flags. Core's test checks validity only, not error identifiers.

use super::{Item, QueryItem, RawCheck};
use crate::check::{ScriptQuery, SpentOutput};
use crate::flags;
use crate::tx::{deserialize_txout, Tx};
use serde_json::Value;

pub const RULE_POLICY_FAILURE: &str =
    "failure expected only under flags that include policy flags (no consensus-only expectation)";

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>, String> {
    let s = v
        .as_str()
        .ok_or_else(|| format!("{what} is not a string"))?;
    crate::hex::try_parse_hex(s).ok_or_else(|| format!("{what} is not hex"))
}

pub fn load(path: &std::path::Path) -> Result<Vec<Item>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let cases: Vec<Value> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let combos = flags::consensus_combinations();
    let mut items = Vec::new();
    for (idx, case) in cases.iter().enumerate() {
        let bad = |m: &str| format!("{} case {idx}: {m}", path.display());
        // TxFromHex: deserialized without witness data.
        let tx_bytes = hex_field(&case["tx"], "tx").map_err(|e| bad(&e))?;
        let (tx, _) = Tx::deserialize(&tx_bytes, false).map_err(|e| bad(&format!("tx: {e}")))?;
        let prevouts: Vec<SpentOutput> = case["prevouts"]
            .as_array()
            .ok_or_else(|| bad("prevouts is not an array"))?
            .iter()
            .map(|p| {
                let raw = hex_field(p, "prevout")?;
                let (out, _) = deserialize_txout(&raw)?;
                Ok(SpentOutput {
                    amount: out.value,
                    script_pubkey: out.script_pubkey,
                })
            })
            .collect::<Result<_, String>>()
            .map_err(|e| bad(&e))?;
        if prevouts.len() != tx.vin.len() {
            return Err(bad("prevouts and inputs differ in number"));
        }
        let index = case["index"]
            .as_u64()
            .ok_or_else(|| bad("index is not an integer"))? as usize;
        if index >= tx.vin.len() {
            return Err(bad("index out of range"));
        }
        let case_flags = flags::parse_core(
            case["flags"]
                .as_str()
                .ok_or_else(|| bad("flags is not a string"))?,
        )
        .map_err(|e| bad(&e))?;
        let fin = case.get("final").and_then(Value::as_bool).unwrap_or(false);
        let comment = case["comment"].as_str().unwrap_or("").to_string();

        let mut queries = Vec::new();
        let mut raw = Vec::new();
        let mut raw_rule = None;
        for kind in ["success", "failure"] {
            let Some(w) = case.get(kind) else { continue };
            let mut spend = tx.clone();
            spend.vin[index].script_sig =
                hex_field(&w["scriptSig"], "scriptSig").map_err(|e| bad(&e))?;
            spend.vin[index].witness = w["witness"]
                .as_array()
                .ok_or_else(|| bad("witness is not an array"))?
                .iter()
                .map(|item| hex_field(item, "witness item"))
                .collect::<Result<_, _>>()
                .map_err(|e| bad(&e))?;
            let q = queries.len();
            queries.push(QueryItem {
                id: format!("{idx}/{kind}"),
                label: format!("{kind} witness"),
                query: ScriptQuery::new(spend.serialize(true), index as u32, prevouts.clone()),
            });
            if kind == "success" {
                for &c in &combos {
                    if fin || c & case_flags == c {
                        raw.push(RawCheck::One {
                            q,
                            flags: c,
                            valid: true,
                            error: Some("OK".into()),
                        });
                    }
                }
            } else if flags::has_policy(case_flags) {
                raw_rule = Some(RULE_POLICY_FAILURE);
            } else {
                for &c in &combos {
                    if c & case_flags == case_flags {
                        raw.push(RawCheck::One {
                            q,
                            flags: c,
                            valid: false,
                            error: None,
                        });
                    }
                }
            }
        }
        items.push(Item {
            id: idx.to_string(),
            label: format!("case {idx}"),
            text: comment,
            tx_check: None,
            queries,
            excluded: Vec::new(),
            raw,
            raw_rule,
            core: None,
        });
    }
    Ok(items)
}
