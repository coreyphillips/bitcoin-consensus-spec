//! tx_valid.json and tx_invalid.json, as `tx_valid` and `tx_invalid` in
//! src/test/transaction_tests.cpp read them.
//!
//! Row format: `[[[prevout_txid, prevout_n, scriptPubKey_asm, amount?]...], tx_hex, flags]`.
//! Rows whose first element is not an array are comments. The txid is in display order, the
//! index is read as a signed int and converted to uint32 (so -1 is 0xffffffff), the amount
//! defaults to 0. Each input of the transaction spends the listed output with the same outpoint
//! (later listings of the same outpoint replace earlier ones, as Core's maps do).
//!
//! tx_valid: `CheckTransaction` passes and every input is valid with every flag except the
//! listed (excluded) ones, and with any subset of those flags. Restricted to consensus flags:
//! every input is valid (error OK) under every consensus combination that contains none of the
//! excluded flags.
//!
//! tx_invalid: `BADTX` rows fail `CheckTransaction` and have no script expectation. Other rows
//! pass `CheckTransaction` and some input fails under the listed flags and any superset; every
//! input passes when any one listed flag is removed (`TrimFlags` applied). This is a consensus
//! expectation only when all listed flags are consensus flags.

use super::{CoreReplay, Item, QueryItem, RawCheck};
use crate::check::{ScriptQuery, SpentOutput};
use crate::flags;
use crate::script::parse_script;
use crate::tx::{OutPoint, Tx};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Valid,
    Invalid,
}

pub const RULE_POLICY_FAILURE: &str =
    "row expects failure only under flags that include policy flags (no consensus-only expectation)";
pub const RULE_BADTX: &str =
    "BADTX row: Core's test checks only CheckTransaction (no script expectation)";
pub const RULE_UNLISTED_PREVOUT: &str =
    "input spends an outpoint the row does not list (no script query)";

pub fn load(path: &std::path::Path, kind: Kind) -> Result<Vec<Item>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let rows: Vec<Value> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let combos = flags::consensus_combinations();
    let mut items = Vec::new();
    // Comment rows directly before a test describe it; the last few are kept for messages.
    let mut comments: Vec<String> = Vec::new();
    for (idx, row) in rows.iter().enumerate() {
        let bad = |m: &str| format!("{} row {idx}: {m}", path.display());
        let cells = row.as_array().ok_or_else(|| bad("row is not an array"))?;
        if !cells.first().is_some_and(Value::is_array) {
            let text: Vec<&str> = cells.iter().filter_map(Value::as_str).collect();
            comments.push(text.join(" "));
            continue;
        }
        let keep = comments.len().saturating_sub(3);
        let row_comment = comments.split_off(keep).join(" ");
        comments.clear();
        if cells.len() != 3 || !cells[1].is_string() || !cells[2].is_string() {
            return Err(bad("bad test"));
        }
        let mut scripts: BTreeMap<OutPoint, Vec<u8>> = BTreeMap::new();
        let mut amounts: BTreeMap<OutPoint, i64> = BTreeMap::new();
        for input in cells[0].as_array().unwrap() {
            let v = input
                .as_array()
                .filter(|v| (3..=4).contains(&v.len()))
                .ok_or_else(|| bad("bad prevout"))?;
            let txid_text = v[0]
                .as_str()
                .ok_or_else(|| bad("prevout txid is not a string"))?;
            if txid_text.len() != 64 {
                return Err(bad("prevout txid is not 64 hex digits"));
            }
            let mut txid = crate::hex::decode32(txid_text).map_err(|e| bad(&e))?;
            txid.reverse(); // Txid::FromHex takes display order
            let n = v[1]
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or_else(|| bad("prevout index is not an int"))?;
            let outpoint = OutPoint { txid, n: n as u32 };
            let spk_text = v[2]
                .as_str()
                .ok_or_else(|| bad("prevout scriptPubKey is not a string"))?;
            scripts.insert(
                outpoint.clone(),
                parse_script(spk_text).map_err(|e| bad(&e))?,
            );
            if v.len() == 4 {
                let amount = v[3]
                    .as_i64()
                    .ok_or_else(|| bad("prevout amount is not an integer"))?;
                amounts.insert(outpoint, amount);
            }
        }
        let tx_hex = cells[1].as_str().unwrap();
        let tx_bytes =
            crate::hex::try_parse_hex(tx_hex).ok_or_else(|| bad("transaction is not hex"))?;
        let (tx, used) = Tx::deserialize(&tx_bytes, true)
            .map_err(|e| bad(&format!("transaction does not deserialize: {e}")))?;
        if used != tx_bytes.len() {
            return Err(bad(&format!(
                "transaction has {} trailing bytes; harnesses require complete transactions",
                tx_bytes.len() - used
            )));
        }
        let flags_text = cells[2].as_str().unwrap();
        let badtx = kind == Kind::Invalid && flags_text == "BADTX";
        let row_flags = if badtx {
            0
        } else {
            flags::parse_core(flags_text).map_err(|e| bad(&e))?
        };
        // Core rejects flag sets VerifyScript would not accept ("Bad test flags").
        let all = flags::all();
        let well_formed = match kind {
            Kind::Valid => flags::fill(all & !row_flags) == all & !row_flags,
            Kind::Invalid => badtx || flags::fill(row_flags) == row_flags,
        };
        if !well_formed {
            return Err(bad("bad test flags"));
        }

        let mut queries = Vec::new();
        let mut excluded = Vec::new();
        for (i, input) in tx.vin.iter().enumerate() {
            let id = format!("{idx}/{i}");
            match scripts.get(&input.prevout) {
                None if badtx => excluded.push((id, RULE_UNLISTED_PREVOUT.to_string())),
                None => {
                    return Err(bad(&format!(
                        "input {i} spends an outpoint the row does not list"
                    )))
                }
                Some(_) => {
                    let spent: Vec<SpentOutput> = tx
                        .vin
                        .iter()
                        .map(|other| SpentOutput {
                            amount: amounts.get(&other.prevout).copied().unwrap_or(0),
                            script_pubkey: scripts.get(&other.prevout).cloned().unwrap_or_default(),
                        })
                        .collect();
                    if tx
                        .vin
                        .iter()
                        .any(|other| !scripts.contains_key(&other.prevout))
                    {
                        // Another input is unlisted: there is no complete spent output list.
                        excluded.push((id, RULE_UNLISTED_PREVOUT.to_string()));
                        continue;
                    }
                    queries.push(QueryItem {
                        id,
                        label: format!("input {i}"),
                        query: ScriptQuery::new(tx_bytes.clone(), i as u32, spent),
                    });
                }
            }
        }

        let mut raw = Vec::new();
        let mut raw_rule = None;
        match kind {
            Kind::Valid => {
                for &c in &combos {
                    if c & row_flags == 0 {
                        for q in 0..queries.len() {
                            raw.push(RawCheck::One {
                                q,
                                flags: c,
                                valid: true,
                                error: Some("OK".into()),
                            });
                        }
                    }
                }
            }
            Kind::Invalid if badtx => raw_rule = Some(RULE_BADTX),
            Kind::Invalid if flags::has_policy(row_flags) => raw_rule = Some(RULE_POLICY_FAILURE),
            Kind::Invalid => {
                for &c in &combos {
                    if c & row_flags == row_flags {
                        raw.push(RawCheck::SomeInvalid { flags: c });
                    }
                }
                let mut minimal: Vec<u32> = Vec::new();
                for (_, bit) in flags::NAMES {
                    if row_flags & bit != 0 {
                        let f = flags::trim(row_flags & !bit);
                        if !minimal.contains(&f) {
                            minimal.push(f);
                        }
                    }
                }
                for f in minimal {
                    for q in 0..queries.len() {
                        raw.push(RawCheck::One {
                            q,
                            flags: f,
                            valid: true,
                            error: Some("OK".into()),
                        });
                    }
                }
            }
        }

        let text = if row_comment.is_empty() {
            row.to_string()
        } else {
            format!("{row_comment} {row}")
        };
        items.push(Item {
            id: idx.to_string(),
            label: format!("row {idx}"),
            text,
            tx_check: Some(super::TxCheckItem {
                tx: tx_bytes,
                expect_valid: !badtx,
            }),
            queries,
            excluded,
            raw,
            raw_rule,
            core: match kind {
                Kind::Valid => Some(CoreReplay::TxValid {
                    excluded: row_flags,
                }),
                Kind::Invalid if badtx => None,
                Kind::Invalid => Some(CoreReplay::TxInvalid { flags: row_flags }),
            },
        });
    }
    Ok(items)
}
