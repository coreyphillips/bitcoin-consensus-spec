//! script_tests.json, as `script_json_test` in src/test/script_tests.cpp reads it.
//!
//! Row format: `[[witness..., amount]?, scriptSig, scriptPubKey, flags, expected_error, comment?]`.
//! Rows with a single element are comments. Witness elements are hex, `#SCRIPT# <asm>` (a script
//! parsed with `ParseScript`) or `#CONTROLBLOCK#`; the last element of the witness array is the
//! amount in BTC. The scriptPubKey `0x51 0x20 #TAPROOTOUTPUT#` is the taproot output of the
//! single-leaf tree (see `taproot.rs`).
//!
//! Each row becomes one query: input 0 of Core's spending transaction (`BuildSpendingTransaction`)
//! of the crediting transaction (`BuildCreditingTransaction`), src/test/util/transaction_utils.cpp.
//!
//! Flag handling follows `DoTest`: CLEANSTACK in the row adds P2SH and WITNESS. The expectations
//! for consensus-only flag sets are:
//! - the row's flags are all consensus flags: the exact result (validity and error) under those
//!   flags; if the row expects success, success under every consensus subset; if it expects
//!   failure, failure under every consensus superset (DoTest's "removing flags from a passing
//!   test or adding flags to a failing test does not change the result");
//! - the row has policy flags and expects success: success under every subset of its
//!   consensus flags;
//! - the row has policy flags and expects failure: nothing (rule counted in raw mode).

use super::{CoreReplay, Item, QueryItem, RawCheck};
use crate::amount::amount_from_btc_text;
use crate::check::{ScriptQuery, SpentOutput};
use crate::flags;
use crate::script::parse_script;
use crate::taproot;
use crate::tx::{OutPoint, Tx, TxIn, TxOut};
use serde_json::value::RawValue;

pub const RULE_POLICY_FAILURE: &str =
    "row expects failure only under flags that include policy flags (no consensus-only expectation)";

/// Error identifiers of the `script_errors[]` table in src/test/script_tests.cpp.
pub const SCRIPT_TEST_ERRORS: &[&str] = &[
    "OK",
    "EVAL_FALSE",
    "OP_RETURN",
    "SCRIPT_SIZE",
    "PUSH_SIZE",
    "OP_COUNT",
    "STACK_SIZE",
    "SIG_COUNT",
    "PUBKEY_COUNT",
    "VERIFY",
    "EQUALVERIFY",
    "CHECKMULTISIGVERIFY",
    "CHECKSIGVERIFY",
    "NUMEQUALVERIFY",
    "BAD_OPCODE",
    "DISABLED_OPCODE",
    "INVALID_STACK_OPERATION",
    "INVALID_ALTSTACK_OPERATION",
    "UNBALANCED_CONDITIONAL",
    "NEGATIVE_LOCKTIME",
    "UNSATISFIED_LOCKTIME",
    "SIG_HASHTYPE",
    "SIG_DER",
    "MINIMALDATA",
    "SIG_PUSHONLY",
    "SIG_HIGH_S",
    "SIG_NULLDUMMY",
    "PUBKEYTYPE",
    "CLEANSTACK",
    "MINIMALIF",
    "NULLFAIL",
    "DISCOURAGE_UPGRADABLE_NOPS",
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
    "WITNESS_PROGRAM_WRONG_LENGTH",
    "WITNESS_PROGRAM_WITNESS_EMPTY",
    "WITNESS_PROGRAM_MISMATCH",
    "WITNESS_MALLEATED",
    "WITNESS_MALLEATED_P2SH",
    "WITNESS_UNEXPECTED",
    "WITNESS_PUBKEYTYPE",
    "TAPSCRIPT_EMPTY_PUBKEY",
    "OP_CODESEPARATOR",
    "SIG_FINDANDDELETE",
    "SCRIPTNUM",
];

fn string(raw: &RawValue, what: &str) -> Result<String, String> {
    serde_json::from_str::<String>(raw.get())
        .map_err(|_| format!("{what} is not a string: {}", raw.get()))
}

/// `BuildCreditingTransaction` + `BuildSpendingTransaction`: the query for input 0 of the
/// spending transaction.
pub fn credit_and_spend(
    script_pubkey: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    amount: i64,
) -> ScriptQuery {
    let credit = Tx {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0; 32],
                n: u32::MAX,
            },
            // CScript() << CScriptNum(0) << CScriptNum(0): two empty pushes.
            script_sig: vec![0x00, 0x00],
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value: amount,
            script_pubkey: script_pubkey.clone(),
        }],
        lock_time: 0,
    };
    let spend = Tx {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: credit.txid(),
                n: 0,
            },
            script_sig,
            sequence: u32::MAX,
            witness,
        }],
        vout: vec![TxOut {
            value: amount,
            script_pubkey: Vec::new(),
        }],
        lock_time: 0,
    };
    ScriptQuery::new(
        spend.serialize(true),
        0,
        vec![SpentOutput {
            amount,
            script_pubkey,
        }],
    )
}

pub fn load(path: &std::path::Path) -> Result<Vec<Item>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let rows: Vec<Box<RawValue>> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let key0 = taproot::key0_xonly();
    let combos = flags::consensus_combinations();
    let mut items = Vec::new();
    for (idx, raw_row) in rows.iter().enumerate() {
        let bad = |m: &str| format!("{} row {idx}: {m}", path.display());
        let row: Vec<Box<RawValue>> =
            serde_json::from_str(raw_row.get()).map_err(|_| bad("row is not an array"))?;
        let mut pos = 0;
        let mut witness: Vec<Vec<u8>> = Vec::new();
        let mut amount = 0i64;
        let mut taproot_output: Option<[u8; 32]> = None;
        if let Some(first) = row.first() {
            if first.get().trim_start().starts_with('[') {
                let elements: Vec<Box<RawValue>> =
                    serde_json::from_str(first.get()).map_err(|e| bad(&e.to_string()))?;
                if elements.is_empty() {
                    return Err(bad("empty witness array"));
                }
                for el in &elements[..elements.len() - 1] {
                    let s = string(el, "witness element").map_err(|e| bad(&e))?;
                    if let Some(asm) = s.strip_prefix("#SCRIPT#") {
                        witness.push(parse_script(asm).map_err(|e| bad(&e))?);
                    } else if s == "#CONTROLBLOCK#" {
                        if taproot_output.is_some() {
                            return Err(bad("more than one #CONTROLBLOCK#"));
                        }
                        let leaf = witness
                            .last()
                            .ok_or_else(|| bad("#CONTROLBLOCK# without a script before it"))?;
                        let (control, output) =
                            taproot::single_leaf(key0, leaf).map_err(|e| bad(&e))?;
                        witness.push(control);
                        taproot_output = Some(output);
                    } else {
                        witness.push(
                            crate::hex::try_parse_hex(&s)
                                .ok_or_else(|| bad(&format!("witness is not hex: {s}")))?,
                        );
                    }
                }
                // AmountFromValue: the exact text of the JSON number.
                amount = amount_from_btc_text(elements[elements.len() - 1].get().trim())
                    .map_err(|e| bad(&e))?;
                pos = 1;
            }
        }
        if row.len() < 4 + pos {
            if row.len() != 1 {
                return Err(bad("bad test (too few elements)"));
            }
            continue; // comment
        }
        let script_sig_text = string(&row[pos], "scriptSig").map_err(|e| bad(&e))?;
        let script_pubkey_text = string(&row[pos + 1], "scriptPubKey").map_err(|e| bad(&e))?;
        let flags_text = string(&row[pos + 2], "flags").map_err(|e| bad(&e))?;
        let expected = string(&row[pos + 3], "expected error").map_err(|e| bad(&e))?;
        if !SCRIPT_TEST_ERRORS.contains(&expected.as_str()) {
            return Err(bad(&format!("unknown script error {expected}")));
        }
        let script_sig = parse_script(&script_sig_text).map_err(|e| bad(&e))?;
        let script_pubkey = if script_pubkey_text == "0x51 0x20 #TAPROOTOUTPUT#" {
            let out =
                taproot_output.ok_or_else(|| bad("#TAPROOTOUTPUT# without #CONTROLBLOCK#"))?;
            let mut spk = vec![0x51, 0x20];
            spk.extend_from_slice(&out);
            spk
        } else {
            parse_script(&script_pubkey_text).map_err(|e| bad(&e))?
        };
        let mut row_flags = flags::parse_core(&flags_text).map_err(|e| bad(&e))?;
        if row_flags & flags::CLEANSTACK != 0 {
            row_flags |= flags::P2SH | flags::WITNESS;
        }
        let query = credit_and_spend(script_pubkey, script_sig, witness, amount);
        let expect_ok = expected == "OK";

        let mut raw = Vec::new();
        let mut raw_rule = None;
        if !flags::has_policy(row_flags) {
            raw.push(RawCheck::One {
                q: 0,
                flags: row_flags,
                valid: expect_ok,
                error: Some(expected.clone()),
            });
            for &c in &combos {
                if c == row_flags {
                    continue;
                }
                if expect_ok && c & row_flags == c {
                    raw.push(RawCheck::One {
                        q: 0,
                        flags: c,
                        valid: true,
                        error: Some("OK".into()),
                    });
                }
                if !expect_ok && c & row_flags == row_flags {
                    raw.push(RawCheck::One {
                        q: 0,
                        flags: c,
                        valid: false,
                        error: None,
                    });
                }
            }
        } else if expect_ok {
            let consensus = row_flags & flags::CONSENSUS;
            for &c in &combos {
                if c & consensus == c {
                    raw.push(RawCheck::One {
                        q: 0,
                        flags: c,
                        valid: true,
                        error: Some("OK".into()),
                    });
                }
            }
        } else {
            raw_rule = Some(RULE_POLICY_FAILURE);
        }

        items.push(Item {
            id: idx.to_string(),
            label: format!("row {idx}"),
            text: raw_row.get().to_string(),
            tx_check: None,
            queries: vec![QueryItem {
                id: idx.to_string(),
                label: String::new(),
                query,
            }],
            excluded: Vec::new(),
            raw,
            raw_rule,
            core: Some(CoreReplay::ScriptTest {
                flags: row_flags,
                expected,
            }),
        });
    }
    Ok(items)
}
