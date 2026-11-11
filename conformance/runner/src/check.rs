//! Queries, expectations and per-suite statistics.

use crate::flags;
use crate::harness::{CallError, Harness};
use crate::hex;
use crate::tx::write_compact_size;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// One spent output of a `script_verify` or `sighash_taproot` request.
#[derive(Clone, Debug)]
pub struct SpentOutput {
    pub amount: i64,
    pub script_pubkey: Vec<u8>,
}

/// One input of one transaction to verify, without the flags: everything a `script_verify`
/// request contains except `flags`.
#[derive(Clone, Debug)]
pub struct ScriptQuery {
    pub tx: Vec<u8>,
    pub index: u32,
    pub spent: Vec<SpentOutput>,
    body: String,
}

impl ScriptQuery {
    pub fn new(tx: Vec<u8>, index: u32, spent: Vec<SpentOutput>) -> Self {
        let mut body = format!("\"tx\":\"{}\",\"index\":{},", hex::encode(&tx), index);
        body.push_str(&spent_outputs_json(&spent));
        ScriptQuery {
            tx,
            index,
            spent,
            body,
        }
    }

    /// Request fields for `script_verify` under `flags` (consensus flags only).
    pub fn body(&self, flags: u32) -> String {
        format!("{},\"flags\":{}", self.body, flags::json_array(flags))
    }

    /// Request fields shared by `script_verify` and `sighash_taproot` (tx, index, spent_outputs).
    pub fn base_body(&self) -> &str {
        &self.body
    }

    /// Request fields for the oracle's `x_core_script_verify` extension: any of Core's flags.
    pub fn body_any_flags(&self, flags: u32) -> String {
        format!("{},\"flags\":{}", self.body, flags::json_array_any(flags))
    }

    /// Short content digest (first 8 bytes of SHA-256 of the transaction, index and spent
    /// outputs). Derived vector files store it next to each result row so the runner can prove
    /// that it builds exactly the request the oracle answered.
    pub fn digest(&self) -> String {
        let mut data = Vec::new();
        write_compact_size(&mut data, self.tx.len() as u64);
        data.extend_from_slice(&self.tx);
        data.extend_from_slice(&self.index.to_le_bytes());
        write_compact_size(&mut data, self.spent.len() as u64);
        for s in &self.spent {
            data.extend_from_slice(&s.amount.to_le_bytes());
            write_compact_size(&mut data, s.script_pubkey.len() as u64);
            data.extend_from_slice(&s.script_pubkey);
        }
        short_digest(&data)
    }
}

pub fn spent_outputs_json(spent: &[SpentOutput]) -> String {
    let items: Vec<String> = spent
        .iter()
        .map(|s| {
            format!(
                "{{\"amount\":{},\"script_pubkey\":\"{}\"}}",
                s.amount,
                hex::encode(&s.script_pubkey)
            )
        })
        .collect();
    format!("\"spent_outputs\":[{}]", items.join(","))
}

pub fn short_digest(data: &[u8]) -> String {
    hex::encode(&Sha256::digest(data)[..8])
}

/// A `script_verify` answer. `error` is normalized: a valid result without `script_error` is
/// `OK`; an invalid result without `script_error` is the empty string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptResult {
    pub valid: bool,
    pub error: String,
}

impl ScriptResult {
    pub fn from_fields(f: &Map<String, Value>) -> Result<Self, CallError> {
        let valid = f.get("valid").and_then(Value::as_bool).ok_or_else(|| {
            CallError::Protocol("script_verify response has no boolean valid".into())
        })?;
        let error = match f.get("script_error") {
            None | Some(Value::Null) => {
                if valid {
                    "OK".to_string()
                } else {
                    String::new()
                }
            }
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(CallError::Protocol("script_error is not a string".into())),
        };
        Ok(ScriptResult { valid, error })
    }

    pub fn describe(&self) -> String {
        let err = if self.error.is_empty() {
            "no script_error"
        } else {
            &self.error
        };
        format!("{} ({err})", if self.valid { "valid" } else { "invalid" })
    }
}

/// A `tx_check` answer. `reason` is empty when absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxCheckResult {
    pub valid: bool,
    pub reason: String,
}

impl TxCheckResult {
    pub fn from_fields(f: &Map<String, Value>) -> Result<Self, CallError> {
        let valid = f
            .get("valid")
            .and_then(Value::as_bool)
            .ok_or_else(|| CallError::Protocol("tx_check response has no boolean valid".into()))?;
        let reason = match f.get("reason") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(CallError::Protocol("reason is not a string".into())),
        };
        Ok(TxCheckResult { valid, reason })
    }

    pub fn describe(&self) -> String {
        if self.valid {
            "valid".into()
        } else if self.reason.is_empty() {
            "invalid (no reason)".into()
        } else {
            format!("invalid ({})", self.reason)
        }
    }
}

/// Counters for one suite.
#[derive(Default, Debug)]
pub struct Stats {
    /// Checks performed (each compares one harness answer, or one group of answers, with an
    /// expectation).
    pub cases: u64,
    pub passed: u64,
    /// Level 1 failures: wrong validity, wrong hash, or no usable answer.
    pub failed: u64,
    /// Failures `--known-failures` names. Counted in `cases`, not in `failed`.
    pub known: u64,
    /// Passed checks whose expectation includes an error identifier.
    pub l2_checked: u64,
    /// Passed checks whose error identifier differs from the expected one.
    pub l2_mismatches: u64,
    /// Checks skipped because the harness does not list the operation.
    pub unsupported: u64,
    /// Rows without a check in this mode, by stated rule.
    pub rules: BTreeMap<String, u64>,
    /// Set when the suite could not run at all.
    pub error: Option<String>,
    /// Extra report lines printed after the summary table (per-file or per-chain detail).
    pub details: Vec<String>,
}

impl Stats {
    pub fn pass(&mut self) {
        self.cases += 1;
        self.passed += 1;
    }

    pub fn fail(&mut self, suite: &str, verbose: bool, loc: &str, detail: &str) {
        self.cases += 1;
        if crate::known::take(suite, loc) {
            self.known += 1;
            if verbose {
                println!("KNOWN    [{suite}] {loc}: {detail}");
            }
            return;
        }
        self.failed += 1;
        if verbose {
            println!("FAIL     [{suite}] {loc}: {detail}");
        }
    }

    pub fn rule(&mut self, rule: &str, count: u64) {
        *self.rules.entry(rule.to_string()).or_default() += count;
    }
}

/// Executes checks for one suite against a harness and keeps the statistics.
pub struct Ctx<'h> {
    pub harness: &'h mut Harness,
    pub suite: &'static str,
    pub verbose: bool,
    pub stats: Stats,
}

impl<'h> Ctx<'h> {
    pub fn new(harness: &'h mut Harness, suite: &'static str, verbose: bool) -> Self {
        Ctx {
            harness,
            suite,
            verbose,
            stats: Stats::default(),
        }
    }

    pub fn supports(&self, op: &str) -> bool {
        self.harness.supports(op)
    }

    pub fn rule(&mut self, rule: &str, count: u64) {
        self.stats.rule(rule, count);
    }

    pub fn unsupported(&mut self, count: u64) {
        self.stats.unsupported += count;
    }

    pub fn script(&mut self, q: &ScriptQuery, flags: u32) -> Result<ScriptResult, CallError> {
        let f = self.harness.call("script_verify", &q.body(flags))?;
        ScriptResult::from_fields(&f)
    }

    pub fn tx_check(&mut self, tx: &[u8]) -> Result<TxCheckResult, CallError> {
        let f = self
            .harness
            .call("tx_check", &format!("\"tx\":\"{}\"", hex::encode(tx)))?;
        TxCheckResult::from_fields(&f)
    }

    pub fn pass(&mut self) {
        self.stats.pass();
    }

    pub fn fail(&mut self, loc: &str, detail: &str) {
        self.stats.fail(self.suite, self.verbose, loc, detail);
    }

    /// A check whose level 1 part passed and whose level 2 part (error identifier) was compared.
    pub fn pass_l2(&mut self, loc: &str, expected: &str, got: &str) {
        self.pass();
        self.stats.l2_checked += 1;
        if expected != got {
            self.stats.l2_mismatches += 1;
            if self.verbose {
                let got = if got.is_empty() { "nothing" } else { got };
                println!(
                    "LEVEL2   [{}] {loc}: expected error {expected}, got {got}",
                    self.suite
                );
            }
        }
    }

    /// Records a call that produced no answer. `unsupported_op` is counted separately.
    pub fn call_failed(&mut self, loc: &str, e: &CallError) {
        match e {
            CallError::Unsupported(_) => self.unsupported(1),
            _ => self.fail(loc, &e.to_string()),
        }
    }

    /// Compares a script result with an expectation. `expected_error` is `None` when only the
    /// validity is known.
    pub fn expect_script(
        &mut self,
        loc: &dyn Fn() -> String,
        got: Result<ScriptResult, CallError>,
        expected_valid: bool,
        expected_error: Option<&str>,
    ) {
        match got {
            Err(e) => self.call_failed(&loc(), &e),
            Ok(r) if r.valid != expected_valid => {
                let want = match expected_error {
                    Some(err) => format!(
                        "{} ({err})",
                        if expected_valid { "valid" } else { "invalid" }
                    ),
                    None => (if expected_valid { "valid" } else { "invalid" }).to_string(),
                };
                self.fail(&loc(), &format!("expected {want}, got {}", r.describe()));
            }
            Ok(r) => match expected_error {
                Some(err) => self.pass_l2(&loc(), err, &r.error),
                None => self.pass(),
            },
        }
    }
}

/// Text of one vector row for messages, shortened to `max` characters.
pub fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let head: String = text.chars().take(max).collect();
        format!("{head}...")
    }
}
