//! Suites.
//!
//! The four script suites (script-tests, tx-valid, tx-invalid, script-assets) turn their vector
//! file into a list of [`Item`]s. An item is one vector row: an optional `tx_check`, the script
//! verification queries the row implies (one per transaction input or witness), and the
//! expectations the original vector states for consensus-only flag sets ([`RawCheck`]).
//!
//! - Default (derived) mode compares the harness with Core's answers recorded in the derived
//!   files for all 64 consensus flag combinations of every query.
//! - Raw mode (`--raw`) checks only what the original vector file states, restricted to
//!   consensus flags; rows whose expectation needs policy flags are counted under a rule.
//! - `derive` asks the oracle for all 64 combinations, then evaluates every raw expectation
//!   against those answers (the cross-check) before writing the derived file. When the oracle
//!   offers its `x_core_script_verify` extension, `derive` also replays Core's own unit tests
//!   with the rows' original flags, policy flags included ([`replay_core`]).
//!
//! sighash, bip341 and bip340 do not involve flags and run identically in both modes.

pub mod bip340;
pub mod bip341;
pub mod corpus;
pub mod custom;
pub mod headers_live;
pub mod interop;
pub mod script_assets;
pub mod script_tests;
pub mod sighash;
pub mod tx_tests;

use crate::check::{shorten, Ctx, ScriptQuery, ScriptResult};
use crate::derived::{self, DerivedFile, ScriptEntry, TxCheckEntry};
use crate::flags;
use crate::harness::CallError;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A suite: name, description, whether a plain run includes it, whether it needs `--impl`.
pub struct SuiteInfo {
    pub name: &'static str,
    pub what: &'static str,
    pub default: bool,
    pub needs_harness: bool,
}

/// All suites, in run order.
pub const SUITES: &[SuiteInfo] = &[
    SuiteInfo { name: "script-tests", what: "src/test/data/script_tests.json: one input per row, Core's crediting and spending transactions", default: true, needs_harness: true },
    SuiteInfo { name: "tx-valid", what: "src/test/data/tx_valid.json: tx_check plus every input", default: true, needs_harness: true },
    SuiteInfo { name: "tx-invalid", what: "src/test/data/tx_invalid.json: tx_check plus every input", default: true, needs_harness: true },
    SuiteInfo { name: "sighash", what: "src/test/data/sighash.json: legacy signature hashes plus tx_check", default: true, needs_harness: true },
    SuiteInfo { name: "bip341", what: "BIP341 wallet vectors: key path sighashes, signed inputs, script path control blocks", default: true, needs_harness: true },
    SuiteInfo { name: "bip340", what: "BIP340 test-vectors.csv: the verification column", default: true, needs_harness: true },
    SuiteInfo { name: "script-assets", what: "qa-assets script_assets_test.json: success and failure witnesses", default: true, needs_harness: true },
    SuiteInfo { name: "custom", what: "vectors/custom/*.jsonl: targeted request and expected response pairs", default: true, needs_harness: true },
    SuiteInfo { name: "corpus", what: "vectors/blocks/*.jsonl.gz: block scenarios recorded from Core's functional tests (CORPUS.md)", default: true, needs_harness: true },
    SuiteInfo { name: "headers-live", what: "the full header chain of a live peer (--peer, --network), fed to the harness", default: false, needs_harness: true },
    SuiteInfo { name: "interop", what: "the implementation as a live node next to a regtest bitcoind (--bitcoind, --node)", default: false, needs_harness: false },
];

pub fn suite(name: &str) -> Option<&'static SuiteInfo> {
    SUITES.iter().find(|s| s.name == name)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Derived,
    Raw,
}

/// Where vectors live.
pub struct Paths {
    pub vectors: PathBuf,
    pub derived: PathBuf,
}

/// The script-suite sources: (suite, source path under vectors/, derived file name).
pub const SCRIPT_SOURCES: &[(&str, &str, &str)] = &[
    (
        "script-tests",
        "core/script_tests.json",
        "script_tests.json",
    ),
    ("tx-valid", "core/tx_valid.json", "tx_valid.json"),
    ("tx-invalid", "core/tx_invalid.json", "tx_invalid.json"),
    (
        "script-assets",
        "qa-assets/script_assets_test.json",
        "script_assets_test.json",
    ),
];

pub fn script_source(suite: &str) -> Option<(&'static str, &'static str)> {
    SCRIPT_SOURCES
        .iter()
        .find(|s| s.0 == suite)
        .map(|s| (s.1, s.2))
}

/// A `tx_check` that a row implies, with the expectation the original vector states.
pub struct TxCheckItem {
    pub tx: Vec<u8>,
    pub expect_valid: bool,
}

/// One script verification query of a row.
pub struct QueryItem {
    /// Stable identifier, unique in the source file ("12" for a script_tests row, "12/0" for
    /// input 0 of a tx row, "12/success" for a script_assets witness).
    pub id: String,
    /// Human readable part of the location ("input 0", "success witness").
    pub label: String,
    pub query: ScriptQuery,
}

/// An expectation stated by the original vector for a consensus-only flag set.
pub enum RawCheck {
    /// The query at `q` (index into `Item::queries`) has this validity under `flags`, and this
    /// script error when `error` is known.
    One {
        q: usize,
        flags: u32,
        valid: bool,
        error: Option<String>,
    },
    /// At least one query of the item is invalid under `flags` (Core's `CheckTxScripts` with
    /// `expect_valid=false` stops at the first failing input).
    SomeInvalid { flags: u32 },
}

/// How Core's own unit test treats a row, with the row's original flags (policy flags included).
/// Only the oracle can answer such queries (its `x_core_script_verify` extension); `derive` uses
/// them to prove that the runner builds every row exactly as Core's test does, including the rows
/// whose expectation needs policy flags.
pub enum CoreReplay {
    /// `DoTest` in script_tests.cpp, with the flags after its CLEANSTACK adjustment.
    ScriptTest { flags: u32, expected: String },
    /// `tx_valid` in transaction_tests.cpp: the flags the row excludes.
    TxValid { excluded: u32 },
    /// `tx_invalid` in transaction_tests.cpp (rows other than BADTX): the row's flags.
    TxInvalid { flags: u32 },
}

/// One vector row.
pub struct Item {
    /// Row identifier ("12").
    pub id: String,
    /// "row 12", "case 12".
    pub label: String,
    /// Row text or comment for messages.
    pub text: String,
    pub tx_check: Option<TxCheckItem>,
    pub queries: Vec<QueryItem>,
    /// Queries that cannot be built, with the rule that excludes them.
    pub excluded: Vec<(String, String)>,
    pub raw: Vec<RawCheck>,
    /// Set when the row states no script expectation for consensus-only flags; the rule text is
    /// counted in raw mode.
    pub raw_rule: Option<&'static str>,
    /// Core's own treatment of the row, for the replay during `derive`.
    pub core: Option<CoreReplay>,
}

impl Item {
    fn loc(&self, q: Option<&QueryItem>, flags: Option<u32>) -> String {
        let mut s = self.label.clone();
        if let Some(q) = q.filter(|q| !q.label.is_empty()) {
            s.push(' ');
            s.push_str(&q.label);
        }
        if let Some(f) = flags {
            s.push_str(" flags ");
            s.push_str(&flags::display(f));
        }
        s.push_str(": ");
        s.push_str(&shorten(&self.text, 240));
        s
    }
}

/// Loads the items of a script suite.
pub fn load_items(suite: &str, vectors: &Path) -> Result<Vec<Item>, String> {
    let (source, _) =
        script_source(suite).ok_or_else(|| format!("{suite} is not a script suite"))?;
    let path = vectors.join(source);
    match suite {
        "script-tests" => script_tests::load(&path),
        "tx-valid" => tx_tests::load(&path, tx_tests::Kind::Valid),
        "tx-invalid" => tx_tests::load(&path, tx_tests::Kind::Invalid),
        "script-assets" => script_assets::load(&path),
        _ => unreachable!(),
    }
}

fn required_ops(items: &[Item]) -> Vec<&'static str> {
    let mut ops = vec!["script_verify"];
    if items.iter().any(|i| i.tx_check.is_some()) {
        ops.push("tx_check");
    }
    ops
}

/// Runs a script suite in the given mode.
pub fn run_script_suite(ctx: &mut Ctx, paths: &Paths, mode: Mode) -> Result<(), String> {
    let items = load_items(ctx.suite, &paths.vectors)?;
    if !required_ops(&items).iter().any(|op| ctx.supports(op)) {
        return Err("the harness supports none of this suite's operations".into());
    }
    match mode {
        Mode::Raw => {
            for item in &items {
                run_raw_item(ctx, item, &mut |ctx, q, f| ctx.script(&q.query, f));
            }
        }
        Mode::Derived => {
            let (source, file_name) = script_source(ctx.suite).unwrap();
            let file = DerivedFile::load(&paths.derived.join(file_name)).map_err(|e| {
                format!("{e} (generate the derived vectors with `bcs-conformance derive`, or use --raw)")
            })?;
            if file.suite != ctx.suite {
                return Err(format!(
                    "{} holds suite {:?}, not {}",
                    paths.derived.join(file_name).display(),
                    file.suite,
                    ctx.suite
                ));
            }
            let sha = derived::sha256_file(&paths.vectors.join(source))?;
            if file.source_sha256 != sha {
                return Err(format!(
                    "{} was derived from a different {source} (sha256 {} instead of {sha}); run `bcs-conformance derive` again",
                    paths.derived.join(file_name).display(),
                    file.source_sha256
                ));
            }
            for item in &items {
                run_derived_item(ctx, item, &file)?;
            }
        }
    }
    Ok(())
}

/// Raw mode for one item: the `tx_check` expectation and every raw script expectation.
fn run_raw_item(
    ctx: &mut Ctx,
    item: &Item,
    source: &mut dyn FnMut(&mut Ctx, &QueryItem, u32) -> Result<ScriptResult, CallError>,
) {
    if let Some(tc) = &item.tx_check {
        tx_check_item(ctx, item, tc, None);
    }
    for (_, reason) in &item.excluded {
        ctx.rule(reason, 1);
    }
    if !ctx.supports("script_verify") {
        ctx.unsupported(item.raw.len() as u64);
        return;
    }
    eval_raw_checks(ctx, item, source);
}

/// Evaluates the raw script expectations of one item. `source` answers a query under a flag
/// set: the harness in raw mode, the recorded oracle answers during `derive`.
fn eval_raw_checks(
    ctx: &mut Ctx,
    item: &Item,
    source: &mut dyn FnMut(&mut Ctx, &QueryItem, u32) -> Result<ScriptResult, CallError>,
) {
    if let Some(rule) = item.raw_rule {
        ctx.rule(rule, 1);
    }
    for check in &item.raw {
        match check {
            RawCheck::One {
                q,
                flags,
                valid,
                error,
            } => {
                let qi = &item.queries[*q];
                let got = source(ctx, qi, *flags);
                ctx.expect_script(
                    &|| item.loc(Some(qi), Some(*flags)),
                    got,
                    *valid,
                    error.as_deref(),
                );
            }
            RawCheck::SomeInvalid { flags } => {
                let mut outcome: Result<bool, (String, CallError)> = Ok(false);
                for qi in &item.queries {
                    match source(ctx, qi, *flags) {
                        Ok(r) if !r.valid => {
                            outcome = Ok(true);
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            outcome = Err((qi.label.clone(), e));
                            break;
                        }
                    }
                }
                match outcome {
                    Ok(true) => ctx.pass(),
                    Ok(false) => ctx.fail(
                        &item.loc(None, Some(*flags)),
                        "expected at least one invalid input, got every input valid",
                    ),
                    Err((label, e)) => {
                        ctx.call_failed(&format!("{} ({label})", item.loc(None, Some(*flags))), &e)
                    }
                }
            }
        }
    }
}

fn tx_check_item(ctx: &mut Ctx, item: &Item, tc: &TxCheckItem, derived: Option<&TxCheckEntry>) {
    if !ctx.supports("tx_check") {
        ctx.unsupported(1);
        return;
    }
    let got = ctx.tx_check(&tc.tx);
    let loc = || format!("{} tx_check: {}", item.label, shorten(&item.text, 240));
    let (expect_valid, expect_reason) = match derived {
        Some(d) => (
            d.valid,
            if d.valid {
                None
            } else {
                Some(d.reason.as_str())
            },
        ),
        None => (tc.expect_valid, None),
    };
    match got {
        Err(e) => ctx.call_failed(&loc(), &e),
        Ok(r) if r.valid != expect_valid => {
            let want = match expect_reason {
                Some(reason) => format!("invalid ({reason})"),
                None => (if expect_valid { "valid" } else { "invalid" }).to_string(),
            };
            ctx.fail(&loc(), &format!("expected {want}, got {}", r.describe()));
        }
        Ok(r) => match expect_reason {
            Some(reason) => ctx.pass_l2(&loc(), reason, &r.reason),
            None => ctx.pass(),
        },
    }
}

fn run_derived_item(ctx: &mut Ctx, item: &Item, file: &DerivedFile) -> Result<(), String> {
    if let Some(tc) = &item.tx_check {
        let entry = file.tx_check(&item.id).ok_or_else(|| {
            format!(
                "derived file has no tx_check for {}; run derive again",
                item.label
            )
        })?;
        if entry.digest != crate::check::short_digest(&tc.tx) {
            return Err(format!(
                "derived tx_check of {} is for a different transaction; run derive again",
                item.label
            ));
        }
        tx_check_item(ctx, item, tc, Some(entry));
    }
    for (_, reason) in &item.excluded {
        ctx.rule(reason, 1);
    }
    let combos = flags::consensus_combinations();
    for qi in &item.queries {
        let entry = file.script(&qi.id).ok_or_else(|| {
            format!(
                "derived file has no entry {} ({} {}); run derive again",
                qi.id, item.label, qi.label
            )
        })?;
        if entry.digest != qi.query.digest() {
            return Err(format!(
                "derived entry {} was computed for a different request than the runner builds now; run derive again",
                qi.id
            ));
        }
        if !ctx.supports("script_verify") {
            ctx.unsupported(combos.len() as u64);
            continue;
        }
        for (i, &f) in combos.iter().enumerate() {
            let expected = &entry.results[i];
            let got = ctx.script(&qi.query, f);
            ctx.expect_script(
                &|| item.loc(Some(qi), Some(f)),
                got,
                expected == "OK",
                Some(expected),
            );
        }
    }
    Ok(())
}

/// Builds the derived file of one script suite from the oracle and cross-checks it against every
/// expectation of the original vector. The cross-check results are recorded in `ctx.stats`.
pub fn derive_suite(
    ctx: &mut Ctx,
    paths: &Paths,
    provenance: &Value,
) -> Result<DerivedFile, String> {
    let (source, _) = script_source(ctx.suite).unwrap();
    let items = load_items(ctx.suite, &paths.vectors)?;
    for op in ["script_verify", "tx_check"] {
        if !ctx.supports(op) {
            return Err(format!("the oracle does not support {op}"));
        }
    }
    let sha = derived::sha256_file(&paths.vectors.join(source))?;
    let mut file = DerivedFile::new(ctx.suite, source, &sha, provenance.clone());
    let combos = flags::consensus_combinations();
    let mut invariant_errors = Vec::new();
    for item in &items {
        if let Some(tc) = &item.tx_check {
            let r = ctx
                .tx_check(&tc.tx)
                .map_err(|e| format!("oracle tx_check failed for {}: {e}", item.label))?;
            file.add_tx_check(
                item.id.clone(),
                TxCheckEntry {
                    digest: crate::check::short_digest(&tc.tx),
                    valid: r.valid,
                    reason: r.reason,
                },
            );
        }
        for qi in &item.queries {
            let mut results = Vec::with_capacity(combos.len());
            for &f in &combos {
                let r = ctx.script(&qi.query, f).map_err(|e| {
                    format!(
                        "oracle script_verify failed for {} {} flags {}: {e}",
                        item.label,
                        qi.label,
                        flags::display(f)
                    )
                })?;
                if r.valid != (r.error == "OK") {
                    invariant_errors.push(format!(
                        "{} {} flags {}: valid={} with script_error {}",
                        item.label,
                        qi.label,
                        flags::display(f),
                        r.valid,
                        r.error
                    ));
                }
                results.push(r.error);
            }
            file.add_script(
                qi.id.clone(),
                ScriptEntry {
                    digest: qi.query.digest(),
                    results,
                },
            );
        }
        for (id, reason) in &item.excluded {
            file.excluded.push((id.clone(), reason.clone()));
        }
    }
    if !invariant_errors.is_empty() {
        return Err(format!(
            "the oracle returned results where validity and error disagree:\n  {}",
            invariant_errors.join("\n  ")
        ));
    }

    // Cross-check: every expectation the original vector states for consensus-only flags must
    // hold for Core's recorded answers. Flag sets outside the 64 combinations (none in the
    // current vectors) are asked from the oracle directly.
    let index: std::collections::HashMap<u32, usize> =
        combos.iter().enumerate().map(|(i, &c)| (c, i)).collect();
    for item in &items {
        if let Some(tc) = &item.tx_check {
            let entry = file.tx_check(&item.id).expect("recorded above");
            if entry.valid == tc.expect_valid {
                ctx.pass();
            } else {
                ctx.fail(
                    &format!("{} tx_check: {}", item.label, shorten(&item.text, 240)),
                    &format!(
                        "the vector expects {}, Core says {}",
                        if tc.expect_valid { "valid" } else { "invalid" },
                        if entry.valid {
                            "valid".to_string()
                        } else {
                            format!("invalid ({})", entry.reason)
                        }
                    ),
                );
            }
        }
        let mut recorded =
            |ctx: &mut Ctx, qi: &QueryItem, f: u32| -> Result<ScriptResult, CallError> {
                match (index.get(&f), file.script(&qi.id)) {
                    (Some(&i), Some(e)) => {
                        let error = e.results[i].clone();
                        Ok(ScriptResult {
                            valid: error == "OK",
                            error,
                        })
                    }
                    _ => ctx.script(&qi.query, f),
                }
            };
        eval_raw_checks(ctx, item, &mut recorded);
    }
    Ok(file)
}

/// The oracle extension used by [`replay_core`].
pub const CORE_REPLAY_OP: &str = "x_core_script_verify";

/// Replays Core's own unit test for every row of a script suite against the oracle, with the
/// rows' original flags (policy flags included), through the oracle's `x_core_script_verify`
/// extension. Random flag sampling in Core's tests is replaced by the deterministic single-flag
/// variations they sample from:
///
/// - script_tests (`DoTest`): the exact result and error under the row's flags; a passing row
///   still passes with any one of its flags removed, a failing row still fails with any one
///   flag added (combinations `VerifyScript` rejects are skipped, as `DoTest` skips them);
/// - tx_valid: every input passes under all flags except the excluded ones, and with any one
///   more flag removed (`TrimFlags`); some input fails when any one excluded flag is put back
///   (`ExcludeIndividualFlags`);
/// - tx_invalid: some input fails under the row's flags and with any one flag added
///   (`FillFlags`); every input passes with any one of the row's flags removed.
///
/// script_assets_test.json uses consensus flags only, so the derive cross-check already covers
/// it completely.
pub fn replay_core(ctx: &mut Ctx, paths: &Paths) -> Result<(), String> {
    let items = load_items(ctx.suite, &paths.vectors)?;
    let all = flags::all();
    for item in &items {
        let Some(core) = &item.core else { continue };
        match core {
            CoreReplay::ScriptTest { flags: f, expected } => {
                let qi = &item.queries[0];
                let expect_ok = expected == "OK";
                let got = core_verify(ctx, qi, *f);
                ctx.expect_script(
                    &|| item.loc(Some(qi), Some(*f)),
                    got,
                    expect_ok,
                    Some(expected),
                );
                for (_, bit) in flags::NAMES {
                    let g = if expect_ok { *f & !bit } else { *f | bit };
                    if g == *f || !flags::valid_combination(g) {
                        continue;
                    }
                    let got = core_verify(ctx, qi, g);
                    ctx.expect_script(&|| item.loc(Some(qi), Some(g)), got, expect_ok, None);
                }
            }
            CoreReplay::TxValid { excluded } => {
                all_valid(ctx, item, all & !excluded);
                for (_, bit) in flags::NAMES {
                    all_valid(ctx, item, flags::trim(all & !(excluded | bit)));
                }
                for g in flags::exclude_individual(*excluded) {
                    some_invalid(ctx, item, all & !g);
                }
            }
            CoreReplay::TxInvalid { flags: f } => {
                some_invalid(ctx, item, *f);
                for (_, bit) in flags::NAMES {
                    some_invalid(ctx, item, flags::fill(f | bit));
                }
                for g in flags::exclude_individual(*f) {
                    all_valid(ctx, item, g);
                }
            }
        }
    }
    Ok(())
}

fn core_verify(ctx: &mut Ctx, qi: &QueryItem, f: u32) -> Result<ScriptResult, CallError> {
    let fields = ctx
        .harness
        .call(CORE_REPLAY_OP, &qi.query.body_any_flags(f))?;
    ScriptResult::from_fields(&fields)
}

fn all_valid(ctx: &mut Ctx, item: &Item, f: u32) {
    for qi in &item.queries {
        let got = core_verify(ctx, qi, f);
        ctx.expect_script(&|| item.loc(Some(qi), Some(f)), got, true, Some("OK"));
    }
}

fn some_invalid(ctx: &mut Ctx, item: &Item, f: u32) {
    for qi in &item.queries {
        match core_verify(ctx, qi, f) {
            Ok(r) if !r.valid => {
                ctx.pass();
                return;
            }
            Ok(_) => {}
            Err(e) => {
                ctx.call_failed(&item.loc(Some(qi), Some(f)), &e);
                return;
            }
        }
    }
    ctx.fail(
        &item.loc(None, Some(f)),
        "expected at least one invalid input, got every input valid",
    );
}
