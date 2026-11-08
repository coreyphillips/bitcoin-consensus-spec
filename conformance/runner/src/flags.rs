//! Script verification flags.
//!
//! The runner represents a flag set as a bit mask. The seven consensus flags use the low seven
//! bits, in the order of Core's `AllConsensusFlags()` (src/test/script_assets_tests.cpp), which is
//! also the order of conformance/PROTOCOL.md section 3.1. The other bits are the policy-only flags
//! that Core's test vectors use; they are never sent to a harness.

pub const P2SH: u32 = 1 << 0;
pub const DERSIG: u32 = 1 << 1;
pub const NULLDUMMY: u32 = 1 << 2;
pub const CHECKLOCKTIMEVERIFY: u32 = 1 << 3;
pub const CHECKSEQUENCEVERIFY: u32 = 1 << 4;
pub const WITNESS: u32 = 1 << 5;
pub const TAPROOT: u32 = 1 << 6;
pub const CONSENSUS: u32 = (1 << 7) - 1;

pub const CLEANSTACK: u32 = 1 << 12;

/// Every flag name of Core's `ScriptFlagNamesToEnum()` (src/script/interpreter.cpp).
pub const NAMES: &[(&str, u32)] = &[
    ("P2SH", P2SH),
    ("DERSIG", DERSIG),
    ("NULLDUMMY", NULLDUMMY),
    ("CHECKLOCKTIMEVERIFY", CHECKLOCKTIMEVERIFY),
    ("CHECKSEQUENCEVERIFY", CHECKSEQUENCEVERIFY),
    ("WITNESS", WITNESS),
    ("TAPROOT", TAPROOT),
    ("STRICTENC", 1 << 7),
    ("LOW_S", 1 << 8),
    ("SIGPUSHONLY", 1 << 9),
    ("MINIMALDATA", 1 << 10),
    ("DISCOURAGE_UPGRADABLE_NOPS", 1 << 11),
    ("CLEANSTACK", CLEANSTACK),
    ("MINIMALIF", 1 << 13),
    ("NULLFAIL", 1 << 14),
    ("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM", 1 << 15),
    ("WITNESS_PUBKEYTYPE", 1 << 16),
    ("CONST_SCRIPTCODE", 1 << 17),
    ("DISCOURAGE_UPGRADABLE_PUBKEYTYPE", 1 << 18),
    ("DISCOURAGE_OP_SUCCESS", 1 << 19),
    ("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION", 1 << 20),
];

/// Core's `ParseScriptFlags` (src/test/transaction_tests.cpp): "" and "NONE" are the empty set,
/// otherwise a comma separated list of exact names.
pub fn parse_core(text: &str) -> Result<u32, String> {
    if text.is_empty() || text == "NONE" {
        return Ok(0);
    }
    let mut bits = 0;
    for word in text.split(',') {
        let bit = NAMES
            .iter()
            .find(|(n, _)| *n == word)
            .map(|(_, b)| *b)
            .ok_or_else(|| format!("unknown verification flag {word:?}"))?;
        bits |= bit;
    }
    Ok(bits)
}

/// Names of the flags in `bits`, in table order.
pub fn names(bits: u32) -> Vec<&'static str> {
    NAMES
        .iter()
        .filter(|(_, b)| bits & b != 0)
        .map(|(n, _)| *n)
        .collect()
}

/// "P2SH,WITNESS" style text, "NONE" for the empty set.
pub fn display(bits: u32) -> String {
    if bits == 0 {
        "NONE".to_string()
    } else {
        names(bits).join(",")
    }
}

/// The JSON array sent in requests (consensus flags only).
pub fn json_array(bits: u32) -> String {
    debug_assert!(
        sendable(bits),
        "flag set {bits:#x} must not be sent to a harness"
    );
    let names: Vec<String> = names(bits).iter().map(|n| format!("\"{n}\"")).collect();
    format!("[{}]", names.join(","))
}

/// Whether the set contains a flag that is not one of the seven consensus flags.
pub fn has_policy(bits: u32) -> bool {
    bits & !CONSENSUS != 0
}

/// Core's `AllConsensusFlags()`: the 64 combinations of the seven consensus flags in which
/// WITNESS implies P2SH and TAPROOT implies WITNESS, in Core's order.
pub fn consensus_combinations() -> Vec<u32> {
    (0u32..128)
        .filter(|&f| !(f & WITNESS != 0 && f & P2SH == 0))
        .filter(|&f| !(f & TAPROOT != 0 && f & WITNESS == 0))
        .collect()
}

/// Whether the harness may be sent this combination (PROTOCOL.md 3.1: never WITNESS without
/// P2SH).
pub fn sendable(bits: u32) -> bool {
    bits & !CONSENSUS == 0 && !(bits & WITNESS != 0 && bits & P2SH == 0)
}

/// Every flag Core's tests know.
pub fn all() -> u32 {
    NAMES.iter().fold(0, |a, (_, b)| a | b)
}

/// Core's `IsValidFlagCombination`: the combinations `VerifyScript` accepts.
pub fn valid_combination(bits: u32) -> bool {
    !(bits & CLEANSTACK != 0 && (bits & P2SH == 0 || bits & WITNESS == 0))
        && !(bits & WITNESS != 0 && bits & P2SH == 0)
}

/// Core's `TrimFlags` (transaction_tests.cpp): WITNESS requires P2SH, CLEANSTACK requires
/// WITNESS.
pub fn trim(mut bits: u32) -> u32 {
    if bits & P2SH == 0 {
        bits &= !WITNESS;
    }
    if bits & WITNESS == 0 {
        bits &= !CLEANSTACK;
    }
    bits
}

/// Core's `FillFlags` (transaction_tests.cpp): CLEANSTACK implies WITNESS, WITNESS implies P2SH.
pub fn fill(mut bits: u32) -> u32 {
    if bits & CLEANSTACK != 0 {
        bits |= WITNESS;
    }
    if bits & WITNESS != 0 {
        bits |= P2SH;
    }
    bits
}

/// Core's `ExcludeIndividualFlags` (transaction_tests.cpp): `bits` with one flag removed (and
/// trimmed), for every flag whose removal changes the set.
pub fn exclude_individual(bits: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for (_, b) in NAMES {
        let f = trim(bits & !b);
        if f != bits && !out.contains(&f) {
            out.push(f);
        }
    }
    out.sort();
    out
}

/// A JSON array with the names of every flag in `bits`, policy flags included (only for the
/// oracle's `x_core_script_verify` extension).
pub fn json_array_any(bits: u32) -> String {
    let names: Vec<String> = names(bits).iter().map(|n| format!("\"{n}\"")).collect();
    format!("[{}]", names.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixty_four_combinations() {
        let c = consensus_combinations();
        assert_eq!(c.len(), 64);
        assert_eq!(c[0], 0);
        assert!(c.iter().all(|&f| sendable(f)));
    }

    #[test]
    fn parse() {
        assert_eq!(parse_core("NONE").unwrap(), 0);
        assert_eq!(parse_core("").unwrap(), 0);
        assert_eq!(parse_core("P2SH,WITNESS").unwrap(), P2SH | WITNESS);
        assert!(parse_core("P2SH, WITNESS").is_err());
        assert!(parse_core("BADTX").is_err());
        assert_eq!(display(P2SH | TAPROOT | (1 << 7)), "P2SH,TAPROOT,STRICTENC");
    }
}
