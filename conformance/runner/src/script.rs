//! Script text parsing, a port of Bitcoin Core's `ParseScript` (src/core_io.cpp), plus the
//! `CScript` push helpers it relies on (src/script/script.h).

/// Opcode names `ParseScript` accepts. Core builds its table from `GetOpName` for every opcode
/// from OP_NOP (0x61) to MAX_OPCODE (OP_NOP10, 0xb9), plus OP_RESERVED (0x50); each name is
/// accepted with and without the `OP_` prefix. Push opcodes (OP_0, OP_1 .. OP_16, OP_1NEGATE,
/// OP_PUSHDATA*) and OP_CHECKSIGADD are not in the table: tests write those as numbers or raw hex.
/// Note that OP_NOP2 and OP_NOP3 are only known by their names OP_CHECKLOCKTIMEVERIFY and
/// OP_CHECKSEQUENCEVERIFY, because that is what `GetOpName` returns for them.
const OPCODES: &[(u8, &str)] = &[
    (0x50, "OP_RESERVED"),
    (0x61, "OP_NOP"),
    (0x62, "OP_VER"),
    (0x63, "OP_IF"),
    (0x64, "OP_NOTIF"),
    (0x65, "OP_VERIF"),
    (0x66, "OP_VERNOTIF"),
    (0x67, "OP_ELSE"),
    (0x68, "OP_ENDIF"),
    (0x69, "OP_VERIFY"),
    (0x6a, "OP_RETURN"),
    (0x6b, "OP_TOALTSTACK"),
    (0x6c, "OP_FROMALTSTACK"),
    (0x6d, "OP_2DROP"),
    (0x6e, "OP_2DUP"),
    (0x6f, "OP_3DUP"),
    (0x70, "OP_2OVER"),
    (0x71, "OP_2ROT"),
    (0x72, "OP_2SWAP"),
    (0x73, "OP_IFDUP"),
    (0x74, "OP_DEPTH"),
    (0x75, "OP_DROP"),
    (0x76, "OP_DUP"),
    (0x77, "OP_NIP"),
    (0x78, "OP_OVER"),
    (0x79, "OP_PICK"),
    (0x7a, "OP_ROLL"),
    (0x7b, "OP_ROT"),
    (0x7c, "OP_SWAP"),
    (0x7d, "OP_TUCK"),
    (0x7e, "OP_CAT"),
    (0x7f, "OP_SUBSTR"),
    (0x80, "OP_LEFT"),
    (0x81, "OP_RIGHT"),
    (0x82, "OP_SIZE"),
    (0x83, "OP_INVERT"),
    (0x84, "OP_AND"),
    (0x85, "OP_OR"),
    (0x86, "OP_XOR"),
    (0x87, "OP_EQUAL"),
    (0x88, "OP_EQUALVERIFY"),
    (0x89, "OP_RESERVED1"),
    (0x8a, "OP_RESERVED2"),
    (0x8b, "OP_1ADD"),
    (0x8c, "OP_1SUB"),
    (0x8d, "OP_2MUL"),
    (0x8e, "OP_2DIV"),
    (0x8f, "OP_NEGATE"),
    (0x90, "OP_ABS"),
    (0x91, "OP_NOT"),
    (0x92, "OP_0NOTEQUAL"),
    (0x93, "OP_ADD"),
    (0x94, "OP_SUB"),
    (0x95, "OP_MUL"),
    (0x96, "OP_DIV"),
    (0x97, "OP_MOD"),
    (0x98, "OP_LSHIFT"),
    (0x99, "OP_RSHIFT"),
    (0x9a, "OP_BOOLAND"),
    (0x9b, "OP_BOOLOR"),
    (0x9c, "OP_NUMEQUAL"),
    (0x9d, "OP_NUMEQUALVERIFY"),
    (0x9e, "OP_NUMNOTEQUAL"),
    (0x9f, "OP_LESSTHAN"),
    (0xa0, "OP_GREATERTHAN"),
    (0xa1, "OP_LESSTHANOREQUAL"),
    (0xa2, "OP_GREATERTHANOREQUAL"),
    (0xa3, "OP_MIN"),
    (0xa4, "OP_MAX"),
    (0xa5, "OP_WITHIN"),
    (0xa6, "OP_RIPEMD160"),
    (0xa7, "OP_SHA1"),
    (0xa8, "OP_SHA256"),
    (0xa9, "OP_HASH160"),
    (0xaa, "OP_HASH256"),
    (0xab, "OP_CODESEPARATOR"),
    (0xac, "OP_CHECKSIG"),
    (0xad, "OP_CHECKSIGVERIFY"),
    (0xae, "OP_CHECKMULTISIG"),
    (0xaf, "OP_CHECKMULTISIGVERIFY"),
    (0xb0, "OP_NOP1"),
    (0xb1, "OP_CHECKLOCKTIMEVERIFY"),
    (0xb2, "OP_CHECKSEQUENCEVERIFY"),
    (0xb3, "OP_NOP4"),
    (0xb4, "OP_NOP5"),
    (0xb5, "OP_NOP6"),
    (0xb6, "OP_NOP7"),
    (0xb7, "OP_NOP8"),
    (0xb8, "OP_NOP9"),
    (0xb9, "OP_NOP10"),
];

fn opcode_by_name(word: &str) -> Option<u8> {
    OPCODES.iter().find_map(|&(op, name)| {
        if name == word || name.strip_prefix("OP_") == Some(word) {
            Some(op)
        } else {
            None
        }
    })
}

/// `CScriptNum::serialize`: minimal little-endian sign-magnitude encoding.
pub fn script_num_serialize(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let neg = value < 0;
    let mut abs = value.unsigned_abs();
    let mut out = Vec::new();
    while abs != 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    let last = *out.last().unwrap();
    if last & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

/// `CScript << std::vector<unsigned char>`: a data push with the smallest length prefix
/// (`AppendDataSize`).
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        script.push(n as u8);
    } else if n <= 0xff {
        script.push(0x4c);
        script.push(n as u8);
    } else if n <= 0xffff {
        script.push(0x4d);
        script.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        script.push(0x4e);
        script.extend_from_slice(&(n as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// `CScript << int64_t` (`push_int64`).
pub fn push_int64(script: &mut Vec<u8>, n: i64) {
    if n == -1 || (1..=16).contains(&n) {
        script.push((n + 0x50) as u8); // OP_1 - 1 = 0x50
    } else if n == 0 {
        script.push(0x00);
    } else {
        push_data(script, &script_num_serialize(n));
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Port of Core's `ParseScript`.
pub fn parse_script(s: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    // SplitString(s, " \t\n"): every one of these characters separates words; empty words are
    // ignored.
    for w in s.split([' ', '\t', '\n']) {
        if w.is_empty() {
            continue;
        }
        let b = w.as_bytes();
        let all_digits = |x: &[u8]| x.iter().all(|c| c.is_ascii_digit());
        if all_digits(b) || (b[0] == b'-' && b.len() > 1 && all_digits(&b[1..])) {
            // Decimal number: ToIntegral<int64_t>, limited to -0xFFFFFFFF..0xFFFFFFFF.
            let num: Option<i64> = w.parse().ok();
            match num {
                Some(n) if (-0xffff_ffff..=0xffff_ffff).contains(&n) => push_int64(&mut result, n),
                _ => {
                    return Err(format!(
                        "script parse error: decimal numeric value only allowed in the range -0xFFFFFFFF...0xFFFFFFFF ({w})"
                    ))
                }
            }
        } else if w.len() > 2 && w.starts_with("0x") && is_hex(&w[2..]) {
            // Raw bytes, inserted as they are (not pushed).
            result.extend(crate::hex::decode(&w[2..])?);
        } else if w.len() >= 2 && w.starts_with('\'') && w.ends_with('\'') {
            // Single-quoted string, pushed as data.
            push_data(&mut result, &b[1..b.len() - 1]);
        } else {
            match opcode_by_name(w) {
                Some(op) => result.push(op),
                None => return Err(format!("script parse error: unknown opcode {w}")),
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn numbers() {
        assert_eq!(parse_script("0").unwrap(), vec![0x00]);
        assert_eq!(parse_script("-1").unwrap(), vec![0x4f]);
        assert_eq!(parse_script("1 16").unwrap(), vec![0x51, 0x60]);
        assert_eq!(parse_script("17").unwrap(), vec![0x01, 0x11]);
        assert_eq!(parse_script("-0").unwrap(), vec![0x00]);
        assert_eq!(parse_script("128").unwrap(), vec![0x02, 0x80, 0x00]);
        assert_eq!(parse_script("-128").unwrap(), vec![0x02, 0x80, 0x80]);
        assert_eq!(
            parse_script("4294967295").unwrap(),
            hex::decode("05ffffffff00").unwrap()
        );
        assert_eq!(
            parse_script("-4294967295").unwrap(),
            hex::decode("05ffffffff80").unwrap()
        );
        assert!(parse_script("4294967296").is_err());
        assert!(parse_script("99999999999999999999").is_err());
    }

    #[test]
    fn hex_strings_and_names() {
        assert_eq!(
            parse_script("0x4c 0x01 0x07").unwrap(),
            vec![0x4c, 0x01, 0x07]
        );
        assert_eq!(parse_script("0xABcd").unwrap(), vec![0xab, 0xcd]);
        assert!(parse_script("0x").is_err());
        assert!(parse_script("0xabc").is_err());
        assert_eq!(parse_script("''").unwrap(), vec![0x00]);
        assert_eq!(parse_script("'Az'").unwrap(), vec![0x02, b'A', b'z']);
        assert_eq!(parse_script("DUP OP_HASH160").unwrap(), vec![0x76, 0xa9]);
        assert_eq!(parse_script("RESERVED NOP10").unwrap(), vec![0x50, 0xb9]);
        assert_eq!(parse_script("CHECKLOCKTIMEVERIFY").unwrap(), vec![0xb1]);
        assert!(parse_script("NOP2").is_err());
        assert!(parse_script("OP_CHECKSIGADD").is_err());
        assert!(parse_script("TRUE").is_err());
        assert_eq!(parse_script(" \t1\n\n2  ").unwrap(), vec![0x51, 0x52]);
    }

    /// Every script text in the vector files (script_tests.json scriptSigs, scriptPubKeys and
    /// `#SCRIPT#` witness elements; tx_valid.json and tx_invalid.json prevout scripts).
    fn vector_script_texts() -> Vec<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/core");
        let read = |name: &str| -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
        };
        let mut out = Vec::new();
        for row in read("script_tests.json").as_array().unwrap() {
            let cells = row.as_array().unwrap();
            if cells.len() == 1 {
                continue;
            }
            let mut pos = 0;
            if let Some(w) = cells[0].as_array() {
                for el in &w[..w.len() - 1] {
                    if let Some(asm) = el.as_str().and_then(|s| s.strip_prefix("#SCRIPT#")) {
                        out.push(asm.to_string());
                    }
                }
                pos = 1;
            }
            out.push(cells[pos].as_str().unwrap().to_string());
            let spk = cells[pos + 1].as_str().unwrap();
            if spk != "0x51 0x20 #TAPROOTOUTPUT#" {
                out.push(spk.to_string());
            }
        }
        for name in ["tx_valid.json", "tx_invalid.json"] {
            for row in read(name).as_array().unwrap() {
                if let Some(inputs) = row[0].as_array() {
                    for input in inputs {
                        out.push(input[2].as_str().unwrap().to_string());
                    }
                }
            }
        }
        out
    }

    /// Compares this port with Bitcoin Core's own `ParseScript` on every script text of the
    /// vectors. Core's `bitcoin-tx` parses the script of `outscript=0:<script>` with
    /// `ParseScript`, so the official binary serves as the reference. Opt-in:
    ///
    /// `BCS_BITCOIN_TX=/path/to/bitcoin-tx cargo test -p conformance-runner -- --ignored`
    ///
    /// Texts that bitcoin-tx cannot take (they contain `:` or parse to more than 10000 bytes, its
    /// output size limit) are skipped and counted.
    #[test]
    #[ignore]
    fn matches_core_parse_script() {
        let bitcoin_tx =
            std::env::var("BCS_BITCOIN_TX").expect("set BCS_BITCOIN_TX to the bitcoin-tx binary");
        let mut texts = vector_script_texts();
        texts.sort();
        texts.dedup();
        let mut skipped = 0;
        let mut usable = Vec::new();
        for t in texts {
            let ours = parse_script(&t).unwrap_or_else(|e| panic!("{t:?}: {e}"));
            if t.contains(':') || ours.len() > 10_000 {
                skipped += 1;
            } else {
                usable.push((t, ours));
            }
        }
        for chunk in usable.chunks(200) {
            let mut cmd = std::process::Command::new(&bitcoin_tx);
            cmd.arg("-json").arg("-create");
            for (t, _) in chunk {
                cmd.arg(format!("outscript=0:{t}"));
            }
            let out = cmd.output().expect("run bitcoin-tx");
            assert!(
                out.status.success(),
                "bitcoin-tx failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            let vout = v["vout"].as_array().unwrap();
            assert_eq!(vout.len(), chunk.len());
            for ((t, ours), o) in chunk.iter().zip(vout) {
                let core = o["scriptPubKey"]["hex"].as_str().unwrap();
                assert_eq!(hex::encode(ours), core, "ParseScript({t:?})");
            }
        }
        eprintln!(
            "compared {} script texts with Core's ParseScript, skipped {skipped}",
            usable.len()
        );
        assert!(skipped < 10, "too many texts could not be compared");
    }

    #[test]
    fn push_sizes() {
        let mut s = Vec::new();
        push_data(&mut s, &[7u8; 75]);
        assert_eq!(&s[..1], &[75]);
        let mut s = Vec::new();
        push_data(&mut s, &[7u8; 76]);
        assert_eq!(&s[..2], &[0x4c, 76]);
        let mut s = Vec::new();
        push_data(&mut s, &[7u8; 256]);
        assert_eq!(&s[..3], &[0x4d, 0x00, 0x01]);
        let mut s = Vec::new();
        push_data(&mut s, &[7u8; 0x10000]);
        assert_eq!(&s[..5], &[0x4e, 0x00, 0x00, 0x01, 0x00]);
    }
}
