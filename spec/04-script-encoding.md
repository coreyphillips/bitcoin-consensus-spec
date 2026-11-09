# 04. Script encoding and numbers

Bitcoin Script is a stack language. A script is a byte string holding a sequence of operations. This chapter defines how the bytes are split into operations, how numbers and booleans are represented on the stack, and the script templates that consensus recognizes by their exact bytes. Chapter 05 defines what each operation does.

## 4.1 Opcodes

Every operation starts with one opcode byte. Opcodes `0x01` to `0x4b` push the next that many bytes; `OP_PUSHDATA1`, `OP_PUSHDATA2` and `OP_PUSHDATA4` push data whose length follows in a 1, 2 or 4 byte little-endian field. All other bytes are single-byte opcodes. The names below are Bitcoin Core's (`src/script/script.h`).

```rust
pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;
pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;
pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f;
pub const OP_LEFT: u8 = 0x80;
pub const OP_RIGHT: u8 = 0x81;
pub const OP_SIZE: u8 = 0x82;
pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;
pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;
pub const OP_RIPEMD160: u8 = 0xa6;
pub const OP_SHA1: u8 = 0xa7;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
pub const OP_NOP1: u8 = 0xb0;
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;
/// Only defined in tapscript (BIP342). In other script versions 0xba is an unknown opcode.
pub const OP_CHECKSIGADD: u8 = 0xba;
pub const OP_INVALIDOPCODE: u8 = 0xff;
```

`OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` were `OP_NOP2` and `OP_NOP3` before BIP65 and BIP112, and still behave as no-ops when their script flags are not set (chapter 05).

## 4.2 Script limits

```rust
/// Largest data push, and largest stack element. Core: `MAX_SCRIPT_ELEMENT_SIZE`.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Largest number of non-push operations per script (not in tapscript). Core: `MAX_OPS_PER_SCRIPT`.
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// Largest number of public keys in CHECKMULTISIG. Core: `MAX_PUBKEYS_PER_MULTISIG`.
pub const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;
/// Largest script that can be executed (not in tapscript). Core: `MAX_SCRIPT_SIZE`.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// Largest combined size of the main stack and the alternate stack. Core: `MAX_STACK_SIZE`.
pub const MAX_STACK_SIZE: usize = 1000;
/// Lock times below this are block heights, at or above it Unix times. Core: `LOCKTIME_THRESHOLD`.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;
```

## 4.3 Splitting a script into operations

`get_op` reads one operation starting at a byte offset and advances the offset. It fails when a push's length field or data runs past the end of the script. On failure the offset has still advanced past the bytes that were read (the opcode and any length bytes), exactly as Bitcoin Core's iterator does; chapter 06 depends on that position in one corner case. (Core: `GetScriptOp`, `src/script/script.cpp`.)

A script that cannot be split completely is *malformed*. Malformed scripts can sit in outputs, since nothing checks an output script until it is spent, but executing one always fails once execution reaches the bad bytes (chapter 05).

```rust
/// One parsed operation: the opcode, and for pushes the pushed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptOp<'a> {
    pub opcode: u8,
    pub data: &'a [u8],
}

/// Reads the operation at `*pos`. Returns `None` if the script is malformed at this point.
/// Core: `GetScriptOp`.
pub fn get_op<'a>(script: &'a [u8], pos: &mut usize) -> Option<ScriptOp<'a>> {
    if *pos >= script.len() {
        return None;
    }
    let opcode = script[*pos];
    *pos += 1;
    if opcode > OP_PUSHDATA4 {
        return Some(ScriptOp { opcode, data: &[] });
    }
    let size = if opcode < OP_PUSHDATA1 {
        opcode as usize
    } else if opcode == OP_PUSHDATA1 {
        if script.len() - *pos < 1 {
            return None;
        }
        let size = script[*pos] as usize;
        *pos += 1;
        size
    } else if opcode == OP_PUSHDATA2 {
        if script.len() - *pos < 2 {
            return None;
        }
        let size = u16::from_le_bytes([script[*pos], script[*pos + 1]]) as usize;
        *pos += 2;
        size
    } else {
        if script.len() - *pos < 4 {
            return None;
        }
        let size = u32::from_le_bytes([script[*pos], script[*pos + 1], script[*pos + 2], script[*pos + 3]]) as usize;
        *pos += 4;
        size
    };
    if script.len() - *pos < size {
        return None;
    }
    let data = &script[*pos..*pos + size];
    *pos += size;
    Some(ScriptOp { opcode, data })
}
```

## 4.4 Encoding pushes

Several rules compare scripts with a *canonical push*: the encoding `CScript() << data` that Bitcoin Core's script builder produces. It uses a direct push for fewer than 76 bytes, `OP_PUSHDATA1` up to 255 bytes, `OP_PUSHDATA2` up to 65535 bytes, and `OP_PUSHDATA4` otherwise. It never turns a one-byte value into `OP_1`..`OP_16`, and the empty string becomes the single byte `0x00` (`OP_0`). (Core: `CScript::operator<<`, `AppendDataSize`.)

Numbers are pushed differently (`CScript() << n`): `0` as `OP_0`, `-1` as `OP_1NEGATE`, `1` to `16` as `OP_1` to `OP_16`, anything else as a canonical push of its script number encoding (section 4.5). (Core: `CScript::push_int64`.)

```rust
/// `CScript() << data`.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    let size = data.len();
    if size < OP_PUSHDATA1 as usize {
        out.push(size as u8);
    } else if size <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(size as u8);
    } else if size <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(size as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend_from_slice(&(size as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

/// `CScript() << n` for an integer.
pub fn push_int(n: i64) -> Vec<u8> {
    if n == -1 || (1..=16).contains(&n) {
        vec![(n + (OP_1 as i64 - 1)) as u8]
    } else if n == 0 {
        vec![OP_0]
    } else {
        push_data(&encode_script_num(n))
    }
}

/// `OP_1`..`OP_16` to 1..16 and `OP_0` to 0. Core: `CScript::DecodeOP_N`.
pub fn decode_op_n(opcode: u8) -> i64 {
    if opcode == OP_0 {
        0
    } else {
        assert!((OP_1..=OP_16).contains(&opcode));
        (opcode - (OP_1 - 1)) as i64
    }
}
```

## 4.5 Numbers

Stack elements are byte strings. Arithmetic opcodes interpret them as *script numbers*: little-endian magnitude with the sign in the most significant bit of the last byte. The empty string is zero. `0x80` and `0x00 0x80` are "negative zero", which equals zero.

Arithmetic inputs are limited to 4 bytes (so the range is `-(2^31 - 1)` to `2^31 - 1`). Results are computed in 64 bits and may exceed that range; such a result can be pushed and compared byte-wise, but using it as an input to further arithmetic fails. `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` accept 5-byte operands, since lock times go up to `2^32 - 1`.

Non-minimal encodings (such as `0x01 0x00` for 1) are accepted by consensus. Requiring minimal encodings (`MINIMALDATA`) is relay policy; this specification carries the `require_minimal` parameter only so that the definition matches Bitcoin Core's function, and consensus always passes `false`.

Decoding fails when the input is longer than the allowed size; in the interpreter that failure aborts the script with the error `SCRIPTNUM` (chapter 05).

```rust
/// Default largest script number input, in bytes. Core: `CScriptNum::nDefaultMaxNumSize`.
pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

/// Why a script number could not be decoded. Core: `scriptnum_error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptNumError {
    Overflow,
    NonMinimal,
}

/// Decodes a script number. Core: `CScriptNum::CScriptNum(const std::vector<unsigned char>&, bool, size_t)`.
pub fn decode_script_num(bytes: &[u8], require_minimal: bool, max_size: usize) -> Result<i64, ScriptNumError> {
    if bytes.len() > max_size {
        return Err(ScriptNumError::Overflow);
    }
    if require_minimal && !bytes.is_empty() {
        let last = bytes[bytes.len() - 1];
        if (last & 0x7f) == 0 && (bytes.len() <= 1 || (bytes[bytes.len() - 2] & 0x80) == 0) {
            return Err(ScriptNumError::NonMinimal);
        }
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut result: i64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }
    let last = bytes[bytes.len() - 1];
    if (last & 0x80) != 0 {
        // Clear the sign bit (`!` on an integer is bitwise NOT).
        let mask = !(0x80i64 << (8 * (bytes.len() - 1)));
        return Ok(-(result & mask));
    }
    Ok(result)
}

/// Encodes a script number minimally. Core: `CScriptNum::serialize`.
pub fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut out = Vec::new();
    while magnitude != 0 {
        out.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    let last = out.len() - 1;
    if (out[last] & 0x80) != 0 {
        out.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        out[last] |= 0x80;
    }
    out
}
```

`decode_script_num` is only ever called with `max_size` of 4 or 5, so the shift never exceeds 32 bits and the result never overflows.

## 4.6 Booleans

A stack element is *false* if every byte is zero, or if every byte is zero except the last, which is `0x80` (negative zero). Everything else, including non-minimal encodings of non-zero numbers, is *true*. The interpreter pushes the empty string for false and `0x01` for true. (Core: `CastToBool`, `src/script/interpreter.cpp`.)

```rust
/// Core: `CastToBool`.
pub fn cast_to_bool(element: &[u8]) -> bool {
    for (i, &byte) in element.iter().enumerate() {
        if byte != 0 {
            // Negative zero is false.
            return !(i == element.len() - 1 && byte == 0x80);
        }
    }
    false
}
```

## 4.7 Script templates recognized by consensus

Consensus treats a few output scripts specially. Each is recognized by an exact byte pattern, never by parsing.

- **Pay-to-script-hash** (BIP16): exactly 23 bytes, `OP_HASH160 0x14 <20 bytes> OP_EQUAL`. (Core: `CScript::IsPayToScriptHash`.)
- **Witness program** (BIP141): 4 to 42 bytes; the first byte is `OP_0` or `OP_1`..`OP_16` (the *version*, 0 to 16), and the second byte is a direct push of all remaining bytes (the *program*, so 2 to 40 bytes). (Core: `CScript::IsWitnessProgram`.)
- **Pay-to-anchor**: witness version 1 with the two-byte program `4e 73`. (Core: `CScript::IsPayToAnchor`.)
- **Unspendable**: a script that starts with `OP_RETURN`, or is longer than `MAX_SCRIPT_SIZE`. Such outputs can never be spent, and they are never added to the set of unspent outputs (chapter 10). (Core: `CScript::IsUnspendable`.)

```rust
/// Core: `CScript::IsPayToScriptHash`.
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
}

/// Returns (version, program) for a witness program. Core: `CScript::IsWitnessProgram`.
pub fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    if script[0] != OP_0 && (script[0] < OP_1 || script[0] > OP_16) {
        return None;
    }
    if script[1] as usize + 2 == script.len() {
        return Some((decode_op_n(script[0]) as u8, &script[2..]));
    }
    None
}

/// Core: `CScript::IsPayToAnchor(int, const std::vector<unsigned char>&)`.
pub fn is_pay_to_anchor(version: u8, program: &[u8]) -> bool {
    version == 1 && program == [0x4e, 0x73]
}

/// Core: `CScript::IsUnspendable`.
pub fn is_unspendable(script: &[u8]) -> bool {
    (!script.is_empty() && script[0] == OP_RETURN) || script.len() > MAX_SCRIPT_SIZE
}

/// True if every operation is a push or `OP_1NEGATE`, `OP_RESERVED`, `OP_1`..`OP_16`, and the script
/// parses completely. `OP_RESERVED` counts as a push here; executing it fails anyway.
/// Core: `CScript::IsPushOnly`.
pub fn is_push_only(script: &[u8]) -> bool {
    let mut pos = 0;
    while pos < script.len() {
        match get_op(script, &mut pos) {
            Some(op) if op.opcode <= OP_16 => {}
            _ => return false,
        }
    }
    true
}
```

## 4.8 OP_SUCCESS opcodes

BIP342 redefines a set of unused or disabled opcodes in tapscript as `OP_SUCCESSx`: the mere presence of one makes a tapscript succeed (chapter 05). The set is 80, 98, 126 to 129, 131 to 134, 137, 138, 141, 142, 149 to 153, and 187 to 254. (Core: `IsOpSuccess`, `src/script/script.cpp`.)

```rust
/// Core: `IsOpSuccess`.
pub fn is_op_success(opcode: u8) -> bool {
    opcode == 80
        || opcode == 98
        || (126..=129).contains(&opcode)
        || (131..=134).contains(&opcode)
        || (137..=138).contains(&opcode)
        || (141..=142).contains(&opcode)
        || (149..=153).contains(&opcode)
        || (187..=254).contains(&opcode)
}
```

## 4.9 Counting signature operations

Blocks limit the number of signature operations ("sigops") they contain (chapter 10). Counting is done statically on script bytes, with two modes:

- **Legacy counting** (`accurate = false`): every `OP_CHECKSIG` or `OP_CHECKSIGVERIFY` counts 1, every `OP_CHECKMULTISIG` or `OP_CHECKMULTISIGVERIFY` counts 20.
- **Accurate counting** (`accurate = true`): the same, except that a multisig opcode immediately preceded by `OP_1`..`OP_16` counts that number instead of 20.

Counting stops silently at the first malformed operation and returns the count so far. Data pushes are skipped, so opcode bytes inside pushed data never count. (Core: `CScript::GetSigOpCount(bool)`.)

For a pay-to-script-hash output, the sigops of the redeem script are counted accurately. The redeem script is the data of the *last* operation in the `script_sig`; if the `script_sig` is malformed or contains any operation above `OP_16`, the count is 0. If the last operation is `OP_0`, `OP_1NEGATE` or `OP_1`..`OP_16` (no data), the redeem script is empty and counts 0. (Core: `CScript::GetSigOpCount(const CScript&)`.)

```rust
/// Core: `CScript::GetSigOpCount(bool)`.
pub fn sig_op_count(script: &[u8], accurate: bool) -> u64 {
    let mut count = 0u64;
    let mut pos = 0;
    let mut last_opcode = OP_INVALIDOPCODE;
    while pos < script.len() {
        let op = match get_op(script, &mut pos) {
            Some(op) => op,
            None => break,
        };
        if op.opcode == OP_CHECKSIG || op.opcode == OP_CHECKSIGVERIFY {
            count += 1;
        } else if op.opcode == OP_CHECKMULTISIG || op.opcode == OP_CHECKMULTISIGVERIFY {
            if accurate && (OP_1..=OP_16).contains(&last_opcode) {
                count += decode_op_n(last_opcode) as u64;
            } else {
                count += MAX_PUBKEYS_PER_MULTISIG as u64;
            }
        }
        last_opcode = op.opcode;
    }
    count
}

/// Sigops of a pay-to-script-hash redeem script given the spending script_sig; for any other
/// script_pubkey, its own accurate count. Core: `CScript::GetSigOpCount(const CScript& scriptSig)`.
pub fn p2sh_sig_op_count(script_pubkey: &[u8], script_sig: &[u8]) -> u64 {
    if !is_p2sh(script_pubkey) {
        return sig_op_count(script_pubkey, true);
    }
    let mut pos = 0;
    let mut last_data: &[u8] = &[];
    while pos < script_sig.len() {
        let op = match get_op(script_sig, &mut pos) {
            Some(op) => op,
            None => return 0,
        };
        if op.opcode > OP_16 {
            return 0;
        }
        last_data = op.data;
    }
    sig_op_count(last_data, true)
}
```

## 4.10 Known-answer tests

```rust
#[cfg(test)]
mod script_encoding_tests {
    use super::*;

    #[test]
    fn script_numbers() {
        for (value, bytes) in [(0i64, ""), (1, "01"), (-1, "81"), (127, "7f"), (128, "8000"), (-128, "8080"), (255, "ff00"), (-255, "ff80")] {
            assert_eq!(hex_encode(&encode_script_num(value)), bytes);
            assert_eq!(decode_script_num(&hex_decode(bytes).unwrap(), true, 4), Ok(value));
        }
        assert_eq!(decode_script_num(&[0x01, 0x00], false, 4), Ok(1));
        assert_eq!(decode_script_num(&[0x01, 0x00], true, 4), Err(ScriptNumError::NonMinimal));
        assert_eq!(decode_script_num(&[0, 0, 0, 0, 1], false, 4), Err(ScriptNumError::Overflow));
        assert_eq!(decode_script_num(&[0x80], false, 4), Ok(0));
        assert!(!cast_to_bool(&[0x00, 0x80]));
        assert!(cast_to_bool(&[0x80, 0x00]));
    }

    #[test]
    fn pushes() {
        assert_eq!(push_data(&[]), vec![0x00]);
        assert_eq!(push_int(16), vec![OP_16]);
        assert_eq!(push_int(17), vec![0x01, 0x11]);
        assert_eq!(push_int(-2), vec![0x01, 0x82]);
        assert_eq!(push_data(&[0xaa; 76])[..2], [OP_PUSHDATA1, 76]);
    }
}
```
