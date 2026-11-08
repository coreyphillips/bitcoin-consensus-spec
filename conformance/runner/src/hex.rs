//! Hexadecimal helpers.

/// Lowercase hex, as the protocol requires.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

/// Decodes hex in either case (vector files are not always lowercase). Rejects odd lengths.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string {s:?}"));
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?} in {s:?}", c as char)),
    };
    bytes
        .chunks(2)
        .map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

/// Core's `TryParseHex` (src/util/strencodings.h): hex digits in either case, with whitespace
/// allowed between bytes. `ParseHex` is the same with an empty result on failure.
pub fn try_parse_hex(s: &str) -> Option<Vec<u8>> {
    let is_space = |c: u8| matches!(c, b' ' | b'\x0c' | b'\n' | b'\r' | b'\t' | b'\x0b');
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        if is_space(b[i]) {
            i += 1;
            continue;
        }
        let c1 = digit(b[i]);
        i += 1;
        if i == b.len() {
            return None;
        }
        let c2 = digit(b[i]);
        i += 1;
        out.push((c1? << 4) | c2?);
    }
    Some(out)
}

/// Decodes exactly 32 bytes.
pub fn decode32(s: &str) -> Result<[u8; 32], String> {
    decode(s)?
        .try_into()
        .map_err(|_| format!("expected 32 bytes of hex, got {s:?}"))
}

/// The hex string of `bytes` in reverse order (display order of hashes).
pub fn encode_reversed(bytes: &[u8]) -> String {
    let mut v = bytes.to_vec();
    v.reverse();
    encode(&v)
}
