# 01. Conventions

This chapter fixes the vocabulary, number formats and helper definitions used by every later chapter.

## 1.1 Source references

Normative definitions name the Bitcoin Core v32.1 function they mirror, in the form

> Core: `CheckTransaction`, `src/consensus/tx_check.cpp`

Paths are relative to the root of the Bitcoin Core source tree at the pinned commit. The reference is behavioural: the Rust code reproduces what the C++ code does, including its order of checks wherever the order is observable (for example in which error is reported first).

## 1.2 Integers

Consensus code works on fixed-width integers. The reference uses the same widths as Bitcoin Core, and the width matters: several historical consensus bugs in other implementations came from a value being read as signed where Bitcoin Core reads it as unsigned, or the reverse.

| Quantity | Width | Signedness | Notes |
|---|---|---|---|
| Transaction `version` | 32 bits | **unsigned** | Comparisons such as "version >= 2" treat `0xffffffff` as large, not as -1 (chapters 05 and 08). |
| Block header `version` | 32 bits | **signed** | "version < 2" treats `0x80000000` and above as negative (chapter 10). |
| `lock_time`, `sequence`, output index | 32 bits | unsigned | |
| Amounts (satoshis) | 64 bits | signed | Negative values are representable on the wire and must be rejected by the rules, not by the parser. |
| Block height | 32 bits | signed | Always non-negative in practice. |
| Header `time`, `bits`, `nonce` | 32 bits | unsigned | |
| Times computed from headers (median time past, lock time comparisons) | 64 bits | signed | |

Unless stated otherwise, arithmetic in this specification never overflows: the reference is compiled with overflow checks enabled, so an unintended overflow aborts instead of silently wrapping. Where Bitcoin Core relies on modular arithmetic (for example 256-bit multiplication in difficulty adjustment), the reference says so and uses explicit wrapping operations.

All multi-byte integers are serialized **little-endian** unless a definition says otherwise.

## 1.3 Byte strings and hexadecimal

`Vec<u8>` and `&[u8]` denote byte strings. Hexadecimal text in this document and in test vectors is written two digits per byte, most significant nibble first.

```rust
/// Lowercase hexadecimal encoding of a byte string.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes hexadecimal text (either case). Returns `None` for odd length or a non-hex character.
pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}
```

## 1.4 Hashes and display order

Hash functions produce byte strings. Bitcoin treats 32-byte hashes such as transaction ids and block hashes as 256-bit little-endian integers: the first byte of the hash output is the least significant byte. Bitcoin Core *displays* such values most significant byte first, which is the reverse of the order in which the hash function produced them. Both orders appear in practice:

- **raw order**: the bytes as the hash function output them, and as they are serialized inside transactions and blocks;
- **display order**: reversed, as printed by Bitcoin Core (the mainnet genesis block is displayed as `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`).

Every 32-byte hash in the reference is held in raw order. Conversion happens only at the edges (test vectors, user interfaces).

```rust
/// A 32-byte hash in raw order.
pub type Hash256 = [u8; 32];

/// The all-zero hash. Used, for example, as the previous-output hash of a coinbase input.
pub const ZERO_HASH: Hash256 = [0u8; 32];

/// Display order (Bitcoin Core's `uint256::GetHex`): reversed bytes, lowercase hex.
pub fn hash_to_display(hash: &Hash256) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    hex_encode(&reversed)
}

/// Parses a display-order hash back to raw order.
pub fn hash_from_display(text: &str) -> Option<Hash256> {
    let bytes = hex_decode(text)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    for i in 0..32 {
        hash[i] = bytes[31 - i];
    }
    Some(hash)
}
```

## 1.5 Failures

Validation functions return either success or a failure. A failure carries a *reason* string and a *kind*.

The reason is the identifier Bitcoin Core uses for the same failure (`bad-txns-vin-empty`, `bad-cb-amount`, ...). Reasons make disagreements between implementations easy to diagnose. Matching them exactly is a SHOULD, not a MUST: two conforming implementations may check rules in a different order and therefore report different reasons for a block that breaks two rules at once. The reference reproduces Bitcoin Core's order, so it reports the same reason Bitcoin Core would.

The kind is a MUST, because it decides what a node remembers:

- **`Invalid`**: the object violates a consensus rule. Its hash (and, for blocks, every descendant) can be remembered as invalid forever, because the hash commits to everything that was checked.
- **`Mutated`**: the data received does not match what the block header commits to. Block hashes commit to the header only, and the header commits to transactions through the merkle root and the witness commitment; a peer can therefore send a corrupted body for a perfectly valid header. Nothing may be remembered about the block hash, or a single malicious peer could make the node reject the real block forever. Chapter 11 lists exactly which failures are `Mutated`.
- **`Temporary`**: the object is rejected only because of the current time (a block timestamp too far in the future). Nothing may be remembered.

```rust
/// What a node may remember about a failed block or header (chapter 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Breaks a consensus rule. The hash, and every descendant, is invalid forever.
    Invalid,
    /// The body does not match the header's commitments. Nothing about the hash may be recorded.
    Mutated,
    /// Rejected only because of the current time. Nothing may be recorded.
    Temporary,
}

/// A validation failure: what kind it is, and Bitcoin Core's identifier for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub reason: String,
}

pub fn invalid(reason: &str) -> Failure {
    Failure { kind: FailureKind::Invalid, reason: reason.to_string() }
}

pub fn mutated(reason: &str) -> Failure {
    Failure { kind: FailureKind::Mutated, reason: reason.to_string() }
}

pub fn temporary(reason: &str) -> Failure {
    Failure { kind: FailureKind::Temporary, reason: reason.to_string() }
}
```

## 1.6 Fail closed

Every check in this specification has the same shape: the object is valid only if the check positively succeeds. When information needed for a check is missing (an input whose coin cannot be found, a block whose ancestor is unknown, a height that cannot be determined), the result is failure, never success and never a default value such as zero. Several real consensus bugs came from code that treated a missing value as 0 and thereby accepted a transaction it could not actually check. Implementations MUST fail closed in the same way.

## 1.7 Constants used throughout

```rust
/// Number of satoshis in one bitcoin.
pub const COIN: i64 = 100_000_000;

/// Upper bound for any single amount and for any sum of amounts. Core: `MAX_MONEY`, `src/consensus/amount.h`.
pub const MAX_MONEY: i64 = 21_000_000 * COIN;

/// Core: `MoneyRange`, `src/consensus/amount.h`.
pub fn money_range(value: i64) -> bool {
    value >= 0 && value <= MAX_MONEY
}
```
