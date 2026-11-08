# 09. Proof of work

Every block header commits to a *target*, encoded in its `bits` field, and is valid only if its hash, read as a number, does not exceed that target. The target itself is not chosen by the miner: it is determined by the chain (difficulty adjustment). Chain selection (chapter 11) prefers the chain with the most cumulative *work*, computed from the targets.

## 9.1 Compact target encoding

`bits` is a floating-point-like encoding of a 256-bit number: the high byte is a size `s` in bytes, the low 23 bits are a mantissa `m`, and bit 23 is a sign bit. The value is `m * 256^(s - 3)` (for `s < 3`, `m` is shifted right instead). Decoding reports two error conditions (Core: `arith_uint256::SetCompact`, `src/arith_uint256.cpp`):

- *negative*: the sign bit is set and the mantissa (after the shift for small sizes) is non-zero;
- *overflow*: the mantissa is non-zero and the value would not fit in 256 bits (`s > 34`, or `s > 33` with `m > 0xff`, or `s > 32` with `m > 0xffff`).

Encoding (Core: `GetCompact`) picks the smallest size that holds the value, and if the mantissa's top bit would be set, shifts it down one byte and increases the size, so the encoding is never negative. Decoding then encoding is not the identity: non-canonical encodings exist. Consensus compares `bits` fields as raw 32-bit values (chapter 10 requires `bits` to equal the computed next target's encoding exactly), so the canonical encoding produced by `target_to_compact` matters.

```rust
/// Decodes compact bits. Returns (value, negative, overflow). Core: `arith_uint256::SetCompact`.
pub fn compact_to_target(bits: u32) -> (U256, bool, bool) {
    let size = bits >> 24;
    let mut word = bits & 0x007f_ffff;
    let value = if size <= 3 {
        word >>= 8 * (3 - size);
        U256::from_u64(word as u64)
    } else {
        U256::from_u64(word as u64).shl(8 * (size - 3))
    };
    let negative = word != 0 && bits & 0x0080_0000 != 0;
    let overflow = word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    (value, negative, overflow)
}

/// Encodes a target in canonical compact form. Core: `arith_uint256::GetCompact` with fNegative false.
pub fn target_to_compact(target: U256) -> u32 {
    let mut size = (target.bits() + 7) / 8;
    let mut compact: u32 = if size <= 3 {
        (target.low_u64() << (8 * (3 - size))) as u32
    } else {
        target.shr(8 * (size - 3)).low_u64() as u32
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (size << 24)
}
```

## 9.2 Checking proof of work

A header's proof of work is valid if its `bits` decode to a target that is not negative, not zero, does not overflow and does not exceed the network's *proof-of-work limit*, and the block hash (raw order, read as a little-endian number) is at most the target. (Core: `CheckProofOfWork`, `DeriveTarget`, `src/pow.cpp`.) This check uses only the header; whether `bits` is the *right* target for its position in the chain is a separate, contextual rule (chapter 10).

```rust
/// Core: `DeriveTarget`.
pub fn derive_target(bits: u32, pow_limit: U256) -> Option<U256> {
    let (target, negative, overflow) = compact_to_target(bits);
    if negative || target.is_zero() || overflow || target > pow_limit {
        return None;
    }
    Some(target)
}

/// Core: `CheckProofOfWorkImpl`.
pub fn check_proof_of_work(hash: &Hash256, bits: u32, pow_limit: U256) -> bool {
    match derive_target(bits, pow_limit) {
        Some(target) => U256::from_le_bytes(hash) <= target,
        None => false,
    }
}
```

## 9.3 Work

The *work* of a block is the expected number of hashes needed to find it: `floor(2^256 / (target + 1))`, or 0 if `bits` is negative, overflows or is zero. A chain's *chain work* is the sum over its blocks, genesis included. (Core: `GetBitsProof`, `src/chain.cpp`.) Since 2^256 does not fit in 256 bits, it is computed as `(~target / (target + 1)) + 1`.

```rust
/// Core: `GetBitsProof`.
pub fn block_proof(bits: u32) -> U256 {
    let (target, negative, overflow) = compact_to_target(bits);
    if negative || overflow || target.is_zero() {
        return U256::ZERO;
    }
    let (quotient, _) = target.not().div_rem(target.wrapping_add(U256::ONE));
    quotient.wrapping_add(U256::ONE)
}
```

## 9.4 Median time past

The *median time past* (MTP) of a block is the median of the timestamps of that block and its up to 10 predecessors (11 blocks; fewer near genesis). The timestamps are sorted and the element at index `count / 2` is taken (for an even count, the upper median). (Core: `CBlockIndex::GetMedianTimePast`, `src/chain.h`.)

```rust
/// Number of blocks in the median time past window. Core: `CBlockIndex::nMedianTimeSpan`.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// `times` are the timestamps of a block and its predecessors, newest first (at most 11 are used).
pub fn median_time_past(times: &[i64]) -> i64 {
    let mut window: Vec<i64> = times.iter().take(MEDIAN_TIME_SPAN).copied().collect();
    window.sort();
    window[window.len() / 2]
}
```

## 9.5 Difficulty adjustment

The target changes only at heights that are multiples of the *adjustment interval* (`target_timespan / target_spacing`, 2016 blocks on every network except regtest, where it is 144). The required `bits` for a block at height h with parent P is (Core: `GetNextWorkRequired`, `CalculateNextWorkRequired`, `src/pow.cpp`):

**If h is not a multiple of the interval:**

- Normally, P's `bits`.
- On networks with `pow_allow_min_difficulty_blocks` (testnet3, testnet4, regtest): if the new block's timestamp is more than twice the target spacing (20 minutes) after P's timestamp, the proof-of-work limit's encoding. Otherwise, walk back from P while the block is not at a multiple of the interval, has a parent, and has `bits` equal to the limit's encoding; return the `bits` of the block where the walk stops. This "20-minute rule" depends on the new block's timestamp, so the same parent can have two different required targets.

**If h is a multiple of the interval:**

1. With `pow_no_retargeting` (regtest), P's `bits`.
2. Otherwise let F be P's ancestor at height `h - interval` (the first block of the period just ending; the period spans `interval - 1` block intervals, an off-by-one that is part of consensus). The *actual timespan* is `time(P) - time(F)`, clamped to `[target_timespan / 4, target_timespan * 4]`.
3. The new target is `old_target * actual_timespan / target_timespan` (integer division), using 256-bit arithmetic, where `old_target` is decoded from P's `bits`, except under BIP94 (testnet4) where it is decoded from F's `bits`, so that a minimum-difficulty block at the end of a period cannot drag the next period down.
4. If the result exceeds the proof-of-work limit, it is the limit. The required `bits` is its canonical compact encoding.

The multiplication cannot overflow on any defined network: every network that retargets has a proof-of-work limit below 2^224 and timespans below 2^23, so the product stays below 2^247 (regtest, whose limit is close to 2^255, never retargets).

```rust
/// Core: `GetNextWorkRequired`. `parent` is P; `ancestor(height)` returns the header of P's ancestor
/// at that height; `new_block_time` is the timestamp of the block being checked.
pub fn next_work_required(
    params: &ConsensusParams,
    parent_height: i32,
    parent: &BlockHeader,
    ancestor: &dyn Fn(i32) -> BlockHeader,
    new_block_time: u32,
) -> u32 {
    let pow_limit_bits = target_to_compact(params.pow_limit);
    let interval = params.difficulty_adjustment_interval();
    let height = parent_height as i64 + 1;
    if height % interval != 0 {
        if params.pow_allow_min_difficulty_blocks {
            if new_block_time as i64 > parent.time as i64 + params.pow_target_spacing * 2 {
                return pow_limit_bits;
            }
            let mut index_height = parent_height;
            let mut header = *parent;
            while index_height > 0 && index_height as i64 % interval != 0 && header.bits == pow_limit_bits {
                index_height -= 1;
                header = ancestor(index_height);
            }
            return header.bits;
        }
        return parent.bits;
    }
    let first_height = parent_height - (interval as i32 - 1);
    assert!(first_height >= 0);
    let first = ancestor(first_height);
    calculate_next_work_required(params, parent, &first)
}

/// Core: `CalculateNextWorkRequired`. `first` is the first block of the period ending at `last`.
pub fn calculate_next_work_required(params: &ConsensusParams, last: &BlockHeader, first: &BlockHeader) -> u32 {
    if params.pow_no_retargeting {
        return last.bits;
    }
    let mut actual_timespan = last.time as i64 - first.time as i64;
    if actual_timespan < params.pow_target_timespan / 4 {
        actual_timespan = params.pow_target_timespan / 4;
    }
    if actual_timespan > params.pow_target_timespan * 4 {
        actual_timespan = params.pow_target_timespan * 4;
    }
    let base_bits = if params.enforce_bip94 { first.bits } else { last.bits };
    let (base, _, _) = compact_to_target(base_bits);
    let mut new_target = base.wrapping_mul(U256::from_u64(actual_timespan as u64));
    new_target = new_target.div_rem(U256::from_u64(params.pow_target_timespan as u64)).0;
    if new_target > params.pow_limit {
        new_target = params.pow_limit;
    }
    target_to_compact(new_target)
}
```

`ConsensusParams` and `difficulty_adjustment_interval` are defined with the network parameters in chapter 12. The walk-back loop above stops at a block whose height is a multiple of the interval (including genesis at height 0), exactly like Bitcoin Core's loop, which stops when it reaches such a block or a block without a parent.

## 9.6 Testnet4 timewarp rule (BIP94)

On networks with `enforce_bip94` (testnet4; regtest with the `bip94` test option), the first block of every difficulty period (height a multiple of the interval) must not have a timestamp more than `MAX_TIMEWARP = 600` seconds earlier than its parent's. The rule is a contextual header check (chapter 10). (Core: `ContextualCheckBlockHeader`, `MAX_TIMEWARP`.)

```rust
/// Core: `MAX_TIMEWARP`, `src/consensus/consensus.h`.
pub const MAX_TIMEWARP: i64 = 600;
```

## 9.7 Known-answer tests

```rust
#[cfg(test)]
mod proof_of_work_tests {
    use super::*;

    #[test]
    fn compact_round_trips() {
        let (target, negative, overflow) = compact_to_target(0x1d00ffff);
        assert!(!negative && !overflow);
        assert_eq!(hex_encode(&target.to_be_bytes()), "00000000ffff0000000000000000000000000000000000000000000000000000");
        assert_eq!(target_to_compact(target), 0x1d00ffff);
        assert_eq!(compact_to_target(0x01003456).0, U256::ZERO);
        assert_eq!(compact_to_target(0x01123456).0, U256::from_u64(0x12));
        assert!(compact_to_target(0x04923456).1); // negative
        assert!(compact_to_target(0xff123456).2); // overflow
        assert_eq!(target_to_compact(U256::from_u64(0x80)), 0x02008000);
        // Mainnet genesis work: 2^256 / (target + 1) = 0x0100010001.
        assert_eq!(block_proof(0x1d00ffff), U256::from_u64(0x0100010001));
    }
}
```
