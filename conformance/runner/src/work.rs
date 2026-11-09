//! Proof of work arithmetic for reporting chain work (Bitcoin Core's `GetBitsProof`).

use std::cmp::Ordering;

/// Unsigned 256-bit integer, little-endian 64-bit limbs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct U256([u64; 4]);

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);

    pub fn from_u64(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    /// Wrapping addition.
    pub fn add(&self, o: &U256) -> U256 {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for (i, limb) in r.iter_mut().enumerate() {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            *limb = s as u64;
            carry = s >> 64;
        }
        U256(r)
    }

    /// Wrapping subtraction.
    fn sub(&self, o: &U256) -> U256 {
        self.add(&o.not().add(&U256::from_u64(1)))
    }

    pub fn not(&self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    fn shl1(&self) -> U256 {
        let mut r = [0u64; 4];
        for (i, limb) in r.iter_mut().enumerate() {
            *limb = self.0[i] << 1 | if i > 0 { self.0[i - 1] >> 63 } else { 0 };
        }
        U256(r)
    }

    fn shl(&self, bits: u32) -> U256 {
        let mut r = *self;
        for _ in 0..bits {
            r = r.shl1();
        }
        r
    }

    fn bit(&self, i: usize) -> bool {
        self.0[i / 64] >> (i % 64) & 1 == 1
    }

    /// Long division. Panics on division by zero.
    pub fn div(&self, d: &U256) -> U256 {
        assert!(!d.is_zero(), "division by zero");
        let mut q = U256::ZERO;
        let mut r = U256::ZERO;
        for i in (0..256).rev() {
            r = r.shl1();
            if self.bit(i) {
                r.0[0] |= 1;
            }
            if r >= *d {
                r = r.sub(d);
                q.0[i / 64] |= 1 << (i % 64);
            }
        }
        q
    }

    /// Big-endian hex, 64 digits (as `getblockchaininfo` prints `chainwork`).
    pub fn to_hex(self) -> String {
        self.0.iter().rev().map(|l| format!("{l:016x}")).collect()
    }

    /// Core's `arith_uint256::SetCompact`. `None` when negative or overflowing.
    pub fn from_compact(bits: u32) -> Option<U256> {
        let size = bits >> 24;
        let mut word = bits & 0x007f_ffff;
        let negative = word != 0 && bits & 0x0080_0000 != 0;
        let overflow =
            word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
        if negative || overflow {
            return None;
        }
        Some(if size <= 3 {
            word >>= 8 * (3 - size);
            U256::from_u64(word as u64)
        } else {
            U256::from_u64(word as u64).shl(8 * (size - 3))
        })
    }

    /// Core's `GetBitsProof`: 2^256 / (target + 1), 0 for an invalid or zero target.
    pub fn proof(bits: u32) -> U256 {
        match U256::from_compact(bits) {
            Some(t) if !t.is_zero() => t
                .not()
                .div(&t.add(&U256::from_u64(1)))
                .add(&U256::from_u64(1)),
            _ => U256::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs() {
        // Regtest genesis: chainwork 2 (getblockchaininfo on a fresh regtest node).
        assert_eq!(U256::proof(0x207fffff), U256::from_u64(2));
        // Difficulty 1: 0x100010001.
        assert_eq!(U256::proof(0x1d00ffff), U256::from_u64(0x1_0001_0001));
        assert_eq!(
            U256::proof(0x1d00ffff).to_hex(),
            format!("{:0>64}", "100010001")
        );
        assert_eq!(U256::proof(0x01803456), U256::ZERO); // negative
        assert_eq!(U256::proof(0), U256::ZERO);
    }
}
