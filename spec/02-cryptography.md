# 02. Cryptography

Consensus uses four hash functions (SHA-256, SHA-1, RIPEMD-160, and tagged SHA-256), and two signature schemes over the secp256k1 elliptic curve: ECDSA for legacy and segwit version 0 scripts, and BIP340 Schnorr signatures for taproot.

The hash functions are standard and any correct implementation of them may be used. The signature schemes are standard *mathematically*, but Bitcoin wraps them in parsing rules that are not: ECDSA signatures are parsed leniently, high-S signatures are accepted, and some public key encodings that most libraries reject are valid. Those wrapping rules are consensus-critical and are specified exactly in sections 2.8 and 2.9.

The reference implements everything here from first principles with the standard library, so that the specification is self-contained. Production implementations SHOULD use libsecp256k1 (the library Bitcoin Core uses) for curve operations, together with the wrapping rules of this chapter; section 2.11 describes the correspondence.

## 2.1 SHA-256

SHA-256 is defined by FIPS 180-4. `sha256d` (Bitcoin Core's `Hash` or `HASH256`) is SHA-256 applied twice.

```rust
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Merkle-Damgard padding: a 0x80 byte, zero bytes up to 56 mod 64, then the message length in bits
/// as a 64-bit integer (big-endian for SHA-256 and SHA-1, little-endian for RIPEMD-160).
fn md_pad(data: &[u8], big_endian_length: bool) -> Vec<u8> {
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(data.len() + 72);
    message.extend_from_slice(data);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    if big_endian_length {
        message.extend_from_slice(&bit_length.to_be_bytes());
    } else {
        message.extend_from_slice(&bit_length.to_le_bytes());
    }
    message
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

/// SHA-256 (FIPS 180-4).
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut state = SHA256_INITIAL;
    for block in md_pad(data, true).chunks(64) {
        sha256_compress(&mut state, block);
    }
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 applied twice. Core: `Hash` / `CHash256`, `src/hash.h`.
pub fn sha256d(data: &[u8]) -> Hash256 {
    sha256(&sha256(data))
}
```

## 2.2 SHA-1

SHA-1 (FIPS 180-4) is used only by the `OP_SHA1` opcode.

```rust
/// SHA-1 (FIPS 180-4).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    for block in md_pad(data, true).chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
```

## 2.3 RIPEMD-160

RIPEMD-160 is defined by Dobbertin, Bosselaers and Preneel (1996). It is used through `HASH160` (section 2.4) and by the `OP_RIPEMD160` opcode.

```rust
const RIPEMD_R_LEFT: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RIPEMD_R_RIGHT: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const RIPEMD_S_LEFT: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const RIPEMD_S_RIGHT: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const RIPEMD_K_LEFT: [u32; 5] = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const RIPEMD_K_RIGHT: [u32; 5] = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

fn ripemd_f(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

/// RIPEMD-160.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    for block in md_pad(data, false).chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        let (mut al, mut bl, mut cl, mut dl, mut el) = (h[0], h[1], h[2], h[3], h[4]);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h[0], h[1], h[2], h[3], h[4]);
        for j in 0..80 {
            let round = j / 16;
            let t = al
                .wrapping_add(ripemd_f(round, bl, cl, dl))
                .wrapping_add(x[RIPEMD_R_LEFT[j]])
                .wrapping_add(RIPEMD_K_LEFT[round])
                .rotate_left(RIPEMD_S_LEFT[j])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;
            let t = ar
                .wrapping_add(ripemd_f(4 - round, br, cr, dr))
                .wrapping_add(x[RIPEMD_R_RIGHT[j]])
                .wrapping_add(RIPEMD_K_RIGHT[round])
                .rotate_left(RIPEMD_S_RIGHT[j])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;
        }
        let t = h[1].wrapping_add(cl).wrapping_add(dr);
        h[1] = h[2].wrapping_add(dl).wrapping_add(er);
        h[2] = h[3].wrapping_add(el).wrapping_add(ar);
        h[3] = h[4].wrapping_add(al).wrapping_add(br);
        h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
        h[0] = t;
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}
```

## 2.4 Composite and tagged hashes

`HASH160` is RIPEMD-160 of SHA-256. It is used by pay-to-public-key-hash, pay-to-script-hash and pay-to-witness-public-key-hash outputs.

BIP340 defines *tagged hashes*: `tagged_hash(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)`. Taproot uses the tags `TapLeaf`, `TapBranch`, `TapTweak`, `TapSighash` and `BIP0340/challenge`.

```rust
/// RIPEMD-160 of SHA-256. Core: `Hash160`, `src/hash.h`.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// BIP340 tagged hash. Core: `TaggedHash`, `src/hash.cpp`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> Hash256 {
    let tag_hash = sha256(tag.as_bytes());
    let mut buffer = Vec::with_capacity(64 + data.len());
    buffer.extend_from_slice(&tag_hash);
    buffer.extend_from_slice(&tag_hash);
    buffer.extend_from_slice(data);
    sha256(&buffer)
}
```

## 2.5 256-bit unsigned integers

Elliptic curve arithmetic and proof of work (chapter 09) both need 256-bit unsigned integers. `U256` holds four 64-bit limbs, least significant first.

Two byte orders convert to and from `U256`:

- `from_be_bytes` reads the most significant byte first. Elliptic curve encodings (coordinates, scalars, signature components, the ECDSA message) use this order.
- `from_le_bytes` reads the least significant byte first. Proof of work compares a block hash, held in raw order, as a little-endian number (Core: `UintToArith256`).

```rust
/// Unsigned 256-bit integer, limbs least significant first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct U256(pub [u64; 4]);

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub fn from_u64(value: u64) -> U256 {
        U256([value, 0, 0, 0])
    }

    /// Reads 32 bytes, most significant first.
    pub fn from_be_bytes(bytes: &[u8]) -> U256 {
        assert_eq!(bytes.len(), 32);
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[24 - 8 * i..32 - 8 * i]);
            limbs[i] = u64::from_be_bytes(chunk);
        }
        U256(limbs)
    }

    /// Writes 32 bytes, most significant first.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[24 - 8 * i..32 - 8 * i].copy_from_slice(&self.0[i].to_be_bytes());
        }
        out
    }

    /// Reads 32 bytes, least significant first. Core: `UintToArith256`.
    pub fn from_le_bytes(bytes: &[u8]) -> U256 {
        assert_eq!(bytes.len(), 32);
        let mut reversed = [0u8; 32];
        for i in 0..32 {
            reversed[i] = bytes[31 - i];
        }
        U256::from_be_bytes(&reversed)
    }

    /// Writes 32 bytes, least significant first. Core: `ArithToUint256`.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut out = self.to_be_bytes();
        out.reverse();
        out
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Bit `index` (0 is the least significant bit).
    pub fn bit(&self, index: usize) -> bool {
        (self.0[index / 64] >> (index % 64)) & 1 == 1
    }

    /// Number of significant bits: 0 for zero, otherwise one more than the index of the highest set bit.
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    pub fn low_u64(&self) -> u64 {
        self.0[0]
    }

    pub fn overflowing_add(self, other: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = self.0[i] as u128 + other.0[i] as u128 + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
        }
        (U256(out), carry != 0)
    }

    pub fn overflowing_sub(self, other: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (d1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow as u64);
            out[i] = d2;
            borrow = b1 || b2;
        }
        (U256(out), borrow)
    }

    /// Addition modulo 2^256.
    pub fn wrapping_add(self, other: U256) -> U256 {
        self.overflowing_add(other).0
    }

    /// Subtraction modulo 2^256.
    pub fn wrapping_sub(self, other: U256) -> U256 {
        self.overflowing_sub(other).0
    }

    /// Bitwise complement (Core: `arith_uint256::operator~`).
    pub fn not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Left shift; bits shifted past bit 255 are discarded. Shifts of 256 or more give zero.
    pub fn shl(self, shift: u32) -> U256 {
        if shift >= 256 {
            return U256::ZERO;
        }
        let limbs = (shift / 64) as usize;
        let bits = shift % 64;
        let mut out = [0u64; 4];
        for i in (limbs..4).rev() {
            out[i] = self.0[i - limbs] << bits;
            if bits > 0 && i > limbs {
                out[i] |= self.0[i - limbs - 1] >> (64 - bits);
            }
        }
        U256(out)
    }

    /// Right shift. Shifts of 256 or more give zero.
    pub fn shr(self, shift: u32) -> U256 {
        if shift >= 256 {
            return U256::ZERO;
        }
        let limbs = (shift / 64) as usize;
        let bits = shift % 64;
        let mut out = [0u64; 4];
        for i in 0..4 - limbs {
            out[i] = self.0[i + limbs] >> bits;
            if bits > 0 && i + limbs + 1 < 4 {
                out[i] |= self.0[i + limbs + 1] << (64 - bits);
            }
        }
        U256(out)
    }

    /// Full 512-bit product, limbs least significant first.
    pub fn mul_wide(self, other: U256) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let product = self.0[i] as u128 * other.0[j] as u128 + out[i + j] as u128 + carry;
                out[i + j] = product as u64;
                carry = product >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }

    /// Product modulo 2^256 (Core: `arith_uint256::operator*=`, which discards the high half).
    pub fn wrapping_mul(self, other: U256) -> U256 {
        let wide = self.mul_wide(other);
        U256([wide[0], wide[1], wide[2], wide[3]])
    }

    /// Quotient and remainder. The divisor must not be zero.
    pub fn div_rem(self, divisor: U256) -> (U256, U256) {
        assert!(!divisor.is_zero(), "division by zero");
        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;
        for i in (0..256).rev() {
            // The shifted remainder can exceed 2^256 only when the divisor exceeds 2^255; the bit
            // shifted out is then exactly what makes the remainder at least the divisor, and the
            // wrapping subtraction below yields the correct value.
            let carry = remainder.bit(255);
            remainder = remainder.shl(1);
            if self.bit(i) {
                remainder.0[0] |= 1;
            }
            if carry || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[i / 64] |= 1u64 << (i % 64);
            }
        }
        (quotient, remainder)
    }
}
```

## 2.6 The secp256k1 field and scalar group

secp256k1 is the curve `y^2 = x^3 + 7` over the prime field of order

`p = 2^256 - 2^32 - 977`

with a generator `G` of prime order

`n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141`.

Both moduli are close to 2^256, so a 512-bit product `hi * 2^256 + lo` reduces quickly: `2^256 = m + (2^256 - m)`, so the product is congruent to `hi * (2^256 - m) + lo`, which is repeated until the high half vanishes.

```rust
/// The field prime p.
pub const FIELD_P: U256 = U256([0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);

/// The group order n.
pub const CURVE_N: U256 = U256([0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff]);

/// Reduces a 512-bit value modulo `modulus`, where `complement = 2^256 - modulus`.
fn reduce_wide(wide: [u64; 8], modulus: U256, complement: U256) -> U256 {
    let mut lo = U256([wide[0], wide[1], wide[2], wide[3]]);
    let mut hi = U256([wide[4], wide[5], wide[6], wide[7]]);
    while !hi.is_zero() {
        let product = hi.mul_wide(complement);
        let (sum, carry) = lo.overflowing_add(U256([product[0], product[1], product[2], product[3]]));
        lo = sum;
        hi = U256([product[4], product[5], product[6], product[7]]);
        if carry {
            hi = hi.wrapping_add(U256::ONE);
        }
    }
    while lo >= modulus {
        lo = lo.wrapping_sub(modulus);
    }
    lo
}

fn mod_add(a: U256, b: U256, modulus: U256) -> U256 {
    let (sum, carry) = a.overflowing_add(b);
    if carry || sum >= modulus {
        sum.wrapping_sub(modulus)
    } else {
        sum
    }
}

fn mod_sub(a: U256, b: U256, modulus: U256) -> U256 {
    let (difference, borrow) = a.overflowing_sub(b);
    if borrow {
        difference.wrapping_add(modulus)
    } else {
        difference
    }
}

fn mod_pow(base: U256, exponent: U256, modulus: U256, complement: U256) -> U256 {
    let mut result = U256::ONE;
    for i in (0..256).rev() {
        result = reduce_wide(result.mul_wide(result), modulus, complement);
        if exponent.bit(i) {
            result = reduce_wide(result.mul_wide(base), modulus, complement);
        }
    }
    result
}

fn field_complement() -> U256 {
    U256::ZERO.wrapping_sub(FIELD_P)
}

fn scalar_complement() -> U256 {
    U256::ZERO.wrapping_sub(CURVE_N)
}

pub fn fe_add(a: U256, b: U256) -> U256 {
    mod_add(a, b, FIELD_P)
}

pub fn fe_sub(a: U256, b: U256) -> U256 {
    mod_sub(a, b, FIELD_P)
}

pub fn fe_mul(a: U256, b: U256) -> U256 {
    reduce_wide(a.mul_wide(b), FIELD_P, field_complement())
}

/// Multiplicative inverse by Fermat's little theorem (a^(p-2)). The inverse of zero is zero.
pub fn fe_inv(a: U256) -> U256 {
    mod_pow(a, FIELD_P.wrapping_sub(U256::from_u64(2)), FIELD_P, field_complement())
}

/// Square root, if one exists. Because p = 3 mod 4, a candidate is a^((p+1)/4).
pub fn fe_sqrt(a: U256) -> Option<U256> {
    let exponent = FIELD_P.wrapping_add(U256::ONE).shr(2);
    let root = mod_pow(a, exponent, FIELD_P, field_complement());
    if fe_mul(root, root) == a {
        Some(root)
    } else {
        None
    }
}

/// Reduces any 256-bit value modulo n. One subtraction suffices because n > 2^255.
pub fn sc_reduce(a: U256) -> U256 {
    if a >= CURVE_N {
        a.wrapping_sub(CURVE_N)
    } else {
        a
    }
}

pub fn sc_add(a: U256, b: U256) -> U256 {
    mod_add(a, b, CURVE_N)
}

pub fn sc_mul(a: U256, b: U256) -> U256 {
    reduce_wide(a.mul_wide(b), CURVE_N, scalar_complement())
}

pub fn sc_neg(a: U256) -> U256 {
    if a.is_zero() {
        U256::ZERO
    } else {
        CURVE_N.wrapping_sub(a)
    }
}

/// Inverse modulo n by Fermat's little theorem.
pub fn sc_inv(a: U256) -> U256 {
    mod_pow(a, CURVE_N.wrapping_sub(U256::from_u64(2)), CURVE_N, scalar_complement())
}
```

## 2.7 Curve points

Points are held in affine coordinates `(x, y)`; the point at infinity is represented by `None` wherever it can occur. Internally, scalar multiplication uses Jacobian coordinates `(X, Y, Z)` representing `(X/Z^2, Y/Z^3)`, with `Z = 0` for infinity.

```rust
/// An affine point on secp256k1 (never the point at infinity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: U256,
    pub y: U256,
}

pub fn generator() -> Point {
    Point {
        x: U256([0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac]),
        y: U256([0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465]),
    }
}

/// True if (x, y) satisfies y^2 = x^3 + 7 (both coordinates already reduced below p).
pub fn on_curve(x: U256, y: U256) -> bool {
    let x3 = fe_mul(fe_mul(x, x), x);
    fe_mul(y, y) == fe_add(x3, U256::from_u64(7))
}

#[derive(Clone, Copy)]
struct Jacobian {
    x: U256,
    y: U256,
    z: U256,
}

const JACOBIAN_INFINITY: Jacobian = Jacobian { x: U256::ONE, y: U256::ONE, z: U256::ZERO };

fn to_jacobian(p: &Point) -> Jacobian {
    Jacobian { x: p.x, y: p.y, z: U256::ONE }
}

fn to_affine(p: &Jacobian) -> Option<Point> {
    if p.z.is_zero() {
        return None;
    }
    let z_inv = fe_inv(p.z);
    let z_inv2 = fe_mul(z_inv, z_inv);
    let z_inv3 = fe_mul(z_inv2, z_inv);
    Some(Point { x: fe_mul(p.x, z_inv2), y: fe_mul(p.y, z_inv3) })
}

/// Point doubling for a = 0 curves.
fn jacobian_double(p: &Jacobian) -> Jacobian {
    if p.z.is_zero() || p.y.is_zero() {
        return JACOBIAN_INFINITY;
    }
    let a = fe_mul(p.x, p.x);
    let b = fe_mul(p.y, p.y);
    let c = fe_mul(b, b);
    let x_plus_b = fe_add(p.x, b);
    let d = fe_sub(fe_sub(fe_mul(x_plus_b, x_plus_b), a), c);
    let d = fe_add(d, d);
    let e = fe_add(fe_add(a, a), a);
    let f = fe_mul(e, e);
    let x3 = fe_sub(f, fe_add(d, d));
    let c8 = fe_add(fe_add(fe_add(c, c), fe_add(c, c)), fe_add(fe_add(c, c), fe_add(c, c)));
    let y3 = fe_sub(fe_mul(e, fe_sub(d, x3)), c8);
    let yz = fe_mul(p.y, p.z);
    let z3 = fe_add(yz, yz);
    Jacobian { x: x3, y: y3, z: z3 }
}

/// General point addition, including the doubling and inverse cases.
fn jacobian_add(p: &Jacobian, q: &Jacobian) -> Jacobian {
    if p.z.is_zero() {
        return *q;
    }
    if q.z.is_zero() {
        return *p;
    }
    let z1z1 = fe_mul(p.z, p.z);
    let z2z2 = fe_mul(q.z, q.z);
    let u1 = fe_mul(p.x, z2z2);
    let u2 = fe_mul(q.x, z1z1);
    let s1 = fe_mul(fe_mul(p.y, q.z), z2z2);
    let s2 = fe_mul(fe_mul(q.y, p.z), z1z1);
    let h = fe_sub(u2, u1);
    let r = fe_sub(s2, s1);
    if h.is_zero() {
        if r.is_zero() {
            return jacobian_double(p);
        }
        return JACOBIAN_INFINITY;
    }
    let hh = fe_mul(h, h);
    let hhh = fe_mul(hh, h);
    let v = fe_mul(u1, hh);
    let x3 = fe_sub(fe_sub(fe_mul(r, r), hhh), fe_add(v, v));
    let y3 = fe_sub(fe_mul(r, fe_sub(v, x3)), fe_mul(s1, hhh));
    let z3 = fe_mul(fe_mul(p.z, q.z), h);
    Jacobian { x: x3, y: y3, z: z3 }
}

/// Computes a*P + b*Q by simultaneous double-and-add. Returns `None` for the point at infinity.
pub fn point_mul_add(a: U256, p: &Point, b: U256, q: &Point) -> Option<Point> {
    let pj = to_jacobian(p);
    let qj = to_jacobian(q);
    let pq = jacobian_add(&pj, &qj);
    let mut acc = JACOBIAN_INFINITY;
    for i in (0..256).rev() {
        acc = jacobian_double(&acc);
        match (a.bit(i), b.bit(i)) {
            (true, true) => acc = jacobian_add(&acc, &pq),
            (true, false) => acc = jacobian_add(&acc, &pj),
            (false, true) => acc = jacobian_add(&acc, &qj),
            (false, false) => {}
        }
    }
    to_affine(&acc)
}

/// The point with x-coordinate `x` and even y (BIP340 `lift_x`), if it exists.
pub fn lift_x(x: U256) -> Option<Point> {
    if x >= FIELD_P {
        return None;
    }
    let c = fe_add(fe_mul(fe_mul(x, x), x), U256::from_u64(7));
    let y = fe_sqrt(c)?;
    let y = if y.bit(0) { fe_sub(U256::ZERO, y) } else { y };
    Some(Point { x, y })
}
```

## 2.8 ECDSA verification as Bitcoin performs it

Legacy and segwit version 0 scripts verify ECDSA signatures (Core: `CPubKey::Verify`, `src/pubkey.cpp`). The mathematical verification is standard, but three wrapping rules are Bitcoin-specific and consensus-critical.

**Public key parsing.** A public key is a byte string whose first byte selects its length: `0x02` or `0x03` require exactly 33 bytes (compressed: x-coordinate plus y parity); `0x04`, `0x06` or `0x07` require exactly 65 bytes (x and y coordinates). Any other first byte, any other length, or an empty string is an invalid key. `0x06` and `0x07` are *hybrid* encodings: the full coordinates plus a redundant parity in the first byte, which must match the parity of y (`0x07` for odd). Most libraries reject hybrid keys; Bitcoin consensus accepts them. Coordinates must be below p and the point must be on the curve. (Core: `CPubKey::GetLen`, `CPubKey::Set`; libsecp256k1 `secp256k1_ec_pubkey_parse`.)

An invalid public key makes verification return false. It does not by itself make a script fail; chapter 05 decides what a false result means.

**Lax DER signature parsing.** Before BIP66 (chapter 05, `DERSIG`), signatures were not required to be strict DER, and blocks contain signatures that strict parsers reject. Bitcoin Core parses every ECDSA signature with the lenient parser below, *even after BIP66*; BIP66 adds a separate strict encoding check in the script interpreter. The lenient parser:

- requires the byte `0x30`, then a length byte; if the length byte has its top bit set, its low 7 bits count further length bytes, which are skipped without being interpreted (there must be at least that many bytes left);
- requires `0x02` followed by the length of R. A short length (top bit clear) is used directly. A long length (top bit set) gives a count of length bytes; leading zero bytes of the length are skipped, at most 3 significant length bytes may remain, and they are read big-endian;
- requires R's bytes to fit in the input, then the same `0x02`, length and fit checks for S;
- ignores anything after S, and ignores the sequence length entirely;
- strips leading zero bytes from R and S. If either still has more than 32 bytes, or its value is not below n, the signature parses successfully but as `(0, 0)`, which never verifies.

**Low-S normalization.** libsecp256k1 only verifies signatures with `s <= n/2`, but Bitcoin consensus has never required that. Bitcoin Core therefore replaces s by `n - s` when `s > n/2` before verifying (Core: `secp256k1_ecdsa_signature_normalize`). Low-S is a relay policy only.

After those steps, verification is standard ECDSA: fail if r or s is zero; with `e` the 32-byte message read big-endian and reduced modulo n, `w = s^-1`, `R = (e*w)*G + (r*w)*Q`; fail if R is infinity; succeed if R's x-coordinate, reduced modulo n, equals r.

The message is the 32-byte signature hash in raw order (chapter 06), read big-endian. In particular, the legacy `SIGHASH_SINGLE` special value "one" (chapter 06) is the byte string `01 00 00 ... 00`, which is the number 2^248 as an ECDSA message, not the number 1.

```rust
/// Parses a public key exactly as Bitcoin Core does. Core: `CPubKey::GetLen`, `CPubKey::Set`,
/// libsecp256k1 `secp256k1_ec_pubkey_parse`.
pub fn parse_pubkey(bytes: &[u8]) -> Option<Point> {
    let expected_length = match bytes.first()? {
        0x02 | 0x03 => 33,
        0x04 | 0x06 | 0x07 => 65,
        _ => return None,
    };
    if bytes.len() != expected_length {
        return None;
    }
    let x = U256::from_be_bytes(&bytes[1..33]);
    if x >= FIELD_P {
        return None;
    }
    if expected_length == 33 {
        let point = lift_x(x)?;
        let want_odd = bytes[0] == 0x03;
        if point.y.bit(0) == want_odd {
            Some(point)
        } else {
            Some(Point { x, y: fe_sub(U256::ZERO, point.y) })
        }
    } else {
        let y = U256::from_be_bytes(&bytes[33..65]);
        if y >= FIELD_P {
            return None;
        }
        if (bytes[0] == 0x06 || bytes[0] == 0x07) && y.bit(0) != (bytes[0] == 0x07) {
            return None;
        }
        if !on_curve(x, y) {
            return None;
        }
        Some(Point { x, y })
    }
}

/// Lenient DER parsing. `None` means the parse failed; `Some((r, s))` may be `(0, 0)` for a
/// signature that parsed but cannot verify. Core: `ecdsa_signature_parse_der_lax`, `src/pubkey.cpp`.
pub fn parse_der_lax(input: &[u8]) -> Option<(U256, U256)> {
    let len = input.len();
    let mut pos = 0usize;

    // Sequence tag and (ignored) sequence length.
    if pos == len || input[pos] != 0x30 {
        return None;
    }
    pos += 1;
    if pos == len {
        return None;
    }
    let mut lenbyte = input[pos] as usize;
    pos += 1;
    if lenbyte & 0x80 != 0 {
        lenbyte -= 0x80;
        if lenbyte > len - pos {
            return None;
        }
        pos += lenbyte;
    }

    // Reads an INTEGER header and returns (start, length) of its content.
    fn integer(input: &[u8], pos: &mut usize) -> Option<(usize, usize)> {
        let len = input.len();
        if *pos == len || input[*pos] != 0x02 {
            return None;
        }
        *pos += 1;
        if *pos == len {
            return None;
        }
        let mut lenbyte = input[*pos] as usize;
        *pos += 1;
        let content_length;
        if lenbyte & 0x80 != 0 {
            lenbyte -= 0x80;
            if lenbyte > len - *pos {
                return None;
            }
            while lenbyte > 0 && input[*pos] == 0 {
                *pos += 1;
                lenbyte -= 1;
            }
            if lenbyte >= 4 {
                return None;
            }
            let mut value = 0usize;
            while lenbyte > 0 {
                value = (value << 8) + input[*pos] as usize;
                *pos += 1;
                lenbyte -= 1;
            }
            content_length = value;
        } else {
            content_length = lenbyte;
        }
        if content_length > len - *pos {
            return None;
        }
        let start = *pos;
        Some((start, content_length))
    }

    let (mut r_pos, mut r_len) = integer(input, &mut pos)?;
    pos += r_len;
    let (mut s_pos, mut s_len) = integer(input, &mut pos)?;

    let mut compact = [0u8; 64];
    let mut overflow = false;
    while r_len > 0 && input[r_pos] == 0 {
        r_len -= 1;
        r_pos += 1;
    }
    if r_len > 32 {
        overflow = true;
    } else {
        compact[32 - r_len..32].copy_from_slice(&input[r_pos..r_pos + r_len]);
    }
    while s_len > 0 && input[s_pos] == 0 {
        s_len -= 1;
        s_pos += 1;
    }
    if s_len > 32 {
        overflow = true;
    } else {
        compact[64 - s_len..64].copy_from_slice(&input[s_pos..s_pos + s_len]);
    }
    let r = U256::from_be_bytes(&compact[0..32]);
    let s = U256::from_be_bytes(&compact[32..64]);
    if overflow || r >= CURVE_N || s >= CURVE_N {
        return Some((U256::ZERO, U256::ZERO));
    }
    Some((r, s))
}

/// ECDSA verification with Bitcoin's wrapping rules. `signature` excludes the sighash type byte.
/// Core: `CPubKey::Verify`, `src/pubkey.cpp`.
pub fn ecdsa_verify(pubkey: &[u8], signature: &[u8], message: &Hash256) -> bool {
    let q = match parse_pubkey(pubkey) {
        Some(q) => q,
        None => return false,
    };
    let (r, mut s) = match parse_der_lax(signature) {
        Some(rs) => rs,
        None => return false,
    };
    if s > CURVE_N.shr(1) {
        s = sc_neg(s);
    }
    if r.is_zero() || s.is_zero() {
        return false;
    }
    let e = sc_reduce(U256::from_be_bytes(message));
    let w = sc_inv(s);
    let u1 = sc_mul(e, w);
    let u2 = sc_mul(r, w);
    match point_mul_add(u1, &generator(), u2, &q) {
        Some(point) => sc_reduce(point.x) == r,
        None => false,
    }
}
```

## 2.9 BIP340 Schnorr verification and x-only keys

Taproot uses 32-byte *x-only* public keys: the x-coordinate of a point whose y-coordinate is taken to be even (`lift_x`). A 32-byte string is a valid x-only key if it is below p and is the x-coordinate of a curve point.

Verification of a 64-byte signature `(r, s)` on a message `m` under key `P` (BIP340): fail if the key is invalid, if `r >= p`, or if `s >= n`; let `e = tagged_hash("BIP0340/challenge", r || P || m)` read big-endian and reduced modulo n; let `R = s*G - e*P`; fail if R is infinity or has odd y; succeed if R's x-coordinate equals r. Consensus only ever verifies 32-byte messages (signature hashes), but the definition holds for any length, and the BIP340 test vectors use other lengths too. (Core: `XOnlyPubKey::VerifySchnorr`; libsecp256k1 `secp256k1_schnorrsig_verify`.)

```rust
/// BIP340 verification. Returns false for malformed inputs rather than failing.
pub fn schnorr_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != 32 || signature.len() != 64 {
        return false;
    }
    let p = match lift_x(U256::from_be_bytes(pubkey)) {
        Some(p) => p,
        None => return false,
    };
    let r = U256::from_be_bytes(&signature[0..32]);
    if r >= FIELD_P {
        return false;
    }
    let s = U256::from_be_bytes(&signature[32..64]);
    if s >= CURVE_N {
        return false;
    }
    let mut challenge = Vec::with_capacity(64 + message.len());
    challenge.extend_from_slice(&signature[0..32]);
    challenge.extend_from_slice(pubkey);
    challenge.extend_from_slice(message);
    let e = sc_reduce(U256::from_be_bytes(&tagged_hash("BIP0340/challenge", &challenge)));
    match point_mul_add(s, &generator(), sc_neg(e), &p) {
        Some(point) => !point.y.bit(0) && point.x == r,
        None => false,
    }
}

/// True if `bytes` is a valid x-only public key. Core: `XOnlyPubKey::IsFullyValid`.
pub fn xonly_pubkey_valid(bytes: &[u8]) -> bool {
    bytes.len() == 32 && lift_x(U256::from_be_bytes(bytes)).is_some()
}
```

## 2.10 Taproot tweak check

A taproot output key Q commits to an internal key P and a script tree with root hash `h`: `Q = P + t*G` where `t = tagged_hash("TapTweak", P || h)`. Script path spending (chapter 07) checks this equation. The check fails if P is not a valid x-only key, if `t >= n`, or if Q is infinity; otherwise it succeeds if Q's x-coordinate (as 32 big-endian bytes) equals the output key bytes and Q's y parity equals the parity bit from the control block. The output key itself is compared as bytes and is never required to be a valid point. (Core: `XOnlyPubKey::CheckTapTweak`; libsecp256k1 `secp256k1_xonly_pubkey_tweak_add_check`.)

```rust
/// Core: `XOnlyPubKey::CheckTapTweak`, `src/pubkey.cpp`.
pub fn taproot_tweak_check(output_key: &[u8], parity_odd: bool, internal_key: &[u8], merkle_root: &Hash256) -> bool {
    if internal_key.len() != 32 || output_key.len() != 32 {
        return false;
    }
    let p = match lift_x(U256::from_be_bytes(internal_key)) {
        Some(p) => p,
        None => return false,
    };
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(internal_key);
    data.extend_from_slice(merkle_root);
    let t = U256::from_be_bytes(&tagged_hash("TapTweak", &data));
    if t >= CURVE_N {
        return false;
    }
    match point_mul_add(U256::ONE, &p, t, &generator()) {
        Some(q) => q.x.to_be_bytes()[..] == output_key[..] && q.y.bit(0) == parity_odd,
        None => false,
    }
}
```

## 2.11 Using libsecp256k1

Implementations that use libsecp256k1 obtain identical results with these calls:

| This chapter | libsecp256k1 |
|---|---|
| `parse_pubkey` | `secp256k1_ec_pubkey_parse`, after checking the first byte and exact length as in `parse_pubkey` (the library accepts hybrid keys; the length rule comes from Bitcoin Core's `CPubKey`) |
| `parse_der_lax` | Bitcoin Core's `ecdsa_signature_parse_der_lax` (`src/pubkey.cpp`), also shipped as `contrib/lax_der_parsing.c` in the libsecp256k1 source tree |
| `ecdsa_verify` | `secp256k1_ecdsa_signature_normalize` followed by `secp256k1_ecdsa_verify` |
| `schnorr_verify` | `secp256k1_xonly_pubkey_parse` followed by `secp256k1_schnorrsig_verify` |
| `taproot_tweak_check` | `secp256k1_xonly_pubkey_parse` followed by `secp256k1_xonly_pubkey_tweak_add_check` |

Strict DER parsers (`secp256k1_ecdsa_signature_parse_der`) MUST NOT be used for verification: they reject signatures that are valid in old blocks, and for some inputs they decode a different (r, s) than the lenient parser does.

## 2.12 Known-answer tests

These tests are part of the specification. The conformance suite (BIP340 vectors, and every signature in Bitcoin Core's script tests) exercises the signature code far more thoroughly.

```rust
#[cfg(test)]
mod cryptography_tests {
    use super::*;

    #[test]
    fn hash_known_answers() {
        assert_eq!(hex_encode(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex_encode(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex_encode(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(hex_encode(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex_encode(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex_encode(&ripemd160(b"")), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        assert_eq!(hex_encode(&ripemd160(b"abc")), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        assert_eq!(hex_encode(&ripemd160(b"message digest")), "5d0689ef49d2fae572b881b123a85ffa21595f36");
        assert_eq!(
            hex_encode(&ripemd160(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        );
    }

    #[test]
    fn curve_known_answers() {
        let g = generator();
        assert!(on_curve(g.x, g.y));
        let two_g = point_mul_add(U256::from_u64(2), &g, U256::ZERO, &g).unwrap();
        assert_eq!(hex_encode(&two_g.x.to_be_bytes()), "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        assert!(point_mul_add(CURVE_N, &g, U256::ZERO, &g).is_none());
        let three = sc_add(U256::ONE, U256::from_u64(2));
        assert_eq!(sc_mul(three, sc_inv(three)), U256::ONE);
    }
}
```
