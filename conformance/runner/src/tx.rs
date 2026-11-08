//! Minimal transaction model with Bitcoin Core's serialization rules
//! (src/primitives/transaction.h, src/serialize.h).
//!
//! The runner needs this to build the transactions of script_tests.json, to rebuild the
//! transactions of script_assets_test.json, and to find which outputs the inputs of
//! tx_valid.json / tx_invalid.json spend. Harnesses always receive serialized bytes.

use sha2::{Digest, Sha256};

/// Core's MAX_SIZE, the largest length a compact size may announce.
const MAX_SIZE: u64 = 0x0200_0000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    /// Transaction id in raw (internal) byte order.
    pub txid: [u8; 32],
    pub n: u32,
}

#[derive(Clone, Debug)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Tx {
    pub version: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_bytes(out: &mut Vec<u8>, data: &[u8]) {
    write_compact_size(out, data.len() as u64);
    out.extend_from_slice(data);
}

impl Tx {
    /// Core's `CTransaction::HasWitness`.
    pub fn has_witness(&self) -> bool {
        self.vin.iter().any(|i| !i.witness.is_empty())
    }

    /// Core's `SerializeTransaction`: the extended format is used only when witness serialization
    /// is allowed and some input has a non-empty witness stack.
    pub fn serialize(&self, allow_witness: bool) -> Vec<u8> {
        let witness = allow_witness && self.has_witness();
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if witness {
            out.push(0x00);
            out.push(0x01);
        }
        write_compact_size(&mut out, self.vin.len() as u64);
        for i in &self.vin {
            out.extend_from_slice(&i.prevout.txid);
            out.extend_from_slice(&i.prevout.n.to_le_bytes());
            write_bytes(&mut out, &i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.vout.len() as u64);
        for o in &self.vout {
            out.extend_from_slice(&o.value.to_le_bytes());
            write_bytes(&mut out, &o.script_pubkey);
        }
        if witness {
            for i in &self.vin {
                write_compact_size(&mut out, i.witness.len() as u64);
                for item in &i.witness {
                    write_bytes(&mut out, item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Transaction id (raw byte order): double SHA-256 of the serialization without witnesses.
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize(false))
    }

    /// Core's `UnserializeTransaction`. Returns the transaction and the number of bytes read
    /// (Core's readers do not require the input to be consumed completely).
    pub fn deserialize(data: &[u8], allow_witness: bool) -> Result<(Tx, usize), String> {
        let mut r = Reader { data, pos: 0 };
        let version = r.u32()?;
        let mut vin = r.inputs()?;
        let mut vout = Vec::new();
        let mut flags = 0u8;
        if vin.is_empty() && allow_witness {
            // Either the extended format marker or a transaction without inputs.
            flags = r.u8()?;
            if flags != 0 {
                vin = r.inputs()?;
                vout = r.outputs()?;
            }
        } else {
            vout = r.outputs()?;
        }
        if (flags & 1) != 0 && allow_witness {
            flags ^= 1;
            for input in vin.iter_mut() {
                let n = r.compact_size()?;
                let mut stack = Vec::new();
                for _ in 0..n {
                    stack.push(r.bytes()?);
                }
                input.witness = stack;
            }
            if !vin.iter().any(|i| !i.witness.is_empty()) {
                return Err("superfluous witness record".into());
            }
        }
        if flags != 0 {
            return Err("unknown transaction optional data".into());
        }
        let lock_time = r.u32()?;
        Ok((
            Tx {
                version,
                vin,
                vout,
                lock_time,
            },
            r.pos,
        ))
    }
}

/// Reads a serialized `CTxOut` (8-byte amount, then the script with its length).
pub fn deserialize_txout(data: &[u8]) -> Result<(TxOut, usize), String> {
    let mut r = Reader { data, pos: 0 };
    let value = r.u64()? as i64;
    let script_pubkey = r.bytes()?;
    Ok((
        TxOut {
            value,
            script_pubkey,
        },
        r.pos,
    ))
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.data.len() - self.pos < n {
            return Err("end of data".into());
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// Core's `ReadCompactSize` with its canonical-encoding and MAX_SIZE checks.
    fn compact_size(&mut self) -> Result<u64, String> {
        let first = self.u8()?;
        let n = match first {
            0..=252 => first as u64,
            253 => {
                let v = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v < 253 {
                    return Err("non-canonical compact size".into());
                }
                v
            }
            254 => {
                let v = self.u32()? as u64;
                if v < 0x10000 {
                    return Err("non-canonical compact size".into());
                }
                v
            }
            255 => {
                let v = self.u64()?;
                if v < 0x1_0000_0000 {
                    return Err("non-canonical compact size".into());
                }
                v
            }
        };
        if n > MAX_SIZE {
            return Err("compact size too large".into());
        }
        Ok(n)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.compact_size()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn inputs(&mut self) -> Result<Vec<TxIn>, String> {
        let n = self.compact_size()?;
        let mut v = Vec::new();
        for _ in 0..n {
            let txid: [u8; 32] = self.take(32)?.try_into().unwrap();
            let index = self.u32()?;
            let script_sig = self.bytes()?;
            let sequence = self.u32()?;
            v.push(TxIn {
                prevout: OutPoint { txid, n: index },
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }
        Ok(v)
    }
    fn outputs(&mut self) -> Result<Vec<TxOut>, String> {
        let n = self.compact_size()?;
        let mut v = Vec::new();
        for _ in 0..n {
            let value = self.u64()? as i64;
            let script_pubkey = self.bytes()?;
            v.push(TxOut {
                value,
                script_pubkey,
            });
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn round_trip_with_witness() {
        // BIP143 native P2WPKH example transaction (signed).
        let raw = hex::decode("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000").unwrap();
        let (tx, used) = Tx::deserialize(&raw, true).unwrap();
        assert_eq!(used, raw.len());
        assert_eq!(tx.vin.len(), 2);
        assert!(tx.vin[0].witness.is_empty());
        assert_eq!(tx.vin[1].witness.len(), 2);
        assert_eq!(tx.serialize(true), raw);
    }

    #[test]
    fn genesis_coinbase_txid() {
        let raw = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap();
        let (tx, used) = Tx::deserialize(&raw, true).unwrap();
        assert_eq!(used, raw.len());
        assert_eq!(tx.serialize(true), raw);
        assert_eq!(
            hex::encode_reversed(&tx.txid()),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn zero_inputs_without_marker() {
        // version, no inputs, "flags" byte 0 (really an empty output list), lock time.
        let raw = hex::decode("01000000000000000000").unwrap();
        let (tx, used) = Tx::deserialize(&raw, true).unwrap();
        assert_eq!(used, raw.len());
        assert!(tx.vin.is_empty() && tx.vout.is_empty());
    }
}
