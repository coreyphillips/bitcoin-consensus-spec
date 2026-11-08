# 03. Serialization

Transactions and blocks travel and are hashed as byte strings. This chapter defines the data structures, their exact byte encodings, and the identifiers (transaction ids, witness transaction ids, block hashes) and sizes derived from those encodings.

Deserialization is consensus-critical in a way that is easy to miss: a block whose bytes do not parse is not a valid block, and two implementations that parse the same bytes into different transactions will disagree about validity. The parser below reproduces Bitcoin Core's, including its edge cases.

## 3.1 Primitive encodings

- Fixed-width integers are little-endian: `u8`, `u16`, `u32`, `i32`, `u64`, `i64` occupy 1, 2, 4, 4, 8 and 8 bytes.
- A 32-byte hash is written in raw order (chapter 01).
- **CompactSize** encodes a non-negative integer `v` in 1, 3, 5 or 9 bytes:

| Value | Encoding |
|---|---|
| `v < 0xfd` | one byte `v` |
| `v <= 0xffff` | `0xfd` followed by `v` as `u16` |
| `v <= 0xffffffff` | `0xfe` followed by `v` as `u32` |
| otherwise | `0xff` followed by `v` as `u64` |

Decoding MUST reject non-canonical encodings (a value encoded with more bytes than needed, for example `fd fc 00` for 252), and MUST reject any CompactSize used as a length or element count that exceeds `MAX_SIZE = 0x02000000` (33,554,432). Both are deserialization failures. (Core: `ReadCompactSize`, `src/serialize.h`.)

- A **byte vector** (scripts, witness items) is a CompactSize length followed by that many bytes.
- A **vector of objects** is a CompactSize count followed by the objects.

```rust
/// Core: `MAX_SIZE`, `src/serialize.h`. Upper bound on any CompactSize used as a length or count.
pub const MAX_SIZE: u64 = 0x0200_0000;

/// A deserialization failure. The message matches Bitcoin Core's exception text where one exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

/// A cursor over a byte string.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        if count > self.remaining() {
            return Err(DecodeError("end of data"));
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_bytes(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn read_i64(&mut self) -> Result<i64, DecodeError> {
        Ok(self.read_u64()? as i64)
    }

    pub fn read_hash(&mut self) -> Result<Hash256, DecodeError> {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(self.read_bytes(32)?);
        Ok(hash)
    }

    /// CompactSize without the MAX_SIZE limit. Core: `ReadCompactSize(is, false)`.
    pub fn read_compact_size_unchecked(&mut self) -> Result<u64, DecodeError> {
        let first = self.read_u8()?;
        let value = match first {
            0xfd => {
                let v = self.read_u16()? as u64;
                if v < 0xfd {
                    return Err(DecodeError("non-canonical ReadCompactSize()"));
                }
                v
            }
            0xfe => {
                let v = self.read_u32()? as u64;
                if v < 0x1_0000 {
                    return Err(DecodeError("non-canonical ReadCompactSize()"));
                }
                v
            }
            0xff => {
                let v = self.read_u64()?;
                if v < 0x1_0000_0000 {
                    return Err(DecodeError("non-canonical ReadCompactSize()"));
                }
                v
            }
            small => small as u64,
        };
        Ok(value)
    }

    /// CompactSize used as a length or count. Core: `ReadCompactSize(is, true)`.
    pub fn read_compact_size(&mut self) -> Result<u64, DecodeError> {
        let value = self.read_compact_size_unchecked()?;
        if value > MAX_SIZE {
            return Err(DecodeError("ReadCompactSize(): size too large"));
        }
        Ok(value)
    }

    /// A byte vector: CompactSize length, then the bytes.
    pub fn read_var_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let length = self.read_compact_size()? as usize;
        Ok(self.read_bytes(length)?.to_vec())
    }
}

/// Appends a CompactSize. Core: `WriteCompactSize`, `src/serialize.h`.
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Number of bytes `write_compact_size` produces for `value`.
pub fn compact_size_len(value: u64) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Appends a byte vector (CompactSize length, then the bytes).
pub fn write_var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
```

## 3.2 Transactions

A transaction consists of a version, inputs, outputs and a lock time. Each input names the output it spends (an *outpoint*: transaction id and output index), carries a `script_sig`, a `sequence` number and a witness (a list of byte vectors, empty for inputs without witness data). Each output has a value in satoshis and a `script_pubkey`.

```rust
/// A reference to a transaction output. Ordered by raw txid bytes, then index (Core: `COutPoint::operator<`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl OutPoint {
    /// The outpoint of a coinbase input: zero hash, index 0xffffffff. Core: `COutPoint::SetNull`.
    pub fn null() -> OutPoint {
        OutPoint { txid: ZERO_HASH, vout: 0xffff_ffff }
    }

    /// Core: `COutPoint::IsNull`.
    pub fn is_null(&self) -> bool {
        self.txid == ZERO_HASH && self.vout == 0xffff_ffff
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    /// The witness stack. Empty when the input has no witness.
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Unsigned (chapter 01): 0xffffffff compares greater than 2.
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}
```

### 3.2.1 Encoding

There are two encodings.

The **legacy encoding** is

```text
version:u32 | CompactSize(#inputs) | inputs | CompactSize(#outputs) | outputs | lock_time:u32
input  = prevout.txid:32 | prevout.vout:u32 | var_bytes(script_sig) | sequence:u32
output = value:i64 | var_bytes(script_pubkey)
```

The **witness encoding** (BIP144) inserts a marker byte `0x00` and a flag byte `0x01` after the version, and the witness stacks after the outputs:

```text
version:u32 | 0x00 | 0x01 | CompactSize(#inputs) | inputs | CompactSize(#outputs) | outputs
            | witness(input 0) | ... | witness(input n-1) | lock_time:u32
witness = CompactSize(#items) | var_bytes(item) ...
```

A transaction is serialized with the witness encoding if and only if at least one input has a non-empty witness stack (a stack containing one empty item is non-empty). (Core: `SerializeTransaction`, `CTransaction::HasWitness`, `src/primitives/transaction.h`.)

```rust
impl Transaction {
    /// True if any input has a non-empty witness stack. Core: `CTransaction::HasWitness`.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Serializes the transaction. With `include_witness` false, or without witness data, this is
    /// the legacy encoding. Core: `SerializeTransaction`.
    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        let extended = include_witness && self.has_witness();
        if extended {
            out.push(0x00);
            out.push(0x01);
        }
        write_compact_size(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prevout.txid);
            out.extend_from_slice(&input.prevout.vout.to_le_bytes());
            write_var_bytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            serialize_txout(&mut out, output);
        }
        if extended {
            for input in &self.inputs {
                write_compact_size(&mut out, input.witness.len() as u64);
                for item in &input.witness {
                    write_var_bytes(&mut out, item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }
}

/// Core: `CTxOut` serialization.
pub fn serialize_txout(out: &mut Vec<u8>, output: &TxOut) {
    out.extend_from_slice(&output.value.to_le_bytes());
    write_var_bytes(out, &output.script_pubkey);
}
```

### 3.2.2 Decoding

Decoding follows Bitcoin Core's algorithm exactly, which differs from "try the witness encoding, else the legacy one" in two corner cases:

1. The decoder first reads an input count. If it is zero, the next byte is read as the *flag*. A non-zero flag means the witness encoding: inputs and outputs are then read normally. A **zero flag** means "no witness encoding", and then *nothing more is read for inputs or outputs*: the transaction has no inputs and no outputs. So the ten bytes `version | 00 00 | lock_time` decode to an empty transaction (which later fails the transaction checks of chapter 08). An implementation that rejects these ten bytes at the parser instead of decoding them breaks consensus whenever they appear inside a block, because the block must then be rejected for the correct reason with the correct failure kind.
2. If the flag has bit 0 set, the witness stacks are read; if every stack turns out empty, decoding fails ("Superfluous witness record"). After bit 0 is cleared, any remaining flag bit is a decoding failure ("Unknown transaction optional data").

A transaction whose input count is non-zero has no flag byte, even if a witness is present elsewhere in the data.

```rust
fn read_txin(reader: &mut Reader) -> Result<TxIn, DecodeError> {
    let txid = reader.read_hash()?;
    let vout = reader.read_u32()?;
    let script_sig = reader.read_var_bytes()?;
    let sequence = reader.read_u32()?;
    Ok(TxIn { prevout: OutPoint { txid, vout }, script_sig, sequence, witness: Vec::new() })
}

fn read_txins(reader: &mut Reader) -> Result<Vec<TxIn>, DecodeError> {
    let count = reader.read_compact_size()?;
    let mut inputs = Vec::new();
    for _ in 0..count {
        inputs.push(read_txin(reader)?);
    }
    Ok(inputs)
}

pub fn read_txout(reader: &mut Reader) -> Result<TxOut, DecodeError> {
    let value = reader.read_i64()?;
    let script_pubkey = reader.read_var_bytes()?;
    Ok(TxOut { value, script_pubkey })
}

fn read_txouts(reader: &mut Reader) -> Result<Vec<TxOut>, DecodeError> {
    let count = reader.read_compact_size()?;
    let mut outputs = Vec::new();
    for _ in 0..count {
        outputs.push(read_txout(reader)?);
    }
    Ok(outputs)
}

fn read_witness_stack(reader: &mut Reader) -> Result<Vec<Vec<u8>>, DecodeError> {
    let count = reader.read_compact_size()?;
    let mut stack = Vec::new();
    for _ in 0..count {
        stack.push(reader.read_var_bytes()?);
    }
    Ok(stack)
}

/// Decodes one transaction with witness data allowed. Core: `UnserializeTransaction` with
/// `TX_WITH_WITNESS`, `src/primitives/transaction.h`.
pub fn read_transaction(reader: &mut Reader) -> Result<Transaction, DecodeError> {
    let version = reader.read_u32()?;
    let mut flags = 0u8;
    let mut inputs = read_txins(reader)?;
    let mut outputs = Vec::new();
    if inputs.is_empty() {
        flags = reader.read_u8()?;
        if flags != 0 {
            inputs = read_txins(reader)?;
            outputs = read_txouts(reader)?;
        }
    } else {
        outputs = read_txouts(reader)?;
    }
    if flags & 1 != 0 {
        flags ^= 1;
        for input in inputs.iter_mut() {
            input.witness = read_witness_stack(reader)?;
        }
        if !inputs.iter().any(|input| !input.witness.is_empty()) {
            return Err(DecodeError("Superfluous witness record"));
        }
    }
    if flags != 0 {
        return Err(DecodeError("Unknown transaction optional data"));
    }
    let lock_time = reader.read_u32()?;
    Ok(Transaction { version, inputs, outputs, lock_time })
}

/// Decodes a transaction that must occupy `bytes` exactly.
pub fn deserialize_transaction(bytes: &[u8]) -> Result<Transaction, DecodeError> {
    let mut reader = Reader::new(bytes);
    let tx = read_transaction(&mut reader)?;
    if reader.remaining() != 0 {
        return Err(DecodeError("trailing data"));
    }
    Ok(tx)
}
```

### 3.2.3 Identifiers and sizes

- The **transaction id** (`txid`) is `sha256d` of the legacy encoding. It never covers witness data.
- The **witness transaction id** (`wtxid`) is `sha256d` of the witness encoding; for a transaction without witness data it equals the txid.
- The **stripped size** is the length of the legacy encoding; the **total size** is the length of the serialization with witness data.
- The **weight** is `3 * stripped size + total size` (BIP141). Witness bytes therefore count once and all other bytes four times.

(Core: `CTransaction::ComputeHash`, `ComputeWitnessHash`, `GetTransactionWeight` in `src/consensus/validation.h`.)

```rust
/// Core: `WITNESS_SCALE_FACTOR`, `src/consensus/consensus.h`.
pub const WITNESS_SCALE_FACTOR: usize = 4;

impl Transaction {
    pub fn txid(&self) -> Hash256 {
        sha256d(&self.serialize(false))
    }

    pub fn wtxid(&self) -> Hash256 {
        sha256d(&self.serialize(true))
    }

    pub fn stripped_size(&self) -> usize {
        self.serialize(false).len()
    }

    pub fn total_size(&self) -> usize {
        self.serialize(true).len()
    }

    /// Core: `GetTransactionWeight`.
    pub fn weight(&self) -> usize {
        self.stripped_size() * (WITNESS_SCALE_FACTOR - 1) + self.total_size()
    }
}
```

## 3.3 Block headers

A block header is exactly 80 bytes:

```text
version:i32 | prev_block:32 | merkle_root:32 | time:u32 | bits:u32 | nonce:u32
```

The **block hash** is `sha256d` of these 80 bytes. Proof of work (chapter 09) compares it, read as a little-endian number, against the target encoded in `bits`. Note the header version is signed (chapter 01).

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block: Hash256,
    pub merkle_root: Hash256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub fn serialize(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_block);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Core: `CBlockHeader::GetHash`.
    pub fn hash(&self) -> Hash256 {
        sha256d(&self.serialize())
    }
}

pub fn read_block_header(reader: &mut Reader) -> Result<BlockHeader, DecodeError> {
    Ok(BlockHeader {
        version: reader.read_i32()?,
        prev_block: reader.read_hash()?,
        merkle_root: reader.read_hash()?,
        time: reader.read_u32()?,
        bits: reader.read_u32()?,
        nonce: reader.read_u32()?,
    })
}
```

## 3.4 Blocks

A block is a header followed by a CompactSize transaction count and the transactions, each in the encoding chosen by section 3.2.1 (witness encoding when it has witness data).

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Serializes the block. Core: `CBlock` serialization.
    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let mut out = self.header.serialize().to_vec();
        write_compact_size(&mut out, self.transactions.len() as u64);
        for tx in &self.transactions {
            out.extend_from_slice(&tx.serialize(include_witness));
        }
        out
    }

    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    pub fn stripped_size(&self) -> usize {
        self.serialize(false).len()
    }

    pub fn total_size(&self) -> usize {
        self.serialize(true).len()
    }

    /// Core: `GetBlockWeight`, `src/consensus/validation.h`.
    pub fn weight(&self) -> usize {
        self.stripped_size() * (WITNESS_SCALE_FACTOR - 1) + self.total_size()
    }
}

/// Decodes a block. Bytes after the last transaction are not part of the block and are ignored,
/// as Bitcoin Core ignores them in `block` messages and `submitblock`.
pub fn deserialize_block(bytes: &[u8]) -> Result<Block, DecodeError> {
    let mut reader = Reader::new(bytes);
    let header = read_block_header(&mut reader)?;
    let count = reader.read_compact_size()?;
    let mut transactions = Vec::new();
    for _ in 0..count {
        transactions.push(read_transaction(&mut reader)?);
    }
    Ok(Block { header, transactions })
}
```

A block that cannot be decoded is not a block at all; a node that received such bytes from a peer has learned nothing about any block hash, so the failure is handled like a `Mutated` failure (chapter 11).

## 3.5 Known-answer tests

```rust
#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn compact_size_canonical() {
        for (bytes, expected) in [(&[0xfcu8][..], Some(0xfc)), (&[0xfd, 0xfd, 0x00][..], Some(0xfd)), (&[0xfd, 0xfc, 0x00][..], None)] {
            let mut reader = Reader::new(bytes);
            assert_eq!(reader.read_compact_size().ok(), expected);
        }
        let mut too_large = vec![0xfe];
        too_large.extend_from_slice(&0x0200_0001u32.to_le_bytes());
        assert!(Reader::new(&too_large).read_compact_size().is_err());
    }

    #[test]
    fn empty_transaction_quirk() {
        // version 1, input count 0, flag 0, lock time 0: decodes to a transaction with nothing in it.
        let bytes = hex_decode("01000000000000000000").unwrap();
        let tx = deserialize_transaction(&bytes).unwrap();
        assert!(tx.inputs.is_empty() && tx.outputs.is_empty());
    }
}
```
