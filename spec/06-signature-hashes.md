# 06. Signature hashes

A signature does not sign a transaction directly. It signs a 32-byte *signature hash* ("sighash") computed from the transaction, the input being spent, and a *hash type* that selects which parts of the transaction are covered. There are three algorithms:

| Algorithm | Used by | Defined in |
|---|---|---|
| Legacy | `Base` scripts | section 6.2 |
| BIP143 | `WitnessV0` scripts | section 6.3 |
| BIP341 | `Taproot` key path and `Tapscript` | section 6.4 |

## 6.1 Hash types

| Name | Value | Meaning of the low bits (legacy and BIP143 use `hash_type & 0x1f`) |
|---|---|---|
| `SIGHASH_ALL` | 1 | All outputs are signed |
| `SIGHASH_NONE` | 2 | No outputs are signed |
| `SIGHASH_SINGLE` | 3 | Only the output with the same index as the input is signed |
| `SIGHASH_ANYONECANPAY` | 0x80 (flag) | Only the input being signed is covered, not the other inputs |
| `SIGHASH_DEFAULT` | 0 | Taproot only: same as `SIGHASH_ALL`, signalled by a 64-byte signature |

In legacy and BIP143 hashing, **any** hash type byte is valid. A base type other than 2 or 3 (including 0 and values like 0x41 or 0x65, all of which appear in real blocks) behaves like `SIGHASH_ALL`, and the full byte, zero-extended to 32 bits, is included in the hash. Restricting hash types to the defined values (`STRICTENC`) is policy.

In taproot hashing, only 0x00, 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are valid; any other value makes the signature check fail.

```rust
pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: i32 = 1;
pub const SIGHASH_NONE: i32 = 2;
pub const SIGHASH_SINGLE: i32 = 3;
pub const SIGHASH_ANYONECANPAY: i32 = 0x80;
```

## 6.2 Legacy signature hash

### 6.2.1 Removing the signature from the script code

Before hashing, legacy signature checking removes from the script code every occurrence of the signature pushed in canonical form (chapter 05 section 5.5.3). The removal is a quirky byte-level procedure (Core: `FindAndDelete`, `src/script/interpreter.cpp`):

- Walk the script operation by operation. At the start of each operation, while the remaining bytes begin with the pattern, skip the pattern (repeatedly, so consecutive copies are all removed). Matches are only recognised at operation boundaries.
- If the script becomes unparsable, stop walking and keep the rest of the bytes unchanged.
- An empty pattern removes nothing.

```rust
/// Removes every operation-aligned occurrence of `pattern` from `script`. Core: `FindAndDelete`.
pub fn find_and_delete(script: &[u8], pattern: &[u8]) -> Vec<u8> {
    if pattern.is_empty() {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut found = false;
    let mut pc = 0usize; // current position
    let mut pc2 = 0usize; // start of bytes not yet copied
    loop {
        result.extend_from_slice(&script[pc2..pc]);
        while script.len() - pc >= pattern.len() && &script[pc..pc + pattern.len()] == pattern {
            pc += pattern.len();
            found = true;
        }
        pc2 = pc;
        if get_op(script, &mut pc).is_none() {
            break;
        }
    }
    if found {
        result.extend_from_slice(&script[pc2..]);
        result
    } else {
        script.to_vec()
    }
}
```

When `get_op` fails at the end of the script, `pc` is the script length and `pc2` was set just before the call, so the final copy appends nothing beyond what remains; when it fails on a malformed operation, `pc2` still points at the start of that operation, so the malformed tail is kept intact.

### 6.2.2 Serializing the script code

The script code is serialized with every `OP_CODESEPARATOR` removed: a CompactSize of (length minus the number of separators found while parsing), followed by the bytes between separators (Core: `CTransactionSignatureSerializer::SerializeScriptCode`). If the script code has a malformed operation, separators after it are not found and the bytes written stop at the position where parsing failed, so the length prefix can then disagree with the bytes that follow. That only happens for scripts that fail anyway, because execution aborts when it reaches the malformed operation (chapter 05), but the reference reproduces it exactly.

```rust
/// Core: `CTransactionSignatureSerializer::SerializeScriptCode`.
fn serialize_script_code_legacy(out: &mut Vec<u8>, script_code: &[u8]) {
    let mut it = 0usize;
    let mut separators = 0usize;
    while let Some(op) = get_op(script_code, &mut it) {
        if op.opcode == OP_CODESEPARATOR {
            separators += 1;
        }
    }
    write_compact_size(out, (script_code.len() - separators) as u64);
    let mut it = 0usize;
    let mut begin = 0usize;
    while let Some(op) = get_op(script_code, &mut it) {
        if op.opcode == OP_CODESEPARATOR {
            out.extend_from_slice(&script_code[begin..it - 1]);
            begin = it;
        }
    }
    if begin != script_code.len() {
        out.extend_from_slice(&script_code[begin..it]);
    }
}
```

### 6.2.3 The legacy algorithm

For input `n_in` with hash type `hash_type` (a 32-bit value; from a signature it is 0 to 255):

1. If `hash_type & 0x1f == SIGHASH_SINGLE` and `n_in` is not a valid output index, the result is the 32-byte value `01 00 00 ... 00` (the number 1 as a little-endian 256-bit integer). This is a historical bug; the value is then used as the ECDSA message, so anyone who can sign that constant can spend such inputs.
2. Otherwise serialize a modified copy of the transaction:
   - the version;
   - the inputs: all of them, or with `SIGHASH_ANYONECANPAY` only the input being signed. Each input is its outpoint, then a script (the serialized script code from 6.2.2 for the input being signed, an empty script for all others), then its sequence, except that with `SIGHASH_NONE` or `SIGHASH_SINGLE` the other inputs' sequences are written as 0;
   - the outputs: none for `SIGHASH_NONE`; for `SIGHASH_SINGLE` the first `n_in + 1` outputs, where every output other than number `n_in` is replaced by an empty output with value -1 (`ff ff ff ff ff ff ff ff 00`); otherwise all outputs;
   - the lock time;
3. append `hash_type` as a 4-byte little-endian integer, and return `sha256d` of the whole.

(Core: `SignatureHash` and `CTransactionSignatureSerializer`, `src/script/interpreter.cpp`.)

```rust
fn legacy_sighash(script_code: &[u8], tx: &Transaction, n_in: usize, hash_type: i32) -> Hash256 {
    let base_type = hash_type & 0x1f;
    if base_type == SIGHASH_SINGLE && n_in >= tx.outputs.len() {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }
    let anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    let hash_single = base_type == SIGHASH_SINGLE;
    let hash_none = base_type == SIGHASH_NONE;

    let mut data = Vec::new();
    data.extend_from_slice(&tx.version.to_le_bytes());
    let input_count = if anyone_can_pay { 1 } else { tx.inputs.len() };
    write_compact_size(&mut data, input_count as u64);
    for position in 0..input_count {
        let index = if anyone_can_pay { n_in } else { position };
        let input = &tx.inputs[index];
        data.extend_from_slice(&input.prevout.txid);
        data.extend_from_slice(&input.prevout.vout.to_le_bytes());
        if index != n_in {
            write_compact_size(&mut data, 0);
        } else {
            serialize_script_code_legacy(&mut data, script_code);
        }
        if index != n_in && (hash_single || hash_none) {
            data.extend_from_slice(&0i32.to_le_bytes());
        } else {
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
    }
    let output_count = if hash_none {
        0
    } else if hash_single {
        n_in + 1
    } else {
        tx.outputs.len()
    };
    write_compact_size(&mut data, output_count as u64);
    for index in 0..output_count {
        if hash_single && index != n_in {
            serialize_txout(&mut data, &TxOut { value: -1, script_pubkey: Vec::new() });
        } else {
            serialize_txout(&mut data, &tx.outputs[index]);
        }
    }
    data.extend_from_slice(&tx.lock_time.to_le_bytes());
    data.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&data)
}
```

## 6.3 BIP143 signature hash (segwit version 0)

BIP143 fixes the quadratic hashing and the missing amount commitment of the legacy algorithm. The preimage is:

```text
version:u32
hash_prevouts:32     sha256d(all outpoints)           zero if ANYONECANPAY
hash_sequence:32     sha256d(all sequences)           zero if ANYONECANPAY, SINGLE or NONE
outpoint:36          of this input
script_code          var_bytes, as executed (no FindAndDelete, no separator removal)
amount:i64           of the output being spent
sequence:u32         of this input
hash_outputs:32      sha256d(all outputs)             for base types other than SINGLE and NONE
                     sha256d(output n_in)             for SINGLE when n_in < number of outputs
                     zero otherwise
lock_time:u32
hash_type:i32
```

and the signature hash is `sha256d` of the preimage. Note that `SIGHASH_SINGLE` without a matching output does **not** produce the legacy "1" value here; it simply hashes zeros for `hash_outputs`. The script code is the executing script from the last executed `OP_CODESEPARATOR` (for pay-to-witness-public-key-hash, the implied script `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`, chapter 07). (Core: `SignatureHash` with `SigVersion::WITNESS_V0`.)

Hashes of whole-transaction data are shared by every input, so they are computed once per transaction. Taproot (section 6.4) uses the same data hashed once (single SHA-256) where BIP143 hashes it twice.

```rust
/// Per-transaction hashes for BIP143 and BIP341. Core: `PrecomputedTransactionData`.
#[derive(Clone, Debug)]
pub struct PrecomputedTx {
    /// SHA256 of all outpoints.
    pub prevouts_single: Hash256,
    /// SHA256 of all sequences.
    pub sequences_single: Hash256,
    /// SHA256 of all serialized outputs.
    pub outputs_single: Hash256,
    /// SHA256 of all spent amounts (BIP341).
    pub spent_amounts_single: Hash256,
    /// SHA256 of all spent scriptPubKeys, each with its CompactSize length (BIP341).
    pub spent_scripts_single: Hash256,
}

impl PrecomputedTx {
    pub fn new(tx: &Transaction, spent_outputs: &[TxOut]) -> PrecomputedTx {
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for input in &tx.inputs {
            prevouts.extend_from_slice(&input.prevout.txid);
            prevouts.extend_from_slice(&input.prevout.vout.to_le_bytes());
            sequences.extend_from_slice(&input.sequence.to_le_bytes());
        }
        let mut outputs = Vec::new();
        for output in &tx.outputs {
            serialize_txout(&mut outputs, output);
        }
        let mut amounts = Vec::new();
        let mut scripts = Vec::new();
        for spent in spent_outputs {
            amounts.extend_from_slice(&spent.value.to_le_bytes());
            write_var_bytes(&mut scripts, &spent.script_pubkey);
        }
        PrecomputedTx {
            prevouts_single: sha256(&prevouts),
            sequences_single: sha256(&sequences),
            outputs_single: sha256(&outputs),
            spent_amounts_single: sha256(&amounts),
            spent_scripts_single: sha256(&scripts),
        }
    }
}

fn bip143_sighash(script_code: &[u8], tx: &Transaction, n_in: usize, hash_type: i32, amount: i64, pre: &PrecomputedTx) -> Hash256 {
    let base_type = hash_type & 0x1f;
    let anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    let mut hash_prevouts = ZERO_HASH;
    let mut hash_sequence = ZERO_HASH;
    let mut hash_outputs = ZERO_HASH;
    if !anyone_can_pay {
        hash_prevouts = sha256(&pre.prevouts_single);
    }
    if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        hash_sequence = sha256(&pre.sequences_single);
    }
    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        hash_outputs = sha256(&pre.outputs_single);
    } else if base_type == SIGHASH_SINGLE && n_in < tx.outputs.len() {
        let mut output = Vec::new();
        serialize_txout(&mut output, &tx.outputs[n_in]);
        hash_outputs = sha256d(&output);
    }
    let input = &tx.inputs[n_in];
    let mut data = Vec::new();
    data.extend_from_slice(&tx.version.to_le_bytes());
    data.extend_from_slice(&hash_prevouts);
    data.extend_from_slice(&hash_sequence);
    data.extend_from_slice(&input.prevout.txid);
    data.extend_from_slice(&input.prevout.vout.to_le_bytes());
    write_var_bytes(&mut data, script_code);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&input.sequence.to_le_bytes());
    data.extend_from_slice(&hash_outputs);
    data.extend_from_slice(&tx.lock_time.to_le_bytes());
    data.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&data)
}

/// The ECDSA signature hash for `Base` and `WitnessV0`. Core: `SignatureHash`.
pub fn signature_hash(script_code: &[u8], tx: &Transaction, n_in: usize, hash_type: i32, amount: i64, sigversion: SigVersion, pre: &PrecomputedTx) -> Hash256 {
    assert!(n_in < tx.inputs.len());
    match sigversion {
        SigVersion::WitnessV0 => bip143_sighash(script_code, tx, n_in, hash_type, amount, pre),
        _ => legacy_sighash(script_code, tx, n_in, hash_type),
    }
}
```

## 6.4 BIP341 signature hash (taproot)

The taproot signature hash is `tagged_hash("TapSighash", 0x00 || SigMsg)`, where `0x00` is the *epoch* and `SigMsg` is:

```text
hash_type:u8
version:u32
lock_time:u32
if not ANYONECANPAY:
    sha_prevouts:32         SHA256 of all outpoints
    sha_amounts:32          SHA256 of all spent amounts (i64 each)
    sha_scriptpubkeys:32    SHA256 of all spent scriptPubKeys (var_bytes each)
    sha_sequences:32        SHA256 of all sequences
if output type is ALL (hash type 0 or base type 1):
    sha_outputs:32          SHA256 of all outputs
spend_type:u8               2 * ext_flag + (1 if an annex is present)
if ANYONECANPAY:
    outpoint:36, spent output (amount:i64, var_bytes script), sequence:u32   of this input
else:
    input_index:u32
if annex present:
    sha_annex:32            SHA256 of var_bytes(annex)
if output type is SINGLE:
    sha_single_output:32    SHA256 of output input_index (fails if there is no such output)
if Tapscript (ext_flag = 1):
    tapleaf_hash:32
    key_version:u8          always 0
    codesep_pos:u32         opcode position of the last executed OP_CODESEPARATOR, or 0xffffffff
```

The hash type must be one of 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83; otherwise there is no signature hash and the signature check fails. The output type is the low two bits of the hash type (with 0 meaning ALL), and ANYONECANPAY is bit 7. (Core: `SignatureHashSchnorr`, `src/script/interpreter.cpp`.)

```rust
/// BIP341/BIP342 signature hash. Returns `None` for an invalid hash type or a SIGHASH_SINGLE
/// without a matching output. Core: `SignatureHashSchnorr`.
pub fn signature_hash_schnorr(
    execdata: &ExecData,
    tx: &Transaction,
    in_pos: usize,
    hash_type: u8,
    sigversion: SigVersion,
    spent_outputs: &[TxOut],
    pre: &PrecomputedTx,
) -> Option<Hash256> {
    let ext_flag: u8 = match sigversion {
        SigVersion::Taproot => 0,
        SigVersion::Tapscript => 1,
        _ => panic!("signature_hash_schnorr requires a taproot sigversion"),
    };
    assert!(in_pos < tx.inputs.len());
    assert!(spent_outputs.len() == tx.inputs.len());
    let output_type = if hash_type == SIGHASH_DEFAULT { SIGHASH_ALL as u8 } else { hash_type & 0x03 };
    let input_type = hash_type & 0x80;
    if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
        return None;
    }
    let mut msg = Vec::new();
    msg.push(0x00); // epoch
    msg.push(hash_type);
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());
    if input_type != SIGHASH_ANYONECANPAY as u8 {
        msg.extend_from_slice(&pre.prevouts_single);
        msg.extend_from_slice(&pre.spent_amounts_single);
        msg.extend_from_slice(&pre.spent_scripts_single);
        msg.extend_from_slice(&pre.sequences_single);
    }
    if output_type == SIGHASH_ALL as u8 {
        msg.extend_from_slice(&pre.outputs_single);
    }
    let have_annex = execdata.annex_hash.is_some();
    msg.push((ext_flag << 1) + have_annex as u8);
    if input_type == SIGHASH_ANYONECANPAY as u8 {
        let input = &tx.inputs[in_pos];
        msg.extend_from_slice(&input.prevout.txid);
        msg.extend_from_slice(&input.prevout.vout.to_le_bytes());
        serialize_txout(&mut msg, &spent_outputs[in_pos]);
        msg.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        msg.extend_from_slice(&(in_pos as u32).to_le_bytes());
    }
    if let Some(annex_hash) = execdata.annex_hash {
        msg.extend_from_slice(&annex_hash);
    }
    if output_type == SIGHASH_SINGLE as u8 {
        if in_pos >= tx.outputs.len() {
            return None;
        }
        let mut output = Vec::new();
        serialize_txout(&mut output, &tx.outputs[in_pos]);
        msg.extend_from_slice(&sha256(&output));
    }
    if sigversion == SigVersion::Tapscript {
        msg.extend_from_slice(&execdata.tapleaf_hash.expect("tapleaf hash is set for tapscript"));
        msg.push(0x00); // key_version
        msg.extend_from_slice(&execdata.codeseparator_pos.to_le_bytes());
    }
    Some(tagged_hash("TapSighash", &msg))
}
```

## 6.5 Notes for implementers

- The legacy and BIP143 algorithms take the hash type as a signed 32-bit value because Bitcoin Core's function does; in consensus it always comes from one signature byte (0 to 255). Test vectors exercise the full 32-bit range, including negative values whose low bits still select the behaviour above.
- A signature hash cache (Bitcoin Core keeps one per input, keyed by the hash type class and the script code) must be invisible: it may only reuse a prefix of the preimage that is byte-for-byte identical.
- Taproot's `sha_annex` covers the annex *including* its CompactSize length; the annex itself includes its leading `0x50` byte.
