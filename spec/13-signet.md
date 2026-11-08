# 13. Signet block solutions

On a signet (BIP325), every block except genesis must also be *signed*: its coinbase carries a solution that satisfies the network's challenge script. The check is part of the context-free block checks (chapter 10) and runs right after the proof-of-work check; a failure is `bad-signet-blksig`. (Core: `CheckSignetBlockSolution`, `SignetTxs::Create`, `src/signet.cpp`.)

## 13.1 Where the solution lives

The solution is carried inside the block's witness commitment output (chapter 10): a block without a commitment output has no valid solution. The commitment output's script is scanned operation by operation; the first push whose data is longer than 4 bytes and starts with the *signet header* `ec c7 da a2` holds the solution in the bytes after the header.

To compute what the signature commits to, the coinbase is modified: its commitment script is rebuilt operation by operation, with every push re-encoded canonically (`push_data`, chapter 04) and the solution push truncated to the 4-byte header, and every operation without push data written as its opcode byte alone. Parsing stops silently at a malformed operation, which drops the rest of the script. If no solution is found, the coinbase is left unmodified and the solution is empty.

The solution bytes must decode as exactly a `script_sig` (a byte vector) followed by a witness stack (a vector of byte vectors), with no bytes left over; otherwise the block is invalid.

```rust
/// Core: `SIGNET_HEADER`.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Returns (rebuilt script, solution) if a solution push is found. Core: `FetchAndClearCommitmentSection`.
fn fetch_and_clear_commitment_section(script: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut replacement = Vec::new();
    let mut solution = None;
    let mut pos = 0;
    while let Some(op) = get_op(script, &mut pos) {
        if !op.data.is_empty() {
            if solution.is_none() && op.data.len() > SIGNET_HEADER.len() && op.data[..4] == SIGNET_HEADER {
                solution = Some(op.data[4..].to_vec());
                replacement.extend_from_slice(&push_data(&SIGNET_HEADER));
            } else {
                replacement.extend_from_slice(&push_data(op.data));
            }
        } else {
            replacement.push(op.opcode);
        }
    }
    solution.map(|s| (replacement, s))
}
```

## 13.2 The virtual transactions

The challenge is checked by verifying a virtual transaction pair, as in BIP325:

- `to_spend`: version 0, lock time 0, one input (null outpoint, sequence 0, `script_sig` = `OP_0` followed by a push of the 72-byte *block data*), one output (value 0, `script_pubkey` = the challenge).
- `to_sign`: version 0, lock time 0, one input spending output 0 of `to_spend` (sequence 0, with the solution's `script_sig` and witness), one output (value 0, `script_pubkey` = `OP_RETURN`).

The block data is `version:i32 || prev_block:32 || signet_merkle_root:32 || time:u32`, where the signet merkle root is the merkle root (without the mutation check) over the *modified* coinbase's txid followed by the other transactions' txids. The nonce and bits are not signed, so a signed block can still be mined.

The input of `to_sign` is verified with `verify_script` (chapter 07) under the flags `P2SH | WITNESS | DERSIG | NULLDUMMY`, spending an amount of 0. The genesis block needs no solution.

```rust
/// Core: `CheckSignetBlockSolution`, `SignetTxs::Create`.
pub fn check_signet_block_solution(block: &Block, params: &ConsensusParams) -> bool {
    if block.hash() == params.genesis_hash {
        return true;
    }
    let challenge = params.signet_challenge.as_ref().expect("signet parameters");
    if block.transactions.is_empty() {
        return false;
    }
    let commitment_index = match witness_commitment_index(block) {
        Some(index) => index,
        None => return false,
    };
    let mut modified_coinbase = block.transactions[0].clone();
    let mut script_sig = Vec::new();
    let mut witness = Vec::new();
    if let Some((replacement, solution)) = fetch_and_clear_commitment_section(&modified_coinbase.outputs[commitment_index].script_pubkey) {
        modified_coinbase.outputs[commitment_index].script_pubkey = replacement;
        let mut reader = Reader::new(&solution);
        let parsed = (|| -> Result<(Vec<u8>, Vec<Vec<u8>>), DecodeError> {
            let script_sig = reader.read_var_bytes()?;
            let count = reader.read_compact_size()?;
            let mut stack = Vec::new();
            for _ in 0..count {
                stack.push(reader.read_var_bytes()?);
            }
            Ok((script_sig, stack))
        })();
        match parsed {
            Ok((s, w)) if reader.remaining() == 0 => {
                script_sig = s;
                witness = w;
            }
            _ => return false,
        }
    }
    let mut leaves = vec![modified_coinbase.txid()];
    for tx in block.transactions.iter().skip(1) {
        leaves.push(tx.txid());
    }
    let signet_merkle_root = compute_merkle_root(leaves).0;
    let mut block_data = Vec::with_capacity(72);
    block_data.extend_from_slice(&block.header.version.to_le_bytes());
    block_data.extend_from_slice(&block.header.prev_block);
    block_data.extend_from_slice(&signet_merkle_root);
    block_data.extend_from_slice(&block.header.time.to_le_bytes());

    let mut to_spend_script_sig = vec![OP_0];
    to_spend_script_sig.extend_from_slice(&push_data(&block_data));
    let to_spend = Transaction {
        version: 0,
        inputs: vec![TxIn { prevout: OutPoint::null(), script_sig: to_spend_script_sig, sequence: 0, witness: Vec::new() }],
        outputs: vec![TxOut { value: 0, script_pubkey: challenge.clone() }],
        lock_time: 0,
    };
    let to_sign = Transaction {
        version: 0,
        inputs: vec![TxIn { prevout: OutPoint { txid: to_spend.txid(), vout: 0 }, script_sig, sequence: 0, witness }],
        outputs: vec![TxOut { value: 0, script_pubkey: vec![OP_RETURN] }],
        lock_time: 0,
    };
    let spent = vec![to_spend.outputs[0].clone()];
    let precomputed = PrecomputedTx::new(&to_sign, &spent);
    let flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_DERSIG | VERIFY_NULLDUMMY;
    verify_input(&to_sign, 0, &spent, &precomputed, flags).is_ok()
}
```
