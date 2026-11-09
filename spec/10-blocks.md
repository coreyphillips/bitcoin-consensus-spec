# 10. Blocks

A block is valid if its header is valid in its position in the chain, its body is consistent with its header, and its transactions, applied in order to the UTXO set left by its ancestors, satisfy every transaction rule. This chapter defines those checks in the four groups Bitcoin Core uses, because the grouping decides what a node may remember about a failure (chapter 11):

| Group | Needs | Core function |
|---|---|---|
| Header, context-free | the header | `CheckBlockHeader` |
| Header, contextual | the header and its ancestors | `ContextualCheckBlockHeader` |
| Body, context-free | the block | `CheckBlock` |
| Body, contextual | the block and its ancestors' headers | `ContextualCheckBlock` |
| Connection | the block and the UTXO set of its parent | `ConnectBlock` |

## 10.1 Block subsidy

The coinbase may claim the subsidy plus all fees. The subsidy starts at 50 BTC and halves (by integer right shift) every `subsidy_halving_interval` blocks; after 64 halvings it is 0. (Core: `GetBlockSubsidy`, `src/validation.cpp`.)

```rust
/// Core: `GetBlockSubsidy`.
pub fn block_subsidy(height: i32, params: &ConsensusParams) -> i64 {
    let halvings = height / params.subsidy_halving_interval;
    if halvings >= 64 {
        return 0;
    }
    (50 * COIN) >> halvings
}
```

## 10.2 Merkle trees

The header's merkle root commits to the transaction ids. The tree is built by repeatedly hashing pairs with `sha256d(left || right)`; a level with an odd number of entries duplicates its last entry. A block with no transactions has the root 0.

Because of the duplication rule, two different transaction lists can have the same root: a list whose last two entries at some level are equal hashes to the same root as the list without the duplicate (CVE-2012-2459). Bitcoin Core therefore reports the tree as **mutated** if, at any level, an entry at an even position equals the entry after it. A mutated tree means the received body is not the one the header commits to. (Core: `ComputeMerkleRoot`, `BlockMerkleRoot`, `src/consensus/merkle.cpp`.)

The *witness merkle root* (BIP141) is built the same way over the witness transaction ids, with the coinbase's replaced by 32 zero bytes. Its mutation flag is not used.

```rust
/// Returns (root, mutated). Core: `ComputeMerkleRoot`.
pub fn compute_merkle_root(mut hashes: Vec<Hash256>) -> (Hash256, bool) {
    let mut mutated = false;
    while hashes.len() > 1 {
        let mut pos = 0;
        while pos + 1 < hashes.len() {
            if hashes[pos] == hashes[pos + 1] {
                mutated = true;
            }
            pos += 2;
        }
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().unwrap());
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| {
                let mut data = [0u8; 64];
                data[..32].copy_from_slice(&pair[0]);
                data[32..].copy_from_slice(&pair[1]);
                sha256d(&data)
            })
            .collect();
    }
    match hashes.first() {
        Some(root) => (*root, mutated),
        None => (ZERO_HASH, mutated),
    }
}

/// Core: `BlockMerkleRoot`.
pub fn block_merkle_root(block: &Block) -> (Hash256, bool) {
    compute_merkle_root(block.transactions.iter().map(|tx| tx.txid()).collect())
}

/// Core: `BlockWitnessMerkleRoot`.
pub fn block_witness_merkle_root(block: &Block) -> Hash256 {
    let mut leaves = vec![ZERO_HASH];
    for tx in block.transactions.iter().skip(1) {
        leaves.push(tx.wtxid());
    }
    compute_merkle_root(leaves).0
}
```

## 10.3 The witness commitment

From segwit activation, a block containing witness data must commit to it in its coinbase (BIP141). The *commitment output* is the **last** coinbase output whose script is at least 38 bytes long and starts with `6a 24 aa 21 a9 ed` (`OP_RETURN`, a 36-byte push, and the magic `aa21a9ed`). Bytes 6 to 37 of that script are the commitment: `sha256d(witness_merkle_root || witness_reserved_value)`, where the *witness reserved value* is the coinbase input's witness, which must then consist of exactly one 32-byte item. (Core: `GetWitnessCommitmentIndex`, `src/consensus/validation.h`; `CheckWitnessMalleation`, `src/validation.cpp`.)

The rules, all of which produce `Mutated` failures because witness data is not covered by the block hash:

- If segwit is active at the block's height and a commitment output exists: the coinbase witness must be exactly one 32-byte item (`bad-witness-nonce-size`), and the commitment must match (`bad-witness-merkle-match`). Then the block is accepted with respect to witnesses.
- Otherwise (segwit not active, or no commitment output): no transaction in the block may have witness data (`unexpected-witness`).

```rust
/// Core: `MINIMUM_WITNESS_COMMITMENT`.
pub const MINIMUM_WITNESS_COMMITMENT: usize = 38;

/// Index of the commitment output in the coinbase, if any. Core: `GetWitnessCommitmentIndex`.
pub fn witness_commitment_index(block: &Block) -> Option<usize> {
    let coinbase = block.transactions.first()?;
    let mut position = None;
    for (index, output) in coinbase.outputs.iter().enumerate() {
        let script = &output.script_pubkey;
        if script.len() >= MINIMUM_WITNESS_COMMITMENT && script[..6] == [OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed] {
            position = Some(index);
        }
    }
    position
}

/// Core: `CheckWitnessMalleation`.
pub fn check_witness_malleation(block: &Block, expect_witness_commitment: bool) -> Result<(), Failure> {
    if expect_witness_commitment {
        if let Some(position) = witness_commitment_index(block) {
            let stack = &block.transactions[0].inputs[0].witness;
            if stack.len() != 1 || stack[0].len() != 32 {
                return Err(mutated("bad-witness-nonce-size"));
            }
            let mut data = block_witness_merkle_root(block).to_vec();
            data.extend_from_slice(&stack[0]);
            let commitment = sha256d(&data);
            if commitment[..] != block.transactions[0].outputs[position].script_pubkey[6..38] {
                return Err(mutated("bad-witness-merkle-match"));
            }
            return Ok(());
        }
    }
    if block.transactions.iter().any(|tx| tx.has_witness()) {
        return Err(mutated("unexpected-witness"));
    }
    Ok(())
}
```

## 10.4 Header checks

**Context-free** (Core: `CheckBlockHeader`): proof of work (chapter 09) against the header's own `bits`, else `high-hash`.

**Contextual**, given the parent P at height h - 1 (Core: `ContextualCheckBlockHeader`):

1. `bits` must equal the required value of chapter 09 (`next_work_required`), else `bad-diffbits`.
2. The timestamp must be **greater than** P's median time past, else `time-too-old`.
3. Under BIP94, if h is a multiple of the adjustment interval, the timestamp must be at least `time(P) - 600`, else `time-timewarp-attack`.
4. The timestamp must not exceed the current time plus two hours (`MAX_FUTURE_BLOCK_TIME = 7200` seconds), else `time-too-new`. This failure is `Temporary`: the same header becomes acceptable later. "Current time" is the node's local clock (Bitcoin Core v32.1 no longer adjusts it by peers' clocks).
5. The version, read as a **signed** 32-bit integer, must be at least 2 from the BIP34 height, at least 3 from the BIP66 height, and at least 4 from the BIP65 height, else `bad-version(0x%08x)` (the version as 8 lowercase hex digits). A version with the top bit set is negative and therefore fails all three.

There is no upper bound on timestamps relative to the parent (other than the two-hour rule), and no checkpoint rule: Bitcoin Core v32.1 has no checkpoints.

```rust
/// Core: `MAX_FUTURE_BLOCK_TIME`, `src/chain.h`.
pub const MAX_FUTURE_BLOCK_TIME: i64 = 2 * 60 * 60;

/// Core: `CheckBlockHeader`.
pub fn check_block_header(header: &BlockHeader, params: &ConsensusParams) -> Result<(), Failure> {
    if !check_proof_of_work(&header.hash(), header.bits, params.pow_limit) {
        return Err(invalid("high-hash"));
    }
    Ok(())
}

/// Core: `ContextualCheckBlockHeader`. `parent` is the entry of the block's parent in `tree`.
pub fn contextual_check_block_header(header: &BlockHeader, parent: &BlockEntry, tree: &BlockTree, params: &ConsensusParams, now: i64) -> Result<(), Failure> {
    let height = parent.height + 1;
    let ancestor = |h: i32| tree.ancestor(&parent.hash, h).expect("ancestor exists").header;
    if header.bits != next_work_required(params, parent.height, &parent.header, &ancestor, header.time) {
        return Err(invalid("bad-diffbits"));
    }
    if header.time as i64 <= parent.median_time_past {
        return Err(invalid("time-too-old"));
    }
    if params.enforce_bip94 && height as i64 % params.difficulty_adjustment_interval() == 0 {
        if (header.time as i64) < parent.header.time as i64 - MAX_TIMEWARP {
            return Err(invalid("time-timewarp-attack"));
        }
    }
    if header.time as i64 > now + MAX_FUTURE_BLOCK_TIME {
        return Err(temporary("time-too-new"));
    }
    if (header.version < 2 && height >= params.bip34_height)
        || (header.version < 3 && height >= params.bip66_height)
        || (header.version < 4 && height >= params.bip65_height)
    {
        return Err(invalid(&format!("bad-version(0x{:08x})", header.version as u32)));
    }
    Ok(())
}
```

## 10.5 Body checks

**Context-free**, in this order (Core: `CheckBlock`):

1. Header proof of work (`high-hash`).
2. On signet, the block solution (chapter 13), else `bad-signet-blksig`.
3. The merkle root must match the header (`bad-txnmrklroot`) and the tree must not be mutated (`bad-txns-duplicate`). Both are `Mutated` failures.
4. The block must have at least one transaction, at most 1,000,000 transactions (4 times the count is at most 4,000,000), and its stripped size times 4 must be at most 4,000,000 (`bad-blk-length`).
5. The first transaction must be a coinbase (`bad-cb-missing`) and no other may be (`bad-cb-multiple`).
6. Every transaction must pass `check_transaction` (chapter 08), with its reason.
7. The legacy sigop count of all transactions times 4 must be at most 80,000 (`bad-blk-sigops`). (The connection checks count more precisely; this early check is implied by them but reports the same reason earlier.)

These checks do not look at witness data: witness data is only trustworthy after the commitment check in the contextual group.

```rust
/// Core: `CheckBlock`.
pub fn check_block(block: &Block, params: &ConsensusParams) -> Result<(), Failure> {
    check_block_header(&block.header, params)?;
    if params.signet_challenge.is_some() && !check_signet_block_solution(block, params) {
        return Err(invalid("bad-signet-blksig"));
    }
    let (root, is_mutated) = block_merkle_root(block);
    if root != block.header.merkle_root {
        return Err(mutated("bad-txnmrklroot"));
    }
    if is_mutated {
        return Err(mutated("bad-txns-duplicate"));
    }
    if block.transactions.is_empty()
        || block.transactions.len() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        || block.stripped_size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    {
        return Err(invalid("bad-blk-length"));
    }
    if !block.transactions[0].is_coinbase() {
        return Err(invalid("bad-cb-missing"));
    }
    if block.transactions.iter().skip(1).any(|tx| tx.is_coinbase()) {
        return Err(invalid("bad-cb-multiple"));
    }
    for tx in &block.transactions {
        check_transaction(tx).map_err(invalid)?;
    }
    let sigops: u64 = block.transactions.iter().map(legacy_sig_op_count).sum();
    if sigops as i64 * WITNESS_SCALE_FACTOR as i64 > MAX_BLOCK_SIGOPS_COST {
        return Err(invalid("bad-blk-sigops"));
    }
    Ok(())
}
```

**Contextual**, for a block at height h with parent P (Core: `ContextualCheckBlock`):

1. Every transaction must be final (chapter 08) at height h and time t, where t is P's median time past from the CSV height on (BIP113), and the block's own timestamp before it (`bad-txns-nonfinal`).
2. From the BIP34 height on, the coinbase `script_sig` must begin with `push_int(h)` (chapter 04): `OP_0` for 0, `OP_1` to `OP_16` for 1 to 16, otherwise a minimal push of the height as a script number (`bad-cb-height`).
3. The witness rules of section 10.3, with the commitment expected from the segwit height on.
4. The block weight must be at most 4,000,000 (`bad-blk-weight`). This is checked only after the witness commitment, so that padding witness data (which does not change the block hash) produces a `Mutated` failure instead of marking a valid header invalid.

```rust
/// Core: `ContextualCheckBlock`. `parent` is `None` only for the genesis block.
pub fn contextual_check_block(block: &Block, parent: Option<&BlockEntry>, params: &ConsensusParams) -> Result<(), Failure> {
    let height = parent.map_or(0, |p| p.height + 1);
    let lock_time_cutoff = match parent {
        Some(p) if height >= params.csv_height => p.median_time_past,
        _ => block.header.time as i64,
    };
    for tx in &block.transactions {
        if !is_final_tx(tx, height, lock_time_cutoff) {
            return Err(invalid("bad-txns-nonfinal"));
        }
    }
    if height >= params.bip34_height {
        let expect = push_int(height as i64);
        let script_sig = &block.transactions[0].inputs[0].script_sig;
        if script_sig.len() < expect.len() || script_sig[..expect.len()] != expect[..] {
            return Err(invalid("bad-cb-height"));
        }
    }
    check_witness_malleation(block, height >= params.segwit_height)?;
    if block.weight() > MAX_BLOCK_WEIGHT {
        return Err(invalid("bad-blk-weight"));
    }
    Ok(())
}
```

## 10.6 Script flags per block

Script verification (chapter 07) runs with these flags for a block at height h with hash H (Core: `GetBlockScriptFlags`, `src/validation.cpp`):

- `P2SH`, `WITNESS` and `TAPROOT`, unless H is listed in the network's script flag exceptions (chapter 12), in which case the listed flags replace these three. Mainnet has two exceptions: block 170060 (`00000000000002dc...ac4f9c22`, the one historical block that violates BIP16) gets no flags, and block 692261 (`0000000000000000000f14c3...e395ad`, which spent a taproot output before taproot activated) gets `P2SH | WITNESS`. Testnet3 has one BIP16 exception.
- `DERSIG` from the BIP66 height, `CHECKLOCKTIMEVERIFY` from the BIP65 height, `CHECKSEQUENCEVERIFY` from the CSV height, `NULLDUMMY` from the segwit height.

Applying P2SH, segwit and taproot rules to all blocks, rather than from their historical activation points, gives the same result on the real chain (Bitcoin Core verified that no other historical block violates them) and is simpler. It means outputs that look like witness programs were already subject to witness rules before segwit activated, and that witness sigops are counted for every block.

```rust
/// Core: `GetBlockScriptFlags`.
pub fn block_script_flags(hash: &Hash256, height: i32, params: &ConsensusParams) -> ScriptFlags {
    let mut flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT;
    if let Some((_, exception)) = params.script_flag_exceptions.iter().find(|(h, _)| h == hash) {
        flags = *exception;
    }
    if height >= params.bip66_height {
        flags |= VERIFY_DERSIG;
    }
    if height >= params.bip65_height {
        flags |= VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if height >= params.csv_height {
        flags |= VERIFY_CHECKSEQUENCEVERIFY;
    }
    if height >= params.segwit_height {
        flags |= VERIFY_NULLDUMMY;
    }
    flags
}
```

## 10.7 BIP30: no overwriting of unspent outputs

Before BIP34, two coinbase transactions could be identical and so have the same txid. That happened twice on mainnet: the coinbases of blocks 91842 and 91880 duplicate those of blocks 91812 and 91722, and in each case the later output replaced the earlier one in the UTXO set, so 2 x 50 BTC became unspendable. BIP30 forbids a block from containing a transaction whose txid has an unspent output in the UTXO set. (Core: the BIP30 section of `ConnectBlock`, `IsBIP30Repeat`.)

The rule applies to every block except:

- the two historical violators: height 91842 with hash `00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec`, and height 91880 with hash `00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721`;
- blocks above the BIP34 height and below height 1,983,702 whose parent's chain contains the network's `bip34_hash` at the BIP34 height. The block at the BIP34 height itself is still checked. Once BIP34 forces unique coinbases, a duplicate needs a pre-BIP34 coinbase that happens to start with a push of a later height, repeated at that height. On mainnet the lowest such heights are 209,921 (below the BIP34 height, where the check still applies), 490,897 and 1,983,702; on testnet3 the first is near height 486,000,000. A repeat at 490,897 of the coinbase of block 176,684 cannot conflict, because that coinbase was spent in block 185,956, before the BIP34 height, so it is no longer in the UTXO set of any chain that contains the BIP34 block. Skipping the check in this range is therefore only an optimization: an implementation that always checks BIP30 gets identical results. (Core: the comments on BIP30 in `ConnectBlock`.)

The check is made against the UTXO set *before* the block's transactions are applied, and unspendable outputs (chapter 04) are never in the UTXO set, so they never conflict.

```rust
/// Core: `IsBIP30Repeat`.
pub fn is_bip30_repeat(height: i32, hash: &Hash256) -> bool {
    (height == 91842 && hash_to_display(hash) == "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")
        || (height == 91880 && hash_to_display(hash) == "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
}

/// Core: `BIP34_IMPLIES_BIP30_LIMIT`.
pub const BIP34_IMPLIES_BIP30_LIMIT: i32 = 1_983_702;
```

## 10.8 Connecting a block

`connect_block` applies a block to the UTXO set of its parent. It fails without changing anything, or succeeds and returns *undo data* (the coins it spent) so the block can later be disconnected (chapter 11). For each block, in this order (Core: `ConnectBlock`, `src/validation.cpp`):

1. **Genesis** is not connected: its transactions are not added to the UTXO set.
2. **BIP30** (section 10.7): `bad-txns-BIP30`.
3. For each transaction, in block order:
   1. For non-coinbase transactions: `check_tx_inputs` (chapter 08) against the UTXO set as modified by the earlier transactions of this block, then add the fee to the running total, which must stay within range (`bad-txns-accumulated-fee-outofrange`), then BIP68 relative lock times from the CSV height on (`bad-txns-nonfinal`).
   2. Add the transaction's signature operation cost (chapter 08) to the running total; more than 80,000 fails with `bad-blk-sigops`.
   3. Queue verification of every input's scripts (non-coinbase transactions).
   4. Update the UTXO set: remove the coins spent, then add the outputs, skipping unspendable ones. A coinbase output replaces an existing entry with the same outpoint (only possible for the two BIP30 exceptions); for any other transaction such a conflict cannot occur.
4. The coinbase's total output value must not exceed the subsidy plus the total fees (`bad-cb-amount`). The coinbase may claim less; the difference is destroyed.
5. Run the queued script verifications. A failure fails the block with `block-script-verify-flag-failed (<error message>)`, using the script error's message from chapter 05; the reference reports the first failing input in block order.

Because transactions are applied in order, a transaction can spend outputs of earlier transactions in the same block but not of later ones. Every failure here is `Invalid`.

Bitcoin Core normally runs script verification on parallel threads and reports a script failure only after all other checks of the block (step 5). When several inputs fail, it reports whichever failing check a thread finishes first, so its message is not deterministic; the reference reports the first failing input in block order. With script threads disabled (`-par=1`), Bitcoin Core checks each transaction's scripts as it connects the transaction, and reports the first failing input of the first failing transaction before the checks of later transactions and before `bad-cb-amount`. The validity of the block is the same in every case; only the reported reason can differ, for blocks that break several rules or have several failing inputs. (Core: `CCheckQueue`, `src/checkqueue.h`.)

```rust
/// Undo data of one block: for each non-coinbase transaction, the coins its inputs spent, in input order.
/// Core: `CBlockUndo`.
pub type BlockUndo = Vec<Vec<Coin>>;

/// The UTXO set: every unspent, spendable output.
pub type UtxoSet = std::collections::HashMap<OutPoint, Coin>;

/// A set of pending changes on top of a UTXO set. `None` marks a spent coin.
pub struct UtxoView<'a> {
    pub base: &'a UtxoSet,
    pub changes: std::collections::HashMap<OutPoint, Option<Coin>>,
}

impl<'a> UtxoView<'a> {
    pub fn new(base: &'a UtxoSet) -> UtxoView<'a> {
        UtxoView { base, changes: std::collections::HashMap::new() }
    }

    pub fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        match self.changes.get(outpoint) {
            Some(entry) => entry.clone(),
            None => self.base.get(outpoint).cloned(),
        }
    }

    pub fn spend(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        let coin = self.get(outpoint);
        if coin.is_some() {
            self.changes.insert(*outpoint, None);
        }
        coin
    }

    pub fn add(&mut self, outpoint: OutPoint, coin: Coin) {
        self.changes.insert(outpoint, Some(coin));
    }

    /// Writes the pending changes into a UTXO set.
    pub fn apply(changes: std::collections::HashMap<OutPoint, Option<Coin>>, utxo: &mut UtxoSet) {
        for (outpoint, entry) in changes {
            match entry {
                Some(coin) => {
                    utxo.insert(outpoint, coin);
                }
                None => {
                    utxo.remove(&outpoint);
                }
            }
        }
    }
}

/// Adds a transaction's spendable outputs. Core: `AddCoins`, `CCoinsViewCache::AddCoin`.
pub fn add_coins(view: &mut UtxoView, tx: &Transaction, height: i32) {
    let txid = tx.txid();
    let is_coinbase = tx.is_coinbase();
    for (index, output) in tx.outputs.iter().enumerate() {
        if is_unspendable(&output.script_pubkey) {
            continue;
        }
        view.add(OutPoint { txid, vout: index as u32 }, Coin { output: output.clone(), height, is_coinbase });
    }
}

/// Connects `block` (whose entry is `entry`, with parent on the active chain) to `utxo`.
/// On success, returns the changes to apply and the undo data. Core: `ConnectBlock`.
pub fn connect_block(
    block: &Block,
    entry: &BlockEntry,
    tree: &BlockTree,
    utxo: &UtxoSet,
    params: &ConsensusParams,
) -> Result<(std::collections::HashMap<OutPoint, Option<Coin>>, BlockUndo), Failure> {
    let mut view = UtxoView::new(utxo);
    if entry.hash == params.genesis_hash {
        return Ok((view.changes, Vec::new()));
    }
    let height = entry.height;
    let parent = tree.get(&entry.parent.expect("non-genesis block has a parent")).expect("parent is known");

    // BIP30.
    let mut enforce_bip30 = !is_bip30_repeat(height, &entry.hash);
    if let Some(bip34_block) = tree.ancestor(&parent.hash, params.bip34_height) {
        if bip34_block.hash == params.bip34_hash {
            enforce_bip30 = false;
        }
    }
    if enforce_bip30 || height >= BIP34_IMPLIES_BIP30_LIMIT {
        for tx in &block.transactions {
            let txid = tx.txid();
            for index in 0..tx.outputs.len() {
                if view.get(&OutPoint { txid, vout: index as u32 }).is_some() {
                    return Err(invalid("bad-txns-BIP30"));
                }
            }
        }
    }

    let enforce_bip68 = height >= params.csv_height;
    let flags = block_script_flags(&entry.hash, height, params);
    let mtp_at = |h: i32| tree.ancestor(&entry.hash, h).expect("ancestor exists").median_time_past;

    let mut fees: i64 = 0;
    let mut sigops_cost: i64 = 0;
    let mut undo: BlockUndo = Vec::new();
    let mut script_checks: Vec<(usize, Vec<TxOut>)> = Vec::new();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        let coins: Vec<Option<Coin>> = if tx.is_coinbase() {
            Vec::new()
        } else {
            tx.inputs.iter().map(|input| view.get(&input.prevout)).collect()
        };
        if !tx.is_coinbase() {
            let fee = check_tx_inputs(tx, &coins, height).map_err(invalid)?;
            fees += fee;
            if !money_range(fees) {
                return Err(invalid("bad-txns-accumulated-fee-outofrange"));
            }
            let coin_heights: Vec<i32> = coins.iter().map(|coin| coin.as_ref().unwrap().height).collect();
            let lock = calculate_sequence_locks(tx, enforce_bip68, &coin_heights, &mtp_at);
            if !evaluate_sequence_locks(height, parent.median_time_past, lock) {
                return Err(invalid("bad-txns-nonfinal"));
            }
        }
        let spent: Vec<Coin> = coins.into_iter().map(|coin| coin.unwrap()).collect();
        sigops_cost += transaction_sig_op_cost(tx, &spent, flags);
        if sigops_cost > MAX_BLOCK_SIGOPS_COST {
            return Err(invalid("bad-blk-sigops"));
        }
        if !tx.is_coinbase() {
            script_checks.push((tx_index, spent.iter().map(|coin| coin.output.clone()).collect()));
            for input in &tx.inputs {
                view.spend(&input.prevout).expect("checked by check_tx_inputs");
            }
            undo.push(spent);
        }
        add_coins(&mut view, tx, height);
    }

    let block_reward = fees + block_subsidy(height, params);
    if block.transactions[0].value_out() > block_reward {
        return Err(invalid("bad-cb-amount"));
    }

    for (tx_index, spent_outputs) in script_checks {
        let tx = &block.transactions[tx_index];
        let precomputed = PrecomputedTx::new(tx, &spent_outputs);
        for input_index in 0..tx.inputs.len() {
            if let Err(error) = verify_input(tx, input_index, &spent_outputs, &precomputed, flags) {
                return Err(invalid(&format!("block-script-verify-flag-failed ({})", error.message())));
            }
        }
    }
    Ok((view.changes, undo))
}
```

Note that `coins` is looked up before any of the transaction's own inputs are spent, so two inputs spending the same coin would both find it: what prevents a transaction from spending one coin twice is `check_transaction` (`bad-txns-inputs-duplicate`, chapter 08), which `check_block` applies to every transaction before the block is connected. The sigop cost is computed with the coins the transaction spends.
