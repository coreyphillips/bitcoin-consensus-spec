# 08. Transactions

This chapter defines the rules a single transaction must satisfy: context-free checks, finality (absolute lock time), relative lock time (BIP68), the checks against the outputs it spends, and how its signature operations are counted. Chapter 10 applies these rules to every transaction of a block, in order.

## 8.1 Constants

```rust
/// Coinbase outputs can be spent only this many blocks later. Core: `COINBASE_MATURITY`.
pub const COINBASE_MATURITY: i32 = 100;
/// Core: `MAX_BLOCK_WEIGHT`, `src/consensus/consensus.h`.
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// Core: `MAX_BLOCK_SIGOPS_COST`.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Relative time locks count units of 2^9 = 512 seconds. Core: `CTxIn::SEQUENCE_LOCKTIME_GRANULARITY`.
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;
```

## 8.2 Coinbase transactions

A transaction is a **coinbase** if it has exactly one input and that input's outpoint is null (zero hash, index `0xffffffff`). Only the first transaction of a block may be a coinbase (chapter 10). A transaction with several inputs, one of which is null, is not a coinbase; it fails `check_transaction`. (Core: `CTransaction::IsCoinBase`.)

```rust
impl Transaction {
    /// Core: `CTransaction::IsCoinBase`.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prevout.is_null()
    }

    /// Sum of output values. Only meaningful after `check_transaction`, which bounds it.
    pub fn value_out(&self) -> i64 {
        self.outputs.iter().map(|output| output.value).sum()
    }
}
```

## 8.3 Context-free checks

`check_transaction` applies the checks that need nothing but the transaction itself, in this order (Core: `CheckTransaction`, `src/consensus/tx_check.cpp`):

| Rule | Reason |
|---|---|
| At least one input | `bad-txns-vin-empty` |
| At least one output | `bad-txns-vout-empty` |
| 4 times the stripped size (no witness) is at most 4,000,000 | `bad-txns-oversize` |
| No output value is negative | `bad-txns-vout-negative` |
| No output value exceeds 21,000,000 BTC | `bad-txns-vout-toolarge` |
| The running sum of output values never exceeds 21,000,000 BTC | `bad-txns-txouttotal-toolarge` |
| No two inputs spend the same outpoint | `bad-txns-inputs-duplicate` |
| A coinbase's `script_sig` is 2 to 100 bytes | `bad-cb-length` |
| A non-coinbase has no null outpoint | `bad-txns-prevout-null` |

The duplicate input rule matters even though a later rule requires every input's coin to exist: without it, one coin could be spent twice inside one transaction, creating money (CVE-2018-17144).

```rust
/// Core: `CheckTransaction`.
pub fn check_transaction(tx: &Transaction) -> Result<(), &'static str> {
    if tx.inputs.is_empty() {
        return Err("bad-txns-vin-empty");
    }
    if tx.outputs.is_empty() {
        return Err("bad-txns-vout-empty");
    }
    if tx.stripped_size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT {
        return Err("bad-txns-oversize");
    }
    let mut value_out: i64 = 0;
    for output in &tx.outputs {
        if output.value < 0 {
            return Err("bad-txns-vout-negative");
        }
        if output.value > MAX_MONEY {
            return Err("bad-txns-vout-toolarge");
        }
        value_out += output.value;
        if !money_range(value_out) {
            return Err("bad-txns-txouttotal-toolarge");
        }
    }
    let mut seen = std::collections::HashSet::new();
    for input in &tx.inputs {
        if !seen.insert(input.prevout) {
            return Err("bad-txns-inputs-duplicate");
        }
    }
    if tx.is_coinbase() {
        let length = tx.inputs[0].script_sig.len();
        if length < 2 || length > 100 {
            return Err("bad-cb-length");
        }
    } else if tx.inputs.iter().any(|input| input.prevout.is_null()) {
        return Err("bad-txns-prevout-null");
    }
    Ok(())
}
```

## 8.4 Finality (absolute lock time)

A transaction is **final** at a given block height and time if any of these holds (Core: `IsFinalTx`, `src/consensus/tx_verify.cpp`):

- its lock time is 0;
- its lock time is *strictly less than* the block height (if the lock time is below 500,000,000) or the block time (otherwise);
- every input's sequence is `0xffffffff`.

Which "block time" is used depends on BIP113 (chapter 10): before it, the block's own timestamp; after it, the median time past of the previous block. Note that `OP_CHECKLOCKTIMEVERIFY` (chapter 05) compares with `<=` against the transaction's lock time, while finality compares the lock time with `<` against the block; they are different predicates.

```rust
/// Core: `IsFinalTx`.
pub fn is_final_tx(tx: &Transaction, block_height: i32, block_time: i64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let lock_time = tx.lock_time as i64;
    let cutoff = if lock_time < LOCKTIME_THRESHOLD as i64 { block_height as i64 } else { block_time };
    if lock_time < cutoff {
        return true;
    }
    tx.inputs.iter().all(|input| input.sequence == SEQUENCE_FINAL)
}
```

## 8.5 Coins

A **coin** is an unspent transaction output together with the height of the block that created it and whether it came from a coinbase. (Core: `Coin`, `src/coins.h`.)

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub output: TxOut,
    /// Height of the block containing the creating transaction.
    pub height: i32,
    pub is_coinbase: bool,
}
```

## 8.6 Relative lock time (BIP68)

When BIP68 is in force (from the CSV deployment height, chapter 12) and the transaction version is at least 2 **as an unsigned number** (so versions `0x80000000` to `0xffffffff` are included), each input's sequence can impose a relative lock time:

- If bit 31 (disable flag) is set, the input imposes nothing.
- Otherwise the low 16 bits are a value v. If bit 22 (type flag) is set, the lock is time-based: the transaction may not be included before `MTP(coin_height - 1) + v * 512` seconds, measured against the median time past of the block *before* the including block. Otherwise it is height-based: not before `coin_height + v` blocks.

The computation uses "last invalid" semantics, matching lock times: each input yields a minimum height `coin_height + v - 1` or minimum time `MTP(max(coin_height - 1, 0)) + v * 512 - 1`, the transaction's lock is the maximum over its inputs (starting from -1), and the transaction is valid in a block at height h whose parent has median time past t only if the minimum height is below h **and** the minimum time is below t. `MTP(x)` is the median time past of the ancestor of the block being connected at height x (chapter 09); a coin created in the same block uses that block's height, so `MTP(coin_height - 1)` is the parent's. (Core: `CalculateSequenceLocks`, `EvaluateSequenceLocks`.)

```rust
/// Returns (minimum height, minimum time), both "last invalid" values, -1 meaning no constraint.
/// `coin_heights[i]` is the height of the coin spent by input i; `mtp_at(h)` is the median time
/// past of the ancestor at height h of the block being connected.
/// Core: `CalculateSequenceLocks`.
pub fn calculate_sequence_locks(tx: &Transaction, enforce_bip68: bool, coin_heights: &[i32], mtp_at: &dyn Fn(i32) -> i64) -> (i32, i64) {
    assert!(coin_heights.len() == tx.inputs.len());
    let mut min_height: i32 = -1;
    let mut min_time: i64 = -1;
    if !(tx.version >= 2 && enforce_bip68) {
        return (min_height, min_time);
    }
    for (input, &coin_height) in tx.inputs.iter().zip(coin_heights) {
        if (input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            continue;
        }
        let value = input.sequence & SEQUENCE_LOCKTIME_MASK;
        if (input.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0 {
            let coin_time = mtp_at((coin_height - 1).max(0));
            min_time = min_time.max(coin_time + ((value << SEQUENCE_LOCKTIME_GRANULARITY) as i64) - 1);
        } else {
            min_height = min_height.max(coin_height + value as i32 - 1);
        }
    }
    (min_height, min_time)
}

/// Core: `EvaluateSequenceLocks`. `block_height` is the height of the block being connected and
/// `prev_mtp` the median time past of its parent.
pub fn evaluate_sequence_locks(block_height: i32, prev_mtp: i64, lock: (i32, i64)) -> bool {
    !(lock.0 >= block_height || lock.1 >= prev_mtp)
}
```

## 8.7 Checks against spent coins

Every input of a non-coinbase transaction must spend a coin that exists in the current UTXO set, which includes outputs created by earlier transactions in the same block and excludes outputs already spent by them (chapter 10). Then (Core: `Consensus::CheckTxInputs`, `src/consensus/tx_verify.cpp`):

| Rule, checked input by input | Reason |
|---|---|
| Every input's coin exists | `bad-txns-inputs-missingorspent` |
| A coinbase coin is spent at least 100 blocks after its creation (`spend_height - coin_height >= 100`) | `bad-txns-premature-spend-of-coinbase` |
| Each coin value, and the running sum of input values, is within 0 to 21,000,000 BTC | `bad-txns-inputvalues-outofrange` |
| Then: total input value is at least total output value | `bad-txns-in-belowout` |
| The fee (input minus output) is within range | `bad-txns-fee-outofrange` |

The result is the transaction fee.

```rust
/// `coins[i]` is the coin spent by input i, or `None` if it does not exist (missing or spent).
/// Returns the fee. Core: `Consensus::CheckTxInputs`.
pub fn check_tx_inputs(tx: &Transaction, coins: &[Option<Coin>], spend_height: i32) -> Result<i64, &'static str> {
    if coins.iter().any(|coin| coin.is_none()) {
        return Err("bad-txns-inputs-missingorspent");
    }
    let mut value_in: i64 = 0;
    for coin in coins.iter().flatten() {
        if coin.is_coinbase && spend_height - coin.height < COINBASE_MATURITY {
            return Err("bad-txns-premature-spend-of-coinbase");
        }
        value_in += coin.output.value;
        if !money_range(coin.output.value) || !money_range(value_in) {
            return Err("bad-txns-inputvalues-outofrange");
        }
    }
    let value_out = tx.value_out();
    if value_in < value_out {
        return Err("bad-txns-in-belowout");
    }
    let fee = value_in - value_out;
    if !money_range(fee) {
        return Err("bad-txns-fee-outofrange");
    }
    Ok(fee)
}
```

Coin values in a valid chain are always in range, because every output passed `check_transaction` when it was created; the range check still runs, exactly as in Bitcoin Core, and the addition cannot overflow because each addend is at most 21,000,000 BTC and the sum is checked after every step.

## 8.8 Signature operation cost

Blocks limit the total *signature operation cost* of their transactions to 80,000 (chapter 10). A transaction's cost is (Core: `GetTransactionSigOpCost`, `src/consensus/tx_verify.cpp`):

- **4 times the legacy count**: chapter 04's `sig_op_count(script, false)` over every input's `script_sig` and every output's `script_pubkey` (output scripts count even though nothing executes them yet);
- for non-coinbase transactions, if `P2SH` is in force, **4 times the P2SH count**: for each input whose spent `script_pubkey` is P2SH, `p2sh_sig_op_count(script_pubkey, script_sig)`;
- for non-coinbase transactions, if `WITNESS` is in force, **1 times the witness count**: for each input, if the spent `script_pubkey` is a witness program, or is P2SH with a push-only `script_sig` whose last push is a witness program, then a version 0 20-byte program counts 1 and a version 0 32-byte program counts the accurate count of the witness script (the last witness item, if the witness is non-empty). Other versions count 0; tapscript signature operations are limited per input by the validation weight budget instead (chapter 05).

The flags are the block's script flags (chapter 10). Because `WITNESS` is set for nearly every historical block, witness sigops are counted for spends of witness-program-shaped outputs even before segwit activated.

```rust
/// Core: `GetLegacySigOpCount`.
pub fn legacy_sig_op_count(tx: &Transaction) -> u64 {
    let inputs: u64 = tx.inputs.iter().map(|input| sig_op_count(&input.script_sig, false)).sum();
    let outputs: u64 = tx.outputs.iter().map(|output| sig_op_count(&output.script_pubkey, false)).sum();
    inputs + outputs
}

/// Core: `GetP2SHSigOpCount`. `coins[i]` is the coin spent by input i.
pub fn p2sh_sig_op_count_tx(tx: &Transaction, coins: &[Coin]) -> u64 {
    if tx.is_coinbase() {
        return 0;
    }
    let mut count = 0;
    for (input, coin) in tx.inputs.iter().zip(coins) {
        if is_p2sh(&coin.output.script_pubkey) {
            count += p2sh_sig_op_count(&coin.output.script_pubkey, &input.script_sig);
        }
    }
    count
}

/// Core: `WitnessSigOps`.
fn witness_sig_ops(version: u8, program: &[u8], witness: &[Vec<u8>]) -> u64 {
    if version == 0 {
        if program.len() == WITNESS_V0_KEYHASH_SIZE {
            return 1;
        }
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE && !witness.is_empty() {
            return sig_op_count(&witness[witness.len() - 1], true);
        }
    }
    0
}

/// Core: `CountWitnessSigOps`.
pub fn witness_sig_op_count(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: ScriptFlags) -> u64 {
    if (flags & VERIFY_WITNESS) == 0 {
        return 0;
    }
    if let Some((version, program)) = witness_program(script_pubkey) {
        return witness_sig_ops(version, program, witness);
    }
    if is_p2sh(script_pubkey) && is_push_only(script_sig) {
        let mut pos = 0;
        let mut last_data: &[u8] = &[];
        while pos < script_sig.len() {
            // Cannot fail: the script is push-only, so it parses completely.
            last_data = get_op(script_sig, &mut pos).unwrap().data;
        }
        if let Some((version, program)) = witness_program(last_data) {
            return witness_sig_ops(version, program, witness);
        }
    }
    0
}

/// Core: `GetTransactionSigOpCost`. `coins[i]` is the coin spent by input i (unused for a coinbase).
pub fn transaction_sig_op_cost(tx: &Transaction, coins: &[Coin], flags: ScriptFlags) -> i64 {
    let mut cost = legacy_sig_op_count(tx) as i64 * WITNESS_SCALE_FACTOR as i64;
    if tx.is_coinbase() {
        return cost;
    }
    if (flags & VERIFY_P2SH) != 0 {
        cost += p2sh_sig_op_count_tx(tx, coins) as i64 * WITNESS_SCALE_FACTOR as i64;
    }
    for (input, coin) in tx.inputs.iter().zip(coins) {
        cost += witness_sig_op_count(&input.script_sig, &coin.output.script_pubkey, &input.witness, flags) as i64;
    }
    cost
}
```
