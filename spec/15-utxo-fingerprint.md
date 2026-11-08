# 15. UTXO set fingerprint

This chapter is informative: it defines no consensus rule. It defines a hash of the UTXO set that matches Bitcoin Core's `gettxoutsetinfo` with `hash_type = hash_serialized_3`, so that an implementation can prove its chain state is identical to Bitcoin Core's at any height. Bitcoin Core also embeds these hashes for specific heights in its source (the assumeutxo snapshot commitments), which gives independent checkpoints for a full synchronization:

| Network | Height | `hash_serialized_3` (display order) |
|---|---|---|
| main | 840,000 | `a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96` |
| main | 880,000 | `dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9` |
| main | 910,000 | `4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568` |
| main | 935,000 | `e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050` |
| main | 965,000 | `4a8d794337118c0c615b574f817c7306c687584a537184b8d233df42bf477ec2` |
| testnet4 | 90,000 | `784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5` |
| testnet4 | 120,000 | `10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0` |
| testnet4 | 150,000 | `ca068cae50679d7c947454bbe4f0e6aeec1fbe2c6c2735a08bb988623649f950` |

(Core: `m_assumeutxo_data`, `src/kernel/chainparams.cpp`.)

## 15.1 Definition

The UTXO set contains every unspent output of the active chain except unspendable ones (chapter 04) and the genesis coinbase output (chapter 10). Each coin is serialized as

```text
outpoint (txid:32 raw order, vout:u32) | code:u32 | value:i64 | var_bytes(script_pubkey)
```

where `code = (height << 1) | (1 if coinbase else 0)`. The coins are hashed with `sha256d` over their concatenation in ascending order of txid (raw bytes, lexicographic), then output index (numeric). The result is reported in display order. (Core: `TxOutSer`, `ApplyHash`, `ComputeUTXOStats`, `src/kernel/coinstats.cpp`.)

```rust
/// Returns (hash_serialized_3 in raw order, number of coins). Core: `ComputeUTXOStats` with `CoinStatsHashType::HASH_SERIALIZED`.
pub fn utxo_hash_serialized_3(utxo: &UtxoSet) -> (Hash256, u64) {
    let mut entries: Vec<(&OutPoint, &Coin)> = utxo.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut data = Vec::new();
    for (outpoint, coin) in &entries {
        data.extend_from_slice(&outpoint.txid);
        data.extend_from_slice(&outpoint.vout.to_le_bytes());
        let code = ((coin.height as u32) << 1) | coin.is_coinbase as u32;
        data.extend_from_slice(&code.to_le_bytes());
        serialize_txout(&mut data, &coin.output);
    }
    (sha256d(&data), entries.len() as u64)
}
```

The reference builds the whole serialization in memory, which is fine for test networks; a production implementation streams the coins through an incremental SHA-256.
