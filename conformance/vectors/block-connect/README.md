# Block connection vectors

Blocks connected with `block_connect` (`PROTOCOL.md` section 4.19): chapter 10's `connect_block`, given the block, the coins it spends and the ancestors it reads. Every corpus scenario is regtest, so without these cases the mainnet and testnet3 rules of chapter 10 were checked only by reading: the script flag exceptions being applied (section 10.6), the two BIP30 exempt blocks and the BIP34-implies-BIP30 limit (section 10.7).

`cases.jsonl.gz` holds:

- mainnet blocks 91842 and 91880, each connected while the coinbase it repeats (blocks 91812 and 91722) is still unspent, and those two earlier blocks;
- block 91842 sent as height 91843, where it is not exempt (`bad-txns-BIP30`): the exemption names a height and a hash together;
- the script flag exception blocks 170060 on mainnet and 394 on testnet3, both of which fail with `P2SH`;
- blocks 363724 and 363725, on each side of the BIP66 height;
- three constructed mainnet blocks whose coinbase has the txid of a pre-BIP34 coinbase: at height 1,983,702 on a chain that contains the BIP34 block, with that coinbase unspent, BIP30 applies again (`bad-txns-BIP30`); at 1,983,701 on a chain with another block at the BIP34 height, also unspent, it applies too; and at 1,983,701 on the BIP34 chain the block is valid. That last case has no conflicting coin: on that chain none can be unspent, and an implementation that always checks BIP30 conforms (chapter 10 section 10.7).

Expectations. Every historic block is on the chain that Bitcoin Core v32.1 accepts, so it is valid when connected to the UTXO set of its parent. The oracle cannot compute the constructed cases: `GetBlockScriptFlags`, `IsBIP30Repeat` and `BIP34_IMPLIES_BIP30_LIMIT` are in `src/validation.cpp`, which needs the rest of the node. Their verdicts follow the BIP30 section of Core's `ConnectBlock`, and are the same whether or not an implementation skips the check below 1,983,702.

Not yet covered: mainnet block 692261 (the second flag exception, which spent a taproot output before taproot activated), the first halving block, and the blocks on each side of the BIP34, BIP65, CSV and segwit heights. Each has hundreds to thousands of transactions, and the public API the generator reads gives one spent transaction per request.

Format as in `vectors/custom`, gzip compressed. `valid` is scored at level 1 and `reason` at level 2.

Regenerate with (the cache directory keeps every response, so a second run reads nothing from the network):

```sh
python3 -I conformance/vectors/block-connect/generate.py <cache-dir> conformance/vectors/block-connect/cases.jsonl.gz
```
