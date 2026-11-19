# Block connection vectors

Blocks connected with `block_connect` (`PROTOCOL.md` section 4.19): chapter 10's `connect_block`, given the block, the coins it spends and the ancestors it reads. Every corpus scenario is regtest, so without these cases the mainnet and testnet3 rules of chapter 10 were checked only by reading: the script flag exceptions being applied (section 10.6), the two BIP30 exempt blocks and the BIP34-implies-BIP30 limit (section 10.7).

`cases.jsonl.gz` holds:

- mainnet blocks 91842 and 91880, each connected while the coinbase it repeats (blocks 91812 and 91722) is still unspent, and those two earlier blocks;
- block 91842 sent as height 91843, where it is not exempt (`bad-txns-BIP30`): the exemption names a height and a hash together;
- the script flag exception blocks 170060 on mainnet and 394 on testnet3, both of which fail with `P2SH`;
- mainnet block 692261, the other flag exception, which spent a taproot output before taproot activated and fails with `TAPROOT`;
- the first halving block, 210000;
- the blocks on each side of the BIP34 (227930, 227931), BIP66 (363724, 363725), BIP65 (388380, 388381), CSV (419327, 419328) and segwit (481823, 481824) heights. From the CSV height on, the ancestors include the block before each coin that a BIP68 sequence lock reads;
- three constructed mainnet blocks whose coinbase has the txid of a pre-BIP34 coinbase: at height 1,983,702 on a chain that contains the BIP34 block, with that coinbase unspent, BIP30 applies again (`bad-txns-BIP30`); at 1,983,701 on a chain with another block at the BIP34 height, also unspent, it applies too; and at 1,983,701 on the BIP34 chain the block is valid. That last case has no conflicting coin: on that chain none can be unspent, and an implementation that always checks BIP30 conforms (chapter 10 section 10.7).

Expectations. Every historic block is on the chain that Bitcoin Core v32.1 accepts, so it is valid when connected to the UTXO set of its parent. The oracle cannot compute the constructed cases: `GetBlockScriptFlags`, `IsBIP30Repeat` and `BIP34_IMPLIES_BIP30_LIMIT` are in `src/validation.cpp`, which needs the rest of the node. Their verdicts follow the BIP30 section of Core's `ConnectBlock`, and are the same whether or not an implementation skips the check below 1,983,702.

Format as in `vectors/custom`, gzip compressed. `valid` is scored at level 1 and `reason` at level 2.

Regenerate with (the cache directory keeps every response, so a second run reads nothing from the network):

```sh
ELECTRUM=electrum.bitaroo.net:50002,fulcrum.sethforprivacy.com:50002 \
  python3 -I conformance/vectors/block-connect/generate.py <cache-dir> conformance/vectors/block-connect/cases.jsonl.gz
```

The blocks and their parents come from mempool.space. The transactions a mainnet block spends, and the ancestors a sequence lock reads, come from the Electrum servers in `ELECTRUM` (SSL ports). Fulcrum servers answer a batch of 50 in a few seconds; the ElectrumX servers tried were slower and dropped the connection after a few thousand requests. Block 692261 alone spends outputs of 5,216 transactions, and mempool.space serves one per request and slows to about 12 seconds a request after about 1,600 of them. Each transaction is checked against its txid, and each height against the hash of the header there. Without `ELECTRUM` everything comes from mempool.space, which is enough for the small blocks (`ONLY=91722,170060` limits a run to those heights).
