# Recording report

Bitcoin Core v32.1 (commit `f0de87f040621468b956f01f526a43a010310501`), official aarch64 Linux release binaries. Scenarios: Core's consensus functional tests (every node except the pruned mining_basic node 2), feature_block once with `--skipreorg` and once with its 1088-block reorg (feature_block_reorg), and the recorder's own test extra/feature_spec_pitfalls.py. Each was recorded twice with `--randomseed=1 --portseed=1 --v1transport`; the corpus comes from the first recording. Verification replays every file through the Core chain harness (a fresh v32.1 regtest node) as CORPUS.md section 4 prescribes. Reproduce with `make all CORE_SRC=<v32.1 checkout> -j6` (README.md).

| Scenario | Events | Blocks | Headers | Invalidate | Restart | Checks | Normative | Size (bytes) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| feature_block.node0 | 477 | 229 | 117 | 2 | 0 | 128 | 128 | 1619494 |
| feature_block_reorg.node0 | 2665 | 2408 | 121 | 2 | 0 | 133 | 133 | 473735 |
| feature_taproot.node0 | 8187 | 4142 | 0 | 0 | 0 | 4044 | 4044 | 6856651 |
| p2p_segwit.node0 | 420 | 307 | 5 | 1 | 0 | 106 | 106 | 443113 |
| p2p_segwit.node1 | 327 | 284 | 0 | 1 | 0 | 41 | 41 | 423984 |
| feature_segwit.node0 | 184 | 171 | 0 | 0 | 0 | 12 | 12 | 36179 |
| feature_segwit.node1 | 184 | 171 | 0 | 0 | 0 | 12 | 12 | 36143 |
| feature_segwit.node2 | 184 | 171 | 0 | 0 | 0 | 12 | 12 | 36178 |
| p2p_invalid_block.node0 | 126 | 108 | 7 | 0 | 0 | 10 | 10 | 17514 |
| feature_cltv.node0 | 129 | 117 | 0 | 0 | 0 | 11 | 11 | 19064 |
| feature_dersig.node0 | 111 | 104 | 0 | 0 | 0 | 6 | 6 | 17329 |
| feature_nulldummy.node0 | 116 | 107 | 0 | 0 | 0 | 8 | 8 | 18485 |
| feature_csv_activation.node0 | 831 | 555 | 124 | 12 | 0 | 139 | 139 | 155826 |
| feature_bip68_sequence.node0 | 480 | 446 | 0 | 2 | 0 | 31 | 31 | 66550 |
| feature_bip68_sequence.node1 | 459 | 445 | 0 | 0 | 0 | 13 | 13 | 65385 |
| mining_basic.node0 | 1007 | 582 | 16 | 0 | 33 | 375 | 375 | 109959 |
| mining_basic.node1 | 672 | 367 | 300 | 0 | 0 | 4 | 3 | 76326 |
| feature_spec_pitfalls.node0 | 276 | 217 | 20 | 0 | 0 | 38 | 38 | 40121 |
| feature_spec_pitfalls.node1 | 23 | 14 | 1 | 0 | 0 | 7 | 7 | 4837 |
| feature_spec_pitfalls.node2 | 295 | 146 | 1 | 0 | 0 | 147 | 147 | 31741 |

Sidecar blobs (blocks over 1,000,000 bytes; over 100,000 bytes in feature_block_reorg): 1097 files, 2948272 bytes. Total corpus size: 13496886 bytes (13.5 MB).

## Verification

Level 0 is the active tip and height at normative checks; level 1 the chain tip set (where recorded); level 2 the UTXO set hash (where recorded).

| Scenario | Level 0 (normative) | Level 0 (non-normative) | Level 1 | Level 2 | Restarts as no-ops (level 0) |
|---|---|---|---|---|---|
| feature_block.node0 | 128/128 | 0/0 | 104/104 | 40/40 | 128/128 |
| feature_block_reorg.node0 | 133/133 | 0/0 | 104/104 | 43/43 | 133/133 |
| feature_taproot.node0 | 4044/4044 | 0/0 | 108/108 | 1467/1467 | 4044/4044 |
| p2p_segwit.node0 | 106/106 | 0/0 | 106/106 | 67/67 | 106/106 |
| p2p_segwit.node1 | 41/41 | 0/0 | 41/41 | 41/41 | 41/41 |
| feature_segwit.node0 | 12/12 | 0/0 | 12/12 | 12/12 | 12/12 |
| feature_segwit.node1 | 12/12 | 0/0 | 12/12 | 12/12 | 12/12 |
| feature_segwit.node2 | 12/12 | 0/0 | 12/12 | 12/12 | 12/12 |
| p2p_invalid_block.node0 | 10/10 | 0/0 | 10/10 | 5/5 | 10/10 |
| feature_cltv.node0 | 11/11 | 0/0 | 11/11 | 5/5 | 11/11 |
| feature_dersig.node0 | 6/6 | 0/0 | 6/6 | 4/4 | 6/6 |
| feature_nulldummy.node0 | 8/8 | 0/0 | 8/8 | 6/6 | 8/8 |
| feature_csv_activation.node0 | 139/139 | 0/0 | 82/82 | 33/33 | 139/139 |
| feature_bip68_sequence.node0 | 31/31 | 0/0 | 31/31 | 29/29 | 31/31 |
| feature_bip68_sequence.node1 | 13/13 | 0/0 | 13/13 | 13/13 | 13/13 |
| mining_basic.node0 | 375/375 | 0/0 | 375/375 | 328/328 | 375/375 |
| mining_basic.node1 | 3/3 | 1/1 | 4/4 | 4/4 | 3/3 |
| feature_spec_pitfalls.node0 | 38/38 | 0/0 | 38/38 | 19/19 | 38/38 |
| feature_spec_pitfalls.node1 | 7/7 | 0/0 | 7/7 | 4/4 | 7/7 |
| feature_spec_pitfalls.node2 | 147/147 | 0/0 | 147/147 | 145/145 | 147/147 |

## Second recording

| Scenario | Differing regions | Racy checks (marked non-normative) |
|---|---:|---:|
| feature_block.node0 | 0 | 0 |
| feature_block_reorg.node0 | 0 | 0 |
| feature_taproot.node0 | 0 | 0 |
| p2p_segwit.node0 | 0 | 0 |
| p2p_segwit.node1 | 0 | 0 |
| feature_segwit.node0 | 0 | 0 |
| feature_segwit.node1 | 0 | 0 |
| feature_segwit.node2 | 0 | 0 |
| p2p_invalid_block.node0 | 0 | 0 |
| feature_cltv.node0 | 0 | 0 |
| feature_dersig.node0 | 0 | 0 |
| feature_nulldummy.node0 | 0 | 0 |
| feature_csv_activation.node0 | 0 | 0 |
| feature_bip68_sequence.node0 | 0 | 0 |
| feature_bip68_sequence.node1 | 0 | 0 |
| mining_basic.node0 | 0 | 0 |
| mining_basic.node1 | 1 | 1 |
| feature_spec_pitfalls.node0 | 0 | 0 |
| feature_spec_pitfalls.node1 | 0 | 0 |
| feature_spec_pitfalls.node2 | 0 | 0 |

## Exclusions and adjustments

- feature_block is recorded with `--skipreorg`; its 1088-block reorg (over 1 GB of block data, mostly zero bytes) is the separate scenario feature_block_reorg.
- mining_basic: node 2 (pruned) is excluded. Every other node of every test is included.
- feature_block.node0: P2P sends dropped because Core never processed them (payload failed to deserialize, or the peer was already disconnected): 1.
- feature_block_reorg.node0: P2P sends dropped because Core never processed them (payload failed to deserialize, or the peer was already disconnected): 1.
- p2p_segwit.node0: empty headers messages dropped (no effect): 2.
- p2p_segwit.node0: P2P sends dropped because Core never processed them (payload failed to deserialize, or the peer was already disconnected): 1.
- p2p_segwit.node0: submitblock calls recorded with the coinbase witness reserved value Core added before validating: 2.
- p2p_segwit.node0: block 4487b02ea9d011e2f56fb4b9bd0a38a3829f55e5865c792d9298c875945569d3 carried 6 trailing bytes, stripped.
- p2p_segwit.node1: blocks the node obtained without passing through the test framework (other nodes, chain cache): 284.
- feature_segwit.node0: blocks the node obtained without passing through the test framework (other nodes, chain cache): 1.
- feature_segwit.node1: blocks the node obtained without passing through the test framework (other nodes, chain cache): 171.
- feature_segwit.node2: blocks the node obtained without passing through the test framework (other nodes, chain cache): 170.
- p2p_invalid_block.node0: byte-identical re-deliveries of blocks whose outcome cannot depend on chain state (mutated, or failing context-free checks), collapsed into the first delivery: 572.
- feature_bip68_sequence.node0: blocks the node obtained without passing through the test framework (other nodes, chain cache): 199.
- feature_bip68_sequence.node0: blocks of the pre-mined 199-block chain cache the node started with, recorded as rpc deliveries before the first check: 199.
- feature_bip68_sequence.node1: blocks the node obtained without passing through the test framework (other nodes, chain cache): 444.
- feature_bip68_sequence.node1: blocks of the pre-mined 199-block chain cache the node started with, recorded as rpc deliveries before the first check: 199.
- mining_basic.node1: blocks the node obtained without passing through the test framework (other nodes, chain cache): 367.
- mining_basic.node1: headers the node obtained from other nodes: 300.
- mining_basic.node1: blocks or headers from other nodes moved after their parent (they arrived in a batch without a log line of their own): 226.
- feature_spec_pitfalls.node0: session 1: Core logged low-work handling 2 times.
