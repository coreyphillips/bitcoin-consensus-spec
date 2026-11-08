# Block corpus recorder

Records Bitcoin Core v32.1's consensus functional tests as block scenarios (format: `../CORPUS.md`), writes them to `../vectors/blocks/`, and verifies them against a fresh v32.1 node.

## Requirements

- Docker with BuildKit (Docker 23 or later).
- The official v32.1 Linux release tarball (`bitcoin-32.1-aarch64-linux-gnu.tar.gz` or `bitcoin-32.1-x86_64-linux-gnu.tar.gz`) in `RELEASE_DIR` (default `~/bcs-data/bin`). Check `SHA256SUMS` and its signatures first; the image build checks the tarball against the SHA256 published there.
- A Bitcoin Core source checkout at tag v32.1 (commit `f0de87f040621468b956f01f526a43a010310501`), mounted read-only. Only `test/functional` is used, unmodified.

Everything Python runs inside the image (`python:3.12-slim`, pinned by digest).

## One command

```sh
make all CORE_SRC=/path/to/bitcoin-v32.1 -j6
```

`all` runs the stages below in order (about four minutes on 18 cores); `-j` runs the recordings in parallel. Variables: `RELEASE_DIR` (tarball directory), `WORK` (raw captures and logs, default `work/`, ignored by git), `VECTORS` (default `../vectors/blocks`), `SEED`.

| Target | What it does |
|---|---|
| `image` | Builds `bcs-recorder:32.1` from the pinned base image and the release tarball |
| `record`, `record2` | Runs every test twice with the same seeds (`work/raw/run1`, `work/raw/run2`) |
| `compare` | Post-processes both recordings and compares their skeletons (`work/racy.json`, `work/compare.json`) |
| `corpus` | Writes `../vectors/blocks/` from the first recording, marking racy checks non-normative |
| `verify` | Replays every corpus file through the Core chain harness; fails unless every normative check matches |
| `verify-noop` | The same, with restarts whose options are unchanged treated as no-ops |
| `report` | Writes `REPORT.md` |
| `reorg` | Optional: `feature_block` including its 1088-block reorg, written to `work/reorg` only |

Tests are run with `--randomseed=1 --portseed=1 --v1transport --timeout-factor=4`, fresh cache and data directories, and `feature_block` with `--skipreorg`. Each test runs in its own container, so ports never collide with anything on the host.

## How recording works

`record.py` verifies the framework files against `pins.json`, installs hooks, then runs the test with `runpy` (catching `SystemExit`):

- `wait_until_helper_internal` is wrapped so the recorder knows when it is inside a wait predicate, and `p2p_lock` is replaced by an `RLock` (before the test is imported) so the recorder can tell whether the current thread holds it. The recorder never syncs from either place.
- `P2PConnection.send_without_ping` is replaced by an equivalent that records `block`, `headers`, `cmpctblock` and `blocktxn` payloads inside `_send_lock`, so the order per connection is exact.
- `P2PInterface.on_message` notes `getdata` requests, `connection_lost` notes disconnects.
- `AuthServiceProxy.__call__` records `submitblock` (with the parent lookup that decides whether Core adds the coinbase witness reserved value), `submitheader`, the mining RPCs (fetching every mined block with `getblock <hash> 0`), `invalidateblock`, `reconsiderblock`, `preciousblock` and `setmocktime`.
- Checkpoints are taken after `send_blocks_and_test`, `send_and_ping`/`sync_with_ping`, every state-changing RPC, `sync_blocks`, node start and node shutdown. Before a checkpoint or a state-changing RPC, every connection that sent block data since it last synced is pinged, so everything sent has been processed.
- At every checkpoint the node's block index is walked back from `getchaintips`; blocks and headers that did not pass through the framework (other bitcoind peers, the pre-mined chain cache) are fetched and recorded.

`postprocess.py` then works from the node's own `debug.log` (the tests run with `-debug`): it matches each recorded send to the line where Core started processing it (dropping sends Core never processed), takes `requested` (was the block in flight) and `now` (mock time or wall-clock second) from the log, orders events between checkpoints by log position (a block or header from another node that arrived inside a batch, without a log line of its own, is moved after its parent), and collapses byte-identical re-deliveries whose outcome cannot depend on state (mutated blocks and context-free `CheckBlock` failures, which Core re-requested from noban peers hundreds of times). Restarts become `restart` events; checks are deduplicated; the full chain tip set is kept where it has at most 64 entries and at the last check before each restart and at the end.

`compare_runs.py` reduces each file to a skeleton (hashes replaced by order of first appearance) and reports checks inside regions where the two recordings differ; `postprocess.py --racy` marks those non-normative.

## Core chain harness

`core_chain_harness.py` speaks the chain operations of `../PROTOCOL.md` (`info`, `chain_reset`, `chain_process_block`, `chain_process_headers`, `chain_invalidate`, `chain_tip`, `chain_tips`, `utxo_hash`) by driving a fresh regtest `bitcoind` per `chain_reset`:

```sh
docker run -i --rm bcs-recorder:32.1 python3 core_chain_harness.py
```

It sets `setmocktime(now)` before each event and uses `submitblock`, `submitheader`, `invalidateblock`, `getchaintips` and `gettxoutsetinfo hash_serialized_3`. For `via: "p2p"` events it reproduces where Core's P2P handling differs from those RPCs (mutated blocks, anti-DoS work threshold, unrequested blocks, headers message checks; see `../CORPUS.md` section 5). `BCS_HARNESS_KEEP=1` keeps each node's data directory with a full debug log.

`replay.py` feeds corpus files to any harness command (`--harness "..."`), maps every event as `../CORPUS.md` section 4 describes, and scores levels 0, 1 and 2.

## Other files

- `blocklib.py`: block and transaction codec, merkle roots, `IsBlockMutated`, `CheckBlock`, proof of work, mirroring v32.1.
- `report.py`: builds `REPORT.md` from the post-processing, comparison and verification outputs.
- `pins.json`: SHA256 of every functional test framework file and each recorded test at v32.1, the release tarballs and the base image.
- `config.ini`: the test framework configuration for the release binaries.
- `REPORT.md`: results of the committed recording.

The corpus has one file per node: the `NODES_<test>` variables in the Makefile list the nodes written for multi-node tests (all of them except the pruned node 2 of `mining_basic`).
