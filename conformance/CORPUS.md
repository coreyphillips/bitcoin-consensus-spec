# Block corpus format, version 1

The block corpus turns Bitcoin Core's own consensus functional tests into frozen, portable scenarios. Each scenario is the ordered list of things that happened to one node while a test ran (blocks and headers delivered to it, with the time it saw them, and operator invalidations) together with checkpoints: the node's active chain tip at many points along the way.

An implementation replays the events through the harness protocol (`PROTOCOL.md`, sections 4.8 to 4.13) and must reproduce every normative checkpoint.

Ground truth is Bitcoin Core v32.1 (commit `f0de87f040621468b956f01f526a43a010310501`). The scenarios were recorded from the official v32.1 release binaries running the unmodified v32.1 functional tests, plus one test written for this corpus in the same framework (`recorder/extra/feature_spec_pitfalls.py`), and every file was then replayed through a fresh v32.1 node (`recorder/core_chain_harness.py`), which reproduced every normative checkpoint. How the corpus is produced is described in `recorder/README.md`; per-scenario figures are in `recorder/REPORT.md`.

## 1. Files

```text
conformance/vectors/blocks/<scenario>.node<N>.jsonl.gz
conformance/vectors/blocks/blobs/<sha256>.blk.gz
```

- One file per scenario and node. `<scenario>` is usually the functional test name without `.py` (for example `feature_block`). Two scenarios are named differently: `feature_block_reorg` is `feature_block.py` run with its 1088-block reorganization (which `feature_block` skips), and `feature_spec_pitfalls` is the corpus's own test. `<N>` is the node index in the test. Node 0 is the node the tests drive directly; the other nodes of multi-node tests mostly receive blocks relayed from their peers. Every node of every test is included except the pruned node 2 of `mining_basic`. Nodes of one test can run with different consensus options (the three nodes of `feature_spec_pitfalls` do, and are never connected to each other); each file's `reset` carries its own. The `meta` event names the source file.
- Each file is gzip-compressed JSON Lines: UTF-8, one JSON object per line, no line spans more than one event. The first line is a `meta` event; every other line is an event with a `type` field, in replay order.
- `blobs/` holds sidecar files for large blocks, so that lines stay short: a `block` event carries either `hex` or `blob`. In this corpus, blocks larger than 1,000,000 bytes use blobs, and in `feature_block_reorg` blocks larger than 100,000 bytes. A blob file is the gzip-compressed raw block, named by the SHA256 of the uncompressed bytes. Blobs are shared between scenarios.
- Unknown fields must be ignored. Field names starting with an underscore never appear.

Encodings follow `PROTOCOL.md` section 3: bytes are lowercase hex, hashes are in display order, integers are JSON numbers, times are Unix seconds.

## 2. Events

### 2.1 `meta`

Always the first line. Describes provenance; a runner only needs `format`, `format_version` and `scenario`.

| Field | Meaning |
|---|---|
| `format` | `"bcs-block-corpus"` |
| `format_version` | `1` |
| `scenario`, `node` | Test name and node index |
| `source` | Test file path (in the Bitcoin Core tree, or `conformance/recorder/extra/`), its SHA256, and the test arguments used |
| `core` | Version, commit, SHA256 of the `bitcoind` binary and of the release tarball |
| `recorder` | Base image digest, built image ID, Python version, SHA256 of every functional test framework file |
| `recorded_at` | UTC time the recording started |
| `counts` | Number of events, blocks, headers events, invalidations, restarts, checks and normative checks |
| `notes` | Free-text remarks about this scenario, if any |

### 2.2 `reset`

Start from a fresh chain. Always the second line.

| Field | Meaning |
|---|---|
| `network` | Always `"regtest"` in this corpus |
| `options` | Consensus parameter overrides, exactly the `options` object of `chain_reset` (`PROTOCOL.md` 4.8): `testactivationheight` (deployment name to activation height) and `test` (list, `"bip94"` enables the BIP94 rules). Empty object if none. |
| `genesis` | Expected genesis hash (a sanity check of the `chain_reset` response) |
| `args` | Informational: the node's command line, without machine-specific paths and ports |

### 2.3 `block`

A full block delivered to the node.

| Field | Meaning |
|---|---|
| `hash` | Block hash, display order (informational; derivable from the header) |
| `hex` | Serialized block with witness data, or absent when `blob` is present |
| `blob`, `sha256`, `size` | Sidecar file path relative to the corpus file's directory, SHA256 and length of the raw block |
| `now` | The node's clock when Core processed the block (section 3) |
| `via` | `"p2p"`: received from a peer (the test framework or another node) in a `block` message, or reconstructed from a compact block. `"rpc"`: submitted with `submitblock`, produced by a mining RPC, or part of the pre-mined chain the node started with |
| `requested` | Only for `via: "p2p"`: whether Core had this block in flight (had asked a peer for it) when it arrived |

The bytes are exactly what Core validated. For `submitblock`, where Core adds the default 32-byte coinbase witness reserved value before validating (`UpdateUncommittedBlockStructures`: the parent is known, segwit is active for the block, the coinbase has a witness commitment output and no witness), the recorded block already contains it.

### 2.4 `headers`

Block headers delivered to the node.

| Field | Meaning |
|---|---|
| `headers` | Array of 80-byte headers (hex), in order, each connecting to the previous one |
| `now` | The node's clock at processing time |
| `via` | `"p2p"`: one `headers` message. `"rpc"`: one `submitheader` call (always a single header) |

### 2.5 `invalidate`

The operator marked a block invalid (`invalidateblock`), as specification chapter 11 defines `invalidate_block`.

| Field | Meaning |
|---|---|
| `hash` | Block hash, display order |
| `now` | The node's clock (informational; invalidation does not depend on time) |

### 2.6 `restart`

The node was stopped and started again with the same data directory, possibly with different options. Block data, headers and validity marks (including invalidations) survive; the active chain is selected again at startup.

| Field | Meaning |
|---|---|
| `options` | Consensus options in force after the restart, same form as in `reset` |
| `now` | The node's clock at startup (informational) |
| `args` | Informational: the new command line |

### 2.7 `check`

A checkpoint: the node's state at this point, read after every earlier event had been fully processed.

| Field | Level | Meaning |
|---|---|---|
| `tip`, `height` | 0 | Active chain tip (display order) and its height |
| `normative` | | `true` if level 0 must match. `false` if it depends on behavior the corpus cannot pin down; `why` says what |
| `tips` | 1 | All chain tips, as Bitcoin Core's `getchaintips` reports them: `hash`, `height`, `status` (`active`, `valid-fork`, `valid-headers`, `headers-only`, `invalid`). Present when the set has at most 64 entries, on the last check before each `restart`, and on the last check of the file (every block a test gets rejected stays a tip, so the set can grow to thousands). |
| `utxo` | 2 | Present when the tip changed since the last check that carried one: `hash_serialized_3` (display order) and `txouts` for the active tip, as `gettxoutsetinfo` reports them |
| `n` | | Ordinal of this check in the file, starting at 1 |
| `label` | | Informational: the test step after which the checkpoint was taken |

## 3. Time

`now` is the value of the node's clock, in whole seconds, when Core began processing the event: the mock time if the test had set one, otherwise the wall-clock second. It is taken from the node's own debug log. An implementation must use `now`, and nothing else, as the current time for every time-dependent rule while processing that event (the "too far in the future" header rule of specification chapter 10). Tests move the clock forward and backward; a block rejected as too far in the future can be delivered again later with a larger `now` and then be accepted.

## 4. Replay

A runner processes the events of a file in order and maps them to `PROTOCOL.md` requests:

| Event | Request |
|---|---|
| `reset` | `chain_reset` with `network` and `options`. The response's `genesis` should equal the event's `genesis`. |
| `block` | `chain_process_block` with `block` (the `hex`, or the bytes of the blob), `now`, `via`, and `requested` when present |
| `headers` | `chain_process_headers` with `headers`, `now`, and `via` (an optional field, see section 7) |
| `invalidate` | `chain_invalidate` with `hash` (a harness may also accept `now`) |
| `restart` | `chain_reset` with the `network` of the last `reset` and the `options` of the `restart`, followed by every `block`, `headers` and `invalidate` request sent since the last `reset`, again, in the same order and with the same fields. Responses to this re-delivery are not scored. |
| `check` | `chain_tip`: level 0 compares `tip` and `height`. `chain_tips`, only if the check has `tips`: level 1 compares the set of (`hash`, `height`, `status`) triples, ignoring order. `utxo_hash`, only if the check has `utxo`: level 2 compares `hash_serialized_3` and `txouts`. |

Shortcut for restarts: when a `restart` carries the same `options` as the ones in force, a runner may skip it entirely (send nothing). Both ways reproduce every normative check in this corpus.

Per-event responses (`result`, `reason`, `best_header`) are diagnostics. Conformance is judged on checks only:

- **Level 0** (required): `tip` and `height` at every check with `normative: true`.
- **Level 1** (optional): chain tips. Bitcoin Core validates side branches lazily and keeps headers of blocks it has not downloaded, so this level depends on storage details that the specification leaves open; it is a debugging aid.
- **Level 2** (optional): the UTXO set commitment (specification chapter 15). Whenever level 0 matches, level 2 should match too; a mismatch points at a bug in UTXO set maintenance even if the tip is right.

## 5. Delivery paths

Bitcoin Core treats a block differently depending on how it arrives. `via` and `requested` record the path so that implementations can reproduce Core exactly; the Core chain harness applies these rules (see its source for the precise conditions):

1. **Mutated blocks over P2P.** If the parent is known and the block is mutated (chapter 11: merkle root mismatch or duplicated transactions, invalid witness commitment or reserved value, witness data without a commitment, or a 64-byte transaction in a block without a coinbase), Core drops it without recording anything, not even the header.
2. **Anti-DoS work threshold over P2P.** The threshold is the tip's chain work minus 144 times the tip's block proof (and at least the minimum chain work, 0 on regtest). A block whose header is new and whose claimed work (parent work plus its own proof) is below it is dropped with nothing stored, not even the header. A headers message of fewer than 2,000 headers whose claimed work (work of the first header's parent plus every header's proof) is below it is ignored entirely, unless its last header is already on the best header chain or the active chain. Core skips the headers check (not the block check) for peers with the noban permission. Only `feature_spec_pitfalls` (part g, from a peer without that permission) reaches the threshold. Five scenarios run with noban peers (`-whitelist=noban` in `reset.args`: `p2p_invalid_block`, `feature_cltv`, `feature_dersig`, `feature_csv_activation`, `p2p_segwit`); none of their headers messages falls below the threshold, so the exemption changes nothing in this corpus.
3. **Unrequested blocks over P2P.** A block Core did not ask for is only fully processed if it passes the context-free block checks and its chain has at least as much work as the active tip and it is at most 288 blocks ahead; otherwise only its header is stored.
4. **Headers messages.** If any header in the message fails proof of work, or the headers are not a continuous chain, nothing is processed. If the first header's parent is unknown, nothing is processed.

Blocks with `via: "rpc"` are always fully processed.

## 6. Restarts and non-normative checks

Bitcoin Core breaks ties between chains of equal work in favor of the block it received first. After a restart it no longer knows the order: blocks loaded from disk get sequence id 1, except the chain that was active at shutdown (id 0), so two equal-work candidates that were both loaded from disk are ordered by memory address, which is not deterministic. The re-delivery of section 4 restores the original arrival order instead. A check after a restart is therefore marked non-normative when another fully available chain tip (`valid-fork` or `valid-headers`) has exactly as much work as the active tip.

Checks are also non-normative when the recorder saw the chain state change while reading it, or when two recordings of the same test with the same seeds disagreed at that point (see `recorder/README.md`).

## 7. Notes for runner authors

- An event `type` not listed in section 4 is an error. New event types come with a new `format_version` (section 8).
- Some scenarios end with blocks dated more than two hours after the wall clock at replay time (tests use mock time). They replay correctly through `PROTOCOL.md`, where `now` is given, but a live node judges time by its own clock, so the interop suite excludes them as a stated rule.
- `now` is never 0.
- Blocks are self-describing: `hash` must equal the double SHA256 of the first 80 bytes of the block, displayed in reverse byte order. Runners may verify this and the blob `sha256` before sending.
- When Core found a block delivered over P2P mutated, or failing the context-free block checks, later byte-identical deliveries of that block cannot change anything and are collapsed into the first one. Core keeps such a block's header valid and re-requests the block, sometimes hundreds of times from the same peer, a timing-dependent number.

## 8. Versioning

This is format version 1. Fields may be added; existing fields will not change meaning. A new `format_version` means an incompatible change.
