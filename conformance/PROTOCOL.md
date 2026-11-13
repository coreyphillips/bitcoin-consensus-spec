# Conformance harness protocol, version 1

This document defines how the conformance runner talks to an implementation under test. Any implementation, in any language, can be tested by providing a small *harness program* that speaks this protocol and calls into the implementation.

The protocol is deliberately narrow. It exposes the consensus functions defined by the specification (script verification, signature hashing, transaction checks, block and header processing, chain state queries) and nothing else.

## 1. Transport

- The runner starts the harness as a child process using a command line supplied by the user (`--impl "<command>"`).
- The runner writes requests to the harness's standard input and reads responses from its standard output.
- Each message is one JSON object encoded as UTF-8 on a single line, terminated by `\n`. Messages never span lines.
- For every request the harness writes exactly one response line, in request order. The runner sends the next request only after it has read the previous response.
- Standard error is free for logging. The runner may save it but never parses it.
- When standard input reaches end of file, the harness exits with status 0.
- The runner starts the harness, and the node commands of sections 5 and 5.1, through `sh -c` in a process group of its own. When it ends one (a harness that stopped answering, a node past its timeout, the end of the run), every process left in that group gets SIGTERM (with SIGCONT, so that a stopped process acts on it), and 10 seconds later SIGKILL, so a wrapper and the processes it started end together. When the runner itself gets SIGINT, SIGQUIT, SIGTERM or SIGHUP, it sends SIGTERM to every such group before it exits.
- When the runner is started from a terminal, these groups are background groups of that terminal. A command has no use of the terminal and must not prompt (a `sudo` password, an `ssh` passphrase or host key question): a process that reads the terminal is stopped by SIGTTIN. The runner fails at once when it finds a stopped process in a command's group, and does not restart a harness that was stopped.
- Blank input lines are ignored and produce no response.

## 2. Requests and responses

Every request has an integer `id` and a string `op`. Every response echoes the `id` and has a boolean `ok`.

```text
request:  {"id": 7, "op": "script_verify", ...op fields...}
success:  {"id": 7, "ok": true, ...result fields...}
failure:  {"id": 7, "ok": false, "error": "unsupported_op", "message": "free text"}
```

`ok: false` means the harness could not perform the operation at all. It is reserved for these error codes:

| `error` | Meaning |
|---|---|
| `unsupported_op` | The implementation does not provide this operation. The runner reports the affected suite as not supported. |
| `bad_request` | The request is malformed (missing field, bad hex). This always indicates a runner or harness bug. If the line is not a JSON object at all, the response's `id` is `null`. |
| `internal` | The implementation failed unexpectedly (panic, assertion). Counted as a test failure. |

A consensus failure is **not** a protocol error. For example, a script that fails verification yields `{"ok": true, "valid": false, ...}`.

## 3. Encodings

- **Bytes** are lowercase hexadecimal strings of even length. The empty byte string is `""`.
- **Hashes** appear in one of two orders, stated for each field:
  - *display order*: the 32 bytes reversed, as Bitcoin Core prints transaction ids and block hashes in its RPC interface (`000000000019d668...` for the mainnet genesis block);
  - *raw order*: the bytes exactly as the hash function outputs them.
- **Integers** are JSON numbers. All values used by the runner fit in the range of a signed 64-bit integer and are exactly representable as JSON numbers (amounts are at most 2,100,000,000,000,000 satoshis in valid data; test data may contain negative or larger values, which are still below 2^53 in magnitude).
- **Amounts** are in satoshis.
- **Times** (`now`) are Unix times in seconds.
- **Transactions** are serialized as defined in the specification, including witness data when present. Blocks are serialized with witness data.

### 3.1 Script verification flags

Flags are sent as an array of names. The runner only ever sends these seven consensus flags:

| Name | Meaning (specification chapter 07) |
|---|---|
| `P2SH` | BIP16 pay-to-script-hash evaluation |
| `DERSIG` | BIP66 strict DER signatures |
| `NULLDUMMY` | BIP147 empty CHECKMULTISIG dummy |
| `CHECKLOCKTIMEVERIFY` | BIP65 |
| `CHECKSEQUENCEVERIFY` | BIP112 |
| `WITNESS` | BIP141/143 segregated witness |
| `TAPROOT` | BIP341/342 taproot and tapscript |

The runner never sends `WITNESS` without `P2SH`. It may send `TAPROOT` without `WITNESS` (in that case `TAPROOT` has no effect, exactly as specified).

## 4. Operations

### 4.1 `info`

Request: `{"id":1,"op":"info"}`

Response fields:

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Implementation name |
| `version` | string | Implementation version |
| `spec_version` | string | Specification version implemented, for example `v32.1-1`. Harnesses that wrap something other than a specification implementation (such as Bitcoin Core itself) report what they wrap, for example `v32.1`. |
| `ops` | array of strings | Operations supported, from this document |
| `extensions` | array of strings, optional | Extra operations outside this document. Their names start with `x_`. |

### 4.2 `script_verify`

Verifies one input of a transaction, exactly as the specification's `verify_script` with a transaction signature checker (chapter 07).

| Request field | Type | Meaning |
|---|---|---|
| `tx` | hex | The spending transaction, serialized with witness data if any |
| `index` | integer | Input index to verify |
| `spent_outputs` | array | One entry per input of `tx`, in input order: `{"amount": integer, "script_pubkey": hex}` |
| `flags` | array of strings | Consensus flags (section 3.1) |

The script under test is `spent_outputs[index].script_pubkey`, the amount is `spent_outputs[index].amount`, and the full list is available to signature hashing (taproot commits to every spent output).

| Response field | Type | Meaning |
|---|---|---|
| `valid` | bool | Verification result |
| `script_error` | string, optional | Error identifier from specification chapter 05 section 5.2 (for example `EVAL_FALSE`, `SIG_DER`), without any prefix. `OK` or absent when valid. |

The identifiers are those of Bitcoin Core's script test table where it has one, and otherwise Bitcoin Core's `SCRIPT_ERR_` enum name without the prefix. Eight identifiers are not in Core's test table: `UNKNOWN_ERROR` (in Bitcoin Core v32.1 reachable only through an unexpected exception, so a conforming implementation never reports it), `SCHNORR_SIG`, `SCHNORR_SIG_HASHTYPE`, `SCHNORR_SIG_SIZE`, `TAPROOT_WRONG_CONTROL_SIZE`, `TAPSCRIPT_CHECKMULTISIG`, `TAPSCRIPT_MINIMALIF` and `TAPSCRIPT_VALIDATION_WEIGHT`. The one name that differs from the enum is `NULLFAIL` (enum `SIG_NULLFAIL`), which never occurs under consensus flags.

The runner scores `valid` (level 1). Where the expected error is known, it also reports whether `script_error` matches (level 2).

### 4.3 `tx_check`

Deserializes a transaction (witness serialization allowed) and applies the context-free transaction checks of specification chapter 08 (`check_transaction`).

| Request field | Type | Meaning |
|---|---|---|
| `tx` | hex | Serialized transaction |

| Response field | Type | Meaning |
|---|---|---|
| `valid` | bool | True if the bytes deserialize completely (no trailing bytes) and pass the checks |
| `reason` | string, optional | Reject reason identifier, for example `bad-txns-vin-empty`, or `tx-decode` when deserialization fails |

Decoding follows specification chapter 03 exactly. In particular the ten bytes `version | 00 00 | lock_time` decode to a transaction with no inputs and no outputs, so they fail with `bad-txns-vin-empty`, not `tx-decode`.

### 4.4 `sighash_legacy`

Computes the legacy (pre-segwit) signature hash of specification chapter 06 for an arbitrary 32-bit hash type.

| Request field | Type | Meaning |
|---|---|---|
| `tx` | hex | Transaction |
| `script_code` | hex | Script code, used as given (OP_CODESEPARATOR removal is part of the algorithm) |
| `index` | integer | Input index (always less than the number of inputs) |
| `hash_type` | integer | Signed 32-bit hash type; negative values are sent as negative numbers |

Response: `{"sighash": hex}` with the 32-byte result in raw order.

### 4.5 `sighash_taproot`

Computes the BIP341/BIP342 signature hash of specification chapter 06.

| Request field | Type | Meaning |
|---|---|---|
| `tx` | hex | Transaction |
| `index` | integer | Input index |
| `spent_outputs` | array | As in `script_verify` |
| `hash_type` | integer | 0 to 255 |
| `annex` | hex, optional | The annex including its leading `0x50` byte, if present |
| `leaf_hash` | hex, optional | Tapleaf hash (raw order) for script path spends; when present the extension for tapscript is used |
| `codesep_pos` | integer, optional | Position of the last executed OP_CODESEPARATOR for tapscript (default `4294967295`) |

Response: `{"valid": bool, "sighash": hex}`. `valid` is false exactly when the specification's algorithm fails (invalid hash type, SIGHASH_SINGLE without a matching output); `sighash` is then omitted. The transaction is usually unsigned: the signature hash does not depend on witness data, and the annex, if any, is passed separately.

### 4.6 `taproot_commitment_verify`

Checks a taproot script path commitment as in specification chapter 07 (`verify_taproot_commitment`).

| Request field | Type | Meaning |
|---|---|---|
| `control_block` | hex | Control block |
| `script` | hex | Leaf script |
| `output_key` | hex | 32-byte x-only output key (the witness program) |

Response: `{"valid": bool}`. The leaf version is taken from the control block. A control block whose length is not `33 + 32m` with `m <= 128` gives `valid: false` (it is a consensus failure, `TAPROOT_WRONG_CONTROL_SIZE`, not a malformed request).

### 4.7 `schnorr_verify`

BIP340 verification (specification chapter 02) of a message of any length.

| Request field | Type | Meaning |
|---|---|---|
| `pubkey` | hex | 32 bytes |
| `msg` | hex | Message, any length |
| `sig` | hex | 64 bytes |

Response: `{"valid": bool}`.

### 4.8 `chain_reset`

Discards all chain state and starts a fresh chain containing only the genesis block of the selected network.

| Request field | Type | Meaning |
|---|---|---|
| `network` | string | `main`, `testnet3`, `testnet4`, `signet` or `regtest` |
| `options` | object, optional | Network parameter overrides (specification chapter 12): `{"testactivationheight": {"bip34": 2, "segwit": 120}, "test": ["bip94"], "signetchallenge": hex}` |

Response: `{"genesis": hash}` in display order.

### 4.9 `chain_process_block`

Delivers a full block, as if it arrived from a peer or through block submission, and processes it according to specification chapters 10 and 11. The harness must apply all effects (validation, storage, chain selection, reorganization) before responding.

| Request field | Type | Meaning |
|---|---|---|
| `block` | hex | Serialized block with witness data |
| `now` | integer | Current time for the future-timestamp rule |
| `via` | string, optional | How Bitcoin Core received the block when the scenario was recorded: `p2p` (default) or `rpc` (block submission). For `p2p`, the implementation MUST first apply the peer-to-peer checks of specification chapter 14 section 14.4 (`is_block_mutated`, `p2p_block_work_acceptable`). |
| `requested` | bool, optional | For `via: p2p`, whether Bitcoin Core had requested the block (default true). The implementation MUST pass it to block processing as specification chapter 11 section 11.6 step 4 requires. |

Ignoring `via` or `requested` can change the active tip: an unrequested block that is reduced to its header, or a mutated block that is dropped, is not linked when its descendants arrive.

Recorded scenarios already contain the bytes Bitcoin Core actually validated. In particular, where `submitblock` would have added the default coinbase witness reserved value (Bitcoin Core's `UpdateUncommittedBlockStructures`), the recorded block already contains it, so no RPC behaviour needs to be emulated.

| Response field | Type | Meaning |
|---|---|---|
| `result` | string | One of the outcomes below |
| `reason` | string, optional | Reject reason identifier for `invalid`, `mutated`, `temporary` |
| `tip` | hash | Active chain tip after processing, display order |
| `height` | integer | Height of that tip |

Outcomes:

| `result` | Meaning |
|---|---|
| `accepted` | The block was stored, and the chain activation this request triggered did not find the block itself invalid. It may or may not be on the active chain, and a block that was not connected has not been fully validated. Also used, with reason `unrequested-header-only`, when an unrequested block was reduced to its header (chapter 11 section 11.6 step 4). |
| `duplicate` | The block's full data was already known before this request, and the block is not known to be invalid. Nothing changed. |
| `orphan` | The parent header is unknown. The block was discarded. Implementations must not keep it for later. |
| `invalid` | The header or the block violates consensus, either before storage or when chain activation tried to connect this block. Whether the hash is now remembered as invalid follows chapter 11 (failures of the context-free body checks are not remembered). A block already known to be invalid gives reason `duplicate-invalid`. Also used, with reason `too-little-chainwork`, for a `via: p2p` block dropped by the anti-denial-of-service work check of chapter 14; nothing is recorded then. If such a block also fails the context-free block checks or the header checks, the reason is that failure instead (chapter 14, `p2p_low_work_failure`). |
| `mutated` | The block data does not match what its header commits to (chapter 11, "Mutated blocks"), or the bytes do not decode as a block (the reason then describes the decoding error and is implementation-defined). Nothing about the block hash was recorded; a correct copy of the same block can still be accepted later. |
| `temporary` | The header's timestamp is too far in the future relative to `now`. Nothing was recorded. |

Conformance is judged on `tip` and `height` at the checkpoints of a scenario. Per-block outcomes are reported as diagnostics only, because implementations may validate side branches earlier or later than Bitcoin Core does without any effect on the active chain.

### 4.10 `chain_process_headers`

Delivers block headers (80 bytes each), as in a `headers` message (chapter 14), and processes them according to chapter 10 header rules.

| Request field | Type | Meaning |
|---|---|---|
| `headers` | array of hex | Headers in order; each must connect to a known header or to the previous one in the array |
| `now` | integer | Current time |
| `via` | string, optional | `p2p` (default): the headers arrived in one `headers` message, and the whole message is dropped unless it passes the message-level checks of specification chapter 14 (`headers_message_acceptable`). `rpc`: header submission by an operator (one header per request), processed directly. |

| Response field | Type | Meaning |
|---|---|---|
| `result` | string | `accepted`, `invalid`, `orphan` or `temporary` (meanings as in 4.9, applied to headers) |
| `reason` | string, optional | Reject reason identifier |
| `index` | integer, optional | Index in `headers` of the first header that was not accepted |
| `best_header` | hash | Most-work valid header known after processing, display order |

A `via: p2p` message dropped as a whole by `headers_message_acceptable` gives `result` `invalid`, `reason` `headers-message-rejected` and no `index`; nothing was processed. Like the outcomes of 4.9, results and reasons are diagnostics; conformance is judged on the chain state.

### 4.10a `chain_invalidate`

Marks a block, and every descendant, invalid by operator decision, exactly as specification chapter 11 defines `invalidate_block` (Bitcoin Core's `invalidateblock` RPC). If the block is on the active chain, the chain is rewound and the best remaining chain is activated. Several of Bitcoin Core's functional tests use this to rewind the chain, so recorded scenarios contain it.

| Request field | Type | Meaning |
|---|---|---|
| `hash` | hash | Block hash, display order. The block must be known (header at least). |
| `now` | integer, optional | Current time; runners send it for symmetry with the other chain operations, and a harness may ignore it |

Response: `{"tip": hash, "height": integer}` after the operation.

### 4.11 `chain_tip`

Response: `{"tip": hash, "height": integer, "chainwork": hex}`. `tip` is in display order. `chainwork` is the cumulative work of the active chain as a 32-byte big-endian number in hex (as Bitcoin Core's `getblockchaininfo` prints it).

### 4.12 `chain_tips`

Response: `{"tips": [{"hash": hash, "height": integer, "status": string}, ...]}` using the status names of Bitcoin Core's `getchaintips`: `active`, `valid-fork`, `valid-headers`, `headers-only`, `invalid`. Diagnostic only.

### 4.13 `utxo_hash`

Response: `{"hash_serialized_3": hash, "txouts": integer}` for the active chain tip, computed as in specification chapter 15. `hash_serialized_3` is in display order, matching Bitcoin Core's `gettxoutsetinfo`.

This operation is optional. A harness for an implementation that keeps no UTXO set leaves it out of `ops`. The runner then does not send it, and counts each UTXO check of the corpus at level 2 as not compared, which fails the run only with `--fail-on-level2` (as for a live node that leaves `hash_serialized_3` out, section 5).

## 5. Live node contract

The interop suite runs the implementation as a real node next to Bitcoin Core (the peer-sync suite has its own contract, section 5.1). For that suite the user supplies a node command template. The runner substitutes these placeholders:

| Placeholder | Value |
|---|---|
| `{network}` | `main`, `testnet3`, `testnet4`, `signet` or `regtest` |
| `{datadir}` | An empty directory for the node's data. A node that keeps no data may ignore it. |
| `{peer}` | `host:port` of the Bitcoin Core node to connect to |
| `{stop_at}` | Block hash (display order) at which to stop |
| `{options}` | The network options object of section 4.8 as one shell-quoted JSON argument, `'{}'` when there are none |

The runner skips, as a stated rule, every scenario that needs network options when the template has no `{options}`.

Required behavior:

1. Start from an empty data directory, apply the network options, connect only to `{peer}` using the version 1 transport (specification chapter 14), and synchronize. When the runner is given `--v2transport`, the peer also accepts the BIP324 version 2 transport, and the node may use either.
2. When the active tip equals `{stop_at}`, write one line to standard output and exit with status 0:
   `{"event":"stopped","tip":hash,"height":integer,"hash_serialized_3":hash}`
   `hash_serialized_3` (specification chapter 15) may be left out by a node that keeps no UTXO set. The runner then reports the chain at level 2 (UTXO hash not compared), which fails the run only with `--fail-on-level2`. When present, it must equal Bitcoin Core's.
3. When the node cannot reach `{stop_at}` (the peer does not offer it, sends a block the node finds invalid, stops answering, or nothing changes for a while), exit with a non-zero status, after writing at most one line `{"event":"error","message":string,"tip":hash,"height":integer}` (`tip` and `height` optional). It must not wait forever: the runner ends the node after its `--node-timeout` (section 1) and counts that as a failure.
4. Progress lines `{"event":"tip","tip":hash,"height":integer}` may be written at any time. Lines whose `event` starts with `x_` are implementation extensions, which the runner ignores. No other line on standard output may start with `{`.

## 5.1 Peer-sync node contract

The peer-sync suite also runs the implementation as a real node, but the runner itself is its only peer. It serves the blocks of each corpus scenario, including blocks Bitcoin Core rejects, through the node's own synchronization, and asks the node for its tip along the way. The user supplies a second node command template, `--sync-node`:

| Placeholder | Value |
|---|---|
| `{network}` | `regtest` |
| `{datadir}` | An empty directory for the node's data |
| `{peer}` | `127.0.0.1:port` of the runner |
| `{options}` | As in section 5 |

There is no `{stop_at}`: the runner says when to stop, and refuses a template that has one.

Required behavior:

1. Start from an empty data directory, apply the network options, connect only to `{peer}`, and synchronize. The runner accepts the version 1 transport and the BIP324 version 2 transport. Keep running when the peer sends a block the node finds invalid. A node that disconnects the peer for it must connect to `{peer}` again; the runner keeps listening.
2. Read requests from standard input, one JSON object per line:
   - `{"op":"tip","id":n}`: once every block the node has received has been processed (connected, or found invalid), write `{"event":"tip","id":n,"tip":hash,"height":integer}`. The runner sends `ping` and waits for the `pong` before each request, so every block it sent before is received.
   - `{"op":"stop"}`: write `{"event":"stopped","tip":hash,"height":integer,"hash_serialized_3":hash}` (`hash_serialized_3` optional, as in section 5) and exit with status 0.
   - When standard input closes, exit. The runner gives the command 10 seconds, then ends its process group (section 1).
3. Standard output follows section 5, item 4. A `tip` line without `id` is a progress line. An `error` line fails the check in progress.

Corpus blocks carry the times they were recorded, usually days or more before the run. A node whose "initial block download" state depends on the age of its tip (Bitcoin Core's `-maxtipage`, 24 hours by default) stays in that state for the whole scenario, so a node command must not wait for it to clear before answering, unless it raises that limit.

A node whose answers can run ahead of its validation still gets a fair verdict: when an answer is not the expected tip, and in the suite's ibd mode for every answer, the runner keeps serving requests and asks again once the node has requested no block of the chain for one second, and it judges the node by two answers in a row that agree with no block of the chain requested between them. The quiet second and both answers must fall on one connection: a node that drops the runner and connects again is still synchronizing.

## 6. Versioning

This is protocol version 1. Operations may be added in later versions; existing fields will not change meaning. The runner asks for `info` first. It runs a suite if at least one of the suite's operations is listed in `ops`, and reports every check that needs an unlisted operation as unsupported (a failure unless the user excludes that suite).
