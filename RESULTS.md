# Results

What has been tested, how, and what was found. Everything here is against Bitcoin Core v32.1 (commit `f0de87f040621468b956f01f526a43a010310501`). Numbers are copied from the tools' output.

## 1. The reference

The reference is the specification's own code (every ```rust block in `spec/`, built by `reference/`).

| Suite | Checks | Result |
|---|---|---|
| `script-tests`: Bitcoin Core `script_tests.json` under all 64 consensus flag combinations | 79,168 | pass, identical error identifiers |
| `tx-valid` / `tx-invalid`: Bitcoin Core `tx_valid.json` / `tx_invalid.json`, derived | 11,385 / 7,197 | pass, identical reasons |
| `sighash`: Bitcoin Core `sighash.json` | 1,000 | pass |
| `bip341` / `bip340`: BIP341 wallet vectors, BIP340 vectors | 26 / 19 | pass |
| `script-assets`: qa-assets `script_assets_test.json` under all 64 flag combinations | 239,168 | pass, identical error identifiers |
| `custom`: edge cases found by mutation testing and by reviewing other implementations, expectations computed by Bitcoin Core's own code | 33 | pass, identical error identifiers |
| `corpus`: 20 block scenarios recorded from Bitcoin Core (17,153 events) | 5,276 normative tips; 1,231 chain tip sets; 2,289 UTXO set hashes | all identical |
| `headers-live`: mainnet and testnet4 header chains from public peers, every header validated | 975,114 / 159,961 headers (2026-11-09) | every header accepted; the best header is the peer's last header |
| `interop`: the reference node synchronizes each scenario's chain from a fresh bitcoind v32.1 over P2P | 20 chains: 300 generated blocks and 19 scenarios (one more is excluded by rule: its blocks are dated in the future, which a live node with a real clock rejects) | identical tip, height and `hash_serialized_3` for all 20; bitcoind ran without a whitelist and logged no misbehaviour |

The derived expectations come from Bitcoin Core's own interpreter compiled from the pinned source (`conformance/oracle-core`), which passes the same script and transaction suites. The interop suite's check for misbehaviour was itself tested: a fake node that sends a `getdata` with 50,001 entries is reported ("Misbehaving: peer=0: getdata message size = 50001"). The vector suites passed on the reference's first complete run; so did the first 16 corpus scenarios. Every corpus scenario is replayed with restarts re-delivered (33 restarts, 10,781 re-delivered events), as `conformance/CORPUS.md` section 4 prescribes.

## 2. Independent reviews

Three reviewers, each a fresh agent given the repository and the Bitcoin Core v32.1 source, audited one part of the specification against Core and tried to make the reference disagree with Core.

**Chapters 02 to 07 (scripts and signatures).** Differential fuzzing of the reference against Core's interpreter (about 2.5 million generated cases through the harnesses, and about 194 million in-process checks) found no case where the two disagree. The review found four prose errors, all fixed: the order in which `OP_CHECKMULTISIG` matches signatures to keys was described backwards (the code was right), chapter 04 named the wrong error for number decoding (`UNKNOWN_ERROR` instead of `SCRIPTNUM`), a cross-reference, and the unstated precondition that `WITNESS` implies `P2SH`. It also asked for a stricter harness (input sizes, ranges, lowercase hexadecimal), now implemented.

**Chapters 08 to 13 and 15 (transactions, proof of work, blocks, chain state).** No consensus split and no chain selection difference: 500 random multi-branch scenarios against a v32.1 node (headers first, out of order delivery, spends across forks, invalidations, future timestamps, mutated copies) gave identical tips, chain tip sets and UTXO hashes; 61,200 random difficulty adjustment chains over all networks and 225,377 compact target and proof cases were identical to Core's own `pow.cpp`; 19 signet blocks with real signatures matched. Findings, all fixed: `process_block` reported `accepted` for a block its own activation found invalid (a reported reason only; the chain state was right), Core's script error is not deterministic when several inputs fail (now documented), unrequested blocks below the minimum chain work, the best header tie after an invalidation, sequence numbers after a restart, and the exception count in chapter 12.

**Chapter 14 (peer to peer), consistency and implementability.** Live runs of the reference node against bitcoind v32.1 matched tip and `hash_serialized_3` in every scenario tried (fresh syncs of up to 4,305 blocks with varied transactions, reorganizations while connected, with and without whitelisting), and bitcoind logged no misbehaviour. Findings, all fixed: the conformance runner passed an implementation that implemented nothing (unsupported checks now fail); `PROTOCOL.md` let implementations ignore `requested`, which changes the tip; chapter 14 said Bitcoin Core answers block requests with `notfound` (it never does, so a node built from that text could wait forever); `getheaders` answers, handshake rules, frame size checks and the end of a synchronization did not match Core; and several release attributions in Appendix C were wrong.

## 3. Mutation audit

Each mutant changes one rule from Appendix A in a copy of the reference (for example "treat the transaction version as signed in BIP68", "count legacy sigops accurately in `check_block`"). A mutant is caught when some suite fails. The mutants and the script that runs them are in `conformance/mutation`.

| Mutants | Caught by the vectors and corpus | Notes |
|---|---|---|
| 44 script and transaction rules | 41 by a wrong verdict, 1 more by a wrong reject reason only | The other 2 cannot be caught: skipping `FindAndDelete` of an empty signature in `OP_CHECKMULTISIG` cannot change any result under the consensus flags (an empty signature always fails), and a taproot tweak at or above the curve order needs a tagged hash that large, which is infeasible to find |
| 33 block and chain rules | 31 by a normative tip check, 2 more only by the chain tip sets (a level the suite reports but does not require) | The 2 change only the status of blocks off the active chain (descendants of an invalid block; unrequested low-work blocks kept in full) and no active tip in any recorded scenario |

Every surviving mutant that could be caught led to new tests: 21 custom vectors (script and transaction edge cases, expectations from Core's own code) and a recorded scenario, `feature_spec_pitfalls` (three nodes with different activation options), of hand-built blocks delivered to Bitcoin Core v32.1: BIP68 with high-bit versions, legacy sigop counting at exactly 80,000, the subsidy halving boundary, negative block versions, the version floor where BIP34 is active and BIP66 and BIP65 are not, the 64-byte transaction ambiguity, the P2SH stack limit, the BIP94 timewarp boundary with full blocks, and the anti-denial-of-service work checks for blocks and headers from peers.

A review of three other published consensus implementations (btc-lean, Hornet and Bitcoin Commons, 2026-11-09) found no consensus rule missing from the specification, and one inaccurate sentence (the genesis outpoint, chapter 12 section 12.3). It also found bugs of eight kinds in those projects, each now a mutant (nine in all; Appendix A gains items 73 to 79, and the tapscript case is item 17): ECDSA R or S reduced modulo the group order, a well-formed oversized R or S treated as a script error, `OP_CHECKMULTISIG` checking encodings it never reaches, P2SH redeem scripts over 520 bytes, the push limit skipped in unexecuted tapscript branches, sigop counting stopped by a long push, the coinbase left out of the sigop cost, and a cap on transaction outputs. Three were already caught by the suites. The other six survived, or were caught only by an error identifier (a 32-byte R or S at or above the order treated as an encoding error), and are now caught by twelve new custom vectors and by part j of `feature_spec_pitfalls` (a transaction with 100,001 outputs), re-recorded from Bitcoin Core v32.1, replayed through it, and synchronized from bitcoind v32.1 by the reference node with identical results.

## 4. The blind implementation

`bitcoin-spec-node` is a Rust node written by an AI agent that was given only the specification package: `spec/` and `conformance/` (protocol, runner, vectors), without `reference/`. It was not allowed to read Bitcoin Core's source, BIPs, other implementations or Bitcoin libraries, and could use only generic crates and libsecp256k1 bindings. It is the same model family as the agent that wrote the specification, so it brings general knowledge of Bitcoin; the experiment tests whether the specification is enough to turn that into an exactly compatible node, not whether a reader with no background could do it.

First runs, before any fix:

| Milestone | Suites | First run |
|---|---|---|
| M1: consensus library and harness | all vector suites, 337,963 checks; 21 custom cases | all pass, identical error identifiers |
| M2: chain state | 16 corpus scenarios: 4,951 normative tips, 935 chain tip sets, 2,078 UTXO set hashes | all pass |
| After the specification errata from the reviews (old build, no code changed yet) | the re-recorded corpus, 18 scenarios: 5,114 normative tips | all pass |
| M3: the node (RocksDB, block and undo files, P2P) | `interop` against bitcoind v32.1 without a whitelist, 18 chains | 18 of 18 identical (tip, height, `hash_serialized_3`) |
| Corpus with the version floor and timewarp nodes | 20 scenarios: 5,275 normative tips, 1,230 chain tip sets, 2,288 UTXO set hashes | all pass |

Its own regtest scenarios against bitcoind (about 90,000 signed transactions of every standard output type, reorganizations while connected, and ten kills with SIGKILL during synchronization followed by restarts) also matched Bitcoin Core's tip and UTXO set hash.

It recorded five places where the specification was unclear (`SPEC_FEEDBACK.md` in its repository); all are resolved in the specification or the protocol. The errata it received during the experiment are the review fixes described in section 2; its log states which of them needed code changes.

Holdouts, run by the experiment owner on a fixed commit of the node, not by the agent (testnet4: `7ddd347`; mainnet: `1124fb7`):

| Network | Source | Comparison | Result |
|---|---|---|---|
| testnet4 | public peers from the DNS seeds | `hash_serialized_3` at heights 90,000, 120,000 and 150,000 against Bitcoin Core's values (chapter 15) | **identical at all three heights.** Every block from genesis to 150,000 fully validated, every script checked, in 68 minutes (2026-11-08) |
| mainnet | a local Bitcoin Core v32.1 node as its only peer | `hash_serialized_3` at heights 840,000, 880,000, 910,000, 935,000 and 965,000 against Bitcoin Core's values (chapter 15), then against that node's `gettxoutsetinfo` at a common tip | **identical at all five heights and at the tip.** Every block from genesis to 975,132 fully validated, every script checked (the node has no assume-valid), in 2 hours 26 minutes (2026-11-08) |

At the common tip, block 975,132 (`00000000000000000000d50927e773416b727bdb5706f62a8ec4a7006011a1a1`), both nodes reported `hash_serialized_3` `0139bed824c0ad6b70c60c63fa2bf09fdd06e02a957b4362d6a9889befe1c0ef` over 163,585,794 unspent outputs. The blind node computed its value after a clean shutdown and a restart from its database. The machine was an Apple M5 Pro (6 performance and 12 efficiency cores, 64 GB); the node verifies signatures with libsecp256k1 on every core, as chapter 02 section 2.11 allows.

## 5. Not covered

- The reference itself has validated mainnet and testnet4 *headers* from real peers, not their blocks: it keeps its state in memory and is written for clarity, not speed. Full block validation of both networks was done by the blind implementation (section 4).
- A full synchronization shows that the node accepts every block of the real chain and reaches the same UTXO set as Bitcoin Core at the compared heights. It does not exercise invalid blocks; their rejection is tested by the vector suites and the block corpus.
- The low-work headers synchronization of Bitcoin Core (download, prove, download again) is described but not implemented by the reference; for honest peers the stored result is the same.
- Out of scope by design: the BIP324 encrypted transport, transaction relay and mempool policy, compact blocks, address relay, mining and wallets.
- No test suite proves the absence of divergence. These results are strong evidence, not a proof.
