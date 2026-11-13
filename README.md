# Bitcoin Consensus Specification

An executable specification of Bitcoin's consensus rules, precise enough that a person or an AI system can build, from this document alone, a node that agrees with Bitcoin Core on every block.

- **Pinned to Bitcoin Core v32.1** (commit `f0de87f040621468b956f01f526a43a010310501`). Specification version `v32.1-1`.
- **Prose plus executable Rust.** Every chapter explains the rules and defines them in Rust code blocks. `reference/build.rs` extracts those blocks into a crate, so the document itself compiles, runs, and is tested against Bitcoin Core.
- **Bitcoin Core is the ground truth.** Every rule names the Bitcoin Core function it mirrors, including the surprising ones. Appendix A lists 79 quirks that independent implementations have gotten wrong.
- **Conformance suite.** A JSON-lines protocol lets any implementation, in any language, be tested against Bitcoin Core's own test vectors, recorded Bitcoin Core block scenarios, and live Bitcoin Core nodes.

## Why

Implementations are becoming cheap to produce. What stays valuable is an exact, testable definition of the protocol they implement. Bitcoin has never had one outside Bitcoin Core's source code; this repository is an attempt to write it down, with tests strong enough that "follows the specification" can be checked mechanically, so that anyone can build a consensus-compatible implementation without being locked in to a particular codebase.

## Status

The reference (the specification's own code) passes:

| Suite | Checks | Result |
|---|---|---|
| Bitcoin Core `script_tests.json`, all 64 consensus flag combinations | 79,168 | pass, identical error codes |
| Bitcoin Core `tx_valid.json` / `tx_invalid.json` | 11,385 / 7,197 | pass |
| Bitcoin Core `sighash.json` | 1,000 | pass |
| BIP341 wallet vectors, BIP340 vectors | 26 / 19 | pass |
| Bitcoin Core qa-assets `script_assets_test.json` (taproot and more), 64 flag combinations | 239,168 | pass, identical error codes |
| Edge cases found by mutation testing and by reviewing other implementations, expectations from Bitcoin Core's own code | 33 | pass |
| Block corpus: 20 scenarios recorded from Bitcoin Core's functional tests and this project's own tests (17,170 events) | 5,282 normative tip checks, 1,237 chain tip sets, 2,292 UTXO set hashes | identical |
| Live interop: the reference node synchronizes each scenario's chain from Bitcoin Core v32.1 over P2P, with no whitelist | tip, height and UTXO set hash for 20 chains | identical, no misbehaviour logged |
| Mainnet and testnet4 header chains from public peers, fully validated | every header | identical tip and chain work |

A separate node written by an AI agent from this document alone ([bitcoin-spec-node](https://github.com/coreyphillips/bitcoin-spec-node)) passed every suite on its first runs. It then synchronized testnet4 from public peers and mainnet from a Bitcoin Core node, checking every script. Its UTXO set was identical to Bitcoin Core's at every height Bitcoin Core publishes for those networks (90,000 to 150,000 on testnet4, 840,000 to 965,000 on mainnet) and at the mainnet tip, block 975,132.

Every expectation above comes from Bitcoin Core v32.1 itself: the "derived" vectors were produced by running Bitcoin Core's own interpreter (compiled from the pinned source) under every consensus flag combination, and the block corpus was recorded from official v32.1 binaries. `RESULTS.md` has the details, the independent reviews, the mutation audit, and the blind implementation experiment (a node built only from this document, which synchronized mainnet next to Bitcoin Core).

## Layout

| Path | Contents |
|---|---|
| `spec/` | The specification: chapters 00 to 15 and appendices A to C |
| `reference/` | Builds the specification's code into a crate, plus `reference-harness` (conformance protocol) and `reference-node` (P2P sync) |
| `conformance/PROTOCOL.md` | The JSON-lines protocol between the runner and an implementation |
| `conformance/runner/` | `bcs-conformance`, the test runner |
| `conformance/oracle-core/` | A harness backed by Bitcoin Core's own consensus code, compiled from the pinned source |
| `conformance/vectors/` | Test data: Bitcoin Core's vectors, qa-assets, BIP340, and vectors derived from Bitcoin Core |
| `conformance/recorder/` | Records Bitcoin Core's functional tests as portable block scenarios |

## Chapters

| | |
|---|---|
| [00 Introduction](spec/00-introduction.md) | [08 Transactions](spec/08-transactions.md) |
| [01 Conventions](spec/01-conventions.md) | [09 Proof of work](spec/09-proof-of-work.md) |
| [02 Cryptography](spec/02-cryptography.md) | [10 Blocks](spec/10-blocks.md) |
| [03 Serialization](spec/03-serialization.md) | [11 Chain state and chain selection](spec/11-chain-state.md) |
| [04 Script encoding and numbers](spec/04-script-encoding.md) | [12 Network parameters](spec/12-network-parameters.md) |
| [05 Script execution](spec/05-script-execution.md) | [13 Signet](spec/13-signet.md) |
| [06 Signature hashes](spec/06-signature-hashes.md) | [14 Peer-to-peer protocol](spec/14-peer-to-peer.md) |
| [07 Script verification](spec/07-script-verification.md) | [15 UTXO set fingerprint](spec/15-utxo-fingerprint.md) |
| [A Quirks checklist](spec/A-quirks-checklist.md) | [B Implementer guide](spec/B-implementer-guide.md) |
| [C Consensus history](spec/C-consensus-history.md) | |

## Quick start

Requirements: a Rust toolchain. The reference has no dependencies outside the Rust standard library; the test runner uses a few crates from crates.io (JSON, gzip, SHA-256, libsecp256k1). The live suites also need network access to Bitcoin Core peers, and `interop` needs a `bitcoind` v32.1 binary.

```sh
# Build the specification's code and run its known-answer tests.
cargo test -p bitcoin-consensus-spec

# Run the conformance suite against the reference.
cargo build --release
./target/release/bcs-conformance --impl ./target/release/reference-harness

# Synchronize from a Bitcoin Core node over P2P (regtest example).
./target/release/reference-node --network regtest --connect 127.0.0.1:18444 --stop-at <block hash>

# Run the reference node against fresh bitcoind instances, one per recorded scenario.
./target/release/bcs-conformance interop --bitcoind /path/to/bitcoind \
  --node "$PWD/target/release/reference-node --network {network} --connect {peer} --stop-at {stop_at} --options {options}"
```

To test your own implementation, give it a harness that speaks [`conformance/PROTOCOL.md`](conformance/PROTOCOL.md) and run `bcs-conformance --impl "<your harness command>"`. See [`conformance/README.md`](conformance/README.md) for the suites and their rules.

## Building an implementation with an AI

Appendix B section B.5 contains a prompt for handing this repository to an AI system, and Appendix A is the checklist to review its output against. The conformance suite is the judge.

## Scope

In scope: everything that decides block and transaction validity and chain selection on mainnet, testnet3, testnet4, signet and regtest; the peer-to-peer subset needed to synchronize with Bitcoin Core. Out of scope: transaction relay policy and the mempool, mining, wallets, RPC, BIP324 encrypted transport.

No test suite proves the absence of divergence. This specification and its suites are strong evidence, built from Bitcoin Core's own tests and code, not a proof. Report a disagreement with Bitcoin Core v32.1 as a defect (Appendix B section B.6).

## Updating

When Bitcoin Core changes consensus, a new specification version is cut against the new release: diff the consensus code between the two tags, update the affected chapters and Appendix A, regenerate the derived vectors with the oracle built from the new tag, and re-record the block corpus.

## License

MIT (see `LICENSE`). Test data from Bitcoin Core (`conformance/vectors/core`) is MIT licensed by the Bitcoin Core developers; `conformance/vectors/qa-assets` comes from the bitcoin-core/qa-assets repository (MIT); `conformance/vectors/bip340` comes from the BIP repository (BSD-2-Clause). See `conformance/vectors/README.md`.
