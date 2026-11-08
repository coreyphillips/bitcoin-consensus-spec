# 00. Introduction

This specification defines the Bitcoin consensus rules precisely enough that an implementation written from it, in any language, accepts exactly the blocks and transactions that Bitcoin Core accepts, rejects exactly the ones it rejects, and follows the same chain. It also defines the subset of the peer-to-peer protocol needed to synchronize with Bitcoin Core nodes.

## 0.1 Ground truth

Bitcoin has no consensus document that predates its software. The rules are whatever the deployed network enforces, and the network's reference implementation is Bitcoin Core. This specification is therefore pinned to one Bitcoin Core release:

| Item | Value |
|---|---|
| Bitcoin Core release | v32.1 |
| Source commit | `f0de87f040621468b956f01f526a43a010310501` |
| Specification version | `v32.1-1` |

Every rule in this document was derived from that source code. Each normative definition names the Bitcoin Core function it mirrors (for example "Core: `CheckTransaction`, `src/consensus/tx_check.cpp`") so that any statement can be audited against the code. Where Bitcoin Core behaves in a surprising way, this specification reproduces the surprise and says so; a consensus specification must describe what the network does, not what would have been cleaner.

When Bitcoin Core changes consensus (for example through a soft fork), a new specification version is released against the new Bitcoin Core release. Version numbers have the form `v<core-release>-<revision>`; the revision counts corrections and clarifications of this document that do not correspond to any change in Bitcoin Core.

## 0.2 How to read this document

Chapters are meant to be read in order. Each chapter mixes prose with Rust code.

- **Code blocks marked `rust` are normative.** Together they form a complete, executable reference implementation: `reference/build.rs` extracts them, in document order, into a Rust crate that is compiled and run against the conformance suite. Names defined in any chapter are visible in every other chapter.
- **Prose explains the code.** It gives intent, history and the pitfalls that implementations have fallen into. If prose and code ever disagree, the code is authoritative and the disagreement is a defect in this specification that should be reported.
- **Code blocks marked `text` are illustrative** and are not compiled.

The reference code is written for clarity, not speed. It uses only the Rust standard library, implements its own hash functions and elliptic curve arithmetic, keeps all state in memory, and validates one block at a time. Production implementations are free to restructure everything (parallel script checking, persistent databases, caches, optimized cryptography libraries) as long as the observable results are identical. Chapter 11 and Appendix B list the properties that such restructuring must preserve, because that is where independent implementations have historically diverged.

### 0.2.1 Requirement language

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Statements about what a function returns are requirements on every implementation: an implementation MUST produce the same result for the same inputs, whatever its internal structure.

## 0.3 Scope

In scope, normative:

- Cryptographic primitives as used by consensus (chapter 02).
- Serialization of transactions, blocks and headers (chapter 03).
- Script: encoding, execution, signature hashing and verification for all script versions (chapters 04 to 07).
- Transaction and block validity, proof of work, and chain selection (chapters 08 to 11).
- Parameters of every network Bitcoin Core supports: main, testnet3, testnet4, signet and regtest (chapters 12 and 13).
- The peer-to-peer messages and behaviour needed to download and serve blocks to and from Bitcoin Core (chapter 14).

In scope, informative (testing aids):

- The UTXO set fingerprint that Bitcoin Core's `gettxoutsetinfo` reports (chapter 15), used to compare an implementation's state with Bitcoin Core's.
- Appendix A, a checklist of every known consensus quirk, each linked to its normative definition.
- Appendix B, guidance for implementers, including how to hand this specification to an AI system.
- Appendix C, the history of consensus changes that explains why the rules look the way they do.

Out of scope:

- Transaction relay policy ("standardness"), the mempool, fee estimation, mining and block template construction. These differ between nodes without splitting the chain. Where policy and consensus are easy to confuse (for example script flags that exist only for policy), this specification says which side of the line a rule is on.
- Wallets, RPC interfaces, address formats and key derivation.
- The encrypted version 2 peer-to-peer transport (BIP324). Bitcoin Core accepts version 1 connections, which chapter 14 specifies.

## 0.4 What "consensus valid" means

A *chain* is a sequence of blocks starting with the network's genesis block, where each block's header names the previous block's hash. A chain is **valid** if every block in it, applied in order to the state produced by the blocks before it, satisfies every rule in chapters 08 to 10. Bitcoin nodes follow the valid chain with the most cumulative proof of work (chapter 11).

Two kinds of disagreement are possible between implementations, and both are consensus failures:

1. One implementation considers a block valid and another considers it invalid. If miners build on such a block, the network splits.
2. Both agree on validity, but they select different chains, or one of them permanently refuses a block it will later need (for example by marking a correct block invalid after receiving a corrupted copy of it). These failures are subtler and are specified in chapter 11.

Some rejections are not about validity at all. A block whose timestamp is too far in the future is rejected *for now* and accepted later. A block whose transactions do not match its header was corrupted in transit and says nothing about the block the header describes. Chapter 01 introduces the vocabulary (`Invalid`, `Mutated`, `Temporary`) that keeps these cases apart.

## 0.5 Conformance

The repository's `conformance/` directory contains a test runner, the test vectors, and a JSON-lines protocol (`conformance/PROTOCOL.md`) through which the runner drives any implementation. An implementation conforms at a level if it passes every test of that level:

| Level | Covers | Runner suites |
|---|---|---|
| 1. Script and transaction | Chapters 02 to 08 for single transactions | `script-tests`, `tx-valid`, `tx-invalid`, `sighash`, `bip341`, `bip340`, `script-assets` |
| 2. Chain | Chapters 09 to 13 and 15 | `corpus`, `headers-live` |
| 3. Network | Chapter 14 | `interop` |

Passing every suite is necessary but not sufficient. The suites are strong (they include every consensus test from Bitcoin Core's own test suite, Core's functional tests replayed as block scenarios, and comparisons against real Bitcoin Core nodes) but no finite test set covers every input. An implementation MUST follow the normative definitions, not merely pass the tests.

## 0.6 Chapter map

| Chapter | Title |
|---|---|
| 00 | Introduction |
| 01 | Conventions |
| 02 | Cryptography |
| 03 | Serialization |
| 04 | Script encoding and numbers |
| 05 | Script execution |
| 06 | Signature hashes |
| 07 | Script verification |
| 08 | Transactions |
| 09 | Proof of work |
| 10 | Blocks |
| 11 | Chain state and chain selection |
| 12 | Network parameters |
| 13 | Signet |
| 14 | Peer-to-peer protocol |
| 15 | UTXO set fingerprint |
| A | Quirks checklist |
| B | Implementer guide |
| C | Consensus history |
