# Appendix B. Implementer guide

This appendix is for people, and AI systems, building a node from this specification. It is informative.

## B.1 What to build

A node that conforms to this specification has, at minimum:

1. The consensus functions of chapters 02 to 13, either translated from the reference code or written independently.
2. A chain state (block tree, active chain, UTXO set, undo data) that behaves exactly like chapter 11, persisted to disk.
3. The peer-to-peer subset of chapter 14, to download headers and blocks from Bitcoin Core.
4. A harness program that speaks `conformance/PROTOCOL.md`, so the conformance suite can test it.

Everything else (multiple peers, mempool, RPC, wallets, indexes) is optional and outside consensus.

## B.2 Recommended process

1. Read chapters 00 and 01 fully, then each chapter in order, translating its code. Keep the structure of the reference while doing so; optimize later.
2. Build the harness early. Run `bcs-conformance --impl "<your harness>"` after each chapter: the suites of the script class (chapter 00 section 0.5) need chapters 02 to 08, those of the chain and network classes need everything.
3. Only when every suite passes, restructure for performance (section B.4), re-running the suite after every change.
4. Run the live tests: regtest interop against Bitcoin Core, then the header chains of testnet4 and mainnet, then a full synchronization of testnet4 and mainnet, comparing the UTXO set fingerprint (chapter 15) with Bitcoin Core's published values.

## B.3 Cryptography in production

The reference implements elliptic curve arithmetic in plain Rust for clarity; it is slow (about a millisecond per signature). A production node SHOULD use libsecp256k1 through bindings, with the wrapping rules of chapter 02 section 2.11:

- Parse public keys after checking the first byte and exact length yourself (Bitcoin Core's `CPubKey` length rule).
- Parse ECDSA signatures with the **lax** DER parser (`ecdsa_signature_parse_der_lax`), normalize S, then verify.
- Enforce strict DER (BIP66) separately in the interpreter, only when `DERSIG` is set and the signature is non-empty.
- Never use a strict DER parser for verification.

Hash functions may come from any correct library.

## B.4 Making it fast without changing behaviour

Every optimization below has caused a consensus failure in some implementation. Each is safe exactly when the node behaves as if blocks were processed one by one by chapter 11's `process_block`.

| Optimization | The trap |
|---|---|
| Parallel script verification | Verify all inputs of all transactions, but report the block invalid if any fails. The block is valid only if all pass; a failure must not be lost when threads race. Which failure is reported when several inputs fail is not deterministic in Bitcoin Core either (chapter 10 section 10.8). |
| Signature and script caches | Key script-execution caches by **witness** transaction id and flags. Keying by txid lets a valid transaction's cache entry vouch for a copy with different, invalid witnesses. |
| Batch validation of many blocks (initial sync) | Within a batch, a transaction may spend an output only if it was created by an *earlier* transaction (earlier block, or earlier in the same block). Coinbase maturity, BIP68 ages and BIP30 must use the heights and times of the blocks as connected in order. |
| UTXO cache with lazy flushing | A coin that is missing from the cache must be looked up on disk, never assumed unspent or assumed to have height 0. |
| Skipping work for known blocks (assume-valid) | Only script checks may be skipped, only under the conditions in chapter 11 section 11.12, and every other rule still runs. |
| Header-first synchronization | A header's validity does not make its block valid; blocks still get every check. A header that fails any header check (proof of work, an unknown or invalid parent, the contextual header checks) is not stored, and nothing is recorded about it (chapter 11 section 11.5). Over the peer-to-peer network Bitcoin Core also holds back headers and blocks of chains with too little work (chapters 11 and 14). |
| Pruning | Keep undo data for reorganizations of realistic depth; a pruned node cannot reorganize below its oldest undo data. |
| Fast paths for common scripts | Templates such as pay-to-public-key-hash must still apply every interpreter rule: push size limits, `FindAndDelete`, strict DER only under `DERSIG`, lax DER always, high-S accepted. The simplest safe fast path is no fast path. |
| Deduplicating transactions by txid | Two transactions with the same txid can differ in witness data; only the one in the block counts. |

## B.5 Handing this specification to an AI

The specification was written so that an AI system can implement it. In our experience the following prompt works; adapt the language and architecture to taste.

```text
You are implementing a Bitcoin full node from the specification in this repository
(bitcoin-consensus-spec). The specification is the only source of truth: spec/*.md,
where every ```rust block is normative reference code, and conformance/PROTOCOL.md.

Language: <your language>. Architecture: <your preferences, for example "async networking,
RocksDB for the UTXO set, parallel script verification">.

Rules:
1. Implement every chapter. Where your prior knowledge of Bitcoin disagrees with the
   specification, follow the specification and note the disagreement in SPEC_FEEDBACK.md.
   Where the prose and the Rust code of the specification disagree, the code is
   authoritative; record the disagreement in SPEC_FEEDBACK.md as well.
2. Do not use third-party Bitcoin protocol libraries. Generic libraries (hashing, storage,
   networking, serialization, libsecp256k1 bindings wrapped as chapter 02 section 2.11 says)
   are fine.
3. Build a harness program that speaks conformance/PROTOCOL.md and run
   `bcs-conformance --impl "<harness command>"` after each chapter. Every suite must pass
   (the runner exits with status 0). Aim for identical error identifiers as well, which
   `bcs-conformance --impl "<harness command>" --fail-on-level2` checks.
4. Read Appendix A (quirks checklist) and Appendix B (this guide) before optimizing anything.
   Re-run the full suite after every optimization.
5. When everything passes, run the interop suite against Bitcoin Core on regtest:
   `bcs-conformance interop --bitcoind <path to bitcoind> --node "<node command using
   {network} {peer} {stop_at} {options}>"`. Then synchronize testnet4 and mainnet, stopping
   at each block hash listed in chapter 15, and compare your UTXO set fingerprint with the
   value listed there.
6. Record every place the specification was unclear in SPEC_FEEDBACK.md, with the chapter and
   section, what you assumed, and how a test confirmed or refuted the assumption.
```

## B.6 Reporting specification defects

If an implementation that follows this specification disagrees with Bitcoin Core v32.1, either the specification has a defect or the implementation deviates from it. Run the reference (`reference-harness`) on the same input: if the reference agrees with Bitcoin Core, the implementation deviates; if it agrees with the implementation, the specification has a defect. Please report specification defects with the failing input.
