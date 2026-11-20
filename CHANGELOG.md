# Changelog

One entry per specification version. A version is `v<core-release>-<revision>` (chapter 00 section 0.1), and `spec/VERSION` holds the current one. Entries cover `spec/`; changes to the conformance suites, the recorded data and the tooling are in the git history.

## v32.1-3 (not yet tagged)

Pinned to Bitcoin Core v32.1, commit `f0de87f040621468b956f01f526a43a010310501`. No consensus rule changed; these are corrections and clarifications.

- Chapter 00: the conformance classes list the `pow`, `signet`, `params`, `block-connect` and `peer-sync` suites. Section 0.1 points to this file.
- Chapter 04: signature operation counting stops only at a push whose length field or data runs past the end of the script; the 520-byte push limit does not apply (section 4.9). The `OP_SUCCESSx` paragraph points to chapter 07 section 7.2.
- Chapter 05: with `DERSIG`, the encoding check constrains the form of R and S, not their size (section 5.5.1). The order in which `OP_CHECKMULTISIG` pops its operands is stated exactly.
- Chapter 06: a note that the code rehashes taproot's `SIGHASH_SINGLE` output on every signature check, where Bitcoin Core hashes it once per input.
- Chapter 08: transactions have no limit on their number of inputs or outputs other than the size rule (section 8.3). The coinbase's legacy signature operations count toward the block's cost limit (section 8.8).
- Chapter 10: the running signature operation cost of a block starts with the coinbase's legacy count (section 10.8).
- Chapter 12: `network_params` returns an error instead of panicking on an unknown deployment name or a mainnet override. Section 12.3 rewords why the genesis coinbase output cannot be spent.
- Chapter 14, the protocol: a message with a malformed command field is dropped (section 14.1), and an oversized locator is not misbehaviour (section 14.2). Section 14.4 describes Bitcoin Core's two block download timeouts correctly. The chapter now covers pruned peers, invalid and unconnected headers, and the peer that stays silent on `getheaders` during a reindex.
- Chapter 14, `sync_from_peer`: synchronization starts only once the peer's `version` has been accepted and answered, and before the handshake only `version` and `verack` are read. The 60-second handshake deadline runs from the TCP connect, and chain progress no longer postpones it. The loop gives up on a peer that never answers `getheaders`, repeats the same full batch, or stops reading. After a full `headers` batch the next locator starts at the best header. Only the oldest block in flight is timed, with Bitcoin Core's 10-minute limit. `--stop-at` stops at a block below the peer's tip. The tests check the node's answers to `getheaders`.
- Chapter 15: the genesis block's own coinbase output is the one left out of the UTXO set.
- Appendix A: items 73 to 79, found by reviewing other implementations. Items 20, 27, 55 and 64 corrected or made precise.
- Appendix B: a failed block in a batch must leave the state that connecting the blocks before it one by one gives. Implementers run `peer-sync` after `interop`, and the prompt in section B.5 asks for it. A note on the code that is slower than Bitcoin Core.

## v32.1-2 (tagged 2026-11-09)

Corrections from the blind implementation (`RESULTS.md`). The files at this tag still state `v32.1-1`.

- Chapter 11 section 11.12: after loading persisted state, a node must run chain activation before it waits for new data.
- Chapter 12: the minimum chain work and assume-valid block of each network, which are not consensus, and when a node needs them.
- Chapter 14 section 14.4: finish headers synchronization with a peer before requesting blocks from it. `p2p_low_work_failure` gives the reason Bitcoin Core reports for an unrequested block with too little work.

## v32.1-1 (tagged 2026-11-09)

First version, pinned to Bitcoin Core v32.1, commit `f0de87f040621468b956f01f526a43a010310501`.
