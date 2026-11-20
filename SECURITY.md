# Security

The security problem this repository can have is a consensus divergence: a block, header or transaction on which the specification, its reference code, or a node built from them disagrees with Bitcoin Core v32.1. Anyone who mines the block that triggers it can split such a node from the network. Only the newest specification version (`spec/VERSION`) is corrected; earlier tags are not.

## What to report privately

Report privately a divergence that a block, header or transaction on mainnet, testnet3, testnet4 or signet could trigger. Use GitHub's private vulnerability reporting: the repository's Security tab, then "Report a vulnerability". Include:

- the failing input, as block, header or transaction hex, or a `conformance/PROTOCOL.md` request line. When the answer depends on chain state, give every block or request from `chain_reset` on. Public chain history can be named by its network and last block hash instead;
- what Bitcoin Core v32.1 does with it, and what the specification says (chapter and section);
- the specification version, and any implementation you know follows the specification there.

If the Security tab has no "Report a vulnerability" button, open an issue that asks for a private contact and says nothing about the problem.

Appendix B section B.6 tells whether the specification is at fault: run `reference-harness` on the same input. If it agrees with Bitcoin Core, the defect is in the implementation, so report it to that implementation's maintainers instead. The harness does not run chapter 14's peer synchronization (`reference-node` does), so a divergence that appears only when headers or blocks arrive from a peer is reported here whatever the harness answers. A bug in Bitcoin Core itself goes to Bitcoin Core (security@bitcoincore.org), not here.

The fix is a new specification revision with a test that fails without it, prepared in the advisory's private fork. The fix, the test and the report are published together, after the maintainers of implementations known to follow the specification have been told and have had time to prepare their own fixes.

## What to report in public

A divergence that no block, header or transaction on those networks can trigger, such as one that needs regtest's activation heights, goes in an issue with the "Disagreement with Bitcoin Core" template. Bugs in the runner, the harnesses and the recorder go in public issues too.
