# Security

The security problem this repository can have is a consensus divergence: a block or transaction on which the specification, its reference code, or a node built from them disagrees with Bitcoin Core v32.1. Anyone who mines the block that triggers it can split such a node from the network. Only the newest specification version (`spec/VERSION`) is corrected; earlier tags are not.

## What to report privately

Report privately a divergence that a block or transaction on mainnet, testnet3, testnet4 or signet could trigger. Use GitHub's private vulnerability reporting: the repository's Security tab, then "Report a vulnerability". Include:

- the failing input, as block or transaction hex, or a `conformance/PROTOCOL.md` request line;
- what Bitcoin Core v32.1 does with it, and what the specification says (chapter and section);
- the specification version, and any implementation you know follows the specification there.

Appendix B section B.6 tells whether the specification is at fault: run `reference-harness` on the same input. If it agrees with Bitcoin Core, the defect is in the implementation, so report it to that implementation's maintainers instead. A bug in Bitcoin Core itself goes to Bitcoin Core (security@bitcoincore.org), not here.

The fix lands as a new specification revision with a test that fails without it. The report is published once the maintainers of implementations known to follow the specification have been told.

## What to report in public

A divergence that no block or transaction on those networks can trigger, such as one that needs regtest's activation heights, goes in an issue with the "Disagreement with Bitcoin Core" template. Bugs in the runner, the harnesses and the recorder go in public issues too.
