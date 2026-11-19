# Network parameter vectors

The consensus parameters of the five networks (chapter 12), each read from Bitcoin Core v32.1's own `CChainParams` (computed with `conformance/oracle-core`). Every corpus scenario is regtest, so without these cases a wrong mainnet or testnet deployment height, halving interval, BIP94 setting or script flag exception list passed every default suite.

`network-params.jsonl` has one case per network and field of `network_params` (`PROTOCOL.md` section 4.18), so a harness with one wrong value fails one check. Format as in `vectors/custom`; every field is scored at level 1.

These cases check the values, not the chapter 10 code that reads them: whether a block's script flags take its exception, and the BIP30 exemptions, still need a block from those networks.

Regenerate with:

```sh
python3 conformance/vectors/params/generate.py <oracle-core-harness> conformance/vectors/params/network-params.jsonl
```
