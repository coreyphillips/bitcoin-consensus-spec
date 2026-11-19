# Proof-of-work vectors

Cases for chapter 09 of the specification, each with the answer of Bitcoin Core v32.1's own `pow.cpp` and `arith_uint256.cpp` (computed with `conformance/oracle-core`). Every corpus scenario is regtest, which never retargets and never needs a minimum-difficulty block, so without these cases an implementation could get difficulty adjustment wrong and still pass every default suite.

`proof-of-work.jsonl` covers, on every network:

- `pow_compact`: decoding of chosen and random `bits` (sizes 0 to 36, the sign bit, both overflow conditions), the canonical re-encoding with its sign step, and the work of a block;
- `pow_check`: a hash at and one above the target, targets at and above each network's proof-of-work limit, and negative, zero and overflowing `bits`;
- `pow_next_work` at a retarget: actual timespans around both clamps (a quarter and four times the target timespan) and beyond, negative ones, the 2,015 intervals of a period, the proof-of-work limit, and periods that open or close with a minimum-difficulty block (BIP94 takes the first block's `bits` on testnet4);
- `pow_next_work` between retargets: new blocks up to and past the 20-minute rule, and the walk back over minimum-difficulty blocks to the start of a period or to genesis;
- 150 random retargets.

Format as in `vectors/custom` (`name`, `request`, `expect`); every field is scored at level 1. The operations are `PROTOCOL.md` sections 4.14 to 4.16.

Regenerate with:

```sh
python3 conformance/vectors/pow/generate.py <oracle-core-harness> conformance/vectors/pow/proof-of-work.jsonl
```
