# Signet vectors

Cases for chapter 13 of the specification, each with the answer of Bitcoin Core v32.1's own `CheckSignetBlockSolution` (computed with `conformance/oracle-core`). Every corpus scenario is regtest and `headers-live` sees only headers, so without these cases an implementation could accept every signet block and still pass every default suite.

`signet-block-solution.jsonl` sends blocks built and signed by `generate.py` under chosen challenges (a key with `OP_CHECKSIG`, a 1-of-1 `OP_CHECKMULTISIG`, `OP_TRUE`, a P2WSH of `OP_TRUE` and a witness version 1 program):

- a signed block; the nonce and bits changed after signing (not signed); the time, version, previous block, transaction list or order changed after signing (signed);
- a signature by another key, over another block, or for another challenge, and one that is not strict DER;
- no commitment output, a commitment output one byte short, a solution outside the commitment output, a commitment without a solution, and no transactions at all;
- solutions with a byte left over, cut short, or without a witness stack;
- where the solution is found: a 4-byte header push is skipped, the first solution push counts and the last commitment output is the commitment;
- what is signed: other pushes re-encoded canonically, an empty `OP_PUSHDATA1` as its opcode alone, opcodes after the solution, and a malformed push dropped;
- the script flags: `NULLDUMMY`, `DERSIG`, `WITNESS` (a P2WSH challenge) and no `TAPROOT` (a witness version 1 challenge accepts any solution);
- the signet genesis block, which needs no solution, and the same block with another nonce.

Format as in `vectors/custom` (`name`, `request`, `expect`); every field is scored at level 1. The operation is `PROTOCOL.md` section 4.17.

Regenerate with:

```sh
python3 conformance/vectors/signet/generate.py <oracle-core-harness> conformance/vectors/signet/signet-block-solution.jsonl
```

Each case states the verdict it was built for, and the script stops if Core's answer differs.

## Blocks through chain processing

`signet_check` alone does not show that an implementation calls the check when it processes a block. `signet-blocks.jsonl.gz` is a scenario in the corpus format (`CORPUS.md`), replayed by the `corpus` suite, not by this one. It runs on a custom signet whose challenge is the key with `OP_CHECKSIG` above. Its blocks carry real proof of work at signet's limit and a valid witness commitment, and all go through `submitblock` (`via: "rpc"`):

- height 1: a block without a solution, then one signed by another key, then the signed block;
- height 2, on the signed block: a block without a solution, then the signed block.

A check follows each block. The two signed blocks must become the tip, and each of the other three must leave it where it was. Bitcoin Core rejects those three with `bad-signet-blksig`, which each check's label records. The runner does not score per-block reasons, so the checks catch an implementation that accepts such a block, whatever reason it gives for a rejection.

Regenerate with the command below (about 25 million double SHA256 hashes in Python worker processes). Every block takes the smallest nonce that meets its target, so the file is the same on every run.

```sh
python3 conformance/vectors/signet/generate_blocks.py conformance/vectors/signet/signet-blocks.jsonl.gz [workers]
```

The expectations, tip sets included, are confirmed against Bitcoin Core v32.1 by replaying the file through `recorder/core_chain_harness.py`:

```sh
target/release/bcs-conformance corpus --corpus conformance/vectors/signet --fail-on-tips \
  --impl "docker run -i --rm -v $PWD/conformance/recorder:/h:ro bcs-recorder:32.1 python3 /h/core_chain_harness.py"
```
