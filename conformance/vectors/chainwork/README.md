# Most work against longest chain

Every block of the recorded corpus (`vectors/blocks`) is regtest, where every block has the same work, so the longest chain is always the chain with most work. An implementation that selects the longest chain, or counts each block as one unit of work, passes all of it.

`most-work.jsonl.gz` is one scenario in the corpus format (`CORPUS.md`), replayed by the `corpus` suite with the recorded scenarios. It runs on a custom signet whose challenge is `OP_TRUE` (`51`), so blocks need no signature but carry real proof of work at signet's proof-of-work limit (about 4.8 million hashes each). The 2,016th block is the first retarget (chapter 09 section 9.5):

- a trunk of 2,014 blocks, one every 100 seconds;
- branch b: block 2,015 two weeks after genesis, so the target stays, and three more blocks (height 2,018);
- branch a: block 2,015 at the same pace as the trunk, so block 2,016 retargets to a quarter of the target (four times the work). At height 2,016 it is two blocks shorter than b and has more work, and must become the tip;
- one more block on b leaves a ahead; a second gives b more work, and b must become the tip again.

Each check carries `chainwork`, the active chain's total work, which the runner compares with `chain_tip`'s. So a wrong `block_proof` fails at the first check. All blocks go through `submitblock` (`via: "rpc"`).

Regenerate with the command below. Mining is about 10^10 double SHA256 hashes in Python worker processes, so it takes a while; the optional third argument names a nonce cache from which an interrupted run resumes. Every block takes the smallest nonce that meets its target, so the file is the same on every run.

```sh
python3 conformance/vectors/chainwork/generate.py conformance/vectors/chainwork/most-work.jsonl.gz [workers] [nonce-cache]
```

The expectations are confirmed against Bitcoin Core v32.1 by replaying the file through `recorder/core_chain_harness.py`, which starts `bitcoind -signet -signetchallenge=51` for this scenario:

```sh
target/release/bcs-conformance corpus --corpus conformance/vectors/chainwork \
  --impl "docker run -i --rm -v $PWD/conformance/recorder:/h:ro bcs-recorder:32.1 python3 /h/core_chain_harness.py"
```
