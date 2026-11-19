# Median time past near genesis

Near genesis a block's median time past has fewer than 11 timestamps, and for an even count chapter 09 section 9.4 takes the upper of the two middle ones (Appendix A item 63). No recorded scenario delivers a block whose fate depends on which one is taken, so an implementation that takes the lower median passes all of them.

`median-time-past.jsonl.gz` is one regtest scenario in the corpus format (`CORPUS.md`), replayed by the `corpus` suite with the recorded scenarios. Blocks 1 to 10 come every 100 seconds after genesis. Before each block at heights 2, 4, 6, 8 and 10, the parent's window holds 2, 4, 6, 8 and 10 timestamps, and a block dated halfway between its two middle timestamps comes first. It is later than the lower median and not later than the upper one, so it must leave the tip where it was; Bitcoin Core rejects it with `time-too-old`, which each check's label records. A check follows each block, with the chain tip set. All blocks go through `submitblock` (`via: "rpc"`).

Regenerate with the command below (well under a second). Every block takes the smallest nonce that meets regtest's target, so the file is the same on every run.

```sh
python3 conformance/vectors/mtp/generate.py conformance/vectors/mtp/median-time-past.jsonl.gz
```

The expectations, tip sets included, are confirmed against Bitcoin Core v32.1 by replaying the file through `recorder/core_chain_harness.py`:

```sh
target/release/bcs-conformance corpus --corpus conformance/vectors/mtp --fail-on-tips \
  --impl "docker run -i --rm -v $PWD/conformance/recorder:/h:ro bcs-recorder:32.1 python3 /h/core_chain_harness.py"
```
