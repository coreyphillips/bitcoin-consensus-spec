# Mutation audit

A test suite is only as good as the bugs it catches. Each mutant in `mutants.json` breaks one rule in a copy of the reference, usually a quirk from Appendix A of the specification (for example "compare the transaction version as signed in BIP68" or "check the block weight before the witness commitment"). `run.py` builds each broken copy's harness and runs the suites that should notice:

- `script` mutants: the vector suites and `custom`;
- `block` mutants: the `corpus` suite.

```sh
cargo build --release
python3 conformance/mutation/run.py --jobs 4            # all mutants, about half an hour
python3 conformance/mutation/run.py --kind block --only bip30-never
```

Verdicts:

| Verdict | Meaning |
|---|---|
| `caught` | A required check fails: a verdict differs, or an active tip at a normative corpus check differs |
| `caught-level2` | Only an optional check differs: an error identifier, a corpus chain tip set or a UTXO set hash |
| `survived` | Nothing differs |

Each mutant records the verdict it got when it was added (`expect`); the script exits with status 1 when a verdict changes, so it can be rerun after changes to the specification or the suites. A mutant whose patched text no longer occurs exactly once reports `patch-not-found` and needs its `old` text updated.

Survivors are explained in their `note`. A survivor that could be caught is a gap in the suites, closed by adding a test: the custom vectors in `vectors/custom` and the `feature_spec_pitfalls` scenario of the block corpus were written that way.
