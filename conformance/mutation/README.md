# Mutation audit

A test suite is only as good as the bugs it catches. Each mutant in `mutants.json` breaks one rule in a copy of the reference, usually a quirk from Appendix A of the specification (for example "compare the transaction version as signed in BIP68" or "check the block weight before the witness commitment"). `run.py` builds each broken copy's harness and runs the suites that should notice:

- `script` mutants: the vector suites and `custom`;
- `block` mutants: the `corpus` suite.

Before any mutant, an unmodified copy goes through the same steps and must pass every check of those suites, at every level. Otherwise a run with no block corpus, or with a harness that does not start, would catch every mutant. The copies build into their own `target` directories, whatever `CARGO_TARGET_DIR` says.

```sh
cargo build --release
python3 conformance/mutation/run.py --jobs 4            # all mutants, about two hours on 4 cores
python3 conformance/mutation/run.py --kind block --only bip30-never
```

Verdicts:

| Verdict | Meaning |
|---|---|
| `caught` | A required check fails: a verdict differs, or an active tip at a normative corpus check differs |
| `caught-level2` | Only an optional check differs: an error identifier, a corpus chain tip set or a UTXO set hash |
| `survived` | Nothing differs |

Three outcomes are not verdicts and never match an `expect`:

| Outcome | Meaning |
|---|---|
| `patch-not-found` | The patched text does not occur exactly once |
| `build-failed` | The copy does not build |
| `error` | The build left no harness, the runner printed no result, or the suites failed with no verdict differing (only harness errors, such as the `internal` answer to a panic, or a harness that died) |

The detail column counts harness errors for every mutant. A `caught` mutant with harness errors may be caught only by what they did to later checks (a block that a panic left unconnected moves the tip), so check it before recording it.

Each mutant records the verdict it got when it was added (`expect`); the script exits with status 1 when a verdict changes, so it can be rerun after changes to the specification or the suites. CI reruns it every week and on pull requests that change them (`.github/workflows/extended.yml`). A mutant that reports `patch-not-found` needs its `old` text updated.

Survivors are explained in their `note`. A survivor that could be caught is a gap in the suites, closed by adding a test: the custom vectors in `vectors/custom` and the `feature_spec_pitfalls` scenario of the block corpus were written that way.
