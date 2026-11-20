# Contributing

Every expectation in this repository is Bitcoin Core v32.1's answer: from Core's own test files, from its consensus code compiled into `conformance/oracle-core`, or from its release binaries. A new test carries the answer a script got from Core. Never write an expected result by hand, and never change one to make the reference pass.

The exception is the constructed cases in `conformance/vectors/block-connect`. The oracle cannot run `ConnectBlock`, so their verdicts follow its source, as that directory's `README.md` explains.

Report a disagreement with Bitcoin Core with an issue template, or privately as `SECURITY.md` describes when a block or transaction on a public network could trigger it.

## Before opening a pull request

Run what the `reference` job of `.github/workflows/ci.yml` runs:

```sh
cargo test --release --workspace
cargo build --release
./target/release/bcs-conformance --impl ./target/release/reference-harness --fail-on-level2 --fail-on-tips --json /tmp/conformance.json
python3 .github/check_doc_numbers.py /tmp/conformance.json
python3 .github/check_spec_version.py
python3 conformance/mutation/run.py --items
python3 -m unittest discover -s conformance/recorder
```

These fail a pull request:

- An em dash (U+2014) or an en dash (U+2013) anywhere in the repository. Use a comma, a colon or parentheses. To find them: `grep -rnI --exclude-dir=target --exclude-dir=.git -e "$(printf '\342\200\224')" -e "$(printf '\342\200\223')" .`
- A suite count in `README.md` or `RESULTS.md` that differs from the run. `check_doc_numbers.py` prints the ones that do.
- A change to `spec/` without the next specification revision (below).

A pull request that changes `spec/`, `reference/`, the runner, the vectors or the mutants also runs `extended.yml` (interop, peer-sync and the mutation audit, which take hours). One that changes the vectors, the oracle, the recorder or the runner also runs `core.yml`, which checks the vectors against Bitcoin Core.

## Changing the specification

- Code in a fenced block whose info string is `rust` is the reference (`reference/build.rs` compiles it). A `text` block is not compiled, and any other fence fails the build.
- A normative definition names the Bitcoin Core function and file it mirrors in a `Core:` line (chapter 01 section 1.1).
- A place where a natural implementation differs from Core gets an Appendix A item and a mutant that breaks it.
- The first change to `spec/` after a version tag moves `spec/VERSION` to the next revision, states it in `README.md` and chapter 00, and opens its entry in `CHANGELOG.md`. Later changes add a line to that entry (`README.md`, "Updating").

## Adding a vector

Targeted cases live in `conformance/vectors/custom`, `pow`, `signet` and `params`, one JSON line each. Add the case to the directory's generator script, then regenerate the file with the command in that directory's `README.md`. The script asks `oracle-core-harness` for Core's answer; build it as `conformance/README.md` ("Building the oracle") says.

Then update the counts the change moves: the suite counts in `README.md` and `RESULTS.md`, and `TOTALS` in `conformance/mutation/run.py`, which the audit's unmodified copy must reproduce.

The files in `core/`, `qa-assets/` and `bip340/` are byte-identical to their upstream sources and listed in `SHA256SUMS`; they change only with the pinned version. `derived/` is written by `bcs-conformance derive` alone, and `core.yml` fails when it differs from a fresh derivation.

## Adding a block scenario

`conformance/vectors/blocks` is recorded from Bitcoin Core v32.1's functional tests by `conformance/recorder`, whose `README.md` lists the requirements. A new consensus case usually goes into `conformance/recorder/extra/feature_spec_pitfalls.py`, the corpus's own test, written in the style of Core's functional tests. To record one of Core's tests instead, add it to `SCENARIOS` in the recorder's `Makefile` and to `conformance/CORPUS.md` section 9.

Then put the test's SHA-256 in `conformance/recorder/pins.json`, which the recorder checks before it runs a test. Run `make -C conformance/recorder all CORE_SRC=/path/to/bitcoin-v32.1` with a fresh `WORK` directory, since recordings already in `WORK` are reused. The `image` stage builds `extra/` and `pins.json` into the image, and the `corpus` stage replaces every file in `VECTORS`. `make all` fails unless every normative check replays identically through a fresh v32.1 node. Commit the new corpus files and `REPORT.md`, and update the counts as for a vector.

## Adding a mutant

A mutant is one entry in `conformance/mutation/mutants.json`:

```json
{
  "name": "csv-version-signed",
  "kind": "script",
  "file": "05-script-execution.md",
  "item": 1,
  "old": "        if self.tx.version < 2 {\n            return false;\n        }",
  "new": "        if (self.tx.version as i32) < 2 {\n            return false;\n        }",
  "expect": "caught"
}
```

`file` is the chapter whose code is patched, and `old` must occur in it exactly once. `kind` is `script` (the vector suites decide) or `block` (`block-connect` and `corpus` decide). `item` is the Appendix A number of the rule it breaks, or `null` for a rule Appendix A does not list. `expect` is the verdict the mutant gets:

```sh
cargo build --release
python3 conformance/mutation/run.py --kind script --only csv-version-signed
```

A `survived` mutant needs a `note`. It either says why no suite can catch it, or names the issue that adds the test that will. `conformance/mutation/README.md` explains the verdicts.
