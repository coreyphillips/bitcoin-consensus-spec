#!/usr/bin/env python3
"""Checks the reference's suite counts in README.md and RESULTS.md against a run of the runner.

Usage: check_doc_numbers.py SUMMARY

SUMMARY is the file that `bcs-conformance --impl target/release/reference-harness --json SUMMARY`
writes for a run of the default suites. The live suites (headers-live, interop, peer-sync) and the
mutation audit are not in that run, so the numbers the documents give for them are not checked.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The corpus suite's directories. blocks/ holds the recorded runs of Bitcoin Core's functional
# tests, one file per node. RESULTS.md describes each of the others as a single scenario.
RECORDED = "blocks"
SINGLE_SCENARIO = ("chainwork", "signet", "mtp")

CELL = r"\| ([\d,]+) \|"
PAIR = r"\| ([\d,]+) / ([\d,]+) \|"


def claims(run):
    """Yields (document, text that picks out one line, pattern, values of the pattern's groups)."""
    suites = run["suites"]

    def cases(*names):
        return [suites[name]["cases"] for name in names]

    files = suites["corpus"]["files"]
    recorded = [f for f in files if f["dir"] == RECORDED]
    runs = {f["name"].rsplit(".", 1)[0] for f in recorded}

    def corpus(field, *dirs):
        return sum(f[field] for f in files if not dirs or f["dir"] in dirs)

    yield "README.md", "| Bitcoin Core `script_tests.json`", CELL, cases("script-tests")
    yield "README.md", "| Bitcoin Core `tx_valid.json`", PAIR, cases("tx-valid", "tx-invalid")
    yield "README.md", "| Bitcoin Core `sighash.json`", CELL, cases("sighash")
    yield "README.md", "| BIP341 wallet vectors", PAIR, cases("bip341", "bip340")
    yield "README.md", "| Bitcoin Core qa-assets", CELL, cases("script-assets")
    yield "README.md", "| Edge cases found by", CELL, cases("custom")
    yield (
        "README.md",
        "| Block corpus:",
        r"([\d,]+) per-node files from ([\d,]+) recorded runs .* \(([\d,]+) events\)",
        [len(recorded), len(runs), corpus("events", RECORDED)],
    )
    yield (
        "README.md",
        "| Block corpus:",
        r"([\d,]+) normative tip checks, ([\d,]+) chain tip sets, ([\d,]+) UTXO set hashes",
        [corpus("normative", RECORDED), corpus("tips", RECORDED), corpus("utxo", RECORDED)],
    )

    for suite in ("script-tests", "sighash", "script-assets", "custom", "pow", "signet", "params", "block-connect"):
        yield "RESULTS.md", f"| `{suite}`:", CELL, cases(suite)
    yield "RESULTS.md", "| `tx-valid` / `tx-invalid`:", PAIR, cases("tx-valid", "tx-invalid")
    yield "RESULTS.md", "| `bip341` / `bip340`:", PAIR, cases("bip341", "bip340")
    yield (
        "RESULTS.md",
        "| `corpus`:",
        r"([\d,]+) per-node block files from ([\d,]+) recorded runs of Bitcoin Core functional tests \(([\d,]+) events\)",
        [len(recorded), len(runs), corpus("events", RECORDED)],
    )
    yield "RESULTS.md", "| `corpus`:", r"most work is shorter \(([\d,]+) events\)", [corpus("events", "chainwork")]
    yield "RESULTS.md", "| `corpus`:", r"signet solution are rejected \(([\d,]+) events\)", [corpus("events", "signet")]
    yield "RESULTS.md", "| `corpus`:", r"even number of timestamps \(([\d,]+) events\)", [corpus("events", "mtp")]
    yield (
        "RESULTS.md",
        "| `corpus`:",
        r"([\d,]+) normative tips \(([\d,]+) with chain work\); ([\d,]+) chain tip sets; ([\d,]+) UTXO set hashes",
        [corpus("normative"), corpus("chainwork"), corpus("tips"), corpus("utxo")],
    )
    yield (
        "RESULTS.md",
        "Every corpus scenario is replayed with restarts re-delivered",
        r"\(([\d,]+) restarts, ([\d,]+) re-delivered events\)",
        [corpus("restarts"), corpus("redelivered")],
    )


def check_run(run):
    """The documents state a derived-mode run in which every suite passed, over these corpus files."""
    errors = []
    if run.get("mode") != "derived":
        errors.append(f"the summary is of a {run.get('mode')} run; the documents state derived counts")
    if run.get("result") != "PASS":
        errors.append("the run failed; the documents state that every suite passes")
    files = run.get("suites", {}).get("corpus", {}).get("files", [])
    for f in files:
        if f["dir"] not in (RECORDED, *SINGLE_SCENARIO):
            errors.append(f"corpus file {f['name']} is in {f['dir']}/, which RESULTS.md does not describe")
    for d in SINGLE_SCENARIO:
        n = sum(f["dir"] == d for f in files)
        if n != 1:
            errors.append(f"RESULTS.md describes one corpus scenario in {d}/, the run replayed {n}")
    return errors


def check(run):
    errors = check_run(run)
    texts = {}
    checked = 0
    try:
        found = list(claims(run))
    except KeyError as e:
        return errors + [f"the summary has no {e}: run the default suites"]
    for doc, key, pattern, values in found:
        lines = texts.setdefault(doc, (ROOT / doc).read_text().splitlines())
        hits = [n for n, line in enumerate(lines, 1) if key in line]
        if len(hits) != 1:
            errors.append(f"{doc}: {len(hits)} lines contain {key!r}, not one; update {pathlib.Path(__file__).name}")
            continue
        line = lines[hits[0] - 1]
        match = re.search(pattern, line)
        if match is None:
            errors.append(f"{doc}:{hits[0]}: no text of the form {pattern!r}; update {pathlib.Path(__file__).name}")
            continue
        want = [f"{v:,}" for v in values]
        if list(match.groups()) != want:
            fixed, end = "", match.start()
            for i, w in enumerate(want, 1):
                fixed += line[end : match.start(i)] + w
                end = match.end(i)
            fixed += line[end : match.end()]
            errors.append(f"{doc}:{hits[0]}: says '{match.group()}', the run gives '{fixed}'")
        checked += len(values)
    if not errors:
        print(f"README.md and RESULTS.md: {checked} numbers match the run")
    return errors


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} SUMMARY (the file bcs-conformance --json writes)")
    run = json.loads(pathlib.Path(sys.argv[1]).read_text())
    errors = check(run)
    for e in errors:
        print(e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
