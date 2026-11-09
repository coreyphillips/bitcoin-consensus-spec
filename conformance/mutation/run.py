#!/usr/bin/env python3
"""Mutation audit for the conformance suites.

Each mutant breaks one rule (usually an Appendix A quirk) in a copy of the reference, builds that
copy's harness, and runs the suites that should notice. A mutant is *caught* when a suite fails.

Usage (from anywhere, after `cargo build --release` in the repository):

    python3 conformance/mutation/run.py [--jobs 4] [--kind script|block] [--only NAME,NAME]

Verdicts: caught (a verdict or an active tip differs), caught-level2 (only an error identifier,
a chain tip set or a UTXO set hash differs), survived, patch-not-found, build-failed. The exit
status is 1 when any verdict differs from the mutant's recorded `expect` in mutants.json.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RUNNER = os.path.join(REPO, "target", "release", "bcs-conformance")
SCRIPT_SUITES = ["script-tests", "tx-valid", "tx-invalid", "sighash", "bip341", "bip340", "script-assets", "custom"]


def run_runner(args):
    return subprocess.run([RUNNER] + args, cwd=REPO, capture_output=True, text=True)


def audit(mutant, work):
    copy = os.path.join(work, mutant["name"])
    shutil.copytree(REPO, copy, ignore=shutil.ignore_patterns("target", ".git", ".idea", "vectors"))
    try:
        path = os.path.join(copy, "spec", mutant["file"])
        with open(path) as f:
            text = f.read()
        if text.count(mutant["old"]) != 1:
            return "patch-not-found", "the patched text occurs %d times" % text.count(mutant["old"])
        with open(path, "w") as f:
            f.write(text.replace(mutant["old"], mutant["new"]))
        build = subprocess.run(
            ["cargo", "build", "--release", "-q", "-p", "bitcoin-consensus-spec", "--bin", "reference-harness"],
            cwd=copy, capture_output=True, text=True)
        if build.returncode != 0:
            return "build-failed", build.stderr.strip().splitlines()[-1] if build.stderr.strip() else ""
        harness = os.path.join(copy, "target", "release", "reference-harness")
        if mutant["kind"] == "script":
            args = ["--impl", harness] + sum((["--suite", s] for s in SCRIPT_SUITES), [])
            if run_runner(args).returncode != 0:
                return "caught", ""
            if run_runner(args + ["--fail-on-level2"]).returncode != 0:
                return "caught-level2", ""
            return "survived", ""
        out = run_runner(["corpus", "--impl", harness])
        total = next((line for line in out.stdout.splitlines() if line.startswith("total (")), None)
        if total is None:
            return "caught", "no corpus total (harness failed)"
        levels = ["level 0", "level 0 non-normative", "level 1", "level 2"]
        fractions = re.findall(r"(\d+)/(\d+)", total)
        misses = ["%s %s/%s" % (levels[i], a, b) for i, (a, b) in enumerate(fractions) if a != b]
        if out.returncode != 0:
            return "caught", ", ".join(misses)
        return ("caught-level2", ", ".join(misses)) if misses else ("survived", "")
    finally:
        shutil.rmtree(copy, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--kind", choices=["script", "block"])
    parser.add_argument("--only", help="comma-separated mutant names")
    opts = parser.parse_args()
    if not os.path.exists(RUNNER):
        raise SystemExit("build the runner first: cargo build --release")
    with open(os.path.join(HERE, "mutants.json")) as f:
        mutants = json.load(f)
    if opts.kind:
        mutants = [m for m in mutants if m["kind"] == opts.kind]
    if opts.only:
        names = set(opts.only.split(","))
        mutants = [m for m in mutants if m["name"] in names]
    unexpected = 0
    with tempfile.TemporaryDirectory(prefix="bcs-mutants-") as work:
        with concurrent.futures.ThreadPoolExecutor(max_workers=opts.jobs) as pool:
            results = pool.map(lambda m: (m, audit(m, work)), mutants)
            for mutant, (verdict, detail) in results:
                ok = verdict == mutant["expect"]
                unexpected += not ok
                print("%-30s %-6s %-15s %-9s %s" % (
                    mutant["name"], mutant["kind"], verdict, "" if ok else "UNEXPECTED", detail), flush=True)
    print("%d mutants, %d with an unexpected verdict" % (len(mutants), unexpected))
    raise SystemExit(1 if unexpected else 0)


if __name__ == "__main__":
    main()
