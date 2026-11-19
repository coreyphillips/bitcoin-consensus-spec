#!/usr/bin/env python3
"""Mutation audit for the conformance suites.

Each mutant breaks one rule (usually an Appendix A quirk) in a copy of the reference, builds that
copy's harness, and runs the suites that should notice. A mutant is *caught* when a suite fails.
An unmodified copy goes through the same steps first and must pass every check of those suites:
without that, missing vectors or a harness that cannot start would catch every mutant.

Usage (from anywhere, after `cargo build --release` in the repository):

    python3 conformance/mutation/run.py [--jobs 4] [--kind script|block] [--only NAME,NAME]
    python3 conformance/mutation/run.py --items

Each mutant names the Appendix A item whose rule it breaks (`item`), or null for a rule that
Appendix A does not list. `--items` builds and runs nothing: it prints the items no mutant names.

Verdicts: caught (a verdict or an active tip differs), caught-level2 (only an error identifier,
a chain tip set or a UTXO set hash differs), survived. Three outcomes are not verdicts:
patch-not-found, build-failed, and error (the build left no harness, the runner printed no
result, or the suites failed only through harness errors such as the `internal` answer to a
panic). The detail column counts harness errors for every mutant. The exit status is 1 when the
unmodified copy does not pass, or when any verdict differs from the mutant's recorded `expect`
in mutants.json.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
APPENDIX_A = os.path.join(REPO, "spec", "A-quirks-checklist.md")
# A row of an Appendix A table: number, quirk, where.
ITEM_ROW = re.compile(r"^\| (\d+) \| (.*) \| [^|]* \|$")
RUNNER = os.path.join(
    os.path.abspath(os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target")),
    "release", "bcs-conformance")
SCRIPT_SUITES = [
    "script-tests", "tx-valid", "tx-invalid", "sighash", "bip341", "bip340", "script-assets", "custom", "pow",
    "signet", "params",
]
# Vector suites that connect blocks, run for block mutants next to the corpus.
BLOCK_VECTOR_SUITES = ["block-connect"]
VERDICTS = ["caught", "caught-level2", "survived"]
# A check whose call got no answer, worded as the runner's CallError (harness.rs), or whose answer
# lacks the field it checks (`custom` prints "no such field", or null). Any other failed check got
# an answer that differs from the expected one.
HARNESS_ERROR = re.compile(
    r": (internal|harness died|protocol violation|bad_request): |: the harness command |: response has no "
    r"|, got (null|no such field)(;|$)")
# A normative corpus check, printed by --verbose, whose tip query answered with a tip: the file and
# the event.
TIP_DIFFERS = re.compile(
    r"^(?:DIVERGE|FAIL) +\[corpus\] (\S+) check \S+ \(event (\d+),.*?: expected tip \S+ height \S+, "
    r"got (?!error: |\(no tip\))")
# The error summary of a corpus file, printed by --verbose: the file and the event that recorded its
# first error.
FIRST_ERROR = re.compile(r"^(?:FAIL|KNOWN) +\[corpus\] (\S+) errors from event (\d+): ")
# A row of the runner's suite table: suite, mode, cases, passed, failed, level2, l2-checked,
# unsupported, time.
SUITE_ROW = re.compile(r"^(\S+)\s+\S+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d.]+s$")
# A file row of the corpus table: name, checks, four level fractions, errors, time.
CORPUS_ROW = re.compile(r"\s\d+(\s+\d+/\d+){4}\s+(\d+)\s+[\d.]+s$")
LEVELS = ["level 0", "level 0 non-normative", "level 1", "level 2"]
# What the unmodified reference runs for each kind. A missing vector or corpus file lowers these
# and still passes, so update them with the vectors.
TOTALS = {
    "script": "339937 checks in 11 suites",
    "block": "22 checks in 1 suite; level 0 5293/5293, level 0 non-normative 1/1, level 1 1243/1243, level 2 2292/2292",
}


def appendix_a_items():
    """The quirk of each Appendix A item, by number."""
    with open(APPENDIX_A) as f:
        return {int(m.group(1)): m.group(2) for m in map(ITEM_ROW.match, f.read().splitlines()) if m}


def print_items(mutants, items):
    named = {m["item"] for m in mutants}
    missing = [n for n in sorted(items) if n not in named]
    print("%d of %d Appendix A items have no mutant:" % (len(missing), len(items)))
    for n in missing:
        quirk = items[n]
        print("%4d  %s" % (n, quirk if len(quirk) <= 100 else quirk[:97] + "..."))
    print("%d of %d mutants break a rule Appendix A does not list" % (
        sum(1 for m in mutants if m["item"] is None), len(mutants)))


def run_runner(args):
    return subprocess.run(
        [RUNNER] + args + ["--vectors", os.path.join(REPO, "conformance", "vectors")],
        cwd=REPO, capture_output=True, text=True)


def last_line(text):
    lines = text.strip().splitlines()
    return lines[-1] if lines else ""


def plural(n, noun):
    return "%d %s%s" % (n, noun, "" if n == 1 else "s")


def script_verdict(harness, suites=SCRIPT_SUITES):
    """Runs the script suites once. Returns the verdict, its detail and what ran."""
    args = ["--impl", shlex.quote(harness), "--fail-on-level2", "--verbose"]
    out = run_runner(args + sum((["--suite", s] for s in suites), []))
    lines = out.stdout.splitlines()
    result = next((line for line in reversed(lines) if line.startswith("RESULT: ")), None)
    if result is None:
        return "error", "no RESULT line from the runner: " + last_line(out.stderr), ""
    rows = [m for m in map(SUITE_ROW.match, lines) if m and m.group(1) in suites]
    ran = "%s in %s" % (plural(sum(int(m.group(2)) for m in rows), "check"), plural(len(rows), "suite"))
    fails = [line for line in lines if line.startswith("FAIL ")]
    errors = sum(1 for line in fails if HARNESS_ERROR.search(line))
    differ = len(fails) - errors
    notes = ([plural(differ, "differing check")] if differ else []) + (
        [plural(errors, "harness error")] if errors else [])
    if result == "RESULT: PASS":
        return "survived", "", ran
    if result.startswith("RESULT: FAIL (level 2"):
        return "caught-level2", result[len("RESULT: FAIL ("):-1], ran
    if differ:
        return "caught", ", ".join(notes), ran
    problems = [" ".join(line.split()) for line in lines if line.lstrip().startswith("error: ")
                or (line.split(" ", 1)[0] in suites and not SUITE_ROW.match(line))]
    return "error", "; ".join(["no verdict differs"] + notes + problems[:1]), ran


def corpus_verdict(harness):
    """Runs the block corpus. Returns the verdict, its detail and what ran."""
    out = run_runner(["corpus", "--impl", shlex.quote(harness), "--verbose"])
    lines = out.stdout.splitlines()
    total = next((line for line in lines if line.startswith("total (")), None)
    if total is None:
        problem = next((" ".join(line.split()) for line in lines if line.startswith("corpus ")),
                       last_line(out.stderr))
        return "error", "no corpus total from the runner: " + problem, ""
    errors = sum(int(m.group(2)) for m in map(CORPUS_ROW.search, lines) if m)
    fractions = re.findall(r"(\d+)/(\d+)", total)
    ran = ", ".join("%s %s/%s" % (LEVELS[i], a, b) for i, (a, b) in enumerate(fractions))
    misses = ["%s %s/%s" % (LEVELS[i], a, b) for i, (a, b) in enumerate(fractions) if a != b]
    notes = misses + ([plural(errors, "harness error")] if errors else [])
    # A failed tip query also counts as a normative miss, and a tip after a file's first error may
    # be state the failed call left behind, so neither is a catch. Only the first 21 misses of
    # each file are printed, so a tip that differs only after those is reported as an error.
    first_error = {m.group(1): int(m.group(2)) for m in map(FIRST_ERROR.match, lines) if m}
    tips = [m for m in map(TIP_DIFFERS.match, lines) if m]
    if any(int(m.group(2)) <= first_error.get(m.group(1), int(m.group(2))) for m in tips):
        return "caught", ", ".join(notes), ran
    if out.returncode != 0 or errors:
        return "error", "; ".join(["no normative tip differs"] + notes), ran
    return ("caught-level2", ", ".join(misses), ran) if misses else ("survived", "", ran)


def block_verdict(harness):
    """Runs the block-connect vectors and the block corpus. The stronger verdict wins: a block
    mutant caught by either is caught."""
    results = [script_verdict(harness, BLOCK_VECTOR_SUITES), corpus_verdict(harness)]
    verdicts = [v for v, _, _ in results]
    for verdict in ["caught", "error", "caught-level2", "survived"]:
        if verdict in verdicts:
            break
    detail = "; ".join(d for v, d, _ in results if v == verdict and d)
    return verdict, detail, "; ".join(ran for _, _, ran in results)


EVALUATE = {"script": script_verdict, "block": block_verdict}


def copy_repo(name, work):
    copy = os.path.join(tempfile.mkdtemp(prefix=name + "-", dir=work), "repo")
    shutil.copytree(REPO, copy, ignore=shutil.ignore_patterns("target", ".git", ".idea", "vectors"))
    return copy


def build(copy):
    """Builds the copy's harness. Returns its path, or None and the outcome that says why not."""
    # The copy's own target directory whatever the environment says: with CARGO_TARGET_DIR the
    # copies would share one and could run each other's harness.
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(copy, "target"))
    out = subprocess.run(
        ["cargo", "build", "--release", "-q", "-p", "bitcoin-consensus-spec", "--bin", "reference-harness"],
        cwd=copy, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        return None, ("build-failed", last_line(out.stderr))
    harness = os.path.join(copy, "target", "release", "reference-harness")
    if not os.access(harness, os.X_OK):
        return None, ("error", "the build left no harness at " + harness)
    return harness, None


def audit(mutant, work):
    copy = copy_repo(mutant["name"], work)
    try:
        path = os.path.join(copy, "spec", mutant["file"])
        with open(path) as f:
            text = f.read()
        if text.count(mutant["old"]) != 1:
            return "patch-not-found", "the patched text occurs %d times" % text.count(mutant["old"])
        with open(path, "w") as f:
            f.write(text.replace(mutant["old"], mutant["new"]))
        harness, failure = build(copy)
        if failure:
            return failure
        return EVALUATE[mutant["kind"]](harness)[:2]
    finally:
        shutil.rmtree(os.path.dirname(copy), ignore_errors=True)


def baseline(kinds, work, pool):
    """Runs the suites of `kinds` against an unmodified copy and exits unless every check passes."""
    copy = copy_repo("unmodified", work)
    try:
        harness, failure = build(copy)
        if failure:
            raise SystemExit("the unmodified reference: %s, %s" % failure)
        for kind, (verdict, detail, ran) in zip(kinds, pool.map(lambda k: EVALUATE[k](harness), kinds)):
            if verdict == "survived" and ran != TOTALS[kind]:
                verdict, detail = "incomplete", "%s, expected %s" % (ran, TOTALS[kind])
            ok = verdict == "survived"
            print("%-30s %-6s %-15s %-9s %s" % (
                "(unmodified)", kind, "passed" if ok else verdict, "" if ok else "UNEXPECTED",
                ran if ok else detail), flush=True)
            if not ok:
                raise SystemExit("the unmodified reference does not pass the %s suites, so no mutant "
                                 "verdict would mean anything" % kind)
    finally:
        shutil.rmtree(os.path.dirname(copy), ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--kind", choices=["script", "block"])
    parser.add_argument("--only", help="comma-separated mutant names")
    parser.add_argument("--items", action="store_true",
                        help="print the Appendix A items that no mutant names, and exit")
    opts = parser.parse_args()
    with open(os.path.join(HERE, "mutants.json")) as f:
        mutants = json.load(f)
    recorded = [m["name"] for m in mutants if m["expect"] not in VERDICTS]
    if recorded:
        raise SystemExit("expect must be one of %s: %s" % (", ".join(VERDICTS), ", ".join(recorded)))
    items = appendix_a_items()
    unknown = [m["name"] for m in mutants
               if "item" not in m or not (m["item"] is None or type(m["item"]) is int and m["item"] in items)]
    if unknown:
        raise SystemExit("item must be null or one of the %d Appendix A item numbers: %s" % (
            len(items), ", ".join(unknown)))
    if opts.items:
        print_items(mutants, items)
        return
    if not os.path.exists(RUNNER):
        raise SystemExit("build the runner first: cargo build --release")
    if opts.kind:
        mutants = [m for m in mutants if m["kind"] == opts.kind]
    if opts.only:
        names = set(opts.only.split(","))
        unknown = names - {m["name"] for m in mutants}
        if unknown:
            raise SystemExit("no %smutant named %s" % (
                opts.kind + " " if opts.kind else "", ", ".join(sorted(unknown))))
        mutants = [m for m in mutants if m["name"] in names]
    kinds = [k for k in EVALUATE if any(m["kind"] == k for m in mutants)]
    unexpected = 0
    with tempfile.TemporaryDirectory(prefix="bcs-mutants-") as work:
        with concurrent.futures.ThreadPoolExecutor(max_workers=opts.jobs) as pool:
            baseline(kinds, work, pool)
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
