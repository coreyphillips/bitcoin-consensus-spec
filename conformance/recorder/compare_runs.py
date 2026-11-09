#!/usr/bin/env python3
"""Compare the skeletons of two recordings of the same scenarios.

Block contents differ between recordings (tests put the wall clock into block
timestamps), so events are compared by structure: every hash is replaced by
the order in which it first appeared in its file, and each event becomes a
token (type, via, requested, hash references, check heights and tip statuses).
Checks that fall inside a differing region of the two token sequences are
reported as racy; postprocess.py --racy marks them non-normative.
"""

import argparse
import difflib
import glob
import gzip
import hashlib
import json
import os
import sys


def skeleton(path):
    refs = {}

    def ref(h):
        if h is None:
            return None
        if h not in refs:
            refs[h] = len(refs)
        return refs[h]

    tokens = []
    with gzip.open(path, "rt") as f:
        for line in f:
            ev = json.loads(line)
            t = ev["type"]
            if t == "meta":
                continue
            if t == "reset":
                ref(ev.get("genesis"))
                tokens.append(("reset", json.dumps(ev.get("options"), sort_keys=True)))
            elif t == "restart":
                tokens.append(("restart", json.dumps(ev.get("options"), sort_keys=True)))
            elif t == "block":
                if "hex" in ev:
                    raw = bytes.fromhex(ev["hex"][:160])
                else:
                    with gzip.open(os.path.join(os.path.dirname(path), ev["blob"]), "rb") as bf:
                        raw = bf.read(80)
                prev = raw[4:36][::-1].hex()
                tokens.append(("block", ev["via"], ev.get("requested"), ref(prev), ref(ev["hash"])))
            elif t == "headers":
                hs = []
                for hx in ev["headers"]:
                    raw = bytes.fromhex(hx)
                    h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
                    hs.append((ref(raw[4:36][::-1].hex()), ref(h)))
                tokens.append(("headers", ev["via"], tuple(hs)))
            elif t == "invalidate":
                tokens.append(("invalidate", ref(ev["hash"])))
            elif t == "check":
                tips = tuple(sorted((ref(x["hash"]), x["height"], x["status"]) for x in ev.get("tips", [])))
                tokens.append(("check", ev.get("n"), ref(ev["tip"]), ev["height"], tips))
            else:
                tokens.append((t,))
    return tokens


def strip_n(tok):
    return tok[:1] + tok[2:] if tok[0] == "check" else tok


def compare(a_path, b_path):
    a = skeleton(a_path)
    b = skeleton(b_path)
    sm = difflib.SequenceMatcher(a=[strip_n(t) for t in a], b=[strip_n(t) for t in b], autojunk=False)
    racy = []
    diffs = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        for t in a[i1:i2]:
            if t[0] == "check":
                racy.append(t[1])
        diffs.append({"op": op, "a": [str(t)[:160] for t in a[i1:i2]][:6], "b": [str(t)[:160] for t in b[j1:j2]][:6],
                      "a_range": [i1, i2], "b_range": [j1, j2]})
    return {"events_a": len(a), "events_b": len(b), "racy_checks": racy, "diffs": diffs}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--a", required=True, help="directory with the first recording's corpus files")
    ap.add_argument("--b", required=True, help="directory with the second recording's corpus files")
    ap.add_argument("--out", required=True, help="racy checks JSON for postprocess.py --racy")
    ap.add_argument("--report", help="detailed differences JSON")
    a = ap.parse_args()
    racy = {}
    report = {}
    for pa in sorted(glob.glob(os.path.join(a.a, "*.jsonl.gz"))):
        name = os.path.basename(pa)[:-len(".jsonl.gz")]
        pb = os.path.join(a.b, os.path.basename(pa))
        if not os.path.exists(pb):
            print("%-40s missing in second recording" % name)
            report[name] = {"missing": True}
            continue
        r = compare(pa, pb)
        report[name] = r
        racy[name] = r["racy_checks"]
        print("%-40s events %d/%d differing regions %d racy checks %d" % (
            name, r["events_a"], r["events_b"], len(r["diffs"]), len(r["racy_checks"])))
        for d in r["diffs"][:5]:
            print("    %s a%s b%s" % (d["op"], d["a_range"], d["b_range"]))
            for x in d["a"][:3]:
                print("      a: %s" % x)
            for x in d["b"][:3]:
                print("      b: %s" % x)
    with open(a.out, "w") as f:
        json.dump(racy, f, indent=1, sort_keys=True)
    if a.report:
        with open(a.report, "w") as f:
            json.dump(report, f, indent=1, sort_keys=True)


if __name__ == "__main__":
    sys.exit(main())
