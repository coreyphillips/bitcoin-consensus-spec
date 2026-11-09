#!/usr/bin/env python3
"""Replay corpus files through a chain harness (by default the Core chain
harness) and compare every checkpoint.

Each file is replayed exactly as CORPUS.md tells a runner to: reset maps to
chain_reset, block to chain_process_block, headers to chain_process_headers,
invalidate to chain_invalidate, restart to chain_reset with the new options
followed by re-delivery of every block, headers and invalidate event since the
last reset, and check to chain_tip (level 0), chain_tips (level 1) and, when
the check carries a UTXO commitment, utxo_hash (level 2).

Exit status is 0 only if every normative level 0 checkpoint matched.
"""

import argparse
import concurrent.futures
import gzip
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def load_corpus(path):
    with gzip.open(path, "rt") as f:
        lines = [json.loads(line) for line in f]
    if not lines or lines[0].get("type") != "meta":
        raise ValueError("%s: first line must be a meta event" % path)
    return lines[0], lines[1:]


class Harness:
    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.id = 0

    def req(self, op, **fields):
        self.id += 1
        msg = {"id": self.id, "op": op}
        msg.update(fields)
        self.p.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("harness exited")
        resp = json.loads(line)
        if resp.get("id") != self.id:
            raise RuntimeError("response id mismatch")
        return resp

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=300)


def block_hex(ev, base):
    if "hex" in ev:
        return ev["hex"]
    with gzip.open(os.path.join(base, ev["blob"]), "rb") as f:
        return f.read().hex()


def event_request(ev, base):
    t = ev["type"]
    if t == "block":
        r = {"op": "chain_process_block", "block": block_hex(ev, base), "now": ev["now"], "via": ev["via"]}
        if ev["via"] == "p2p":
            r["requested"] = ev["requested"]
        return r
    if t == "headers":
        return {"op": "chain_process_headers", "headers": ev["headers"], "now": ev["now"], "via": ev["via"]}
    if t == "invalidate":
        return {"op": "chain_invalidate", "hash": ev["hash"], "now": ev["now"]}
    raise ValueError("not a chain event: %s" % t)


def replay(path, cmd, restart_mode, max_report):
    base = os.path.dirname(path)
    meta, events = load_corpus(path)
    h = Harness(cmd)
    res = {"file": os.path.basename(path), "checks": 0, "normative": 0,
           "level0": {"match": 0, "mismatch": 0}, "level0_nonnormative": {"match": 0, "mismatch": 0},
           "level1": {"match": 0, "mismatch": 0}, "level2": {"match": 0, "mismatch": 0},
           "errors": [], "mismatches": [], "outcomes": {}}
    started = time.time()
    try:
        info = h.req("info")
        if not info.get("ok"):
            raise RuntimeError("info failed: %s" % info)
        network = None
        options = None
        prefix = []
        for idx, ev in enumerate(events):
            t = ev["type"]
            if t == "reset":
                network, options = ev["network"], ev.get("options") or {}
                r = h.req("chain_reset", network=network, options=options)
                if not r.get("ok"):
                    raise RuntimeError("chain_reset failed: %s" % r)
                if ev.get("genesis") and r["genesis"] != ev["genesis"]:
                    res["errors"].append("genesis mismatch")
                prefix = []
            elif t == "restart":
                new_options = ev.get("options") or {}
                if restart_mode == "noop-if-same" and new_options == options:
                    continue
                options = new_options
                r = h.req("chain_reset", network=network, options=options)
                if not r.get("ok"):
                    raise RuntimeError("chain_reset failed: %s" % r)
                for pev in prefix:
                    rr = h.req(**event_request(pev, base))
                    if not rr.get("ok"):
                        res["errors"].append("event %d (re-delivery): %s" % (idx, rr))
            elif t in ("block", "headers", "invalidate"):
                rq = event_request(ev, base)
                r = h.req(**rq)
                if not r.get("ok"):
                    res["errors"].append("event %d: %s" % (idx, r))
                    if len(res["errors"]) > 20:
                        break
                else:
                    key = "%s:%s" % (t, r.get("result", "ok"))
                    res["outcomes"][key] = res["outcomes"].get(key, 0) + 1
                prefix.append(ev)
            elif t == "check":
                res["checks"] += 1
                normative = ev.get("normative", True)
                if normative:
                    res["normative"] += 1
                tip = h.req("chain_tip")
                ok0 = tip.get("ok") and tip["tip"] == ev["tip"] and tip["height"] == ev["height"]
                bucket = res["level0"] if normative else res["level0_nonnormative"]
                bucket["match" if ok0 else "mismatch"] += 1
                if not ok0 and len(res["mismatches"]) < max_report:
                    res["mismatches"].append({"check": ev.get("n"), "event": idx, "level": 0, "normative": normative,
                                              "label": ev.get("label"),
                                              "want": [ev["tip"], ev["height"]],
                                              "got": [tip.get("tip"), tip.get("height")]})
                if "tips" in ev:
                    tips = h.req("chain_tips")
                    got = sorted((t["hash"], t["height"], t["status"]) for t in tips.get("tips", []))
                    want = sorted((t["hash"], t["height"], t["status"]) for t in ev["tips"])
                    ok1 = got == want
                    res["level1"]["match" if ok1 else "mismatch"] += 1
                    if not ok1 and len(res["mismatches"]) < max_report:
                        res["mismatches"].append({"check": ev.get("n"), "event": idx, "level": 1,
                                                  "label": ev.get("label"),
                                                  "missing": [x for x in want if x not in got][:5],
                                                  "extra": [x for x in got if x not in want][:5]})
                if "utxo" in ev:
                    u = h.req("utxo_hash")
                    ok2 = u.get("ok") and u["hash_serialized_3"] == ev["utxo"]["hash_serialized_3"] \
                        and u["txouts"] == ev["utxo"]["txouts"]
                    res["level2"]["match" if ok2 else "mismatch"] += 1
                    if not ok2 and len(res["mismatches"]) < max_report:
                        res["mismatches"].append({"check": ev.get("n"), "event": idx, "level": 2,
                                                  "want": ev["utxo"], "got": u})
            else:
                res["errors"].append("unknown event type %s" % t)
    except Exception as e:
        res["errors"].append("replay aborted: %r" % e)
    finally:
        try:
            h.close()
        except Exception as e:
            res["errors"].append("harness close: %r" % e)
    res["seconds"] = round(time.time() - started, 1)
    res["passed"] = (not res["errors"] and res["level0"]["mismatch"] == 0 and res["normative"] == res["level0"]["match"])
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", help="corpus files (*.jsonl.gz)")
    ap.add_argument("--harness", default="%s %s" % (sys.executable, os.path.join(HERE, "core_chain_harness.py")),
                    help="harness command line")
    ap.add_argument("--restart-mode", choices=["replay", "noop-if-same"], default="replay")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--max-report", type=int, default=10)
    ap.add_argument("--json", help="write the full results to this file")
    a = ap.parse_args()
    cmd = a.harness.split()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(replay, f, cmd, a.restart_mode, a.max_report) for f in a.files]
        for fut in futs:
            r = fut.result()
            results.append(r)
            l0, l0n, l1, l2 = r["level0"], r["level0_nonnormative"], r["level1"], r["level2"]
            print("%-40s %s checks=%d normative=%d L0 %d/%d (non-normative %d/%d) L1 %d/%d L2 %d/%d errors=%d %.0fs" % (
                r["file"], "PASS" if r["passed"] else "FAIL", r["checks"], r["normative"],
                l0["match"], l0["match"] + l0["mismatch"], l0n["match"], l0n["match"] + l0n["mismatch"],
                l1["match"], l1["match"] + l1["mismatch"], l2["match"], l2["match"] + l2["mismatch"],
                len(r["errors"]), r["seconds"]))
            for m in r["mismatches"]:
                print("    mismatch: %s" % json.dumps(m))
            for e in r["errors"][:5]:
                print("    error: %s" % e)
            sys.stdout.flush()
    if a.json:
        with open(a.json, "w") as f:
            json.dump(results, f, indent=1)
    sys.exit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    main()
