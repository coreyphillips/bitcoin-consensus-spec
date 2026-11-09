#!/usr/bin/env python3
"""Write REPORT.md from postprocess.py --stats, compare_runs.py --report and
replay.py --json outputs."""

import argparse
import json
import os

EXPLAIN = {
    "p2p_not_processed": "P2P sends dropped because Core never processed them (payload failed to deserialize, or the peer was already disconnected)",
    "repeat_noeffect_collapsed": "byte-identical re-deliveries of blocks whose outcome cannot depend on chain state (mutated, or failing context-free checks), collapsed into the first delivery",
    "empty_headers_dropped": "empty headers messages dropped (no effect)",
    "submitblock_updated": "submitblock calls recorded with the coinbase witness reserved value Core added before validating",
    "preload_blocks": "blocks of the pre-mined 199-block chain cache the node started with, recorded as rpc deliveries before the first check",
    "bypass_blocks": "blocks the node obtained without passing through the test framework (other nodes, chain cache)",
    "bypass_headers": "headers the node obtained from other nodes",
    "bypass_reordered": "blocks or headers from other nodes moved after their parent (they arrived in a batch without a log line of their own)",
    "p2p_unresolved": "sends on connections whose peer id could not be resolved, dropped",
    "requested_model_disagreements": "blocks where the framework-side getdata model and the debug.log model of `requested` disagreed (the log wins)",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--stats", required=True)
    ap.add_argument("--compare", required=True)
    ap.add_argument("--verify", required=True)
    ap.add_argument("--verify-noop")
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    stats = [json.loads(line) for line in open(a.stats)]
    compare = json.load(open(a.compare))
    verify = {r["file"]: r for r in json.load(open(a.verify))}
    noop = {r["file"]: r for r in json.load(open(a.verify_noop))} if a.verify_noop and os.path.exists(a.verify_noop) else {}

    lines = []
    w = lines.append
    w("# Recording report")
    w("")
    w("Bitcoin Core v32.1 (commit `f0de87f040621468b956f01f526a43a010310501`), official aarch64 Linux release binaries, every node of each test except the pruned mining_basic node 2. "
      "Recorded twice with `--randomseed=1 --portseed=1 --v1transport` (feature_block with `--skipreorg`); the corpus comes from the first recording. "
      "Verification replays every file through the Core chain harness (a fresh v32.1 regtest node) as CORPUS.md section 4 prescribes. "
      "Reproduce with `make all CORE_SRC=<v32.1 checkout> -j6` (README.md).")
    w("")
    w("| Scenario | Events | Blocks | Headers | Invalidate | Restart | Checks | Normative | Size (bytes) |")
    w("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    total_size = 0
    for s in stats:
        c = s["counts"]
        total_size += s["bytes"]
        w("| %s | %d | %d | %d | %d | %d | %d | %d | %d |" % (
            s["scenario"], c["events"], c["blocks"], c["headers"], c["invalidate"], c["restart"],
            c["checks"], c["normative_checks"], s["bytes"]))
    blob_dir = os.path.join(a.vectors, "blobs")
    blobs = sorted(os.listdir(blob_dir)) if os.path.isdir(blob_dir) else []
    blob_size = sum(os.path.getsize(os.path.join(blob_dir, b)) for b in blobs)
    w("")
    w("Sidecar blobs (blocks over 1,000,000 bytes): %d files, %d bytes. Total corpus size: %d bytes (%.1f MB)." % (
        len(blobs), blob_size, total_size + blob_size, (total_size + blob_size) / 1e6))
    w("")
    w("## Verification")
    w("")
    w("Level 0 is the active tip and height at normative checks; level 1 the chain tip set (where recorded); level 2 the UTXO set hash (where recorded).")
    w("")
    w("| Scenario | Level 0 (normative) | Level 0 (non-normative) | Level 1 | Level 2 | Restarts as no-ops (level 0) |")
    w("|---|---|---|---|---|---|")
    for s in stats:
        f = s["file"]
        r = verify.get(f)
        if r is None:
            w("| %s | not run | | | | |" % s["scenario"])
            continue
        n = noop.get(f)
        fmt = lambda d: "%d/%d" % (d["match"], d["match"] + d["mismatch"])
        w("| %s | %s | %s | %s | %s | %s |" % (
            s["scenario"], fmt(r["level0"]), fmt(r["level0_nonnormative"]), fmt(r["level1"]), fmt(r["level2"]),
            fmt(n["level0"]) if n else "not run"))
    w("")
    w("## Second recording")
    w("")
    w("| Scenario | Differing regions | Racy checks (marked non-normative) |")
    w("|---|---:|---:|")
    for s in stats:
        cmp = compare.get(s["scenario"], {})
        w("| %s | %s | %s |" % (s["scenario"], len(cmp.get("diffs", [])) if cmp else "n/a",
                                 len(cmp.get("racy_checks", [])) if cmp else "n/a"))
    w("")
    w("## Exclusions and adjustments")
    w("")
    w("- feature_block: the 1088-block reorg (over 1 GB of block data) is skipped with `--skipreorg`; `make reorg` records it locally into `work/reorg`.")
    w("- mining_basic: node 2 (pruned) is excluded. Every other node of every test is included.")
    for s in stats:
        for k, v in sorted(s["stats"].items()):
            w("- %s: %s: %d." % (s["scenario"], EXPLAIN.get(k, k), v))
        for n in s["notes"]:
            w("- %s: %s." % (s["scenario"], n.rstrip(".")))
    w("")
    open(a.out, "w").write("\n".join(lines))


if __name__ == "__main__":
    main()
