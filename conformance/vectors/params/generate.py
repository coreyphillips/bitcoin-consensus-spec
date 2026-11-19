"""Writes the params suite's cases, with the answers of the Core oracle as expectations.

Usage: python3 generate.py <oracle-core-harness> <out.jsonl>

One case per network and field, so a harness with one wrong value fails one check.
"""

import json
import subprocess
import sys

ORACLE, OUT = sys.argv[1], sys.argv[2]
NETWORKS = ["main", "testnet3", "testnet4", "signet", "regtest"]

proc = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
count = 0
with open(OUT, "w") as out:
    for i, network in enumerate(NETWORKS):
        request = {"op": "network_params", "network": network}
        proc.stdin.write(json.dumps({"id": i, **request}) + "\n")
        proc.stdin.flush()
        answer = json.loads(proc.stdout.readline())
        if answer.get("id") != i or answer.get("ok") is not True:
            sys.exit(f"{network}: {answer}")
        del answer["id"], answer["ok"]
        for field, value in answer.items():
            case = {"name": f"{network} {field}", "request": request, "expect": {field: value}}
            out.write(json.dumps(case, separators=(", ", ": ")) + "\n")
            count += 1
proc.stdin.close()
proc.wait()
print(f"{count} cases written to {OUT}")
