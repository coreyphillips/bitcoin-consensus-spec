#!/usr/bin/env python3
"""Bitcoin Core as the node of the peer-sync suite (conformance/PROTOCOL.md
section 5.1), to check the suite against the implementation it is derived from.

usage: core_sync_node.py --bitcoind PATH --network regtest --datadir D
                         --peer HOST:PORT [--options JSON] [--v2transport 0|1]

Starts bitcoind on the empty data directory, connected only to the peer
(-connect, a manual connection: Core never disconnects it for an invalid
block), with the scenario's consensus options. Answers each request on
standard input:

  {"op":"tip","id":n}  ->  {"event":"tip","id":n,"tip":hash,"height":n}
  {"op":"stop"}        ->  {"event":"stopped","tip":...,"height":...,"hash_serialized_3":...}

Core handles the messages of one peer in order and connects a block before it
reads the next message, so once the runner has its pong every block sent before
the ping is processed. Standard input closing stops bitcoind.

Example:
  bcs-conformance peer-sync --bitcoind "$BITCOIND" --sync-node \
    "python3 conformance/recorder/core_sync_node.py --bitcoind $BITCOIND \
     --network {network} --datadir {datadir} --peer {peer} --options {options}"
"""

import argparse
import base64
import http.client
import json
import os
import socket
import subprocess
import sys
import time


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Rpc:
    def __init__(self, port, cookie):
        self.port = port
        self.cookie = cookie
        self.auth = None

    def call(self, method, *params):
        if self.auth is None:
            with open(self.cookie) as f:
                self.auth = "Basic " + base64.b64encode(f.read().strip().encode()).decode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=600)
        try:
            body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
            conn.request("POST", "/", body, {"Authorization": self.auth, "Content-Type": "application/json"})
            obj = json.loads(conn.getresponse().read())
        finally:
            conn.close()
        if obj.get("error"):
            raise RuntimeError("%s: %s" % (method, obj["error"]))
        return obj["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--network", required=True)
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--options", default="{}")
    ap.add_argument("--v2transport", default="1")
    a = ap.parse_args()
    if a.network != "regtest":
        emit({"event": "error", "message": "only regtest"})
        return 1
    options = json.loads(a.options or "{}")
    port = free_port()
    args = [a.bitcoind, "-regtest", "-datadir=" + a.datadir, "-connect=" + a.peer, "-listen=0",
            "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % port,
            "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-natpmp=0", "-listenonion=0",
            "-v2transport=" + a.v2transport, "-debug=net", "-debug=validation",
            "-printtoconsole=0", "-daemon=0"]
    for name, height in sorted(options.get("testactivationheight", {}).items()):
        args.append("-testactivationheight=%s@%d" % (name, height))
    for t in options.get("test", []):
        args.append("-test=" + t)
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=sys.stderr)
    rpc = Rpc(port, os.path.join(a.datadir, "regtest", ".cookie"))

    def stop():
        try:
            rpc.call("stop")
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    deadline = time.time() + 120
    while True:
        if proc.poll() is not None:
            emit({"event": "error", "message": "bitcoind exited at start with %s" % proc.returncode})
            return 1
        try:
            rpc.call("getblockcount")
            break
        except Exception:  # noqa: BLE001
            rpc.auth = None
            if time.time() > deadline:
                stop()
                emit({"event": "error", "message": "bitcoind RPC did not come up"})
                return 1
            time.sleep(0.1)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("op") == "tip":
            emit({"event": "tip", "id": req["id"], "tip": rpc.call("getbestblockhash"),
                  "height": rpc.call("getblockcount")})
        elif req.get("op") == "stop":
            info = rpc.call("gettxoutsetinfo", "hash_serialized_3")
            emit({"event": "stopped", "tip": info["bestblock"], "height": info["height"],
                  "hash_serialized_3": info["hash_serialized_3"]})
            stop()
            return 0
    stop()
    return 1


if __name__ == "__main__":
    sys.exit(main())
