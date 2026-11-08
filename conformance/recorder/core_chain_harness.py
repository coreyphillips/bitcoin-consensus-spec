#!/usr/bin/env python3
"""Core chain harness: the chain operations of conformance/PROTOCOL.md, answered
by Bitcoin Core v32.1 itself.

Every chain_reset starts a fresh regtest bitcoind (no network, no wallet) with
the requested consensus options; every event first sets the node clock with
setmocktime(now). Blocks go through submitblock, headers through submitheader,
invalidations through invalidateblock.

For events recorded as P2P deliveries ("via": "p2p", the default) the harness
reproduces the places where Core's P2P block and headers handling differs from
the RPCs (net_processing.cpp and validation.cpp, v32.1):

- a block whose parent is known and which IsBlockMutated reports as mutated is
  dropped without any effect;
- a block whose header is new and whose claimed chain work is below the anti-DoS
  threshold (tip work minus 144 blocks of work) is dropped without any effect;
- a block Core had not requested is fully processed only if it has at least as
  much work as the tip and is at most 288 blocks ahead of it; otherwise only its
  header is stored (after the context-free CheckBlock, which runs first);
- a headers message is ignored entirely if any header fails proof of work or
  the headers are not continuous, ignored if the first header does not connect,
  and ignored if its chain work is below the anti-DoS threshold (unless its last
  header is already an ancestor of the tip).

Run inside the recorder image: python3 core_chain_harness.py
"""

import base64
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blocklib  # noqa: E402

BITCOIND = os.environ.get("BCS_BITCOIND", os.path.join(os.environ.get("BCS_CORE_DIR", "/opt/bitcoin-32.1"), "bin", "bitcoind"))
KEEP = bool(os.environ.get("BCS_HARNESS_KEEP"))
OPS = ["info", "chain_reset", "chain_process_block", "chain_process_headers", "chain_invalidate",
       "chain_tip", "chain_tips", "utxo_hash"]
MIN_BLOCKS_TO_KEEP = 288
ANTI_DOS_BUFFER = 144


class RPCError(Exception):
    def __init__(self, code, message):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


class BadRequest(Exception):
    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def log(msg):
    sys.stderr.write("harness: %s\n" % msg)
    sys.stderr.flush()


def core_version():
    """First line of `bitcoind -version`, for example "Bitcoin Core daemon version v32.1.0 bitcoind"."""
    for _ in range(5):
        tmp = tempfile.mkdtemp(prefix="bcs-version-")
        try:
            out = subprocess.run([BITCOIND, "-version", "-datadir=" + tmp], capture_output=True, text=True).stdout
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if out.strip():
            return out.splitlines()[0]
        time.sleep(0.1)
    raise RuntimeError("bitcoind -version printed nothing")


class Node:
    def __init__(self, options):
        self.dir = tempfile.mkdtemp(prefix="bcs-harness-")
        self.port = free_port()
        self.id = 0
        args = [BITCOIND, "-regtest", "-datadir=" + self.dir, "-rpcport=%d" % self.port,
                "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-server=1", "-listen=0", "-connect=0",
                "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-natpmp=0", "-listenonion=0",
                "-disablewallet", "-printtoconsole=0", "-rpcthreads=4", "-rpcservertimeout=600",
                "-shrinkdebugfile=0"]
        if KEEP:
            args += ["-debug", "-logtimemicros", "-debugexclude=leveldb", "-debugexclude=rand"]
        for name, h in sorted((options or {}).get("testactivationheight", {}).items()):
            args.append("-testactivationheight=%s@%d" % (name, h))
        for t in (options or {}).get("test", []):
            args.append("-test=" + t)
        for vb in (options or {}).get("vbparams", []):
            args.append("-vbparams=" + vb)
        unknown = set((options or {}).keys()) - {"testactivationheight", "test", "vbparams"}
        if unknown:
            raise BadRequest("unsupported options: %s" % ", ".join(sorted(unknown)))
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.conn = None
        self.auth = None
        deadline = time.time() + 120
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError("bitcoind exited: %s" % self.proc.stderr.read().decode(errors="replace"))
            try:
                cookie = open(os.path.join(self.dir, "regtest", ".cookie")).read().strip()
                self.auth = "Basic " + base64.b64encode(cookie.encode()).decode()
                self.call("getblockcount")
                break
            except (OSError, RPCError, ValueError):
                if time.time() > deadline:
                    raise RuntimeError("bitcoind did not come up")
                self.conn = None
                time.sleep(0.05)
        self.mocktime = None

    def call(self, method, *params):
        if self.auth is None:
            raise OSError("no cookie yet")
        self.id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": list(params)})
        for attempt in range(2):
            if self.conn is None:
                self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=900)
            try:
                self.conn.request("POST", "/", body, {"Authorization": self.auth, "Content-Type": "application/json"})
                resp = self.conn.getresponse()
                data = resp.read()
                break
            except (http.client.HTTPException, ConnectionError):
                self.conn = None
                if attempt:
                    raise
        obj = json.loads(data)
        if obj.get("error"):
            raise RPCError(obj["error"].get("code"), obj["error"].get("message"))
        return obj["result"]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        if KEEP:
            log("kept datadir %s" % self.dir)
        else:
            shutil.rmtree(self.dir, ignore_errors=True)

    # ------------------------------------------------------------ helpers

    def set_now(self, now):
        if now is None:
            return
        now = int(now)
        if now <= 0:
            raise BadRequest("now must be positive")
        if now != self.mocktime:
            self.call("setmocktime", now)
            self.mocktime = now

    def header(self, h):
        try:
            return self.call("getblockheader", h)
        except RPCError as e:
            if e.code == -5:
                return None
            raise

    def tip(self):
        info = self.call("getblockchaininfo")
        return info

    def antidos_threshold(self, info):
        tip_work = int(info["chainwork"], 16)
        bits = int(self.call("getblockheader", info["bestblockhash"])["bits"], 16)
        near = tip_work - min(ANTI_DOS_BUFFER * blocklib.block_proof(bits), tip_work)
        return max(near, 0)

    def segwit_after(self, prev_hash):
        return bool(self.call("getdeploymentinfo", prev_hash)["deployments"]["segwit"]["active"])

    def is_ancestor_of_tip(self, h):
        hdr = self.header(h)
        return hdr is not None and hdr.get("confirmations", -1) >= 1

    def best_header(self, info):
        # Diagnostic only: a not-invalid chain tip at the best header height.
        tips = self.call("getchaintips")
        cands = [t for t in tips if t["height"] == info["headers"] and t["status"] != "invalid"]
        if cands:
            return sorted(cands, key=lambda t: (t["status"] != "active", t["hash"]))[0]["hash"]
        return info["bestblockhash"]

    # ------------------------------------------------------------ blocks

    @staticmethod
    def classify(res):
        if res is None or res == "inconclusive":
            return "accepted", None
        if res == "duplicate":
            return "duplicate", None
        if res == "prev-blk-not-found":
            return "orphan", res
        if res == "time-too-new":
            return "temporary", res
        if res in blocklib.MUTATED_REASONS:
            return "mutated", res
        return "invalid", res

    def submit(self, raw):
        try:
            res = self.call("submitblock", raw.hex())
        except RPCError as e:
            return "invalid", "rpc-error: %s" % e.message
        return self.classify(res)

    def process_block(self, raw, via, requested):
        try:
            blk = blocklib.parse_block(raw, allow_trailing=False)
        except blocklib.DecodeError as e:
            raise BadRequest("block does not decode: %s" % e)
        if via == "rpc":
            return self.submit(raw)
        if via != "p2p":
            raise BadRequest("via must be p2p or rpc")
        h = blk.header.hash_hex()
        prev = blk.header.prev_hex()
        prev_hdr = self.header(prev)
        known = None
        if prev_hdr is not None:
            reason = blocklib.is_block_mutated(blk, self.segwit_after(prev))
            if reason:
                return "mutated", reason
            known = self.header(h)
            if known is None:
                info = self.tip()
                claimed = int(prev_hdr["chainwork"], 16) + blocklib.block_proof(blk.header.bits)
                if claimed < self.antidos_threshold(info):
                    return "invalid", "too-little-chainwork"
        if not requested:
            cb = blocklib.check_block(blk)
            if cb is not None:
                result, reason = self.submit(raw)
                if reason not in blocklib.CHECKBLOCK_REASONS:
                    log("CheckBlock emulation disagrees with Core for %s: python=%s core=%s/%s" % (h, cb, result, reason))
                return result, reason
            if prev_hdr is not None:
                if known is None:
                    try:
                        self.call("submitheader", blk.header.raw.hex())
                    except RPCError as e:
                        return self.classify_header_error(e)
                    known = self.header(h)
                if known["nTx"] == 0:
                    info = self.tip()
                    less_work = int(known["chainwork"], 16) < int(info["chainwork"], 16)
                    too_far = known["height"] > info["blocks"] + MIN_BLOCKS_TO_KEEP
                    if less_work or too_far:
                        return "accepted", "unrequested-header-only"
        return self.submit(raw)

    # ------------------------------------------------------------ headers

    @staticmethod
    def classify_header_error(e):
        msg = e.message or ""
        if "Must submit previous header" in msg:
            return "orphan", "prev-blk-not-found"
        if msg.startswith("time-too-new"):
            return "temporary", "time-too-new"
        return "invalid", msg

    def process_headers(self, hdrs_hex, via):
        try:
            hdrs = [blocklib.Header(bytes.fromhex(x)) for x in hdrs_hex]
        except (ValueError, blocklib.DecodeError) as e:
            raise BadRequest("bad header: %s" % e)
        if not hdrs:
            return "accepted", None, None
        if via == "p2p":
            for i, hd in enumerate(hdrs):
                if not blocklib.check_proof_of_work(hd.hash(), hd.bits):
                    return "invalid", "high-hash", i
            if not blocklib.headers_continuous(hdrs):
                return "invalid", "non-continuous-headers", 0
            start = self.header(hdrs[0].prev_hex())
            if start is None:
                return "orphan", "prev-blk-not-found", 0
            if not self.is_ancestor_of_tip(hdrs[-1].hash_hex()):
                total = int(start["chainwork"], 16) + sum(blocklib.block_proof(hd.bits) for hd in hdrs)
                if total < self.antidos_threshold(self.tip()):
                    return "invalid", "too-little-chainwork", 0
        elif via != "rpc":
            raise BadRequest("via must be p2p or rpc")
        for i, hd in enumerate(hdrs):
            try:
                self.call("submitheader", hd.raw.hex())
            except RPCError as e:
                result, reason = self.classify_header_error(e)
                return result, reason, i
        return "accepted", None, None


class Harness:
    def __init__(self):
        self.node = None

    def need_node(self):
        if self.node is None:
            raise BadRequest("chain_reset has not been called")
        return self.node

    def tipinfo(self):
        info = self.node.tip()
        return {"tip": info["bestblockhash"], "height": info["blocks"]}

    def handle(self, req):
        op = req.get("op")
        if op == "info":
            return {"name": "bitcoin-core-chain-harness", "version": core_version(), "spec_version": "v32.1-1", "ops": OPS}
        if op == "chain_reset":
            if req.get("network", "regtest") != "regtest":
                raise BadRequest("only regtest is supported")
            if self.node is not None:
                self.node.stop()
                self.node = None
            self.node = Node(req.get("options") or {})
            return {"genesis": self.node.call("getblockhash", 0)}
        if op == "chain_process_block":
            node = self.need_node()
            if "block" not in req or "now" not in req:
                raise BadRequest("block and now are required")
            try:
                raw = bytes.fromhex(req["block"])
            except ValueError:
                raise BadRequest("block is not hex")
            node.set_now(req["now"])
            result, reason = node.process_block(raw, req.get("via", "p2p"), req.get("requested", True))
            out = {"result": result}
            if reason:
                out["reason"] = reason
            out.update(self.tipinfo())
            return out
        if op == "chain_process_headers":
            node = self.need_node()
            if "headers" not in req or "now" not in req:
                raise BadRequest("headers and now are required")
            node.set_now(req["now"])
            result, reason, index = node.process_headers(req["headers"], req.get("via", "p2p"))
            out = {"result": result}
            if reason:
                out["reason"] = reason
            if index is not None:
                out["index"] = index
            out["best_header"] = node.best_header(node.tip())
            return out
        if op == "chain_invalidate":
            node = self.need_node()
            node.set_now(req.get("now"))
            try:
                node.call("invalidateblock", req["hash"])
            except RPCError as e:
                raise BadRequest("invalidateblock failed: %s" % e.message)
            return self.tipinfo()
        if op == "chain_tip":
            node = self.need_node()
            info = node.tip()
            return {"tip": info["bestblockhash"], "height": info["blocks"], "chainwork": info["chainwork"]}
        if op == "chain_tips":
            node = self.need_node()
            return {"tips": [{"hash": t["hash"], "height": t["height"], "status": t["status"]}
                             for t in node.call("getchaintips")]}
        if op == "utxo_hash":
            node = self.need_node()
            u = node.call("gettxoutsetinfo", "hash_serialized_3")
            return {"hash_serialized_3": u["hash_serialized_3"], "txouts": u["txouts"]}
        return None


def main():
    h = Harness()
    out = sys.stdout
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            rid = None
            try:
                req = json.loads(line)
                rid = req.get("id")
                res = h.handle(req)
                if res is None:
                    resp = {"id": rid, "ok": False, "error": "unsupported_op", "message": str(req.get("op"))}
                else:
                    resp = {"id": rid, "ok": True}
                    resp.update(res)
            except BadRequest as e:
                resp = {"id": rid, "ok": False, "error": "bad_request", "message": str(e)}
            except Exception as e:
                log(traceback.format_exc())
                resp = {"id": rid, "ok": False, "error": "internal", "message": repr(e)}
            out.write(json.dumps(resp, separators=(",", ":")) + "\n")
            out.flush()
    finally:
        if h.node is not None:
            h.node.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
