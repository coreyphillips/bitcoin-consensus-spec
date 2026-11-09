#!/usr/bin/env python3
"""Run one Bitcoin Core v32.1 functional test, unmodified, with recording hooks.

The hooks capture, for every node the test starts:

- block, headers, cmpctblock and blocktxn payloads sent over the framework's
  P2P connections, recorded inside the connection's send lock so the order per
  connection is exact (P2PConnection.send_without_ping);
- getdata requests from the node (P2PInterface.on_message) and connection loss;
- state-changing RPCs (AuthServiceProxy.__call__): submitblock, submitheader,
  generatetoaddress, generatetodescriptor, generateblock, invalidateblock,
  reconsiderblock, preciousblock, setmocktime, with their results and, for
  mined blocks, the stored block bytes;
- checkpoints (best block, height, chain tips, and the UTXO set hash when the
  tip changed) after send_blocks_and_test, send_and_ping/sync_with_ping,
  state-changing RPCs, sync_blocks, node start and node shutdown;
- blocks and headers the node obtained without passing through the framework
  (other bitcoind peers, the pre-mined chain cache), found at each checkpoint
  by walking the node's block index.

Raw events are written to <out>/events.jsonl; debug.log files are copied to
<out>/debug/ once the test has finished. postprocess.py turns this into corpus
files.
"""

import argparse
import contextlib
import glob
import gzip
import hashlib
import json
import os
import platform
import runpy
import shutil
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blocklib  # noqa: E402

STATE_RPCS = {
    "submitblock", "submitheader", "generatetoaddress", "generatetodescriptor",
    "generateblock", "invalidateblock", "reconsiderblock", "preciousblock",
    "setmocktime",
}
# RPCs that would change chain state in ways this recorder does not capture.
UNSUPPORTED_RPCS = {"loadtxoutset", "getblockfrompeer", "importblocks"}
RECORD_P2P = {b"block", b"headers", b"cmpctblock", b"blocktxn"}
MSG_TYPE_MASK = 0xffffffff >> 2
BLOCK_INV_TYPES = {2, 3, 4}  # MSG_BLOCK, MSG_FILTERED_BLOCK, MSG_CMPCT_BLOCK
PING_NONCE_BASE = 0x6263735f00000000  # distinct from the framework's small counters
PAYLOAD_INLINE_MAX = 256 * 1024  # larger payloads go to <out>/payloads/<sha256>.bin


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class RecorderError(Exception):
    pass


class NodeState:
    """Per node index state that survives restarts (the data directory persists)."""

    def __init__(self, index, datadir):
        self.index = index
        self.datadir = datadir
        self.session = None
        self.known_block = set()
        self.known_header = set()
        self.complete = set()
        self.meta = {}
        self.last_utxo_tip = None


class Session:
    def __init__(self, sid, index, args, conf, log_offset, mocktime):
        self.id = sid
        self.node = index
        self.args = args
        self.conf = conf
        self.log_offset = log_offset
        self.mocktime = mocktime
        self.rpc = None
        self.alive = True

    def now(self):
        return self.mocktime if self.mocktime is not None else int(time.time())


class ConnInfo:
    def __init__(self, key, obj, node, session, kind):
        self.key = key
        self.obj = obj
        self.node = node
        self.session = session
        self.kind = kind
        self.peer = None
        self.local = None
        self.dirty = False
        self.closed = False


class Recorder:
    def __init__(self):
        self.lock = threading.RLock()
        self.tls = threading.local()
        self.f = None
        self.seq = 0
        self.nodes = {}
        self.conns = {}
        self.inflight = {}
        self.pending_start = {}
        self.next_conn = 1
        self.next_session = 1
        self.nonce = PING_NONCE_BASE
        self.cachedir = None
        self.payload_dir = None
        self.rpc_port_map = None
        self.P = None  # test_framework.p2p
        self.U = None  # test_framework.util
        self.messages = None
        self.AuthServiceProxy = None
        self.stats = {"checkpoints": 0, "checkpoints_skipped": 0, "unstable": 0}

    # ------------------------------------------------------------ plumbing

    def open(self, path):
        self.f = open(path, "w", buffering=1 << 20)

    def emit(self, ev):
        with self.lock:
            ev["seq"] = self.seq
            self.seq += 1
            ev.setdefault("t", time.time())
            self.f.write(json.dumps(ev, separators=(",", ":")) + "\n")

    def flush_file(self):
        with self.lock:
            self.f.flush()

    def payload(self, raw):
        """Event fields carrying raw bytes: inline hex, or a content-addressed side file."""
        if len(raw) <= PAYLOAD_INLINE_MAX:
            return {"hex": raw.hex()}
        sha = hashlib.sha256(raw).hexdigest()
        path = os.path.join(self.payload_dir, sha + ".bin")
        if not os.path.exists(path):
            tmp = path + ".%d.tmp" % threading.get_ident()
            with open(tmp, "wb") as f:
                f.write(raw)
            os.replace(tmp, path)
        return {"payload": sha}

    def tl(self, name, default):
        return getattr(self.tls, name, default)

    @contextlib.contextmanager
    def internal(self):
        prev = self.tl("internal", False)
        self.tls.internal = True
        try:
            yield
        finally:
            self.tls.internal = prev

    @contextlib.contextmanager
    def nested(self):
        self.tls.depth = self.tl("depth", 0) + 1
        try:
            yield
        finally:
            self.tls.depth -= 1

    def can_sync(self):
        if threading.current_thread() is not threading.main_thread():
            return False
        if self.tl("pred", 0) > 0:
            return False
        lock = self.P.p2p_lock
        if hasattr(lock, "_is_owned") and lock._is_owned():
            return False
        return True

    def node_for_port(self, port):
        if self.rpc_port_map is None:
            self.rpc_port_map = {self.U.rpc_port(i): i for i in range(self.U.MAX_NODES)}
        return self.rpc_port_map.get(port)

    def session_for(self, index):
        ns = self.nodes.get(index)
        if ns is None or ns.session is None or not ns.session.alive:
            return None
        return ns.session

    def conn_info(self, conn):
        return self.conns.get(id(conn))

    def is_cache_node(self, node):
        return self.cachedir is not None and str(node.datadir_path).startswith(self.cachedir)

    # ------------------------------------------------------------ nodes

    def on_node_starting(self, node):
        if self.is_cache_node(node):
            return
        path = str(node.debug_log_path)
        off = os.path.getsize(path) if os.path.exists(path) else 0
        self.pending_start[node.index] = {"log_offset": off}

    def on_node_process(self, node):
        if self.is_cache_node(node):
            return
        p = self.pending_start.setdefault(node.index, {"log_offset": 0})
        proc = node.__dict__.get("process")
        p["args"] = [str(a) for a in proc.args] if proc is not None else []

    def on_node_up(self, node):
        if self.is_cache_node(node):
            return
        idx = node.index
        p = self.pending_start.pop(idx, {"log_offset": 0, "args": []})
        args = p.get("args", [])
        conf = ""
        try:
            with open(os.path.join(str(node.datadir_path), "bitcoin.conf")) as cf:
                conf = cf.read()
        except OSError:
            pass
        mocktime = None
        for a in args:
            if a.startswith("-mocktime="):
                v = int(a.split("=", 1)[1])
                mocktime = v if v != 0 else None
        ns = self.nodes.get(idx)
        if ns is None:
            ns = self.nodes[idx] = NodeState(idx, str(node.datadir_path))
        if ns.session is not None and ns.session.alive:
            ns.session.alive = False
            self.emit({"ev": "node_stop", "node": idx, "session": ns.session.id, "implicit": True})
        s = Session(self.next_session, idx, args, conf, p["log_offset"], mocktime)
        self.next_session += 1
        s.rpc = self.AuthServiceProxy(node.url, timeout=600)
        ns.session = s
        with self.internal():
            genesis = s.rpc.getblockhash(0)
            gh = s.rpc.getblockheader(genesis)
        ns.complete.add(genesis)
        ns.known_block.add(genesis)
        ns.known_header.add(genesis)
        ns.meta[genesis] = {"height": 0, "chainwork": gh["chainwork"], "prev": None, "ntx": gh["nTx"]}
        self.emit({"ev": "node_start", "node": idx, "session": s.id, "args": args, "conf": conf,
                   "log_offset": s.log_offset, "mocktime": mocktime, "genesis": genesis,
                   "datadir": ns.datadir})
        self.checkpoint(idx, "start")

    def on_node_stopping(self, node):
        idx = node.index
        s = self.session_for(idx)
        if s is None:
            return
        if node.__dict__.get("running") and node.__dict__.get("rpc_connected"):
            self.checkpoint(idx, "shutdown")
        s.alive = False
        self.emit({"ev": "node_stop", "node": idx, "session": s.id})

    # ------------------------------------------------------------ P2P

    def register_conn(self, conn, node, kind):
        with self.lock:
            s = self.session_for(node.index)
            ci = ConnInfo(self.next_conn, conn, node.index, s.id if s else None, kind)
            self.next_conn += 1
            self.conns[id(conn)] = ci
        return ci

    def resolve_peer(self, conn):
        ci = self.conn_info(conn)
        if ci is None:
            return
        s = self.session_for(ci.node)
        local = None
        try:
            sock = conn._transport.get_extra_info("socket")
            name = sock.getsockname()
            local = "%s:%d" % (name[0], name[1])
        except Exception:
            local = None
        peer = None
        if s is not None and local is not None:
            with self.internal():
                for _ in range(100):
                    for p in s.rpc.getpeerinfo():
                        if p.get("addr") == local:
                            peer = p["id"]
                            break
                    if peer is not None:
                        break
                    time.sleep(0.05)
        ci.peer = peer
        ci.local = local
        self.emit({"ev": "conn_open", "conn": ci.key, "node": ci.node, "session": ci.session,
                   "kind": ci.kind, "peer": peer, "local": local})

    def on_p2p_send(self, conn, msgtype, payload):
        ci = self.conn_info(conn)
        if ci is None:
            # Connection not created through add_p2p_connection: attribute by destination port.
            node = None
            for i in self.nodes:
                if getattr(conn, "dstport", None) == self.U.p2p_port(i):
                    node = i
            with self.lock:
                s = self.session_for(node) if node is not None else None
                ci = ConnInfo(self.next_conn, conn, node, s.id if s else None, "unregistered")
                self.next_conn += 1
                self.conns[id(conn)] = ci
        ev = {"ev": "p2p", "conn": ci.key, "node": ci.node, "session": ci.session,
              "type": msgtype, "size": len(payload)}
        ev.update(self.payload(payload))
        ns = self.nodes.get(ci.node)
        with self.lock:
            if msgtype == "block" and len(payload) >= 80:
                h = blocklib.hash_to_hex(blocklib.sha256d(payload[:80]))
                ev["hash"] = h
                infl = self.inflight.setdefault(ci.node, {}).get(h)
                ev["req_model"] = bool(infl)
                if infl:
                    infl.discard(ci.key)
                if ns is not None:
                    ns.known_block.add(h)
                    ns.known_header.add(h)
            elif msgtype == "headers":
                hashes = []
                try:
                    r = blocklib.Reader(payload)
                    for _ in range(r.compact()):
                        hashes.append(blocklib.hash_to_hex(blocklib.sha256d(r.read(80))))
                        r.compact()
                except blocklib.DecodeError:
                    pass
                ev["hashes"] = hashes
                if ns is not None:
                    ns.known_header.update(hashes)
            ci.dirty = True
            self.emit(ev)

    def on_getdata(self, conn, message):
        ci = self.conn_info(conn)
        if ci is None:
            return
        hashes = []
        with self.lock:
            for inv in message.inv:
                if (inv.type & MSG_TYPE_MASK) in BLOCK_INV_TYPES:
                    h = "%064x" % inv.hash
                    hashes.append([inv.type, h])
                    self.inflight.setdefault(ci.node, {}).setdefault(h, set()).add(ci.key)
            if hashes:
                self.emit({"ev": "getdata", "conn": ci.key, "node": ci.node, "invs": hashes})

    def on_conn_lost(self, conn):
        ci = self.conn_info(conn)
        if ci is None:
            return
        with self.lock:
            ci.closed = True
            ci.dirty = False
            for hs in self.inflight.get(ci.node, {}).values():
                hs.discard(ci.key)
            self.emit({"ev": "conn_close", "conn": ci.key, "node": ci.node})

    def on_synced(self, conn):
        ci = self.conn_info(conn)
        if ci is None:
            return
        ci.dirty = False
        if self.tl("depth", 0) == 0:
            self.checkpoint(ci.node, "sync_with_ping")

    def flush_node(self, index):
        """Ping every connection that sent block data since it last synced, so
        everything sent so far is processed before the caller proceeds."""
        for ci in list(self.conns.values()):
            if ci.node != index or not ci.dirty or ci.closed:
                continue
            self.ping(ci)

    def ping(self, ci):
        conn = ci.obj
        if not conn.is_connected:
            ci.dirty = False
            return
        with self.lock:
            self.nonce += 1
            nonce = self.nonce
        try:
            conn.send_without_ping(self.messages.msg_ping(nonce=nonce))
        except IOError:
            ci.dirty = False
            return
        deadline = time.time() + 300
        while time.time() < deadline:
            with self.P.p2p_lock:
                pong = conn.last_message.get("pong")
                if pong is not None and pong.nonce == nonce:
                    ci.dirty = False
                    return
                if not conn.is_connected:
                    ci.dirty = False
                    return
            time.sleep(0.002)
        raise RecorderError("timed out waiting for pong on connection %d" % ci.key)

    # ------------------------------------------------------------ RPC

    def rpc_call(self, proxy, orig, args, kwargs):
        method = proxy._service_name
        if self.tl("internal", False) or method is None:
            return orig(proxy, *args, **kwargs)
        if method in UNSUPPORTED_RPCS:
            self.emit({"ev": "unsupported_rpc", "method": method})
        if method not in STATE_RPCS:
            return orig(proxy, *args, **kwargs)
        url = proxy._AuthServiceProxy__url
        idx = self.node_for_port(url.port)
        s = self.session_for(idx) if idx is not None else None
        if s is None:
            return orig(proxy, *args, **kwargs)
        synced = self.can_sync()
        if synced:
            self.flush_node(idx)
        pre = self.pre_rpc(s, method, args, kwargs)
        now0 = s.now()
        t0 = time.time()
        try:
            result = orig(proxy, *args, **kwargs)
        except Exception as e:
            self.post_rpc(s, method, args, kwargs, pre, False, None, e, t0, now0, synced)
            raise
        self.post_rpc(s, method, args, kwargs, pre, True, result, None, t0, now0, synced)
        if synced and method != "setmocktime" and self.tl("depth", 0) == 0:
            self.checkpoint(idx, "rpc:" + method)
        return result

    @staticmethod
    def arg(args, kwargs, pos, name, default=None):
        if name in kwargs:
            return kwargs[name]
        if len(args) > pos:
            return args[pos]
        return default

    def pre_rpc(self, s, method, args, kwargs):
        pre = {}
        if method == "submitblock":
            hexdata = self.arg(args, kwargs, 0, "hexdata")
            try:
                raw = bytes.fromhex(hexdata)
                block = blocklib.parse_block(raw)
            except Exception as e:
                pre["decode_error"] = repr(e)
                return pre
            prev = block.header.prev_hex()
            with self.internal():
                try:
                    s.rpc.getblockheader(prev)
                    known = True
                except Exception:
                    known = False
                segwit = None
                if known:
                    segwit = bool(s.rpc.getdeploymentinfo(prev)["deployments"]["segwit"]["active"])
            pre["parent_known"] = known
            pre["segwit_after_parent"] = segwit
            updated = False
            if known:
                updated = blocklib.update_uncommitted_block_structures(block, segwit)
            pre["updated"] = updated
            pre["trailing"] = block.trailing
            pre.update(self.payload(block.serialize()))
            pre["hash"] = block.header.hash_hex()
        elif method == "submitheader":
            hexdata = self.arg(args, kwargs, 0, "hexdata")
            try:
                raw = bytes.fromhex(hexdata)
                if len(raw) < 80:
                    raise ValueError("short header")
                pre["header"] = raw[:80].hex()
                pre["hash"] = blocklib.hash_to_hex(blocklib.sha256d(raw[:80]))
            except Exception as e:
                pre["decode_error"] = repr(e)
        return pre

    def post_rpc(self, s, method, args, kwargs, pre, ok, result, error, t0, now0, synced):
        ns = self.nodes[s.node]
        ev = {"ev": "rpc", "node": s.node, "session": s.id, "method": method, "ok": ok,
              "now": now0, "mocktime": s.mocktime, "t0": t0, "in_sync": synced}
        if error is not None:
            ev["error"] = str(getattr(error, "error", None) or error)
        if method == "setmocktime":
            ts = int(self.arg(args, kwargs, 0, "timestamp"))
            ev["value"] = ts
            if ok:
                s.mocktime = ts if ts != 0 else None
        elif method == "submitblock":
            ev.update({k: v for k, v in pre.items()})
            ev["result"] = result if ok else None
            if "hash" in pre:
                ns.known_block.add(pre["hash"])
                ns.known_header.add(pre["hash"])
        elif method == "submitheader":
            ev.update({k: v for k, v in pre.items()})
            if "hash" in pre:
                ns.known_header.add(pre["hash"])
        elif method in ("generatetoaddress", "generatetodescriptor", "generateblock"):
            hashes = []
            if ok:
                if method == "generateblock":
                    submit = self.arg(args, kwargs, 3, "submit", True)
                    if submit is not False and isinstance(result, dict) and "hash" in result:
                        hashes = [result["hash"]]
                else:
                    hashes = list(result or [])
            blocks = []
            with self.internal():
                for h in hashes:
                    b = {"hash": h}
                    b.update(self.payload(bytes.fromhex(s.rpc.getblock(h, 0))))
                    blocks.append(b)
                    ns.known_block.add(h)
                    ns.known_header.add(h)
            ev["blocks"] = blocks
            ev["now_end"] = s.now()
        elif method in ("invalidateblock", "reconsiderblock", "preciousblock"):
            ev["hash"] = self.arg(args, kwargs, 0, "blockhash")
        ev["t1"] = time.time()
        self.emit(ev)

    # ------------------------------------------------------------ checkpoints

    def checkpoint(self, index, label):
        s = self.session_for(index)
        if s is None:
            return
        if not self.can_sync():
            self.stats["checkpoints_skipped"] += 1
            self.emit({"ev": "checkpoint_skipped", "node": index, "session": s.id, "label": label})
            return
        self.flush_node(index)
        ns = self.nodes[index]
        with self.internal():
            stable = False
            for _ in range(20):
                info = s.rpc.getblockchaininfo()
                tips = s.rpc.getchaintips()
                found = self.walk(ns, s, tips)
                for kind, h, hexdata in found:
                    m = ns.meta[h]
                    ev = {"ev": "bypass", "node": index, "session": s.id, "kind": kind,
                          "hash": h, "height": m["height"], "prev": m["prev"],
                          "chainwork": m["chainwork"], "now": s.now()}
                    ev.update(self.payload(bytes.fromhex(hexdata)))
                    self.emit(ev)
                info2 = s.rpc.getblockchaininfo()
                key = ("bestblockhash", "blocks", "headers")
                if all(info[k] == info2[k] for k in key):
                    stable = True
                    break
                time.sleep(0.1)
            if not stable:
                self.stats["unstable"] += 1
            utxo = None
            best = info["bestblockhash"]
            if best != ns.last_utxo_tip:
                u = s.rpc.gettxoutsetinfo("hash_serialized_3")
                if u["bestblock"] == best:
                    utxo = {"hash_serialized_3": u["hash_serialized_3"], "txouts": u["txouts"]}
                    ns.last_utxo_tip = best
        out_tips = []
        for t in tips:
            m = ns.meta.get(t["hash"], {})
            out_tips.append({"hash": t["hash"], "height": t["height"], "status": t["status"],
                             "branchlen": t["branchlen"], "chainwork": m.get("chainwork")})
        self.stats["checkpoints"] += 1
        self.emit({"ev": "checkpoint", "node": index, "session": s.id, "label": label,
                   "best": best, "height": info["blocks"], "headers": info["headers"],
                   "chainwork": info["chainwork"], "tips": out_tips, "utxo": utxo,
                   "stable": stable, "now": s.now(), "mocktime": s.mocktime})

    def walk(self, ns, s, tips):
        """Find block index entries this recorder has not seen delivered."""
        found = []
        for t in tips:
            h = t["hash"]
            stack = []
            while h is not None and h not in ns.complete:
                hdr = s.rpc.getblockheader(h)
                ns.meta[h] = {"height": hdr["height"], "chainwork": hdr["chainwork"],
                              "prev": hdr.get("previousblockhash"), "ntx": hdr["nTx"]}
                stack.append(h)
                h = hdr.get("previousblockhash")
            for h in stack:
                ns.complete.add(h)
            for h in reversed(stack):
                m = ns.meta[h]
                if m["ntx"] > 0 and h not in ns.known_block:
                    found.append(("block", h, s.rpc.getblock(h, 0)))
                    ns.known_block.add(h)
                    ns.known_header.add(h)
                elif m["ntx"] == 0 and h not in ns.known_header:
                    found.append(("header", h, s.rpc.getblockheader(h, False)))
                    ns.known_header.add(h)
        return found


REC = Recorder()


# ---------------------------------------------------------------- hooks

def install_hooks(functional_dir):
    sys.path.insert(0, functional_dir)

    import test_framework.util as U
    REC.U = U
    orig_wait = U.wait_until_helper_internal

    def wait_until_helper_internal(predicate, **kwargs):
        def pred():
            REC.tls.pred = REC.tl("pred", 0) + 1
            try:
                return predicate()
            finally:
                REC.tls.pred -= 1
        pred.__wrapped__ = predicate
        return orig_wait(pred, **kwargs)

    U.wait_until_helper_internal = wait_until_helper_internal

    import test_framework.p2p as P
    REC.P = P
    # Tests import p2p_lock by name, so it must be replaced before they are loaded.
    P.p2p_lock = threading.RLock()

    import test_framework.messages as M
    REC.messages = M

    def send_without_ping(self, message, is_decoy=False):
        with self._send_lock:
            tmsg = self.build_message(message, is_decoy)
            self._log_message("send", message)
            r = self.send_raw_message(tmsg)
            if not is_decoy and message.msgtype in RECORD_P2P:
                payload = message.serialize() if self.supports_v2_p2p else tmsg[24:]
                REC.on_p2p_send(self, message.msgtype.decode(), payload)
            return r

    P.P2PConnection.send_without_ping = send_without_ping

    orig_on_message = P.P2PInterface.on_message

    def on_message(self, message):
        if message.msgtype == b"getdata":
            REC.on_getdata(self, message)
        return orig_on_message(self, message)

    P.P2PInterface.on_message = on_message

    orig_connection_lost = P.P2PConnection.connection_lost

    def connection_lost(self, exc):
        REC.on_conn_lost(self)
        return orig_connection_lost(self, exc)

    P.P2PConnection.connection_lost = connection_lost

    orig_sync_with_ping = P.P2PInterface.sync_with_ping

    def sync_with_ping(self, *args, **kwargs):
        r = orig_sync_with_ping(self, *args, **kwargs)
        REC.on_synced(self)
        return r

    P.P2PInterface.sync_with_ping = sync_with_ping

    orig_send_blocks_and_test = P.P2PDataStore.send_blocks_and_test

    def send_blocks_and_test(self, blocks, node, *args, **kwargs):
        with REC.nested():
            r = orig_send_blocks_and_test(self, blocks, node, *args, **kwargs)
        if REC.tl("depth", 0) == 0:
            REC.checkpoint(node.index, "send_blocks_and_test")
        return r

    P.P2PDataStore.send_blocks_and_test = send_blocks_and_test

    import test_framework.authproxy as A
    REC.AuthServiceProxy = A.AuthServiceProxy
    orig_call = A.AuthServiceProxy.__call__

    def call(self, *args, **kwargs):
        return REC.rpc_call(self, orig_call, args, kwargs)

    A.AuthServiceProxy.__call__ = call
    orig_batch = A.AuthServiceProxy.batch

    def batch(self, rpc_call_list):
        calls = list(rpc_call_list)
        for c in calls:
            if isinstance(c, dict) and c.get("method") in STATE_RPCS and not REC.tl("internal", False):
                raise RecorderError("state-changing RPC %s in a batch is not supported" % c.get("method"))
        return orig_batch(self, calls)

    A.AuthServiceProxy.batch = batch

    import test_framework.test_node as TN
    orig_start = TN.TestNode.start

    def start(self, *args, **kwargs):
        REC.on_node_starting(self)
        r = orig_start(self, *args, **kwargs)
        REC.on_node_process(self)
        return r

    TN.TestNode.start = start
    orig_wait_rpc = TN.TestNode.wait_for_rpc_connection

    def wait_for_rpc_connection(self, *args, **kwargs):
        r = orig_wait_rpc(self, *args, **kwargs)
        REC.on_node_up(self)
        return r

    TN.TestNode.wait_for_rpc_connection = wait_for_rpc_connection
    orig_stop_node = TN.TestNode.stop_node

    def stop_node(self, *args, **kwargs):
        REC.on_node_stopping(self)
        return orig_stop_node(self, *args, **kwargs)

    TN.TestNode.stop_node = stop_node

    def wrap_add(orig, kind):
        def add(self, p2p_conn, *args, **kwargs):
            REC.register_conn(p2p_conn, self, kind)
            with REC.nested():
                r = orig(self, p2p_conn, *args, **kwargs)
            REC.resolve_peer(p2p_conn)
            return r
        return add

    TN.TestNode.add_p2p_connection = wrap_add(TN.TestNode.add_p2p_connection, "inbound")
    TN.TestNode.add_outbound_p2p_connection = wrap_add(TN.TestNode.add_outbound_p2p_connection, "outbound")

    import test_framework.test_framework as TF
    orig_sync_blocks = TF.BitcoinTestFramework.sync_blocks

    def sync_blocks(self, nodes=None, *args, **kwargs):
        r = orig_sync_blocks(self, nodes, *args, **kwargs)
        if REC.tl("depth", 0) == 0:
            for n in (nodes or self.nodes):
                REC.checkpoint(n.index, "sync_blocks")
        return r

    TF.BitcoinTestFramework.sync_blocks = sync_blocks


# ---------------------------------------------------------------- main

def verify_pins(functional_dir, test, allow_unpinned):
    with open(os.path.join(HERE, "pins.json")) as f:
        pins = json.load(f)
    actual = {}
    problems = []
    for rel, want in sorted(pins["framework"].items()):
        got = sha256_file(os.path.join(functional_dir, rel))
        actual[rel] = got
        if got != want:
            problems.append("%s: %s != pinned %s" % (rel, got, want))
    present = set(os.path.relpath(p, functional_dir)
                  for p in glob.glob(os.path.join(functional_dir, "test_framework", "**", "*.py"), recursive=True))
    for rel in sorted(present - set(pins["framework"])):
        problems.append("%s: not pinned" % rel)
    test_sha = sha256_file(os.path.join(functional_dir, test))
    if pins["tests"].get(test) != test_sha:
        problems.append("%s: %s not pinned (%s)" % (test, test_sha, pins["tests"].get(test)))
    if problems and not allow_unpinned:
        raise RecorderError("framework files do not match pins.json:\n  " + "\n  ".join(problems))
    return pins, actual, test_sha, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--test", required=True, help="functional test file name, e.g. feature_block.py")
    ap.add_argument("--out", required=True, help="raw capture directory (created)")
    ap.add_argument("--work", required=True, help="scratch directory for the test cache and datadirs (created)")
    ap.add_argument("--core-src", default=os.environ.get("BCS_CORE_SRC", "/core"))
    ap.add_argument("--configfile", default="/opt/bcs/config.ini")
    ap.add_argument("--allow-unpinned", action="store_true")
    ap.add_argument("test_args", nargs=argparse.REMAINDER, help="arguments passed to the test (after --)")
    a = ap.parse_args()
    test_args = [x for x in a.test_args if x != "--"]

    functional = os.path.join(a.core_src, "test", "functional")
    pins, actual, test_sha, problems = verify_pins(functional, a.test, a.allow_unpinned)

    os.makedirs(a.out, exist_ok=False)
    os.makedirs(a.work, exist_ok=False)
    cachedir = os.path.join(a.work, "cache")
    tmpdir = os.path.join(a.work, "tmp")
    REC.cachedir = cachedir
    REC.payload_dir = os.path.join(a.out, "payloads")
    os.makedirs(REC.payload_dir)
    REC.open(os.path.join(a.out, "events.jsonl"))

    core_dir = os.environ.get("BCS_CORE_DIR", "/opt/bitcoin-32.1")
    bitcoind = os.path.join(core_dir, "bin", "bitcoind")
    tarball_sha = ""
    try:
        with open(os.path.join(core_dir, "TARBALL_SHA256")) as f:
            tarball_sha = f.read().strip()
    except OSError:
        pass
    test_path = os.path.join(functional, a.test)
    argv = [test_path, "--cachedir=" + cachedir, "--tmpdir=" + tmpdir,
            "--configfile=" + a.configfile, "--nocleanup"] + test_args
    REC.emit({
        "ev": "run_start", "test": a.test, "argv": argv[1:], "test_sha256": test_sha,
        "framework_sha256": actual, "unpinned": problems,
        "bitcoind_sha256": sha256_file(bitcoind), "tarball_sha256": tarball_sha,
        "image": os.environ.get("BCS_IMAGE_ID", ""), "base_image": pins["base_image"],
        "python": sys.version.split()[0], "platform": platform.platform(),
        "core": pins["core"],
    })

    install_hooks(functional)
    sys.argv = argv
    exit_code = None
    error = None
    try:
        runpy.run_path(test_path, run_name="__main__")
    except SystemExit as e:
        exit_code = e.code
    except BaseException:
        error = traceback.format_exc()
        exit_code = 1
    REC.emit({"ev": "run_end", "exit_code": exit_code, "error": error, "stats": REC.stats})
    REC.flush_file()
    REC.f.close()
    events_path = os.path.join(a.out, "events.jsonl")
    with open(events_path, "rb") as fi, gzip.open(events_path + ".gz", "wb", compresslevel=6) as fo:
        shutil.copyfileobj(fi, fo, 1 << 22)
    os.remove(events_path)

    debug_out = os.path.join(a.out, "debug")
    os.makedirs(debug_out, exist_ok=True)
    for d in sorted(glob.glob(os.path.join(tmpdir, "node*"))):
        name = os.path.basename(d)
        src = os.path.join(d, "regtest", "debug.log")
        if os.path.exists(src):
            with open(src, "rb") as fi, gzip.open(os.path.join(debug_out, name + ".log.gz"), "wb") as fo:
                shutil.copyfileobj(fi, fo)
    tfl = os.path.join(tmpdir, "test_framework.log")
    if os.path.exists(tfl):
        with open(tfl, "rb") as fi, gzip.open(os.path.join(debug_out, "test_framework.log.gz"), "wb") as fo:
            shutil.copyfileobj(fi, fo)
    if exit_code == 0 and not os.environ.get("BCS_KEEP_WORK"):
        shutil.rmtree(a.work, ignore_errors=True)
    print("record.py: %s exit=%s checkpoints=%d skipped=%d unstable=%d" % (
        a.test, exit_code, REC.stats["checkpoints"], REC.stats["checkpoints_skipped"], REC.stats["unstable"]))
    sys.exit(0 if exit_code == 0 else 1)


if __name__ == "__main__":
    main()
