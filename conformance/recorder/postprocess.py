#!/usr/bin/env python3
"""Turn a raw capture written by record.py into corpus files (see CORPUS.md).

For each requested node the post-processor:

1. splits the node's debug.log into one segment per node session (start to
   start), and parses the lines that matter: message receipt, block receipt
   and outcome, block requests, peer versions, RPC dispatch, tip updates;
2. matches every recorded P2P send to the line where Core began processing it
   (per peer and message type, in order, checking payload sizes); sends Core
   never processed (connection already closed, payload that failed to
   deserialize) are dropped;
3. derives, for every block delivered over P2P, whether Core had the block in
   flight (requested) and the node clock at processing time (now) from the log;
4. orders the events between two checkpoints by the position of their log
   lines, which is the order Core processed them in, including blocks obtained
   from other bitcoind peers;
5. collapses repeated deliveries of byte-identical blocks whose outcome cannot
   depend on chain state (mutated blocks and context-free CheckBlock failures),
   which Core may re-request from a peer many times in a timing-dependent way;
6. writes meta, reset, block, headers, invalidate, restart and check events.
"""

import argparse
import calendar
import collections
import gzip
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blocklib  # noqa: E402

FORMAT = "bcs-block-corpus"
FORMAT_VERSION = 1
STATE_RPCS = {"submitblock", "submitheader", "generatetoaddress", "generatetodescriptor",
              "generateblock", "invalidateblock", "reconsiderblock", "preciousblock", "setmocktime"}
NOEFFECT_FAILS = blocklib.CHECKBLOCK_REASONS
DEFAULT_BLOB_THRESHOLD = 1_000_000  # raw bytes; larger blocks go to a sidecar blob
MAX_TIPS_EVERY_CHECK = 64
MACHINE_ARGS = ("-datadir=", "-bind=", "-uacomment=", "-rpcport=", "-port=")

LINE_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\.(\d+)Z(?: \(mocktime: (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)Z\))? \[([^\]]*)\] (.*)$")
RE_RECV = re.compile(r"\breceived: (\S+) \((\d+) bytes\) peer=(\d+)$")
RE_BLOCK = re.compile(r"\breceived block ([0-9a-f]{64}) peer=(\d+)")
RE_MUT = re.compile(r"Received mutated block from peer=(\d+)")
RE_FAIL = re.compile(r"ProcessNewBlock: AcceptBlock FAILED \(([^,)]*)")
RE_REQ = re.compile(r"Requesting block ([0-9a-f]{64})(?: \(\d+\))? (?:from )?peer=(\d+)")
RE_CLEAR = re.compile(r"Cleared nodestate for peer=(\d+)")
RE_VER = re.compile(r"receive version message: (.*?): version (\d+), .*peer=(\d+)")
RE_RPC = re.compile(r"ThreadRPCServer method=(\S+) user=")
RE_RECON = re.compile(r"Successfully reconstructed block ([0-9a-f]{64})")
RE_SAW = re.compile(r"Saw new (?:cmpctblock )?header hash=([0-9a-f]{64})")
RE_TIP = re.compile(r"UpdateTip: new best=([0-9a-f]{64}) height=(\d+)")
RE_EXC = re.compile(r"ProcessMessages\((\S+), (\d+) bytes\): (?:Exception|Unknown exception)")
RE_LOWWORK = re.compile(r"Ignoring low-work chain|missing anti-dos proof-of-work validation")


def iso_to_epoch(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%S"))


class LogLine:
    __slots__ = ("i", "ts", "mock", "thread", "msg")

    def __init__(self, i, ts, mock, thread, msg):
        self.i = i
        self.ts = ts
        self.mock = mock
        self.thread = thread
        self.msg = msg

    def now(self):
        """The node clock (NodeClock::now()) at this line, in whole seconds."""
        return self.mock if self.mock is not None else int(self.ts)


def parse_log_segment(text):
    out = []
    for raw in text.splitlines():
        m = LINE_RE.match(raw)
        if not m:
            continue
        ts = iso_to_epoch(m.group(1)) + int(m.group(2)) / 10 ** len(m.group(2))
        mock = iso_to_epoch(m.group(3)) if m.group(3) else None
        out.append(LogLine(len(out), ts, mock, m.group(4), m.group(5)))
    return out


class SessionLog:
    """Index of the debug.log lines of one node session."""

    def __init__(self, lines):
        self.lines = lines
        self.recv = collections.defaultdict(list)       # (peer, type) -> [line index]
        self.rpc = collections.defaultdict(list)        # method -> [line index]
        self.first_block_recv = {}                      # hash -> (index, peer)
        self.first_recon = {}
        self.first_saw = {}
        self.first_tip = {}
        self.subver = {}
        self.requested_at = {}                          # line index of "received block" -> bool
        self.lowwork = []
        inflight = collections.defaultdict(set)
        for ln in lines:
            msg = ln.msg
            if ln.thread == "msghand":
                m = RE_RECV.search(msg)
                if m:
                    self.recv[(int(m.group(3)), m.group(1))].append(ln.i)
                    continue
                m = RE_BLOCK.search(msg)
                if m:
                    h, p = m.group(1), int(m.group(2))
                    self.first_block_recv.setdefault(h, (ln.i, p))
                    self.requested_at[ln.i] = bool(inflight.get(h))
                    inflight[h].discard(p)
                    continue
                m = RE_REQ.search(msg)
                if m:
                    inflight[m.group(1)].add(int(m.group(2)))
                    continue
                m = RE_VER.search(msg)
                if m:
                    self.subver[int(m.group(3))] = m.group(1)
                    continue
            m = RE_CLEAR.search(msg)
            if m:
                p = int(m.group(1))
                for s in inflight.values():
                    s.discard(p)
                continue
            m = RE_RPC.search(msg)
            if m:
                self.rpc[m.group(1)].append(ln.i)
                continue
            m = RE_RECON.search(msg)
            if m:
                self.first_recon.setdefault(m.group(1), ln.i)
                continue
            m = RE_SAW.search(msg)
            if m:
                self.first_saw.setdefault(m.group(1), ln.i)
                continue
            m = RE_TIP.search(msg)
            if m:
                self.first_tip.setdefault(m.group(1), ln.i)
                continue
            if RE_LOWWORK.search(msg):
                self.lowwork.append(ln.i)

    def follow_block(self, recv_index, peer, want_hash):
        """After a "received: block" line, find whether the block was processed
        and how it ended. Returns (block_line_index or None, outcome)."""
        lines = self.lines
        j = recv_index + 1
        block_line = None
        while j < len(lines):
            ln = lines[j]
            if ln.thread == "msghand":
                if RE_RECV.search(ln.msg) or RE_EXC.search(ln.msg):
                    return None, "not-processed"
                m = RE_BLOCK.search(ln.msg)
                if m:
                    if int(m.group(2)) == peer and m.group(1) == want_hash:
                        block_line = j
                        break
                    return None, "not-processed"
            j += 1
        if block_line is None:
            return None, "not-processed"
        outcome = "ok"
        j = block_line + 1
        while j < len(lines):
            ln = lines[j]
            if ln.thread == "msghand":
                if RE_RECV.search(ln.msg):
                    break
                if RE_MUT.search(ln.msg):
                    outcome = "mutated"
                    break
                m = RE_FAIL.search(ln.msg)
                if m:
                    outcome = "failed:" + m.group(1)
                    break
            j += 1
        return block_line, outcome

    def headers_processed(self, recv_index):
        lines = self.lines
        j = recv_index + 1
        while j < len(lines):
            ln = lines[j]
            if ln.thread == "msghand":
                if RE_EXC.search(ln.msg):
                    return False
                if RE_RECV.search(ln.msg):
                    return True
            j += 1
        return True


def parse_options(args, conf):
    """Consensus-relevant options from bitcoind arguments and bitcoin.conf."""
    opts = {}
    warnings = []
    items = list(args)
    for line in (conf or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("[") and "=" in line:
            items.append("-" + line)
    for a in items:
        if a.startswith("-testactivationheight="):
            name, h = a.split("=", 1)[1].split("@")
            opts.setdefault("testactivationheight", {})[name] = int(h)
        elif a.startswith("-test="):
            v = a.split("=", 1)[1]
            if v == "bip94":
                opts.setdefault("test", [])
                if v not in opts["test"]:
                    opts["test"].append(v)
        elif a.startswith("-vbparams="):
            opts.setdefault("vbparams", []).append(a.split("=", 1)[1])
            warnings.append("uses -vbparams, which PROTOCOL.md chain_reset options do not define")
        elif a.split("=", 1)[0] in ("-assumevalid", "-minimumchainwork", "-signetchallenge", "-checkpoints"):
            warnings.append("consensus-adjacent option %s not represented" % a)
    return opts, warnings


def clean_args(args):
    out = []
    for a in args[1:]:
        if a.startswith(MACHINE_ARGS):
            continue
        out.append(a)
    return out


class Builder:
    def __init__(self, raw_dir, node, scenario, blob_dir, blob_rel, blob_threshold):
        self.raw_dir = raw_dir
        self.node = node
        self.scenario = scenario
        self.blob_dir = blob_dir
        self.blob_rel = blob_rel
        self.blob_threshold = blob_threshold
        self.stats = collections.Counter()
        self.warnings = []
        self.events = []
        self.run_start = None
        self.run_end = None
        self.raw = []
        events_path = os.path.join(raw_dir, "events.jsonl")
        opener = (lambda: gzip.open(events_path + ".gz", "rt")) if os.path.exists(events_path + ".gz") else (lambda: open(events_path))
        last_big = {}
        with opener() as f:
            for line in f:
                e = json.loads(line)
                if e["ev"] == "run_start":
                    self.run_start = e
                elif e["ev"] == "run_end":
                    self.run_end = e
                elif e.get("node") != node and e["ev"] not in ("node_start", "conn_open"):
                    continue
                if e["ev"] == "checkpoint":
                    self.reduce_tips(e, last_big)
                self.raw.append(e)
        log_path = os.path.join(raw_dir, "debug", "node%d.log.gz" % node)
        with gzip.open(log_path, "rb") as f:
            self.log_bytes = f.read()

    def warn(self, msg):
        self.warnings.append(msg)

    def reduce_tips(self, e, last_big):
        """Summarize a checkpoint's chain tips: a digest for deduplication, the
        tips that tie the active tip on work (for the restart rule), and the
        full list only where the corpus will keep it (small sets, and the last
        checkpoint of each session)."""
        tips = sorted(({"hash": t["hash"], "height": t["height"], "status": t["status"]} for t in e["tips"]),
                      key=lambda t: (-t["height"], t["hash"]))
        e["tips_digest"] = hashlib.sha256(json.dumps(tips, separators=(",", ":")).encode()).hexdigest()
        e["tie_candidates"] = [t["hash"] for t in e["tips"]
                               if t["status"] in ("valid-fork", "valid-headers") and t.get("chainwork") == e["chainwork"]]
        e["tips_count"] = len(tips)
        e["tips"] = tips
        if len(tips) > MAX_TIPS_EVERY_CHECK:
            prev = last_big.get(e["session"])
            if prev is not None:
                prev["tips"] = None
            last_big[e["session"]] = e

    def payload(self, e):
        if "hex" in e:
            return bytes.fromhex(e["hex"])
        with open(os.path.join(self.raw_dir, "payloads", e["payload"] + ".bin"), "rb") as f:
            return f.read()

    def block_event(self, raw, *, h, now, via, requested=None, source=None, outcome=None):
        ev = {"type": "block", "hash": h, "now": now, "via": via}
        if via == "p2p":
            ev["requested"] = bool(requested)
        try:
            block = blocklib.parse_block(raw)
        except blocklib.DecodeError as e:
            raise RuntimeError("block %s does not decode: %s" % (h, e))
        if block.trailing:
            self.warn("block %s carried %d trailing bytes, stripped" % (h, block.trailing))
            raw = raw[:len(raw) - block.trailing]
        if block.header.hash_hex() != h:
            raise RuntimeError("hash mismatch for %s" % h)
        if len(raw) > self.blob_threshold:
            sha = hashlib.sha256(raw).hexdigest()
            os.makedirs(self.blob_dir, exist_ok=True)
            path = os.path.join(self.blob_dir, sha + ".blk.gz")
            if not os.path.exists(path):
                with gzip.GzipFile(path, "wb", mtime=0) as f:
                    f.write(raw)
            ev["blob"] = self.blob_rel + "/" + sha + ".blk.gz"
            ev["sha256"] = sha
            ev["size"] = len(raw)
        else:
            ev["hex"] = raw.hex()
        ev["_source"] = source
        ev["_outcome"] = outcome
        ev["_sha"] = hashlib.sha256(raw).hexdigest()
        ev["_prev"] = block.header.prev_hex()
        return ev

    def build(self, racy=None):
        node = self.node
        sessions = [e for e in self.raw if e["ev"] == "node_start" and e["node"] == node]
        if not sessions:
            raise RuntimeError("node %d never started" % node)
        conns = {e["conn"]: e for e in self.raw if e["ev"] == "conn_open" and e["node"] == node}
        out = []
        noeffect_seen = set()
        prev_session_tip = None
        delivered = set()
        pending = collections.defaultdict(list)

        def emit(ev):
            # Blocks and headers from other peers carry no log line of their own
            # when they arrived inside a batch, so one may sort ahead of its
            # parent; hold it back until the parent has been delivered.
            if ev["type"] in ("block", "headers") and ev.get("_source") in ("peer", "peer-cmpct"):
                prev = ev["_prev"] if ev["type"] == "block" else blocklib.Header(bytes.fromhex(ev["headers"][0])).prev_hex()
                if prev not in delivered:
                    pending[prev].append(ev)
                    self.stats["bypass_reordered"] += 1
                    return
            out.append(ev)
            if ev["type"] == "block":
                hashes = [ev["hash"]]
            elif ev["type"] == "headers":
                hashes = [blocklib.Header(bytes.fromhex(x)).hash_hex() for x in ev["headers"]]
            else:
                return
            for h in hashes:
                delivered.add(h)
                for child in pending.pop(h, []):
                    emit(child)
        for si, sess in enumerate(sessions):
            sid = sess["session"]
            start = sess["log_offset"]
            end = sessions[si + 1]["log_offset"] if si + 1 < len(sessions) else len(self.log_bytes)
            log = SessionLog(parse_log_segment(self.log_bytes[start:end].decode("utf-8", "replace")))
            if log.lowwork:
                self.warn("session %d: Core logged low-work handling %d times" % (sid, len(log.lowwork)))
            items = []  # (segment, position, seq, sub, event)
            seg = 0
            segment_of = {}
            sess_raw = [e for e in self.raw if e.get("session") == sid and e.get("node") == node]
            for e in sess_raw:
                if e["ev"] == "checkpoint":
                    segment_of[e["seq"]] = seg
                    seg += 1
                else:
                    segment_of[e["seq"]] = seg
            framework_peers = {c["peer"] for c in conns.values() if c.get("session") == sid and c.get("peer") is not None}

            # P2P sends, matched to the log per (peer, type).
            per_key = collections.defaultdict(list)
            for e in sess_raw:
                if e["ev"] == "p2p":
                    c = conns.get(e["conn"])
                    if c is None or c.get("peer") is None:
                        self.warn("send seq %d on unresolved connection %s dropped" % (e["seq"], e["conn"]))
                        self.stats["p2p_unresolved"] += 1
                        continue
                    per_key[(c["peer"], e["type"])].append(e)
            for (peer, mtype), sends in per_key.items():
                lines = log.recv.get((peer, mtype), [])
                if len(lines) > len(sends):
                    raise RuntimeError("session %d peer %d: %d %s lines in debug.log but only %d recorded sends"
                                       % (sid, peer, len(lines), mtype, len(sends)))
                for k, e in enumerate(sends):
                    if k >= len(lines):
                        self.stats["p2p_not_processed"] += 1
                        continue
                    li = lines[k]
                    m = RE_RECV.search(log.lines[li].msg)
                    if int(m.group(2)) != e["size"]:
                        raise RuntimeError("size mismatch aligning %s sends on peer %d (seq %d: %d vs %s)"
                                           % (mtype, peer, e["seq"], e["size"], m.group(2)))
                    payload = self.payload(e)
                    if mtype == "block":
                        bl, outcome = log.follow_block(li, peer, e["hash"])
                        if bl is None:
                            self.stats["p2p_not_processed"] += 1
                            continue
                        ln = log.lines[bl]
                        ev = self.block_event(payload, h=e["hash"], now=ln.now(), via="p2p",
                                              requested=log.requested_at.get(bl), source="framework", outcome=outcome)
                        if e.get("req_model") is not None and bool(e["req_model"]) != bool(log.requested_at.get(bl)):
                            self.stats["requested_model_disagreements"] += 1
                        items.append((segment_of[e["seq"]], bl, e["seq"], 0, ev))
                    elif mtype == "headers":
                        if not log.headers_processed(li):
                            self.stats["p2p_not_processed"] += 1
                            continue
                        r = blocklib.Reader(payload)
                        hdrs = []
                        for _ in range(r.compact()):
                            hdrs.append(r.read(80).hex())
                            r.compact()
                        if not hdrs:
                            self.stats["empty_headers_dropped"] += 1
                            continue
                        ev = {"type": "headers", "now": log.lines[li].now(), "via": "p2p", "headers": hdrs}
                        items.append((segment_of[e["seq"]], li, e["seq"], 0, ev))
                    else:
                        raise RuntimeError("unsupported framework message %s (seq %d)" % (mtype, e["seq"]))

            # RPC events, matched to "ThreadRPCServer method=" lines.
            rpcs = [e for e in sess_raw if e["ev"] == "rpc"]
            by_method = collections.defaultdict(list)
            for e in rpcs:
                by_method[e["method"]].append(e)
            rpc_pos = {}
            for mth, evs in by_method.items():
                lines = log.rpc.get(mth, [])
                if len(lines) != len(evs):
                    self.warn("session %d: %d %s calls recorded, %d in debug.log; using record order"
                              % (sid, len(evs), mth, len(lines)))
                    continue
                for e, li in zip(evs, lines):
                    rpc_pos[e["seq"]] = li
            last_pos = -1
            for e in sess_raw:
                if e["seq"] in rpc_pos:
                    last_pos = rpc_pos[e["seq"]]
                elif e["ev"] == "rpc":
                    rpc_pos[e["seq"]] = last_pos
            for e in rpcs:
                pos = rpc_pos[e["seq"]]
                line = log.lines[pos] if 0 <= pos < len(log.lines) else None
                now = line.now() if line is not None else e["now"]
                m = e["method"]
                if m == "submitblock":
                    if not e["ok"] or ("hex" not in e and "payload" not in e):
                        if e.get("decode_error") and e["ok"]:
                            self.warn("submitblock seq %d: Core decoded a block this recorder could not" % e["seq"])
                        continue
                    ev = self.block_event(self.payload(e), h=e["hash"], now=now, via="rpc",
                                          source="submitblock", outcome=e.get("result"))
                    if e.get("updated"):
                        ev["_note"] = "coinbase witness reserved value added as submitblock does"
                        self.stats["submitblock_updated"] += 1
                    items.append((segment_of[e["seq"]], pos, e["seq"], 0, ev))
                elif m == "submitheader":
                    if "header" not in e:
                        continue
                    if not e["ok"] and "decode failed" in e.get("error", ""):
                        continue
                    ev = {"type": "headers", "now": now, "via": "rpc", "headers": [e["header"]]}
                    items.append((segment_of[e["seq"]], pos, e["seq"], 0, ev))
                elif m in ("generatetoaddress", "generatetodescriptor", "generateblock"):
                    for k, b in enumerate(e.get("blocks", [])):
                        tl = log.first_tip.get(b["hash"])
                        bnow = log.lines[tl].now() if tl is not None else e.get("now_end", now)
                        ev = self.block_event(self.payload(b), h=b["hash"], now=bnow, via="rpc",
                                              source="mined", outcome=None)
                        items.append((segment_of[e["seq"]], pos, e["seq"], k, ev))
                elif m == "invalidateblock":
                    if e["ok"]:
                        items.append((segment_of[e["seq"]], pos, e["seq"], 0,
                                      {"type": "invalidate", "now": now, "hash": e["hash"]}))
                elif m in ("reconsiderblock", "preciousblock"):
                    if e["ok"]:
                        self.warn("%s used; not part of PROTOCOL.md v1" % m)
                        items.append((segment_of[e["seq"]], pos, e["seq"], 0,
                                      {"type": "reconsider" if m == "reconsiderblock" else "precious",
                                       "now": now, "hash": e["hash"]}))

            # Blocks and headers that reached the node another way.
            for e in sess_raw:
                if e["ev"] != "bypass":
                    continue
                h = e["hash"]
                if e["kind"] == "block":
                    if h in log.first_block_recv:
                        li, peer = log.first_block_recv[h]
                        if peer in framework_peers:
                            self.warn("bypass block %s was received from a framework peer" % h)
                        ev = self.block_event(self.payload(e), h=h, now=log.lines[li].now(), via="p2p",
                                              requested=log.requested_at.get(li), source="peer")
                        pos = li
                    elif h in log.first_recon:
                        li = log.first_recon[h]
                        ev = self.block_event(self.payload(e), h=h, now=log.lines[li].now(), via="p2p",
                                              requested=True, source="peer-cmpct")
                        pos = li
                    else:
                        # Present at node start: the pre-mined chain cache. Delivered in height order.
                        ev = self.block_event(self.payload(e), h=h, now=e["now"], via="rpc", source="preload")
                        pos = -1
                        self.stats["preload_blocks"] += 1
                    self.stats["bypass_blocks"] += 1
                    items.append((segment_of[e["seq"]], pos, e["seq"], 0, ev))
                else:
                    li = log.first_saw.get(h)
                    now = log.lines[li].now() if li is not None else e["now"]
                    ev = {"type": "headers", "now": now, "via": "p2p", "headers": [self.payload(e).hex()], "_source": "peer"}
                    self.stats["bypass_headers"] += 1
                    items.append((segment_of[e["seq"]], li if li is not None else 10 ** 9, e["seq"], 0, ev))

            # Checkpoints close their segment.
            for e in sess_raw:
                if e["ev"] == "checkpoint":
                    ev = {"type": "check", "label": e["label"], "tip": e["best"], "height": e["height"],
                          "tips": e["tips"], "_digest": e["tips_digest"], "_ties": e["tie_candidates"],
                          "_count": e["tips_count"], "_stable": e["stable"]}
                    if e.get("utxo"):
                        ev["utxo"] = e["utxo"]
                    items.append((segment_of[e["seq"]], 10 ** 10, e["seq"], 0, ev))

            items.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
            delivered.add(sess["genesis"])
            if si == 0:
                opts, warns = parse_options(sess["args"], sess["conf"])
                for w in warns:
                    self.warn(w)
                out.append({"type": "reset", "network": "regtest", "options": opts,
                            "args": clean_args(sess["args"]), "genesis": sess["genesis"]})
            else:
                opts, warns = parse_options(sess["args"], sess["conf"])
                for w in warns:
                    self.warn(w)
                rnow = sess["mocktime"] if sess.get("mocktime") else int(sess["t"])
                out.append({"type": "restart", "now": rnow, "options": opts, "args": clean_args(sess["args"]),
                            "_prev_tip": prev_session_tip})
            for _, _, _, _, ev in items:
                if ev["type"] == "block" and ev.get("_source") == "framework":
                    oc = ev.get("_outcome") or ""
                    if oc == "mutated" or (oc.startswith("failed:") and oc[7:] in NOEFFECT_FAILS):
                        key = (ev["_sha"], oc)
                        if key in noeffect_seen:
                            self.stats["repeat_noeffect_collapsed"] += 1
                            continue
                        noeffect_seen.add(key)
                emit(ev)
            for waiting in list(pending.values()):
                for ev in waiting:
                    self.warn("a block or header from another peer never had its parent delivered")
                    out.append(ev)
            pending.clear()
            last_checks = [ev for _, _, _, _, ev in items if ev["type"] == "check"]
            if last_checks:
                prev_session_tip = last_checks[-1]["tip"]
        self.events = self.finish(out, racy or set())
        return self.events

    def finish(self, out, racy):
        """Drop redundant checks, mark non-normative ones, strip private fields."""
        result = []
        last_check = None
        since_restart = False
        events_since_check = 0
        check_no = 0
        for ev in out:
            t = ev["type"]
            if t == "restart":
                since_restart = True
            if t != "check":
                events_since_check += 1
                result.append(ev)
                continue
            same = (last_check is not None and events_since_check == 0 and last_check["tip"] == ev["tip"]
                    and last_check["height"] == ev["height"] and last_check["_digest"] == ev["_digest"])
            if same:
                if "utxo" in ev and "utxo" not in last_check:
                    last_check["utxo"] = ev["utxo"]
                if last_check["tips"] is None and ev["tips"] is not None:
                    last_check["tips"] = ev["tips"]
                if not ev["_stable"]:
                    last_check["_stable"] = False
                continue
            ev["normative"] = True
            why = []
            if not ev["_stable"]:
                why.append("chain state changed while the checkpoint was read")
            if since_restart and ev["_ties"]:
                why.append("after a restart, %s ties the active tip on work; Core breaks such ties "
                           "between blocks loaded from disk by memory address" % ev["_ties"][0])
            check_no += 1
            ev["n"] = check_no
            if check_no in racy:
                why.append("differed between two recordings with the same seeds")
            if why:
                ev["normative"] = False
                ev["why"] = "; ".join(why)
            result.append(ev)
            last_check = ev
            events_since_check = 0
        # Level 1: the full tip set is kept where it is small, on the last check
        # before every restart, and on the final check. (Every block a test
        # gets rejected stays a chain tip, so the set can grow to thousands.)
        for i, ev in enumerate(result):
            if ev["type"] != "check":
                continue
            if ev["tips"] is not None and ev["_count"] <= MAX_TIPS_EVERY_CHECK:
                continue
            nxt = next((x for x in result[i + 1:] if x["type"] != "check"), None)
            later_check = any(x["type"] == "check" for x in result[i + 1:])
            keep = not later_check or (nxt is not None and nxt["type"] == "restart")
            if keep and ev["tips"] is None:
                raise RuntimeError("check %d lost its chain tips" % ev["n"])
            if not keep:
                del ev["tips"]
        clean = []
        for ev in result:
            clean.append({k: v for k, v in ev.items() if not k.startswith("_")})
        return clean


def write_corpus(path, meta, events):
    tmp = path + ".tmp"
    with open(tmp, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as f:
            f.write((json.dumps(meta, separators=(",", ":"), sort_keys=True) + "\n").encode())
            for ev in events:
                f.write((json.dumps(ev, separators=(",", ":")) + "\n").encode())
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw", required=True, help="raw capture directory written by record.py")
    ap.add_argument("--scenario", required=True, help="scenario name, e.g. feature_block")
    ap.add_argument("--out-dir", required=True, help="corpus directory (vectors/blocks)")
    ap.add_argument("--nodes", default="0", help="comma separated node indexes")
    ap.add_argument("--racy", help="JSON file from compare_runs.py: {\"<scenario>.node<i>\": [check numbers]}")
    ap.add_argument("--blob-threshold", type=int, default=DEFAULT_BLOB_THRESHOLD)
    ap.add_argument("--stats", help="append a JSON summary line to this file")
    a = ap.parse_args()

    racy_all = {}
    if a.racy and os.path.exists(a.racy):
        with open(a.racy) as f:
            racy_all = json.load(f)
    os.makedirs(a.out_dir, exist_ok=True)
    for node in [int(x) for x in a.nodes.split(",")]:
        name = "%s.node%d" % (a.scenario, node)
        b = Builder(a.raw, node, a.scenario, os.path.join(a.out_dir, "blobs"), "blobs", a.blob_threshold)
        events = b.build(set(racy_all.get(name, [])))
        rs = b.run_start
        if b.run_end is None or b.run_end.get("exit_code") != 0:
            raise SystemExit("%s: the recorded test did not pass (exit %s)" % (name, b.run_end and b.run_end.get("exit_code")))
        counts = collections.Counter(ev["type"] for ev in events)
        checks = [ev for ev in events if ev["type"] == "check"]
        meta = {
            "type": "meta", "format": FORMAT, "format_version": FORMAT_VERSION,
            "scenario": a.scenario, "node": node,
            "source": {"test": "test/functional/" + rs["test"], "test_sha256": rs["test_sha256"],
                       "test_args": [x for x in rs["argv"] if not x.startswith(("--cachedir=", "--tmpdir=", "--configfile="))]},
            "core": {"version": rs["core"]["version"], "commit": rs["core"]["commit"],
                     "bitcoind_sha256": rs["bitcoind_sha256"], "release_tarball_sha256": rs["tarball_sha256"]},
            "recorder": {"base_image": rs["base_image"], "image_id": rs["image"], "python": rs["python"],
                         "framework_sha256": rs["framework_sha256"]},
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(rs["t"])),
            "counts": {"events": len(events), "blocks": counts["block"], "headers": counts["headers"],
                       "invalidate": counts["invalidate"], "restart": counts["restart"],
                       "checks": len(checks), "normative_checks": sum(1 for c in checks if c["normative"])},
            "notes": sorted(set(b.warnings)),
        }
        path = os.path.join(a.out_dir, name + ".jsonl.gz")
        write_corpus(path, meta, events)
        summary = {"scenario": name, "file": os.path.basename(path), "bytes": os.path.getsize(path),
                   "counts": meta["counts"], "stats": dict(b.stats), "notes": meta["notes"]}
        print(json.dumps(summary))
        if a.stats:
            with open(a.stats, "a") as f:
                f.write(json.dumps(summary) + "\n")


if __name__ == "__main__":
    main()
