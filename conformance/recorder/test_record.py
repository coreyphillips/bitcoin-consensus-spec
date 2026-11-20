"""record.py's block index walk with a fake RPC, and what postprocess.py refuses.

Run: python3 -m unittest discover -s conformance/recorder
"""

import gzip
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import postprocess  # noqa: E402
import record  # noqa: E402

GENESIS = "00" * 32


class FakeIndex:
    """A block index answering getblockheader and getblock, counting header lookups."""

    def __init__(self):
        self.entries = {GENESIS: {"height": 0, "prev": None, "ntx": 1}}
        self.header_calls = 0

    def add(self, h, prev, ntx):
        self.entries[h] = {"height": self.entries[prev]["height"] + 1, "prev": prev, "ntx": ntx}

    def getblockheader(self, h, verbose=True):
        e = self.entries[h]
        if not verbose:
            return "header-" + h
        self.header_calls += 1
        out = {"height": e["height"], "chainwork": "%064x" % (2 * e["height"] + 2), "nTx": e["ntx"]}
        if e["prev"] is not None:
            out["previousblockhash"] = e["prev"]
        return out

    def getblock(self, h, verbosity):
        assert self.entries[h]["ntx"] > 0, "getblock on a header-only entry"
        return "block-" + h


def name(c):
    return c * 64


class WalkTest(unittest.TestCase):
    def setUp(self):
        self.rec = record.Recorder()
        self.rec.f = io.StringIO()
        self.index = FakeIndex()
        self.ns = record.NodeState(0, "/nonexistent")
        self.ns.complete.add(GENESIS)
        self.ns.known_block.add(GENESIS)
        self.ns.known_header.add(GENESIS)
        self.rec.nodes[0] = self.ns
        self.session = record.Session(1, 0, [], "", 0, None)
        self.session.rpc = self.index

    def walk(self, *tips):
        return [(kind, h) for kind, h, _ in
                self.rec.walk(self.ns, self.session, [{"hash": h, "status": st} for h, st in tips])]

    def test_block_after_its_header(self):
        a, b = name("a"), name("b")
        self.index.add(a, GENESIS, 0)
        self.index.add(b, a, 0)
        self.assertEqual(self.walk((b, "headers-only")), [("header", a), ("header", b)])
        self.index.entries[a]["ntx"] = 1
        self.index.entries[b]["ntx"] = 1
        self.assertEqual(self.walk((b, "active")), [("block", a), ("block", b)])
        calls = self.index.header_calls
        self.assertEqual(self.walk((b, "active")), [])
        self.assertEqual(self.index.header_calls, calls)

    def test_parent_block_after_child_block(self):
        a, b = name("a"), name("b")
        self.index.add(a, GENESIS, 0)
        self.index.add(b, a, 1)
        self.assertEqual(self.walk((b, "headers-only")), [("header", a), ("block", b)])
        self.index.entries[a]["ntx"] = 1
        self.assertEqual(self.walk((b, "active")), [("block", a)])

    def test_invalid_tip_is_not_walked_again(self):
        a, bad = name("a"), name("c")
        self.index.add(a, GENESIS, 1)
        self.index.add(bad, a, 0)
        self.assertEqual(self.walk((a, "active"), (bad, "invalid")), [("block", a), ("header", bad)])
        calls = self.index.header_calls
        self.assertEqual(self.walk((a, "active"), (bad, "invalid")), [])
        self.assertEqual(self.index.header_calls, calls)

    def test_reconsiderblock_walks_invalid_tips_again(self):
        bad = name("c")
        self.index.add(bad, GENESIS, 0)
        self.assertEqual(self.walk((bad, "invalid")), [("header", bad)])
        self.rec.post_rpc(self.session, "reconsiderblock", (bad,), {}, {}, True, None, None, 0, 0, True)
        self.index.entries[bad]["ntx"] = 1
        self.assertEqual(self.walk((bad, "active")), [("block", bad)])


class PostprocessTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.raw = self.dir.name
        os.makedirs(os.path.join(self.raw, "debug"))
        with gzip.open(os.path.join(self.raw, "debug", "node0.log.gz"), "wb"):
            pass

    def tearDown(self):
        self.dir.cleanup()

    def capture(self, *events, unpinned=()):
        start = {"ev": "run_start", "test": "t.py", "test_path": "test/functional/t.py", "argv": [],
                 "test_sha256": "", "framework_sha256": {}, "unpinned": list(unpinned),
                 "bitcoind_sha256": "", "tarball_sha256": "", "image": "", "base_image": "", "python": "",
                 "platform": "", "core": {"version": "32.1", "commit": ""}}
        node = {"ev": "node_start", "node": 0, "session": 1, "args": [], "conf": "", "log_offset": 0,
                "mocktime": None, "genesis": GENESIS}
        evs = [start, node] + list(events) + [{"ev": "run_end", "exit_code": 0}]
        with open(os.path.join(self.raw, "events.jsonl"), "w") as f:
            for seq, e in enumerate(evs):
                f.write(json.dumps(dict(e, seq=seq, t=1.0)) + "\n")

    def build(self):
        return postprocess.Builder(self.raw, 0, "t", os.path.join(self.raw, "blobs"), "blobs", 10 ** 6).build()

    def test_unsupported_rpc_is_refused(self):
        for node in (0, None):
            self.capture({"ev": "unsupported_rpc", "node": node, "session": 1, "method": "loadtxoutset", "ok": True})
            with self.assertRaisesRegex(RuntimeError, "loadtxoutset"):
                self.build()

    def test_failed_or_other_node_unsupported_rpc_is_ignored(self):
        self.capture({"ev": "unsupported_rpc", "node": 0, "session": 1, "method": "loadtxoutset", "ok": False},
                     {"ev": "unsupported_rpc", "node": 1, "session": 2, "method": "importblocks", "ok": True})
        self.assertEqual([e["type"] for e in self.build()], ["reset"])

    def test_reconsider_and_precious_are_refused(self):
        for method in ("reconsiderblock", "preciousblock"):
            self.capture({"ev": "rpc", "node": 0, "session": 1, "method": method, "ok": True, "now": 1,
                          "hash": name("a")})
            with self.assertRaisesRegex(RuntimeError, method):
                self.build()

    def meta(self):
        out = os.path.join(self.raw, "out")
        argv = ["postprocess.py", "--raw", self.raw, "--scenario", "t", "--out-dir", out]
        with mock.patch.object(sys, "argv", argv), mock.patch("sys.stdout", io.StringIO()):
            postprocess.main()
        with gzip.open(os.path.join(out, "t.node0.jsonl.gz"), "rt") as f:
            return json.loads(f.readline())

    def test_unpinned_files_reach_the_meta(self):
        self.capture(unpinned=["test_framework/util.py: aa != pinned bb"])
        self.assertEqual(self.meta()["recorder"]["unpinned"], ["test_framework/util.py: aa != pinned bb"])

    def test_pinned_recording_has_no_unpinned_field(self):
        self.capture()
        self.assertNotIn("unpinned", self.meta()["recorder"])


if __name__ == "__main__":
    unittest.main()
