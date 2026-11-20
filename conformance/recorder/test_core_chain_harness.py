"""The request loop of core_chain_harness.py, with a stub in place of bitcoind.

Run: python3 -m unittest discover -s conformance/recorder
"""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core_chain_harness as harness  # noqa: E402


class StubNode:
    """Answers the RPCs chain_reset and chain_tip make, with a genesis named after the network."""

    def __init__(self, network, options):
        self.genesis = "genesis-" + network

    def call(self, method, *params):
        if method == "getblockhash":
            return self.genesis
        if method == "getblockchaininfo":
            return {"bestblockhash": self.genesis, "blocks": 0, "chainwork": "00"}
        raise AssertionError("unexpected RPC %s" % method)

    def tip(self):
        return self.call("getblockchaininfo")

    def stop(self):
        pass


def reject_constant(name):
    raise ValueError("%s is not JSON" % name)


def run(lines):
    stdin = io.TextIOWrapper(io.BytesIO(b"".join(line + b"\n" for line in lines)))
    stdout = io.StringIO()
    with mock.patch.object(harness, "Node", StubNode), mock.patch.object(sys, "stdin", stdin), \
            mock.patch.object(sys, "stdout", stdout), mock.patch.object(harness, "log"):
        try:
            harness.main()
        except SystemExit as e:
            assert e.code == 0, e.code
    return [json.loads(line, parse_constant=reject_constant) for line in stdout.getvalue().splitlines()]


class RequestIdTest(unittest.TestCase):
    def test_requests_without_an_integer_id_do_not_run(self):
        signet = b'"op":"chain_reset","network":"signet","options":{"signetchallenge":"51"}'
        cases = [
            (b'{"id":1,"op":"chain_reset","network":"regtest"}', 1),
            (b"{" + signet + b"}", None),
            (b'{"id":null,' + signet + b"}", None),
            (b'{"id":"2",' + signet + b"}", None),
            (b'{"id":true,' + signet + b"}", None),
            (b'{"id":2.0,' + signet + b"}", None),
            (b'{"id":2.5,' + signet + b"}", None),
            (b'{"id":9223372036854775808,' + signet + b"}", None),
            (b'{"id":NaN,' + signet + b"}", None),
            (b'{"id":NaN,"id":2,' + signet + b"}", None),
            (b'{"id":1e400,"op":"chain_tip"}', None),
            (b'{"id":3,"op":"chain_tip","x":"\xff"}', None),
            (b"[1]", None),
            (b"[" * 100000, None),
            (b"not json", None),
            (b'{"id":-9223372036854775808,"op":"chain_tip"}', -9223372036854775808),
        ]
        responses = run([line for line, _ in cases])
        self.assertEqual(len(responses), len(cases))
        for (line, rid), resp in zip(cases, responses):
            self.assertEqual(resp["id"], rid, line)
            if rid is None:
                self.assertIs(resp["ok"], False, line)
                self.assertEqual(resp["error"], "bad_request", line)
            else:
                self.assertIs(resp["ok"], True, resp)
        self.assertEqual(responses[-1]["tip"], "genesis-regtest", "the chain changed after the regtest reset")

    def test_blank_lines_get_no_response(self):
        responses = run([b"", b"  ", b'{"id":1,"op":"chain_reset","network":"regtest"}', b""])
        self.assertEqual([r["id"] for r in responses], [1])


if __name__ == "__main__":
    unittest.main()
