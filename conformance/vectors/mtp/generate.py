"""Writes median-time-past.jsonl.gz: a regtest scenario in the corpus format (CORPUS.md) whose
blocks are decided by the median time past of fewer than 11 blocks.

Usage: python3 generate.py <out.jsonl.gz>

Near genesis the window has fewer than 11 timestamps, and for an even count chapter 09 section 9.4
takes the upper of the two middle ones (Core: `pbegin[(pend - pbegin) / 2]`). The recorded corpus
never delivers a block that depends on which middle one is taken. Here blocks 1 to 10 come every
100 seconds. Before each block at heights 2, 4, 6, 8 and 10, whose parent's window has 2, 4, 6, 8
and 10 timestamps, comes a block dated between the two middle ones. It is above the lower median,
so taking that one accepts it, and not above the upper median, so Bitcoin Core rejects it
(`time-too-old`) and the tip must stay where it was.

Blocks hold only a coinbase and regtest's target is met by about half of all nonces, so the file
is written in well under a second. Every block takes the smallest nonce that meets its target, so
the file is the same on every run. Replaying it through `conformance/recorder/core_chain_harness.py`
(README.md) confirms the checks against Bitcoin Core.
"""

import gzip
import hashlib
import json
import sys

GENESIS_HASH = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
GENESIS_TIME = 1296688602
BITS = 0x207FFFFF
TARGET = (BITS & 0x7FFFFF) << 8 * ((BITS >> 24) - 3)
MEDIAN_TIME_SPAN = 11
SPACING = 100
TOP = 10


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def coinbase(height, tag):
    """A coinbase with the BIP34 height (OP_1 to OP_16), a tag that keeps it at least two bytes
    long and different between blocks at one height, and one OP_TRUE output of zero."""
    assert 1 <= height <= 16 and len(tag) < 0x4C
    script_sig = bytes([0x50 + height, len(tag)]) + tag
    raw = (1).to_bytes(4, "little") + b"\x01" + bytes(32) + b"\xff\xff\xff\xff"
    raw += bytes([len(script_sig)]) + script_sig + b"\xff\xff\xff\xff"
    raw += b"\x01" + bytes(8) + b"\x01\x51" + bytes(4)
    return sha256d(raw), raw


def mine(prefix):
    """The smallest nonce that completes `prefix` (the first 76 bytes of a header)."""
    for nonce in range(1 << 32):
        header = prefix + nonce.to_bytes(4, "little")
        if int.from_bytes(sha256d(header), "little") <= TARGET:
            return header
    raise RuntimeError("no nonce")


def main():
    out = sys.argv[1]
    events = [{"type": "reset", "network": "regtest", "options": {}, "genesis": GENESIS_HASH}]
    checks = []
    # Timestamps of the active chain, from genesis up.
    times = [GENESIS_TIME]
    tip = GENESIS_HASH

    def block(time, tag):
        height = len(times)
        txid, cb = coinbase(height, tag)
        prefix = (0x20000000).to_bytes(4, "little") + bytes.fromhex(tip)[::-1] + txid
        prefix += time.to_bytes(4, "little") + BITS.to_bytes(4, "little")
        header = mine(prefix)
        h = sha256d(header)[::-1].hex()
        # `now` an hour after the block: never too far in the future, and the same on every run.
        events.append({"type": "block", "hash": h, "hex": (header + b"\x01" + cb).hex(), "now": time + 3600,
                       "via": "rpc"})
        return h

    def check(label):
        checks.append(tip)
        height = len(times) - 1
        events.append({"type": "check", "n": len(checks), "label": label, "normative": True,
                       "tip": tip, "height": height, "tips": [{"hash": tip, "height": height, "status": "active"}]})

    check("genesis")
    for height in range(1, TOP + 1):
        window = sorted(times[-MEDIAN_TIME_SPAN:])
        if len(window) % 2 == 0:
            lower, upper = window[len(window) // 2 - 1], window[len(window) // 2]
            between = (lower + upper) // 2
            assert lower < between <= upper
            block(between, b"between")
            check("block %d dated %d, between the two middle timestamps of %d: rejected (time-too-old)"
                  % (height, between, len(window)))
        tip = block(GENESIS_TIME + height * SPACING, b"mtp")
        times.append(GENESIS_TIME + height * SPACING)
        check("block %d: accepted" % height)

    blocks = sum(1 for e in events if e["type"] == "block")
    meta = {"type": "meta", "format": "bcs-block-corpus", "format_version": 1, "scenario": "median-time-past",
            "node": 0, "source": {"path": "conformance/vectors/mtp/generate.py"},
            "notes": "Synthetic: regtest blocks decided by the upper median of an even number of timestamps. "
                     "Expectations confirmed against Bitcoin Core v32.1 (core_chain_harness.py).",
            "counts": {"events": len(events), "blocks": blocks, "headers": 0, "invalidate": 0,
                       "restart": 0, "checks": len(checks), "normative_checks": len(checks)}}
    # No file name or time in the gzip header, so that a run gives the same bytes wherever it writes.
    with open(out, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as f:
        for e in [meta] + events:
            f.write((json.dumps(e, separators=(",", ":")) + "\n").encode())


if __name__ == "__main__":
    main()
