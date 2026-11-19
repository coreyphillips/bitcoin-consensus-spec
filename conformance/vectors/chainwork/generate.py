"""Writes most-work.jsonl.gz: a scenario in the corpus format (CORPUS.md) in which the chain with
the most work is not the longest one.

Usage: python3 generate.py <out.jsonl.gz> [workers] [nonce-cache]

Every block of the regtest corpus has the same work, so there the longest chain always has the most
work. Here the network is a custom signet whose challenge is OP_TRUE (no block needs a signature)
and blocks carry real proof of work. The first 2,014 blocks come every 100 seconds, so the block
at height 2,016 retargets to a quarter of the target (four times the work) when block 2,015 keeps
that pace (branch a), and keeps the target when block 2,015 is dated two weeks after genesis
(branch b). Branch b is delivered first and grows to height 2,018; branch a, two blocks shorter,
then has more work and must become the tip. Two more blocks on branch b give it more work again.

Mining takes about 10^10 double SHA256 hashes. Nonces found are appended to the nonce cache file,
if one is named, so an interrupted run resumes where it stopped. The script asserts that the
branches compare by height and work as intended; replaying the file through
`conformance/recorder/core_chain_harness.py` (README.md) confirms the checks against Bitcoin Core.
"""

import gzip
import hashlib
import json
import multiprocessing
import os
import struct
import sys

GENESIS_HASH = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
GENESIS_TIME = 1598918400
POW_LIMIT = 0x00000377AE000000000000000000000000000000000000000000000000000000
TIMESPAN = 14 * 24 * 60 * 60
INTERVAL = 2016
SPACING = 100
CHALLENGE = "51"
CHUNK = 1 << 16


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n):
    assert n < 0xFD
    return bytes([n])


def var_bytes(b):
    return compact_size(len(b)) + b


def script_num(n):
    """CScript() << n for a block height."""
    if n == 0:
        return b"\x00"
    if n <= 16:
        return bytes([0x50 + n])
    out = n.to_bytes((n.bit_length() + 8) // 8, "little")
    return bytes([len(out)]) + out


def compact_to_target(bits):
    size, word = bits >> 24, bits & 0x007FFFFF
    return word >> 8 * (3 - size) if size <= 3 else word << 8 * (size - 3)


def target_to_compact(target):
    size = (target.bit_length() + 7) // 8
    word = target << 8 * (3 - size) if size <= 3 else target >> 8 * (size - 3)
    if word & 0x00800000:
        word >>= 8
        size += 1
    return size << 24 | word


def block_proof(bits):
    target = compact_to_target(bits)
    return (1 << 256) // (target + 1)


GENESIS_BITS = target_to_compact(POW_LIMIT)
assert GENESIS_BITS == 0x1E0377AE


def coinbase(height, tag):
    """A coinbase with the BIP34 height, a branch tag, an OP_TRUE output and the witness
    commitment of a block with no other transaction (BIP141), which a signet block needs even
    without a solution."""
    commitment = sha256d(bytes(32) + bytes(32))
    script_sig = script_num(height) + var_bytes(tag)
    outputs = [(0, bytes.fromhex("51")), (0, bytes.fromhex("6a24aa21a9ed") + commitment)]
    body = compact_size(1) + bytes(32) + b"\xff\xff\xff\xff" + var_bytes(script_sig) + b"\xff\xff\xff\xff"
    body += compact_size(len(outputs)) + b"".join(v.to_bytes(8, "little") + var_bytes(s) for v, s in outputs)
    version, lock_time = (1).to_bytes(4, "little"), bytes(4)
    txid = sha256d(version + body + lock_time)
    full = version + b"\x00\x01" + body + b"\x01" + var_bytes(bytes(32)) + lock_time
    return txid, full


def search(args):
    """The smallest nonce in [start, start + CHUNK) that meets the target, or None."""
    prefix, target, start = args
    mid = hashlib.sha256(prefix[:64])
    tail = bytearray(prefix[64:] + bytes(4))
    for nonce in range(start, min(start + CHUNK, 1 << 32)):
        struct.pack_into("<I", tail, 12, nonce)
        h = mid.copy()
        h.update(tail)
        d = hashlib.sha256(h.digest()).digest()
        if d[31] == 0 and int.from_bytes(d, "little") <= target:
            return nonce
    return None


class Miner:
    def __init__(self, workers, cache):
        self.pool = multiprocessing.Pool(workers)
        self.workers = workers
        self.cache, self.found = cache, {}
        if cache and os.path.exists(cache):
            with open(cache) as f:
                self.found = dict(line.split() for line in f)

    def mine(self, prefix, target):
        """The smallest nonce that completes `prefix` (the first 76 bytes of a header)."""
        if prefix.hex() in self.found:
            return int(self.found[prefix.hex()])
        start = 0
        while start < 1 << 32:
            batch = [(prefix, target, start + i * CHUNK) for i in range(self.workers)]
            for nonce in self.pool.imap(search, batch):
                if nonce is not None:
                    if self.cache:
                        with open(self.cache, "a") as f:
                            f.write("%s %d\n" % (prefix.hex(), nonce))
                    return nonce
            start += len(batch) * CHUNK
        raise RuntimeError("no nonce")


class Chain:
    """Header data of every block made so far, for the next block's bits and the checks."""

    def __init__(self):
        self.entries = {GENESIS_HASH: {"height": 0, "time": GENESIS_TIME, "bits": GENESIS_BITS,
                                       "prev": None, "work": block_proof(GENESIS_BITS)}}

    def ancestor(self, h, height):
        while self.entries[h]["height"] > height:
            h = self.entries[h]["prev"]
        return h

    def next_bits(self, parent):
        """Chapter 09 section 9.5 on signet: no minimum-difficulty blocks, retarget every 2,016."""
        p = self.entries[parent]
        if (p["height"] + 1) % INTERVAL:
            return p["bits"]
        first = self.entries[self.ancestor(parent, p["height"] - (INTERVAL - 1))]
        actual = min(max(p["time"] - first["time"], TIMESPAN // 4), TIMESPAN * 4)
        target = compact_to_target(p["bits"]) * actual // TIMESPAN
        return target_to_compact(min(target, POW_LIMIT))

    def make(self, miner, parent, time, tag):
        p = self.entries[parent]
        height = p["height"] + 1
        bits = self.next_bits(parent)
        txid, cb = coinbase(height, tag)
        prefix = (0x20000000).to_bytes(4, "little") + bytes.fromhex(parent)[::-1] + txid
        prefix += time.to_bytes(4, "little") + bits.to_bytes(4, "little")
        nonce = miner.mine(prefix, compact_to_target(bits))
        header = prefix + nonce.to_bytes(4, "little")
        h = sha256d(header)[::-1].hex()
        self.entries[h] = {"height": height, "time": time, "bits": bits, "prev": parent,
                           "work": p["work"] + block_proof(bits)}
        return h, (header + compact_size(1) + cb).hex()


def main():
    out = sys.argv[1]
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else os.cpu_count()
    miner = Miner(workers, sys.argv[3] if len(sys.argv) > 3 else None)
    chain = Chain()
    events = [{"type": "reset", "network": "signet", "options": {"signetchallenge": CHALLENGE},
               "genesis": GENESIS_HASH}]
    checks = []

    def block(parent, time, tag):
        h, raw = chain.make(miner, parent, time, tag)
        # `now` an hour after the block: never too far in the future, and the same on every run.
        events.append({"type": "block", "hash": h, "hex": raw, "now": time + 3600, "via": "rpc"})
        return h

    def check(tip, label):
        e = chain.entries[tip]
        checks.append(tip)
        events.append({"type": "check", "n": len(checks), "label": label, "normative": True,
                       "tip": tip, "height": e["height"], "chainwork": "%064x" % e["work"]})

    tip = GENESIS_HASH
    for height in range(1, INTERVAL - 1):
        tip = block(tip, GENESIS_TIME + height * SPACING, b"trunk")
        if height % 100 == 0:
            print("height", height, file=sys.stderr, flush=True)
    trunk = tip
    check(trunk, "trunk of 2014 blocks at the proof-of-work limit")

    # Branch b: block 2,015 two weeks after genesis, so block 2,016 keeps the target.
    b = block(trunk, GENESIS_TIME + TIMESPAN, b"b")
    for i in range(3):
        b = block(b, GENESIS_TIME + TIMESPAN + (i + 1) * SPACING, b"b")
    check(b, "branch b: 4 blocks, the target unchanged at the retarget")

    # Branch a: block 2,015 keeps the pace, so block 2,016 has a quarter of the target.
    a = block(trunk, GENESIS_TIME + (INTERVAL - 1) * SPACING, b"a")
    a = block(a, GENESIS_TIME + INTERVAL * SPACING, b"a")
    assert chain.entries[a]["bits"] != GENESIS_BITS
    assert chain.entries[a]["height"] < chain.entries[b]["height"]
    assert chain.entries[a]["work"] > chain.entries[b]["work"]
    check(a, "branch a: 2 blocks, the second retargeted to 4 times the work; shorter than b, more work")

    b = block(b, GENESIS_TIME + TIMESPAN + 4 * SPACING, b"b")
    assert chain.entries[a]["work"] > chain.entries[b]["work"]
    check(a, "branch b: 5 blocks, still less work than a")
    b = block(b, GENESIS_TIME + TIMESPAN + 5 * SPACING, b"b")
    assert chain.entries[a]["work"] < chain.entries[b]["work"]
    check(b, "branch b: 6 blocks, more work than a")

    blocks = sum(1 for e in events if e["type"] == "block")
    meta = {"type": "meta", "format": "bcs-block-corpus", "format_version": 1, "scenario": "most-work",
            "node": 0, "source": {"path": "conformance/vectors/chainwork/generate.py"},
            "notes": "Synthetic: custom signet (challenge OP_TRUE) with real proof of work. "
                     "Expectations confirmed against Bitcoin Core v32.1 (core_chain_harness.py).",
            "counts": {"events": len(events), "blocks": blocks, "headers": 0, "invalidate": 0,
                       "restart": 0, "checks": len(checks), "normative_checks": len(checks)}}
    # No file name or time in the gzip header, so that a run gives the same bytes wherever it writes.
    with open(out, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as f:
        for e in [meta] + events:
            f.write((json.dumps(e, separators=(",", ":")) + "\n").encode())


if __name__ == "__main__":
    main()
