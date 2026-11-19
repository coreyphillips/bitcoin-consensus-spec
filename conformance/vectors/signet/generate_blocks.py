"""Writes signet-blocks.jsonl.gz: a scenario in the corpus format (CORPUS.md) on a custom signet
whose challenge is a key with OP_CHECKSIG.

Usage: python3 generate_blocks.py <out.jsonl.gz> [workers]

The signet suite asks `signet_check` about single blocks, so it cannot tell whether an
implementation runs that check when it processes a block. Here every block carries real proof of
work at signet's limit and a valid witness commitment, so a block without a valid solution fails
only the signet rule (`bad-signet-blksig`) and must leave the tip where it was:

- height 1: no solution, then a solution signed by another key, then the signed block;
- height 2, on the signed block: no solution, then the signed block.

At each height the rejected blocks come first, so an implementation that accepts them makes one of
them the tip. Every block takes the smallest nonce that meets its target and signatures use a
nonce derived from the key and the digest, so the file is the same on every run. Replaying it
through `conformance/recorder/core_chain_harness.py` (README.md) confirms the checks against
Bitcoin Core.
"""

import gzip
import hashlib
import hmac
import json
import multiprocessing
import os
import struct
import sys

GENESIS_HASH = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
GENESIS_TIME = 1598918400
BITS = 0x1E0377AE
SIGNET_HEADER = bytes.fromhex("ecc7daa2")
SIGHASH_ALL = 1
CHUNK = 1 << 16

# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def point_mul(k, point=G):
    result = None
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def pubkey(secret):
    x, y = point_mul(secret)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def der_int(v):
    return b"\x02" + bytes([(v.bit_length() + 8) // 8]) + v.to_bytes((v.bit_length() + 8) // 8, "big")


def sign(secret, digest):
    """Low-S ECDSA, strict DER, with a nonce derived from the key and the digest."""
    z = int.from_bytes(digest, "big")
    k = int.from_bytes(hmac.new(secret.to_bytes(32, "big"), digest, hashlib.sha256).digest(), "big") % N
    r = point_mul(k)[0] % N
    s = pow(k, N - 2, N) * (z + r * secret) % N
    s = min(s, N - s)
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([SIGHASH_ALL])


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n):
    assert n < 0xFD
    return bytes([n])


def var_bytes(b):
    return compact_size(len(b)) + b


def push(data):
    """Canonical push of 1 to 255 bytes (CScript << vector)."""
    assert 0 < len(data) <= 0xFF
    return bytes([len(data)]) + data if len(data) < 0x4C else b"\x4c" + bytes([len(data)]) + data


def tx(inputs, outputs, version, witness=None):
    """Serialized transaction; `inputs` are (prevout, script_sig, sequence)."""
    body = compact_size(len(inputs)) + b"".join(o + var_bytes(s) + q.to_bytes(4, "little") for o, s, q in inputs)
    body += compact_size(len(outputs)) + b"".join(v.to_bytes(8, "little") + var_bytes(s) for v, s in outputs)
    v = version.to_bytes(4, "little")
    if witness is None:
        return v + body + bytes(4)
    return v + b"\x00\x01" + body + compact_size(len(witness)) + b"".join(var_bytes(w) for w in witness) + bytes(4)


KEY, OTHER_KEY = 0x5157, 0x7E57
CHALLENGE = push(pubkey(KEY)) + b"\xac"
# The witness commitment of a block whose only transaction is the coinbase (BIP141): its wtxid is
# zero and its witness is the 32-byte reserved value of zeros.
COMMITMENT = bytes.fromhex("6a24aa21a9ed") + sha256d(bytes(64))


def coinbase(height, solution_push):
    """The coinbase of a block at `height`: the BIP34 height (OP_1 or OP_2), an OP_TRUE output and
    the commitment output with `solution_push` after the commitment. Returns (txid, serialized)."""
    assert 1 <= height <= 16
    inputs = [(bytes(32) + b"\xff\xff\xff\xff", bytes([0x50 + height]) + push(b"signet"), 0xFFFFFFFF)]
    outputs = [(0, b"\x51"), (0, COMMITMENT + solution_push)]
    return sha256d(tx(inputs, outputs, 1)), tx(inputs, outputs, 1, witness=[bytes(32)])


def signature_hash(prev, height, time):
    """BIP325: the legacy SIGHASH_ALL digest of to_sign, which spends to_spend, whose output is the
    challenge and whose input commits to the header fields and the merkle root of the block with
    the solution cleared (the push of the signet header alone)."""
    root, _ = coinbase(height, push(SIGNET_HEADER))
    block_data = (0x20000000).to_bytes(4, "little") + prev + root + time.to_bytes(4, "little")
    to_spend = sha256d(tx([(bytes(32) + b"\xff\xff\xff\xff", b"\x00" + push(block_data), 0)], [(0, CHALLENGE)], 0))
    to_sign = tx([(to_spend + bytes(4), CHALLENGE, 0)], [(0, b"\x6a")], 0)
    return sha256d(to_sign + SIGHASH_ALL.to_bytes(4, "little"))


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


def main():
    out = sys.argv[1]
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else os.cpu_count()
    pool = multiprocessing.Pool(workers)
    target = (BITS & 0x7FFFFF) << 8 * ((BITS >> 24) - 3)

    def mine(prefix):
        start = 0
        while True:
            batch = [(prefix, target, start + i * CHUNK) for i in range(workers)]
            for nonce in pool.imap(search, batch):
                if nonce is not None:
                    return nonce
            start += len(batch) * CHUNK

    events = [{"type": "reset", "network": "signet", "options": {"signetchallenge": CHALLENGE.hex()},
               "genesis": GENESIS_HASH}]
    checks = []

    def block(parent, height, key):
        """A block on `parent` signed with `key`, or with no solution when `key` is None."""
        prev = bytes.fromhex(parent)[::-1]
        time = GENESIS_TIME + height * 100
        if key is None:
            solution_push = b""
        else:
            sig = sign(key, signature_hash(prev, height, time))
            # The solution: the scriptSig (the signature push) and an empty witness stack.
            solution_push = push(SIGNET_HEADER + var_bytes(push(sig)) + b"\x00")
        txid, cb = coinbase(height, solution_push)
        prefix = (0x20000000).to_bytes(4, "little") + prev + txid + time.to_bytes(4, "little")
        prefix += BITS.to_bytes(4, "little")
        header = prefix + mine(prefix).to_bytes(4, "little")
        h = sha256d(header)[::-1].hex()
        # `now` an hour after the block: never too far in the future, and the same on every run.
        events.append({"type": "block", "hash": h, "hex": (header + b"\x01" + cb).hex(), "now": time + 3600,
                       "via": "rpc"})
        return h

    def check(tip, height, label):
        checks.append(tip)
        events.append({"type": "check", "n": len(checks), "label": label, "normative": True,
                       "tip": tip, "height": height, "tips": [{"hash": tip, "height": height, "status": "active"}]})

    check(GENESIS_HASH, 0, "genesis")
    block(GENESIS_HASH, 1, None)
    check(GENESIS_HASH, 0, "block 1 without a solution: rejected (bad-signet-blksig)")
    block(GENESIS_HASH, 1, OTHER_KEY)
    check(GENESIS_HASH, 0, "block 1 signed by another key: rejected (bad-signet-blksig)")
    one = block(GENESIS_HASH, 1, KEY)
    check(one, 1, "block 1 signed: accepted")
    block(one, 2, None)
    check(one, 1, "block 2 without a solution: rejected (bad-signet-blksig)")
    two = block(one, 2, KEY)
    check(two, 2, "block 2 signed: accepted")
    pool.close()
    pool.join()

    blocks = sum(1 for e in events if e["type"] == "block")
    meta = {"type": "meta", "format": "bcs-block-corpus", "format_version": 1, "scenario": "signet-blocks",
            "node": 0, "source": {"path": "conformance/vectors/signet/generate_blocks.py"},
            "notes": "Synthetic: custom signet (challenge: a key with OP_CHECKSIG) with real proof of work. "
                     "Expectations confirmed against Bitcoin Core v32.1 (core_chain_harness.py).",
            "counts": {"events": len(events), "blocks": blocks, "headers": 0, "invalidate": 0,
                       "restart": 0, "checks": len(checks), "normative_checks": len(checks)}}
    # No file name or time in the gzip header, so that a run gives the same bytes wherever it writes.
    with open(out, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as f:
        for e in [meta] + events:
            f.write((json.dumps(e, separators=(",", ":")) + "\n").encode())


if __name__ == "__main__":
    main()
