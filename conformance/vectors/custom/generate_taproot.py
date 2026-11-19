"""Writes taproot.jsonl: direct cases for the sighash_taproot and taproot_commitment_verify operations.
The bip341 suite only ever expects a valid commitment and only hashes key path spends without an annex,
so a harness that accepts every commitment, or ignores annex, leaf_hash and codesep_pos, passed it.
Expectations are Bitcoin Core v32.1's answers, taken from oracle-core-harness.

Usage: python3 generate_taproot.py <oracle-core-harness> <out.jsonl>
"""
import hashlib, json, struct, subprocess, sys

ORACLE, OUT = sys.argv[1], sys.argv[2]


# ---- encoding and secp256k1

def sha256(b): return hashlib.sha256(b).digest()
def tagged(tag, msg): t = sha256(tag.encode()); return sha256(t + t + msg)
def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)
def tx(ins, outs):
    b = struct.pack("<I", 2) + cs(len(ins))
    for txid, vout, seq in ins: b += txid + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", seq)
    b += cs(len(outs))
    for v, spk in outs: b += struct.pack("<q", v) + cs(len(spk)) + spk
    return b + struct.pack("<I", 0)

P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def padd(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)
def pmul(k, pt):
    r = None
    while k:
        if k & 1: r = padd(r, pt)
        pt = padd(pt, pt); k >>= 1
    return r
def lift_x(x):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if x >= P or y * y % P != y2: return None
    return (x, y if y % 2 == 0 else P - y)
def xonly(pt): return pt[0].to_bytes(32, "big")


# ---- taproot trees

def leaf_hash(version, script): return tagged("TapLeaf", bytes([version]) + cs(len(script)) + script)
def branch(a, b): return tagged("TapBranch", min(a, b) + max(a, b))
def root_of(leaf, path):
    for node in path: leaf = branch(leaf, node)
    return leaf
def output_for(internal, root):
    tweak = int.from_bytes(tagged("TapTweak", internal + root), "big")
    return padd(lift_x(int.from_bytes(internal, "big")), pmul(tweak, G))
def key_with_parity(root, parity):
    """The first internal key k*G whose output key for root has the given parity."""
    for k in range(1, 100):
        internal = xonly(pmul(k, G))
        out = output_for(internal, root)
        if out[1] & 1 == parity: return internal, out
def control(version, parity, internal, path): return bytes([version | parity]) + internal + b"".join(path)


# ---- oracle

h = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
next_id = [0]
def ask(req):
    next_id[0] += 1
    req2 = dict(req); req2["id"] = next_id[0]
    h.stdin.write(json.dumps(req2) + "\n"); h.stdin.flush()
    resp = json.loads(h.stdout.readline())
    assert resp.get("ok"), (req, resp)
    return resp

out = []
def add(name, req, want_valid):
    resp = ask(req)
    assert resp["valid"] == want_valid, (name, resp)
    expect = {k: resp[k] for k in ("valid", "sighash") if k in resp}
    out.append({"name": name, "request": req, "expect": expect})


# ---- taproot_commitment_verify

def tcv(name, ctrl, script, out_key, want_valid):
    add("taproot_commitment_verify: " + name, {"op": "taproot_commitment_verify", "control_block": ctrl.hex(),
                                               "script": script.hex(), "output_key": xonly(out_key).hex()}, want_valid)

# Tree T1 is [A, [B, C]]; C has the unknown leaf version 0xc2, which the control block carries. Its output key
# has odd y. Hashing A's path compares A with [B, C], and hashing B's path compares [B, C] with A, so the two
# valid paths below put the node on each side of the running hash.
A, B, C = b"\x51", b"\x52", b"\x53"
hA, hB, hC = leaf_hash(0xc0, A), leaf_hash(0xc0, B), leaf_hash(0xc2, C)
paths = {"A": [branch(hB, hC)], "B": [hC, hA], "C": [hB, hA]}
root1 = root_of(hA, paths["A"])
assert root_of(hB, paths["B"]) == root1 == root_of(hC, paths["C"])
k1, q1 = key_with_parity(root1, 1)
ctlA, ctlB, ctlC = control(0xc0, 1, k1, paths["A"]), control(0xc0, 1, k1, paths["B"]), control(0xc2, 1, k1, paths["C"])
# Tree T2 is the single leaf D, a 33-byte control block. Its output key has even y.
D = b"\x54"
k2, q2 = key_with_parity(leaf_hash(0xc0, D), 0)
ctlD = control(0xc0, 0, k2, [])

tcv("leaf A at depth 1 (odd output key)", ctlA, A, q1, True)
tcv("leaf B at depth 2", ctlB, B, q1, True)
tcv("leaf C at depth 2, leaf version 0xc2", ctlC, C, q1, True)
tcv("single leaf D, no path (even output key)", ctlD, D, q2, True)
tcv("leaf A, parity bit 0 for an odd output key", bytes([ctlA[0] ^ 1]) + ctlA[1:], A, q1, False)
tcv("leaf D, parity bit 1 for an even output key", bytes([ctlD[0] ^ 1]) + ctlD[1:], D, q2, False)
tcv("leaf B, path nodes in reverse order", control(0xc0, 1, k1, paths["B"][::-1]), B, q1, False)
tcv("leaf B, last byte of the first path node changed", ctlB[:64] + bytes([ctlB[64] ^ 1]) + ctlB[65:], B, q1, False)
tcv("leaf B, last path node left out", ctlB[:65], B, q1, False)
tcv("leaf A, path of leaf B", control(0xc0, 1, k1, paths["B"]), A, q1, False)
tcv("leaf A, script of leaf B", ctlA, B, q1, False)
tcv("leaf A, leaf version 0xc2 in the control block", control(0xc2, 1, k1, paths["A"]), A, q1, False)
tcv("leaf C, leaf version 0xc0 in the control block", control(0xc0, 1, k1, paths["C"]), C, q1, False)
tcv("leaf A, internal key of tree T2", control(0xc0, 1, k2, paths["A"]), A, q1, False)
tcv("leaf A, output key of tree T2", ctlA, A, q2, False)
x = next(x for x in range(1, 100) if lift_x(x) is None)
tcv("internal key x = %d, not on the curve" % x, control(0xc0, 0, x.to_bytes(32, "big"), []), D, q2, False)

# Control block size: 33 + 32m bytes with m <= 128. Each wrong size below holds a commitment that verifies if
# the trailing bytes are ignored or the node limit is not checked.
tcv("control block of 0 bytes", b"", D, q2, False)
tcv("control block of 32 bytes (leaf D's without its last byte)", ctlD[:32], D, q2, False)
tcv("control block of 34 bytes (leaf D's and one zero byte)", ctlD + b"\x00", D, q2, False)
tcv("control block of 64 bytes (leaf A's without its last byte)", ctlA[:64], A, q1, False)
tcv("control block of 96 bytes (leaf A's and 31 zero bytes)", ctlA + bytes(31), A, q1, False)
for nodes in (128, 129):
    path = [bytes([i + 1]) * 32 for i in range(nodes)]
    kn, qn = key_with_parity(root_of(leaf_hash(0xc0, D), path), 0)
    tcv("control block of %d bytes, a correct path of %d nodes" % (33 + 32 * nodes, nodes), control(0xc0, 0, kn, path), D, qn, nodes <= 128)


# ---- sighash_taproot

FUND1, FUND2 = bytes(range(32)), bytes(range(32, 64))
TX = tx([(FUND1, 0, 0xfffffffd), (FUND2, 1, 0xffffffff)], [(1000, b"\x51"), (2000, b"\x00\x14" + bytes([7]) * 20)])
TX_ONE_OUT = tx([(FUND1, 0, 0xfffffffd), (FUND2, 1, 0xffffffff)], [(1000, b"\x51")])
SPENT = [{"amount": 5000, "script_pubkey": "5120" + xonly(q1).hex()}, {"amount": 7000, "script_pubkey": "5120" + xonly(q2).hex()}]
ANNEX = b"\x50annex"
LONG_ANNEX = b"\x50" + bytes(range(256)) + bytes(43)  # 300 bytes: its length is a three-byte CompactSize
assert len(LONG_ANNEX) == 300
LEAF = hA.hex()

def sh(name, hash_type, extra, want_valid, index=1, raw=TX):
    req = {"op": "sighash_taproot", "tx": raw.hex(), "index": index, "spent_outputs": SPENT, "hash_type": hash_type}
    req.update(extra)
    add("sighash_taproot: hash type 0x%02x, %s" % (hash_type, name), req, want_valid)

# Every valid hash type with each optional field. The annex hash comes before the hash of the SIGHASH_SINGLE
# output, and the tapscript extension after both.
for hash_type in (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
    sh("key path with an annex", hash_type, {"annex": ANNEX.hex()}, True)
    sh("script path", hash_type, {"leaf_hash": LEAF}, True)
    sh("script path, codesep_pos 1", hash_type, {"leaf_hash": LEAF, "codesep_pos": 1}, True)
    sh("script path with an annex, codesep_pos 1", hash_type, {"leaf_hash": LEAF, "annex": ANNEX.hex(), "codesep_pos": 1}, True)
sh("script path, codesep_pos 0", 0x00, {"leaf_hash": LEAF, "codesep_pos": 0}, True)
sh("script path, codesep_pos 4294967295 (the default, given)", 0x00, {"leaf_hash": LEAF, "codesep_pos": 0xffffffff}, True)
sh("key path with a one-byte annex", 0x00, {"annex": "50"}, True)
sh("key path with a 300-byte annex", 0x00, {"annex": LONG_ANNEX.hex()}, True)
sh("script path with a 300-byte annex, codesep_pos 7", 0x01, {"leaf_hash": LEAF, "annex": LONG_ANNEX.hex(), "codesep_pos": 7}, True)
for hash_type in (0x04, 0x80, 0x84, 0xff):
    sh("key path with an annex (not a valid hash type)", hash_type, {"annex": ANNEX.hex()}, False)
    sh("script path with an annex, codesep_pos 1 (not a valid hash type)", hash_type, {"leaf_hash": LEAF, "annex": ANNEX.hex(), "codesep_pos": 1}, False)
# SIGHASH_SINGLE fails for an input with no output at its index.
sh("input 0 of 2, one output, script path with an annex", 0x03, {"leaf_hash": LEAF, "annex": ANNEX.hex()}, True, index=0, raw=TX_ONE_OUT)
for hash_type in (0x03, 0x83):
    sh("input 1 of 2, one output, key path with an annex", hash_type, {"annex": ANNEX.hex()}, False, raw=TX_ONE_OUT)
    sh("input 1 of 2, one output, script path with an annex", hash_type, {"leaf_hash": LEAF, "annex": ANNEX.hex()}, False, raw=TX_ONE_OUT)

with open(OUT, "w") as f:
    for o in out:
        f.write(json.dumps(o) + "\n")
for o in out:
    print("%-100s %s" % (o["name"], o["expect"]))
