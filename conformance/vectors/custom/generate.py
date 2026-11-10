import json, subprocess, sys, hashlib, struct
ORACLE, OUT = sys.argv[1], sys.argv[2]
def sha256(b): return hashlib.sha256(b).digest()
def h160(b):
    r = hashlib.new("ripemd160"); r.update(sha256(b)); return r.digest()
def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)
def push(d):
    l = len(d)
    if l < 0x4c: return bytes([l]) + d
    if l <= 0xff: return bytes([0x4c, l]) + d
    return bytes([0x4d]) + struct.pack("<H", l) + d
def tx(ver, ins, outs, lock, wits=None):
    hw = wits is not None and any(len(w) for w in wits)
    b = struct.pack("<I", ver) + (b"\x00\x01" if hw else b"") + cs(len(ins))
    for txid, vout, ss, seq in ins: b += txid + struct.pack("<I", vout) + cs(len(ss)) + ss + struct.pack("<I", seq)
    b += cs(len(outs))
    for v, spk in outs: b += struct.pack("<q", v) + cs(len(spk)) + spk
    if hw:
        for w in wits:
            b += cs(len(w))
            for it in w: b += cs(len(it)) + it
    return b + struct.pack("<I", lock)
FUND = bytes(range(32))
OUTS = [(1000, b"\x51")]
ALL = ["P2SH", "DERSIG", "NULLDUMMY", "CHECKLOCKTIMEVERIFY", "CHECKSEQUENCEVERIFY", "WITNESS", "TAPROOT"]
cases = []
def sv(name, script_sig, spk, witness, flags=ALL, amount=5000):
    t = tx(2, [(FUND, 0, script_sig, 0xffffffff)], OUTS, 0, [witness])
    cases.append((name, {"op": "script_verify", "tx": t.hex(), "index": 0, "spent_outputs": [{"amount": amount, "script_pubkey": spk.hex()}], "flags": flags}))
# P2SH-wrapped P2WSH whose witness script is OP_TRUE.
ws = b"\x51"
redeem = b"\x00\x20" + sha256(ws)
p2sh = b"\xa9\x14" + h160(redeem) + b"\x87"
sv("p2sh-p2wsh canonical push", push(redeem), p2sh, [ws])
sv("p2sh-p2wsh extra leading push", b"\x00" + push(redeem), p2sh, [ws])
sv("p2sh-p2wsh pushdata1 encoding", bytes([0x4c, len(redeem)]) + redeem, p2sh, [ws])
sv("p2sh-p2wsh pushdata2 encoding", bytes([0x4d]) + struct.pack("<H", len(redeem)) + redeem, p2sh, [ws])
sv("p2sh-p2wsh trailing OP_NOP after push", push(redeem) + b"\x61", p2sh, [ws])
sv("p2sh-p2wsh without WITNESS flag", push(redeem), p2sh, [ws], flags=["P2SH"])
# Native witness program with a non-empty scriptSig.
p2wsh = b"\x00\x20" + sha256(ws)
sv("native p2wsh with scriptSig OP_0", b"\x00", p2wsh, [ws])
sv("native p2wsh empty scriptSig", b"", p2wsh, [ws])
# P2SH-wrapped version 1 programs are not taproot.
v1 = b"\x51\x20" + bytes([7] * 32)
p2sh_v1 = b"\xa9\x14" + h160(v1) + b"\x87"
sv("p2sh-wrapped v1 32-byte program with junk witness", push(v1), p2sh_v1, [b"\x01" * 70])
sv("native v1 33-byte program with junk witness", b"", b"\x51\x21" + bytes([7] * 33), [b"\x02"])
sv("pay-to-anchor with witness item", b"", b"\x51\x02\x4e\x73", [b"\x03"])
sv("v0 program of 21 bytes", b"", b"\x00\x15" + bytes([9] * 21), [b"\x51"])
sv("v0 all-zero 32-byte program", b"", b"\x00\x20" + bytes(32), [b"\x51"])
# tx_check decoding edge cases.
def tc(name, raw): cases.append((name, {"op": "tx_check", "tx": raw.hex()}))
good = tx(1, [(FUND, 0, b"\x51", 0xffffffff)], OUTS, 0)
tc("canonical transaction", good)
tc("ten-byte empty transaction", bytes.fromhex("01000000000000000000"))
tc("non-canonical input count (fd 01 00)", good[:4] + b"\xfd\x01\x00" + good[5:])
tc("non-canonical script length (fd 01 00)", good[:4] + good[4:5] + FUND + struct.pack("<I", 0) + b"\xfd\x01\x00" + b"\x51" + good[4+1+36+2:])
tc("witness flag with only empty witnesses", good[:4] + b"\x00\x01" + good[4:-4] + b"\x00" + good[-4:])
tc("unknown flag 0x02", good[:4] + b"\x00\x02" + good[4:])
tc("trailing byte", good + b"\x00")
tc("output count above MAX_SIZE", good[:4] + good[4:4+1+36+2+4] + b"\xfe\x01\x00\x00\x02" + good[4+1+36+2+4+1:])
# Found by reviewing other implementations (Appendix A items 75, 76 and 79, and quirk 17 in
# tapscript): each case below separates Bitcoin Core from a published implementation.
h = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
next_id = [0]
def ask(req):
    next_id[0] += 1
    req2 = dict(req); req2["id"] = next_id[0]
    h.stdin.write(json.dumps(req2) + "\n"); h.stdin.flush()
    resp = json.loads(h.stdout.readline())
    assert resp.get("ok"), (req, resp)
    return resp
# secp256k1 arithmetic, enough to build keys and the forgeries below.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
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
def compressed(pt): return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")
def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80: b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b
def der(r, s): body = der_int(r) + der_int(s); return b"\x30" + bytes([len(body)]) + body
def tagged(tag, msg): t = sha256(tag.encode()); return sha256(t + t + msg)
# ECDSA r or s at or above the group order is invalid; it is not reduced modulo n. R = (1, y) is a
# curve point (8 is a square mod p). With e the message, Q = R - e*G makes (r mod n, s mod n) =
# (1, 1) a valid signature for Q, so an implementation that reduces accepts these spends.
checksig = b"\xac"
y = pow(8, (P + 1) // 4, P); assert y * y % P == 8
R = (1, y)
e = int(ask({"op": "sighash_legacy", "tx": tx(2, [(FUND, 0, b"", 0xffffffff)], OUTS, 0).hex(), "script_code": checksig.hex(), "index": 0, "hash_type": 1})["sighash"], 16) % N
Q = padd(R, pmul(N - e, G))
for name, r, s in (("ecdsa r = n + 1 forged for r mod n, bare CHECKSIG", N + 1, 1), ("ecdsa s = n + 1 forged for s mod n, bare CHECKSIG", 1, N + 1)):
    sv(name, push(der(r, s) + b"\x01") + push(compressed(Q)), checksig, [])
# With DERSIG, an R or S longer than 32 bytes passes the encoding check; CHECKSIG returns false.
not_checksig = push(compressed(G)) + b"\xac\x91"
sv("DERSIG 33-byte R, CHECKSIG NOT", push(der(2**256, 1) + b"\x01"), not_checksig, [])
sv("DERSIG 33-byte S, CHECKSIG NOT", push(der(1, 2**256) + b"\x01"), not_checksig, [])
# A P2SH redeem script is pushed by the signature script, so it is at most 520 bytes.
for nops in (3, 4):
    redeem = bytes([0x4d, 0x00, 0x02]) + bytes(512) + b"\x75" + b"\x61" * nops + b"\x51"
    sv("p2sh redeem script of %d bytes" % len(redeem), push(redeem), b"\xa9\x14" + h160(redeem) + b"\x87", [])
# Tapscript: the 520-byte push limit applies in an unexecuted branch too.
for size in (520, 521):
    leaf = b"\x00\x63" + push(bytes(size)) + b"\x68\x51"
    leaf_hash = tagged("TapLeaf", b"\xc0" + cs(len(leaf)) + leaf)
    tweak = int.from_bytes(tagged("TapTweak", G[0].to_bytes(32, "big") + leaf_hash), "big")
    out = padd(G, pmul(tweak, G))
    control = bytes([0xc0 | (out[1] & 1)]) + G[0].to_bytes(32, "big")
    sv("tapscript %d-byte push in an unexecuted branch" % size, b"", b"\x51\x20" + out[0].to_bytes(32, "big"), [leaf, control])
with open(OUT, "w") as f:
    for name, req in cases:
        resp = ask(req)
        expect = {k: v for k, v in resp.items() if k in ("valid", "script_error", "reason")}
        f.write(json.dumps({"name": name, "request": req, "expect": expect}) + "\n")
        print("%-52s %s" % (name, expect))
