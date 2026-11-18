"""Writes script-versions.jsonl: interpreter rules exercised inside witness version 0 scripts, P2SH-wrapped
witness programs and tapscripts, plus legacy FindAndDelete. Each case separates Bitcoin Core from a one-line
wrong implementation that passed every other suite (conformance/mutation/mutants.json). Expectations are
Bitcoin Core v32.1's answers, taken from oracle-core-harness.

Usage: python3 generate_script_versions.py <oracle-core-harness> <out.jsonl>
"""
import hashlib, json, struct, subprocess, sys

ORACLE, OUT = sys.argv[1], sys.argv[2]


# ---- encoding

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def h160(b):
    r = hashlib.new("ripemd160"); r.update(sha256(b)); return r.digest()
def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)
def push(d):
    l = len(d)
    if l < 0x4c: return bytes([l]) + d
    if l <= 0xff: return bytes([0x4c, l]) + d
    if l <= 0xffff: return bytes([0x4d]) + struct.pack("<H", l) + d
    return bytes([0x4e]) + struct.pack("<I", l) + d
def scriptnum(v):
    if v == 0: return b""
    neg = v < 0; m = abs(v); out = bytearray()
    while m: out.append(m & 0xff); m >>= 8
    if out[-1] & 0x80: out.append(0x80 if neg else 0)
    elif neg: out[-1] |= 0x80
    return bytes(out)
def pushnum(v):
    if v == 0: return b"\x00"
    if v == -1: return b"\x4f"
    if 1 <= v <= 16: return bytes([0x50 + v])
    return push(scriptnum(v))
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


# ---- secp256k1, ECDSA and BIP340 signing

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
def xonly(pt): return pt[0].to_bytes(32, "big")
def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80: b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b
def der(r, s): body = der_int(r) + der_int(s); return b"\x30" + bytes([len(body)]) + body
def tagged(tag, msg): t = sha256(tag.encode()); return sha256(t + t + msg)
def ecdsa_sign(d, msg32, k=None):
    z = int.from_bytes(msg32, "big")
    if k is None: k = int.from_bytes(sha256(msg32 + d.to_bytes(32, "big")), "big") % N or 1
    R = pmul(k, G); r = R[0] % N
    s = pow(k, N - 2, N) * (z + r * d) % N
    if s > N // 2: s = N - s
    return der(r, s)
def bip340_sign(d, msg):
    pt = pmul(d, G)
    if pt[1] & 1: d = N - d
    px = pt[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(tagged("BIP0340/aux", bytes(32)), "big")).to_bytes(32, "big")
    k = int.from_bytes(tagged("BIP0340/nonce", t + px + msg), "big") % N
    rp = pmul(k, G)
    if rp[1] & 1: k = N - k
    rx = rp[0].to_bytes(32, "big")
    c = int.from_bytes(tagged("BIP0340/challenge", rx + px + msg), "big") % N
    return rx + ((k + c * d) % N).to_bytes(32, "big")


# ---- the three signature hashes, written independently of the specification's code

def get_op(s, pos):
    """Returns (opcode, data, next position), or (None, None, position) when the script ends or a push is cut short."""
    if pos >= len(s): return None, None, pos
    op = s[pos]; pos += 1
    if op > 0x4e: return op, b"", pos
    if op < 0x4c: n = op
    elif op == 0x4c:
        if len(s) - pos < 1: return None, None, pos
        n = s[pos]; pos += 1
    elif op == 0x4d:
        if len(s) - pos < 2: return None, None, pos
        n = s[pos] | (s[pos + 1] << 8); pos += 2
    else:
        if len(s) - pos < 4: return None, None, pos
        n = int.from_bytes(s[pos:pos + 4], "little"); pos += 4
    if len(s) - pos < n: return None, None, pos
    return op, s[pos:pos + n], pos + n

def find_and_delete(script, pat):
    if not pat: return script
    out = b""; pc = 0; pc2 = 0; found = False
    while True:
        out += script[pc2:pc]
        while len(script) - pc >= len(pat) and script[pc:pc + len(pat)] == pat:
            pc += len(pat); found = True
        pc2 = pc
        op, _, pc = get_op(script, pc)
        if op is None: break
    if found:
        return out + script[pc2:]
    return script

def ser_script_code_legacy(sc):
    it = 0; seps = 0
    while True:
        op, _, it = get_op(sc, it)
        if op is None: break
        if op == 0xab: seps += 1
    out = cs(len(sc) - seps)
    it = 0; begin = 0
    while True:
        op, _, it = get_op(sc, it)
        if op is None: break
        if op == 0xab:
            out += sc[begin:it - 1]; begin = it
    if begin != len(sc):
        out += sc[begin:it]
    return out

class Tx:
    def __init__(self, ver, ins, outs, lock):
        self.ver, self.ins, self.outs, self.lock = ver, ins, outs, lock   # ins: (txid, vout, script_sig, sequence)

def legacy_sighash(sc, t, n_in, ht):
    base = ht & 0x1f
    if base == 3 and n_in >= len(t.outs):
        return (1).to_bytes(32, "little")
    acp = bool(ht & 0x80)
    b = struct.pack("<I", t.ver)
    idxs = [n_in] if acp else list(range(len(t.ins)))
    b += cs(len(idxs))
    for i in idxs:
        txid, vout, _, seq = t.ins[i]
        b += txid + struct.pack("<I", vout)
        b += ser_script_code_legacy(sc) if i == n_in else b"\x00"
        if i != n_in and base in (2, 3): b += struct.pack("<I", 0)
        else: b += struct.pack("<I", seq)
    if base == 2: b += cs(0)
    elif base == 3:
        b += cs(n_in + 1)
        for i in range(n_in + 1):
            if i != n_in: b += b"\xff" * 8 + b"\x00"
            else: b += struct.pack("<q", t.outs[i][0]) + cs(len(t.outs[i][1])) + t.outs[i][1]
    else:
        b += cs(len(t.outs))
        for v, spk in t.outs: b += struct.pack("<q", v) + cs(len(spk)) + spk
    b += struct.pack("<I", t.lock)
    b += struct.pack("<I", ht & 0xffffffff)
    return sha256d(b)

def bip143_sighash(sc, t, n_in, ht, amount):
    base = ht & 0x1f; acp = bool(ht & 0x80)
    hp = hs = ho = bytes(32)
    if not acp: hp = sha256d(b"".join(i[0] + struct.pack("<I", i[1]) for i in t.ins))
    if not acp and base not in (2, 3): hs = sha256d(b"".join(struct.pack("<I", i[3]) for i in t.ins))
    if base not in (2, 3): ho = sha256d(b"".join(struct.pack("<q", v) + cs(len(s)) + s for v, s in t.outs))
    elif base == 3 and n_in < len(t.outs):
        v, s = t.outs[n_in]; ho = sha256d(struct.pack("<q", v) + cs(len(s)) + s)
    txid, vout, _, seq = t.ins[n_in]
    b = (struct.pack("<I", t.ver) + hp + hs + txid + struct.pack("<I", vout) + cs(len(sc)) + sc + struct.pack("<q", amount)
         + struct.pack("<I", seq) + ho + struct.pack("<I", t.lock) + struct.pack("<I", ht & 0xffffffff))
    return sha256d(b)

def bip341_sighash(t, n_in, ht, spent, check_hash_type=True):
    """Key path message for input n_in; spent is a list of (amount, script_pubkey)."""
    if check_hash_type and not (ht <= 3 or 0x81 <= ht <= 0x83): return None
    out_type = 1 if ht == 0 else ht & 3
    acp = (ht & 0x80) == 0x80
    m = b"\x00" + bytes([ht]) + struct.pack("<I", t.ver) + struct.pack("<I", t.lock)
    if not acp:
        m += sha256(b"".join(i[0] + struct.pack("<I", i[1]) for i in t.ins))
        m += sha256(b"".join(struct.pack("<q", a) for a, _ in spent))
        m += sha256(b"".join(cs(len(s)) + s for _, s in spent))
        m += sha256(b"".join(struct.pack("<I", i[3]) for i in t.ins))
    if out_type == 1:
        m += sha256(b"".join(struct.pack("<q", v) + cs(len(s)) + s for v, s in t.outs))
    m += b"\x00"
    if acp:
        txid, vout, _, seq = t.ins[n_in]
        m += txid + struct.pack("<I", vout) + struct.pack("<q", spent[n_in][0]) + cs(len(spent[n_in][1])) + spent[n_in][1] + struct.pack("<I", seq)
    else:
        m += struct.pack("<I", n_in)
    if out_type == 3:
        if n_in >= len(t.outs): return None
        v, s = t.outs[n_in]; m += sha256(struct.pack("<q", v) + cs(len(s)) + s)
    return tagged("TapSighash", m)


# ---- requests

def req_for(t, n_in, spent, wits, flags=ALL):
    raw = tx(t.ver, t.ins, t.outs, t.lock, wits)
    return {"op": "script_verify", "tx": raw.hex(), "index": n_in, "spent_outputs": [{"amount": a, "script_pubkey": s.hex()} for a, s in spent], "flags": flags}
def sv_req(script_sig, spk, witness, flags=ALL, amount=5000, ver=2, seq=0xffffffff, lock=0, outs=OUTS):
    t = tx(ver, [(FUND, 0, script_sig, seq)], outs, lock, [witness])
    return {"op": "script_verify", "tx": t.hex(), "index": 0, "spent_outputs": [{"amount": amount, "script_pubkey": spk.hex()}], "flags": flags}
def p2wsh(ws): return b"\x00\x20" + sha256(ws)
def p2sh(rs): return b"\xa9\x14" + h160(rs) + b"\x87"
def taproot_spk_for_leaf(leaf, leaf_ver=0xc0, internal=G, path=b""):
    """(script_pubkey, control block) for one leaf under the internal key G, with optional Merkle path nodes."""
    k = tagged("TapLeaf", bytes([leaf_ver]) + cs(len(leaf)) + leaf)
    for i in range(0, len(path), 32):
        node = path[i:i + 32]
        k = tagged("TapBranch", (k + node) if k < node else (node + k))
    tweak = int.from_bytes(tagged("TapTweak", internal[0].to_bytes(32, "big") + k), "big")
    ik = internal if internal[1] % 2 == 0 else (internal[0], P - internal[1])
    out = padd(ik, pmul(tweak, G))
    control = bytes([leaf_ver | (out[1] & 1)]) + internal[0].to_bytes(32, "big") + path
    return b"\x51\x20" + out[0].to_bytes(32, "big"), control

h = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
next_id = [0]
def ask(req):
    next_id[0] += 1
    req2 = dict(req); req2["id"] = next_id[0]
    h.stdin.write(json.dumps(req2) + "\n"); h.stdin.flush()
    resp = json.loads(h.stdout.readline())
    assert resp.get("ok") is True, (req, resp)
    return resp

out = []
def add(name, req):
    r = ask(req)
    out.append({"name": name, "request": req, "expect": {"script_error": r.get("script_error", "OK"), "valid": r["valid"]}})

NOP = b"\x61"
NODER = [f for f in ALL if f != "DERSIG"]

# Legacy FindAndDelete removes a signature push only at an operation boundary, and every copy of it. The
# signature is searched for until it is a fixed point: signed over the script code it leaves behind.
t = Tx(2, [(FUND, 0, b"", 0xffffffff)], OUTS, 0)
d1 = 0x1111; pk1 = push(compressed(pmul(d1, G)))
def fad_unaligned(script, pat):
    o = b""; i = 0
    while i < len(script):
        if script[i:i + len(pat)] == pat: i += len(pat)
        else: o += script[i:i + 1]; i += 1
    return o
def fixpoint(build, delete):
    for L in (71, 72, 70):
        dummy = b"\x30" + bytes(L - 1)
        sc = delete(build(dummy), push(dummy))
        h_ = legacy_sighash(sc, t, 0, 1)
        for k in range(1, 60):
            new = ecdsa_sign(d1, h_, k=k * 7919 + 12345) + b"\x01"
            if len(new) == L and delete(build(new), push(new)) == sc:
                return new, build(new)
    raise Exception("no fixpoint")
build = lambda sig: push(push(sig)) + b"\x75" + pk1 + b"\xac"                       # <push(sig) inside a push> DROP <pk> CHECKSIG
sig, spk = fixpoint(build, fad_unaligned); t.ins = [(FUND, 0, push(sig), 0xffffffff)]
add("legacy checksig: signature push inside a larger push is not deleted (signed as if deleted)", req_for(t, 0, [(5000, spk)], None))
build = lambda sig: push(sig) + push(sig) + b"\x6d" + pk1 + b"\xac"                 # <sig> <sig> 2DROP <pk> CHECKSIG
sig, spk = fixpoint(build, find_and_delete); t.ins = [(FUND, 0, push(sig), 0xffffffff)]
add("legacy checksig: two consecutive signature pushes are both deleted", req_for(t, 0, [(5000, spk)], None))
build = lambda sig: push(sig) + b"\x75" + push(sig) + push(sig) + b"\x6d" + pk1 + b"\xac"
sig, spk = fixpoint(build, find_and_delete); t.ins = [(FUND, 0, push(sig), 0xffffffff)]
add("legacy checksig: three signature pushes (one, then two consecutive) are all deleted", req_for(t, 0, [(5000, spk)], None))

# OP_CHECKMULTISIG deletes an empty signature from the script code too, which removes every OP_0. The empty
# signature itself always fails, but the deletion decides whether K3's signature verifies, and so whether the
# badly encoded signature after it is reached (SIG_DER) or the operation returns false and NOT succeeds.
mks = [compressed(pmul(d, G)) for d in (0x6661, 0x6662, 0x6663)]
spk = b"\x00\x75\x53" + b"".join(push(k) for k in mks) + b"\x53\xae\x91"         # OP_0 DROP 3 <K1> <K2> <K3> 3 CHECKMULTISIG NOT
for label, sc in (("signed without the OP_0, so the bad signature is reached", find_and_delete(spk, push(b""))),
                  ("signed with the OP_0 kept, so the operation returns false", spk)):
    sig = ecdsa_sign(0x6663, legacy_sighash(sc, t, 0, 1)) + b"\x01"
    t.ins = [(FUND, 0, b"\x00\x00" + push(b"\x01") + push(sig), 0xffffffff)]
    add("legacy checkmultisig not: an empty signature deletes OP_0 from the script code, " + label, req_for(t, 0, [(5000, spk)], None))

# The 201-operation limit, with OP_CHECKMULTISIG's key count, in witness version 0.
keys = b"".join(push(compressed(G)) for _ in range(20))
for name, ws in (
    ("p2wsh: 201 counted opcodes", NOP * 201 + b"\x51"),
    ("p2wsh: 202 counted opcodes", NOP * 202 + b"\x51"),
    ("p2wsh: 202 counted opcodes, 200 of them in an unexecuted branch", b"\x00\x63" + NOP * 200 + b"\x68\x51"),
    ("p2wsh: 181 counted opcodes plus 20 multisig keys", NOP * 180 + b"\x00\x00" + keys + pushnum(20) + b"\xae"),
    ("p2wsh: 182 counted opcodes plus 20 multisig keys", NOP * 181 + b"\x00\x00" + keys + pushnum(20) + b"\xae"),
):
    add(name, sv_req(b"", p2wsh(ws), [ws]))
    add("p2sh-" + name, sv_req(push(p2wsh(ws)), p2sh(p2wsh(ws)), [ws]))

# An unknown tapleaf version: the control block must still commit to the leaf.
spk_c0, control_c0 = taproot_spk_for_leaf(b"\x51", 0xc0)
spk_c2, control_c2 = taproot_spk_for_leaf(b"\x51", 0xc2)
add("taproot: unknown leaf version 0xc2 with its own commitment", sv_req(b"", spk_c2, [b"\x51", control_c2]))
for parity in (0, 1):
    add("taproot: unknown leaf version 0xc2 claimed for an output that commits to another leaf, parity bit %d" % parity,
        sv_req(b"", spk_c0, [b"\x51", bytes([0xc2 | parity]) + control_c0[1:]]))
add("taproot: unknown leaf version 0xc2, any script, control block of an unrelated key",
    sv_req(b"", spk_c0, [b"\x6a", bytes([0xc2]) + xonly(pmul(7, G))]))

# OP_CHECKMULTISIG fails a tapscript only when executed.
for name, leaf in (("checkmultisig", b"\x00\x63\xae\x68\x51"), ("checkmultisigverify", b"\x00\x63\xaf\x68\x51")):
    spk, control = taproot_spk_for_leaf(leaf)
    add("tapscript: %s in a branch that does not execute" % name, sv_req(b"", spk, [leaf, control]))
leaf = b"\x51\x63\xae\x68\x51"
spk, control = taproot_spk_for_leaf(leaf)
add("tapscript: checkmultisig in a branch that executes", sv_req(b"", spk, [leaf, control]))

# A P2SH-wrapped version 0 witness program of a wrong length.
for n in (2, 19, 21, 31, 33, 40):
    redeem = b"\x00" + push(bytes([1]) * n)
    add("p2sh-wrapped version 0 program of %d bytes" % n, sv_req(push(redeem), p2sh(redeem), [b"\x51"]))

# A P2SH-wrapped witness program that is false as a stack element fails the P2SH evaluation (Appendix A item 32).
for name, redeem in (("version 1, 32 zero bytes", b"\x51" + push(bytes(32))), ("version 1, 2 zero bytes", b"\x51" + push(bytes(2))),
                     ("version 16, 40 zero bytes", b"\x60" + push(bytes(40))), ("version 1, negative zero", b"\x51" + push(bytes(31) + b"\x80"))):
    add("p2sh-wrapped witness program that is false: " + name, sv_req(push(redeem), p2sh(redeem), []))
    add("p2sh-wrapped witness program that is false: " + name + ", with a witness", sv_req(push(redeem), p2sh(redeem), [b"\x51"]))

# A witness on a P2SH input whose redeem script is not a witness program.
redeem = b"\x51"
add("p2sh, redeem script not a witness program, empty witness", sv_req(push(redeem), p2sh(redeem), []))
add("p2sh, redeem script not a witness program, with a witness", sv_req(push(redeem), p2sh(redeem), [b"\x51"]))
add("p2sh, redeem script not a witness program, with a witness holding one empty item", sv_req(push(redeem), p2sh(redeem), [b""]))

# OP_CHECKMULTISIG NOT: strict DER applies to a reached signature even when the public key cannot be parsed.
for name, key in (("empty", b""), ("33 bytes not on the curve", b"\x02" + bytes(32)), ("20 bytes", bytes([3]) * 20)):
    spk = b"\x51" + push(key) + b"\x51\xae\x91"                      # 1 <key> 1 CHECKMULTISIG NOT
    add("checkmultisig not: badly encoded signature against an unparsable public key (%s)" % name, sv_req(b"\x00" + push(b"\x01"), spk, []))
    add("checkmultisig not: badly encoded signature against an unparsable public key (%s), without DERSIG" % name,
        sv_req(b"\x00" + push(b"\x01"), spk, [], flags=NODER))

# Strict DER (DERSIG) in witness version 0, for OP_CHECKSIG and OP_CHECKMULTISIG.
def rs_sign(d, msg32):
    z = int.from_bytes(msg32, "big"); k = int.from_bytes(sha256(msg32 + d.to_bytes(32, "big")), "big") % N or 1
    r = pmul(k, G)[0] % N; s = pow(k, N - 2, N) * (z + r * d) % N
    if s > N // 2: s = N - s
    return r, s
def der_padded(r, s):                      # R with one unnecessary leading zero byte: lax DER accepts it, strict DER does not
    rb = b"\x00" + der_int(r)[2:]
    body = b"\x02" + bytes([len(rb)]) + rb + der_int(s)
    return b"\x30" + bytes([len(body)]) + body
dw = 0x4444; kw = compressed(pmul(dw, G))
tw = Tx(2, [(FUND, 0, b"", 0xffffffff)], OUTS, 0)
for name, spk, code, wit in (
    ("p2wpkh", b"\x00\x14" + h160(kw), b"\x76\xa9\x14" + h160(kw) + b"\x88\xac", lambda sig: [sig, kw]),
    ("p2wsh checksig", p2wsh(push(kw) + b"\xac"), push(kw) + b"\xac", lambda sig: [sig, push(kw) + b"\xac"]),
    ("p2wsh 1-of-1 checkmultisig", p2wsh(b"\x51" + push(kw) + b"\x51\xae"), b"\x51" + push(kw) + b"\x51\xae", lambda sig: [b"", sig, b"\x51" + push(kw) + b"\x51\xae"]),
):
    r, s_ = rs_sign(dw, bip143_sighash(code, tw, 0, 1, 5000))
    for label, sig in (("strict DER signature", der(r, s_) + b"\x01"), ("signature with a padded R (valid only for the lax parser)", der_padded(r, s_) + b"\x01")):
        add("%s: %s" % (name, label), req_for(tw, 0, [(5000, spk)], [wit(sig)]))
        add("%s: %s, without DERSIG" % (name, label), req_for(tw, 0, [(5000, spk)], [wit(sig)], NODER))
for name, ws, wit in (("checksig not", push(kw) + b"\xac\x91", [b"\x01"]), ("1-of-1 checkmultisig not", b"\x51" + push(kw) + b"\x51\xae\x91", [b"", b"\x01"])):
    add("p2wsh %s: one-byte signature" % name, sv_req(b"", p2wsh(ws), wit + [ws]))
    add("p2wsh %s: one-byte signature, without DERSIG" % name, sv_req(b"", p2wsh(ws), wit + [ws], flags=NODER))

# The 520-byte push limit inside a witness version 0 script, executed or not.
for n in (520, 521):
    data = b"\x4d" + n.to_bytes(2, "little") + bytes(n)
    for name, ws in (("executed", data + b"\x75\x51"), ("in a branch that does not execute", b"\x00\x63" + data + b"\x68\x51")):
        add("p2wsh: push of %d bytes in the witness script, %s" % (n, name), sv_req(b"", p2wsh(ws), [ws]))
        add("p2sh-p2wsh: push of %d bytes in the witness script, %s" % (n, name), sv_req(push(p2wsh(ws)), p2sh(p2wsh(ws)), [ws]))

# Arithmetic operands in witness version 0 are limited to 4 bytes.
for name, ws in (("4-byte operands", push(b"\xff\xff\xff\x7f") + b"\x51\x93\x75\x51"), ("5-byte operand", push(b"\x00\x00\x00\x80\x00") + b"\x51\x93\x75\x51"),
                 ("5-byte operand, second position", b"\x51" + push(b"\x00\x00\x00\x80\x00") + b"\x93\x75\x51")):
    add("p2wsh: OP_ADD with " + name, sv_req(b"", p2wsh(ws), [ws]))

# OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY in witness version 0 and in tapscript.
def lock_cases(kind, mk):
    add(kind + ": checklocktimeverify satisfied", mk(b"\x01\x64\xb1\x75\x51", lock=100, seq=0xfffffffe))
    add(kind + ": checklocktimeverify operand above the lock time", mk(b"\x01\x65\xb1\x75\x51", lock=100, seq=0xfffffffe))
    add(kind + ": checklocktimeverify with a final sequence", mk(b"\x01\x64\xb1\x75\x51", lock=100, seq=0xffffffff))
    add(kind + ": checklocktimeverify with a negative operand", mk(b"\x4f\xb1\x75\x51", lock=100, seq=0xfffffffe))
    add(kind + ": checklocktimeverify on an empty stack", mk(b"\xb1\x51", lock=100, seq=0xfffffffe))
    add(kind + ": checksequenceverify satisfied", mk(b"\x5a\xb2\x75\x51", seq=10))
    add(kind + ": checksequenceverify operand above the sequence", mk(b"\x5b\xb2\x75\x51", seq=10))
    add(kind + ": checksequenceverify with transaction version 1", mk(b"\x5a\xb2\x75\x51", seq=10, ver=1))
    add(kind + ": checksequenceverify with the disable bit in the input sequence", mk(b"\x5a\xb2\x75\x51", seq=0x8000000a))
    add(kind + ": checksequenceverify with a negative operand", mk(b"\x4f\xb2\x75\x51", seq=10))
lock_cases("p2wsh", lambda ws, **kw: sv_req(b"", p2wsh(ws), [ws], **kw))
def mk_tap(leaf, **kw):
    spk, control = taproot_spk_for_leaf(leaf)
    return sv_req(b"", spk, [leaf, control], **kw)
lock_cases("tapscript", mk_tap)

# Disabled and undefined opcodes in branches that do not execute, in witness version 0 and in tapscript.
for name, op in (("op_cat", b"\x7e"), ("op_mul", b"\x95"), ("op_verif", b"\x65"), ("op_vernotif", b"\x66"), ("op_ver", b"\x62"), ("op_reserved", b"\x50"), ("op_checksigadd", b"\xba")):
    ws = b"\x00\x63" + op + b"\x68\x51"
    add("p2wsh: %s in a branch that does not execute" % name, sv_req(b"", p2wsh(ws), [ws]))
for name, op in (("op_verif", b"\x65"), ("op_vernotif", b"\x66"), ("op_invalidopcode 0xff", b"\xff"), ("op_checkmultisig", b"\xae")):
    add("tapscript: %s in a branch that does not execute" % name, mk_tap(b"\x00\x63" + op + b"\x68\x51"))

# The 1,000-element stack limit, the alternate stack included, in witness version 0 and in tapscript.
add("p2wsh: 1000 witness stack items then a push (stack of 1001)", sv_req(b"", p2wsh(b"\x51"), [b""] * 1000 + [b"\x51"]))
add("p2wsh: 999 witness stack items then a push (stack of 1000)", sv_req(b"", p2wsh(b"\x51"), [b""] * 999 + [b"\x51"]))
add("tapscript: stack reaches 1001 elements", mk_tap(b"\x51" * 1001 + b"\x6d" * 500))
add("tapscript: stack reaches 1000 elements", mk_tap(b"\x51" * 1000 + b"\x6d" * 499 + b"\x77"))
add("tapscript: stack 601 plus alternate stack 500", mk_tap(b"\x51" * 600 + b"\x6b" * 500 + b"\x51" * 501 + b"\x6d" * 300))
add("tapscript: 500 elements moved to the alternate stack, then 500 more on the stack (1000 together)", mk_tap(b"\x51" * 500 + b"\x6b" * 500 + b"\x51" * 500 + b"\x6d" * 249 + b"\x77"))

# Tapscript MINIMALIF applies to OP_NOTIF as well as OP_IF.
for name, op in (("op_if", b"\x63"), ("op_notif", b"\x64")):
    for arg_name, arg in (("0x02", b"\x02"), ("0x0100", b"\x01\x00"), ("0x00", b"\x00"), ("0x01", b"\x01"), ("empty", b"")):
        spk, control = taproot_spk_for_leaf(op + b"\x68\x51")
        add("tapscript: %s with argument %s" % (name, arg_name), sv_req(b"", spk, [arg, op + b"\x68\x51", control]))

# Rules that only the block corpus reached before: the witness script size limit, the 520-byte limit on P2WPKH
# items, NULLDUMMY in witness version 0, taproot key path hash types, a lone item that starts with 0x50 (not an
# annex), and the control block size limit.
def pad_to(n):                                     # a witness script of exactly n bytes that leaves one true element
    body = n - 4; sc = b""
    while body - len(sc) >= 523: sc += push(bytes(520))
    while len(sc) < body:
        r = body - len(sc)
        sc += b"\x00" if r == 1 else push(bytes(min(r - 1, 75)))
    sc = b"\x00\x63" + sc + b"\x68\x51"; assert len(sc) == n
    return sc
for n in (521, 10000, 10001):
    ws = pad_to(n)
    add("p2wsh: witness script of %d bytes" % n, sv_req(b"", p2wsh(ws), [ws]))
    add("p2sh-p2wsh: witness script of %d bytes" % n, sv_req(push(p2wsh(ws)), p2sh(p2wsh(ws)), [ws]))
big = bytes([2]) + bytes(520)
add("p2wpkh: public key item of 521 bytes", sv_req(b"", b"\x00\x14" + h160(big), [b"\x01", big]))
add("p2wpkh: signature item of 521 bytes", sv_req(b"", b"\x00\x14" + h160(kw), [bytes(521), kw]))
ws = b"\x51" + push(kw) + b"\x51\xae"
r, s_ = rs_sign(dw, bip143_sighash(ws, tw, 0, 1, 5000))
for label, dummy in (("empty dummy", b""), ("dummy 0x00", b"\x00"), ("dummy 0x01", b"\x01")):
    add("p2wsh 1-of-1 checkmultisig: " + label, req_for(tw, 0, [(5000, p2wsh(ws))], [[dummy, der(r, s_) + b"\x01", ws]]))
    add("p2wsh 1-of-1 checkmultisig: " + label + ", without NULLDUMMY", req_for(tw, 0, [(5000, p2wsh(ws))], [[dummy, der(r, s_) + b"\x01", ws]], [f for f in ALL if f != "NULLDUMMY"]))
dk = 0x5555; Pk = pmul(dk, G)
if Pk[1] % 2: dk = N - dk; Pk = pmul(dk, G)
spk_k = b"\x51\x20" + xonly(Pk)
tk = Tx(2, [(FUND, 0, b"", 0xffffffff)], OUTS, 0)
for ht in (0x00, 0x01, 0x80, 0x81, 0x04, 0x84):
    sig = bip340_sign(dk, bip341_sighash(tk, 0, ht, [(5000, spk_k)], check_hash_type=False)) + (bytes([ht]) if ht else b"")
    add("taproot key path: hash type 0x%02x" % ht + (" given as a 65th byte" if ht == 0 else ""), req_for(tk, 0, [(5000, spk_k)], [[sig + (b"\x00" if ht == 0 else b"")]]))
for lock in range(1, 4000):
    tk.lock = lock
    sig = bip340_sign(dk, bip341_sighash(tk, 0, 0, [(5000, spk_k)]))
    if sig[0] == 0x50: break
assert sig[0] == 0x50
add("taproot key path: 64-byte signature that starts with 0x50 as the only witness item", req_for(tk, 0, [(5000, spk_k)], [[sig]]))
tk.lock = 0
for nodes in (128, 129):
    spk, control = taproot_spk_for_leaf(b"\x51", path=bytes([9]) * (32 * nodes))
    add("tapscript: correctly committed leaf at depth %d" % nodes, sv_req(b"", spk, [b"\x51", control]))

# P2SH-wrapped witness programs of versions above 0: the signature script must still be the canonical push.
for name, redeem in (("version 1, 32 bytes", b"\x51" + push(bytes([1]) * 32)), ("version 2, 2 bytes", b"\x52" + push(bytes([1]) * 2)), ("version 16, 40 bytes", b"\x60" + push(bytes([1]) * 40))):
    add("p2sh-wrapped %s: canonical push" % name, sv_req(push(redeem), p2sh(redeem), []))
    add("p2sh-wrapped %s: redeem script pushed with OP_PUSHDATA1" % name, sv_req(b"\x4c" + bytes([len(redeem)]) + redeem, p2sh(redeem), []))
    add("p2sh-wrapped %s: an extra push before the redeem script" % name, sv_req(b"\x51" + push(redeem), p2sh(redeem), []))

# The edges of every OP_SUCCESS range: a leaf of OP_RETURN followed by the opcode.
for op in (0x4f, 0x50, 0x51, 0x61, 0x62, 0x63, 0x7d, 0x7e, 0x81, 0x82, 0x83, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x94, 0x95, 0x99, 0x9a, 0xba, 0xbb, 0xfe, 0xff):
    add("tapscript: op_return then opcode 0x%02x" % op, mk_tap(b"\x6a" + bytes([op])))

# Every opcode from 0x4f to 0xff alone as a tapscript, so that each OP_SUCCESS opcode is decisive in some case and
# not only at the edges of its range.
for op in range(0x4f, 0x100):
    add("tapscript: the single opcode 0x%02x" % op, mk_tap(bytes([op])))

with open(OUT, "w") as f:
    for o in out:
        f.write(json.dumps(o) + "\n")
for o in out:
    print("%-105s %s" % (o["name"], o["expect"]))
