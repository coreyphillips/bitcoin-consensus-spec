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
h = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
with open(OUT, "w") as f:
    for i, (name, req) in enumerate(cases):
        req2 = dict(req); req2["id"] = i + 1
        h.stdin.write(json.dumps(req2) + "\n"); h.stdin.flush()
        resp = json.loads(h.stdout.readline())
        assert resp.get("ok"), (name, resp)
        expect = {k: v for k, v in resp.items() if k in ("valid", "script_error", "reason")}
        f.write(json.dumps({"name": name, "request": req, "expect": expect}) + "\n")
        print("%-52s %s" % (name, expect))
