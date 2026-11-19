"""Writes the signet suite's cases, with the answers of the Core oracle as expectations.

Usage: python3 generate.py <oracle-core-harness> <out.jsonl>

Every block is built and signed here, under challenges chosen for the case. Each case also states
the verdict it was built for, and the script stops if the oracle disagrees, so a mistake in this
file cannot quietly turn a case meant to be valid into one more invalid case.
"""

import hashlib
import hmac
import json
import subprocess
import sys

ORACLE, OUT = sys.argv[1], sys.argv[2]

SIGNET_HEADER = bytes.fromhex("ecc7daa2")
COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")
SIGNET_BITS = 0x1E0377AE
SIGHASH_ALL = 1

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


def der_int(v, pad=False):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")  # a leading zero when the top bit is set
    if pad:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sign(secret, digest, pad_r=False):
    """Low-S ECDSA with a nonce derived from the key and the digest. `pad_r` gives R a superfluous
    leading zero, which strict DER (BIP66) rejects."""
    z = int.from_bytes(digest, "big")
    k = int.from_bytes(hmac.new(secret.to_bytes(32, "big"), digest, hashlib.sha256).digest(), "big") % N
    r = point_mul(k)[0] % N
    s = pow(k, N - 2, N) * (z + r * secret) % N
    s = min(s, N - s)
    body = der_int(r, pad_r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([SIGHASH_ALL])


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def var_bytes(b):
    return compact_size(len(b)) + b


def push(data):
    """Canonical push encoding of non-empty data (CScript << vector)."""
    if len(data) < 0x4C:
        return bytes([len(data)]) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes([len(data)]) + data
    return b"\x4d" + len(data).to_bytes(2, "little") + data


class Tx:
    def __init__(self, inputs, outputs, version=1, lock_time=0):
        self.version, self.inputs, self.outputs, self.lock_time = version, inputs, outputs, lock_time

    def serialize(self, witness=True):
        witness = witness and any(i[4] for i in self.inputs)
        out = self.version.to_bytes(4, "little")
        if witness:
            out += b"\x00\x01"
        out += compact_size(len(self.inputs))
        for txid, vout, script_sig, sequence, _ in self.inputs:
            out += txid + vout.to_bytes(4, "little") + var_bytes(script_sig) + sequence.to_bytes(4, "little")
        out += compact_size(len(self.outputs))
        for value, script in self.outputs:
            out += value.to_bytes(8, "little") + var_bytes(script)
        if witness:
            for *_, stack in self.inputs:
                out += compact_size(len(stack)) + b"".join(var_bytes(item) for item in stack)
        return out + self.lock_time.to_bytes(4, "little")

    def txid(self):
        return sha256d(self.serialize(witness=False))

    def wtxid(self):
        return sha256d(self.serialize())


def merkle_root(leaves):
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves = leaves + leaves[-1:]
        leaves = [sha256d(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
    return leaves[0]


def get_ops(script):
    """(opcode, data) pairs as CScript::GetOp reads them, stopping at a malformed operation."""
    pos, ops = 0, []
    while pos < len(script):
        opcode = script[pos]
        pos += 1
        if opcode <= 0x4E:
            if opcode < 0x4C:
                size = opcode
            else:
                width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[opcode]
                if pos + width > len(script):
                    break
                size = int.from_bytes(script[pos:pos + width], "little")
                pos += width
            if pos + size > len(script):
                break
            ops.append((opcode, script[pos:pos + size]))
            pos += size
        else:
            ops.append((opcode, b""))
    return ops


def cleared(script):
    """The commitment script with the solution cleared, as BIP325 signs it."""
    out, found = b"", False
    for opcode, data in get_ops(script):
        if data:
            if not found and len(data) > 4 and data[:4] == SIGNET_HEADER:
                data, found = SIGNET_HEADER, True
            out += push(data)
        else:
            out += bytes([opcode])
    return out


def commitment_script(extra=b""):
    return COMMITMENT_PREFIX + bytes(32) + extra


class Block:
    def __init__(self, prev=b"\x11" * 32, time=1_700_000_000, extra_txs=(), outputs=None, version=0x20000000):
        self.version, self.prev, self.time, self.bits, self.nonce = version, prev, time, SIGNET_BITS, 0
        self.extra_txs = list(extra_txs)
        # The coinbase's outputs; `None` stands for the commitment output, completed by `finish`.
        self.outputs = outputs if outputs is not None else [(50_0000_0000, bytes.fromhex("51")), None]

    def coinbase(self, commitment_tail):
        outputs = []
        for out in self.outputs:
            if out is None:
                outputs.append((0, commitment_script(commitment_tail)))
            else:
                outputs.append(out)
        return Tx([(bytes(32), 0xFFFFFFFF, bytes.fromhex("0151"), 0xFFFFFFFF, [bytes(32)])], outputs)

    def block_data(self, commitment_tail, clear=True):
        """What the solution signs: the coinbase with `commitment_tail`, the solution cleared from
        the last commitment output unless `clear` is false (the tail is then signed as it is)."""
        cb = self.coinbase(commitment_tail)
        if clear:
            last = max(i for i, (_, s) in enumerate(cb.outputs) if s[:6] == COMMITMENT_PREFIX and len(s) >= 38)
            value, script = cb.outputs[last]
            cb.outputs[last] = (value, cleared(script))
        root = merkle_root([cb.txid()] + [tx.txid() for tx in self.extra_txs])
        return self.version.to_bytes(4, "little", signed=True) + self.prev + root + self.time.to_bytes(4, "little")

    def serialize(self, commitment_tail):
        cb = self.coinbase(commitment_tail)
        txs = [cb] + self.extra_txs
        root = merkle_root([tx.txid() for tx in txs])
        header = (self.version.to_bytes(4, "little", signed=True) + self.prev + root
                  + self.time.to_bytes(4, "little") + self.bits.to_bytes(4, "little") + self.nonce.to_bytes(4, "little"))
        return header + compact_size(len(txs)) + b"".join(tx.serialize() for tx in txs)


def to_sign_sighash(block_data, challenge):
    """Legacy SIGHASH_ALL digest of BIP325's to_sign, whose script code is the challenge."""
    to_spend = Tx([(bytes(32), 0xFFFFFFFF, b"\x00" + push(block_data), 0, [])], [(0, challenge)], version=0)
    to_sign = Tx([(to_spend.txid(), 0, challenge, 0, [])], [(0, b"\x6a")], version=0)
    return sha256d(to_sign.serialize(witness=False) + SIGHASH_ALL.to_bytes(4, "little"))


def solution(script_sig, witness=()):
    return var_bytes(script_sig) + compact_size(len(witness)) + b"".join(var_bytes(w) for w in witness)


KEY, OTHER_KEY = 0x5157, 0x7E57
P2PK = push(pubkey(KEY)) + b"\xac"
MULTISIG = b"\x51" + push(pubkey(KEY)) + b"\x51\xae"
OP_TRUE = b"\x51"
P2WSH_TRUE = b"\x00\x20" + hashlib.sha256(OP_TRUE).digest()
WITNESS_V1 = b"\x51\x20" + bytes(range(32))

cases = []


def case(name, block_bytes, challenge, valid):
    cases.append((name, {"op": "signet_check", "block": block_bytes.hex(), "challenge": challenge.hex()}, valid))


def signed_tail(block, challenge=P2PK, key=KEY, before=b"", after=b"", sign_tail=None, wrap=push, pad_r=False,
                script_sig=None):
    """The commitment output's tail with a P2PK (or 1-of-1 multisig) solution: `before` and `after`
    surround the solution push. The signature covers the tail with the solution cleared, or
    `sign_tail` exactly as given."""
    # Any solution longer than nothing clears to the same script as the real one.
    placeholder = before + wrap(SIGNET_HEADER + b"\x00") + after
    data = block.block_data(placeholder) if sign_tail is None else block.block_data(sign_tail, clear=False)
    sig = sign(key, to_sign_sighash(data, challenge), pad_r)
    return before + wrap(SIGNET_HEADER + solution(script_sig(sig) if script_sig else push(sig))) + after


b = Block()
tail = signed_tail(b)
case("P2PK challenge, signed block", b.serialize(tail), P2PK, True)
b.nonce, b.bits = 12345, 0x1D00FFFF
case("P2PK challenge, nonce and bits changed after signing (not signed)", b.serialize(tail), P2PK, True)
for field, value in [("time", 1_700_000_001), ("version", 0x20000001), ("prev", b"\x22" * 32)]:
    b = Block()
    tail = signed_tail(b)
    setattr(b, field, value)
    case(f"P2PK challenge, {field} changed after signing", b.serialize(tail), P2PK, False)

spend = Tx([(b"\x33" * 32, 0, b"\x51", 0xFFFFFFFF, [])], [(1000, b"\x51")])
b = Block()
tail = signed_tail(b)
b.extra_txs = [spend]
case("P2PK challenge, transaction added after signing", b.serialize(tail), P2PK, False)
b = Block(extra_txs=[spend])
case("P2PK challenge, signed block with two transactions", b.serialize(signed_tail(b)), P2PK, True)
b = Block(extra_txs=[spend, Tx([(b"\x44" * 32, 1, b"", 0, [b"\x51"])], [(1, b"\x51")])])
tail = signed_tail(b)
b.extra_txs.reverse()
case("P2PK challenge, transactions reordered after signing", b.serialize(tail), P2PK, False)
b = Block(extra_txs=[Tx([(b"\x44" * 32, 1, b"", 0, [b"\x51"])], [(1, b"\x51")])])
tail = signed_tail(b)
b.extra_txs[0].inputs[0] = (b"\x44" * 32, 1, b"", 0, [b"\x52"])
case("P2PK challenge, witness of a transaction changed after signing (wtxid not signed)", b.serialize(tail), P2PK, True)

case("P2PK challenge, signed by another key", Block().serialize(signed_tail(Block(), key=OTHER_KEY)), P2PK, False)
case("P2PK challenge, solution of a different block", Block().serialize(signed_tail(Block(prev=b"\x22" * 32))), P2PK, False)
case("P2PK challenge, solution signed for a different challenge",
     Block().serialize(signed_tail(Block(), challenge=MULTISIG)), P2PK, False)
case("P2PK challenge, signature not strict DER", Block().serialize(signed_tail(Block(), pad_r=True)), P2PK, False)
case("P2PK challenge, commitment output without solution", Block().serialize(b""), P2PK, False)
case("P2PK challenge, solution push of the header alone", Block().serialize(push(SIGNET_HEADER)), P2PK, False)

b = Block(outputs=[(50_0000_0000, b"\x51"), (0, b"\x6a" + signed_tail(Block()))])
case("P2PK challenge, solution in an OP_RETURN output that is not a commitment", b.serialize(b""), P2PK, False)
b = Block(outputs=[(50_0000_0000, b"\x51")])
case("OP_TRUE challenge, no commitment output", b.serialize(b""), OP_TRUE, False)
b = Block(outputs=[(50_0000_0000, b"\x51"), (0, bytes.fromhex("6a23aa21a9ed") + bytes(31) + push(SIGNET_HEADER + solution(b"")))])
case("OP_TRUE challenge, commitment output one byte short", b.serialize(b""), OP_TRUE, False)
case("OP_TRUE challenge, commitment output without solution", Block().serialize(b""), OP_TRUE, True)
case("OP_TRUE challenge, empty solution", Block().serialize(push(SIGNET_HEADER + solution(b""))), OP_TRUE, True)
case("OP_TRUE challenge, solution with a byte left over", Block().serialize(push(SIGNET_HEADER + solution(b"") + b"\x00")), OP_TRUE, False)
case("OP_TRUE challenge, solution cut short", Block().serialize(push(SIGNET_HEADER + b"\x05\x01")), OP_TRUE, False)
case("OP_TRUE challenge, solution without its witness stack", Block().serialize(push(SIGNET_HEADER + b"\x00")), OP_TRUE, False)
case("OP_TRUE challenge, block without transactions", bytes(72) + SIGNET_BITS.to_bytes(4, "little") + bytes(4) + b"\x00", OP_TRUE, False)

# Where the solution is found, and what the signed coinbase looks like around it.
b = Block()
case("P2PK challenge, a 4-byte header push before the solution is skipped",
     b.serialize(signed_tail(b, before=push(SIGNET_HEADER))), P2PK, True)
b = Block()
case("P2PK challenge, only the first solution push counts",
     b.serialize(signed_tail(b, after=push(SIGNET_HEADER + b"\xff\xff"))), P2PK, True)
b = Block()
case("P2PK challenge, a solution push after an invalid one is not read",
     b.serialize(signed_tail(b, before=push(SIGNET_HEADER + b"\xff\xff"))), P2PK, False)
b = Block()
case("P2PK challenge, solution pushed with OP_PUSHDATA2",
     b.serialize(signed_tail(b, wrap=lambda d: b"\x4d" + len(d).to_bytes(2, "little") + d)), P2PK, True)
b = Block()
case("P2PK challenge, another push re-encoded canonically before signing",
     b.serialize(signed_tail(b, after=b"\x4c\x01\x07", sign_tail=push(SIGNET_HEADER) + b"\x01\x07")), P2PK, True)
b = Block()
case("P2PK challenge, signed over the push as it is encoded instead of canonically",
     b.serialize(signed_tail(b, after=b"\x4c\x01\x07", sign_tail=push(SIGNET_HEADER) + b"\x4c\x01\x07")), P2PK, False)
b = Block()
case("P2PK challenge, an empty OP_PUSHDATA1 push signed as its opcode alone",
     b.serialize(signed_tail(b, after=b"\x4c\x00", sign_tail=push(SIGNET_HEADER) + b"\x4c")), P2PK, True)
b = Block()
case("P2PK challenge, opcodes after the solution are signed",
     b.serialize(signed_tail(b, after=b"\x61\x75")), P2PK, True)
b = Block()
case("P2PK challenge, a malformed push after the solution is dropped before signing",
     b.serialize(signed_tail(b, after=b"\x4c\x09\x01", sign_tail=push(SIGNET_HEADER))), P2PK, True)
b = Block()
case("P2PK challenge, signed with the malformed push kept",
     b.serialize(signed_tail(b, after=b"\x4c\x09\x01", sign_tail=push(SIGNET_HEADER) + b"\x4c\x09\x01")), P2PK, False)

# Two commitment outputs: the last one is the commitment.
b = Block(outputs=[(50_0000_0000, b"\x51"), (0, commitment_script()), None])
case("P2PK challenge, two commitment outputs, solution in the last", b.serialize(signed_tail(b)), P2PK, True)
b = Block(outputs=[(50_0000_0000, b"\x51"), None, (0, commitment_script())])
case("P2PK challenge, two commitment outputs, solution in the first", b.serialize(signed_tail(b)), P2PK, False)

# Script flags: P2SH, WITNESS, DERSIG and NULLDUMMY, nothing else.
b = Block()
case("1-of-1 multisig challenge, null dummy", b.serialize(signed_tail(b, challenge=MULTISIG, script_sig=lambda s: b"\x00" + push(s))), MULTISIG, True)
b = Block()
case("1-of-1 multisig challenge, dummy OP_1 (NULLDUMMY)", b.serialize(signed_tail(b, challenge=MULTISIG, script_sig=lambda s: b"\x51" + push(s))), MULTISIG, False)
case("P2WSH challenge, witness script OP_TRUE", Block().serialize(push(SIGNET_HEADER + solution(b"", [OP_TRUE]))), P2WSH_TRUE, True)
case("P2WSH challenge, empty witness", Block().serialize(push(SIGNET_HEADER + solution(b""))), P2WSH_TRUE, False)
case("P2WSH challenge, script_sig not empty", Block().serialize(push(SIGNET_HEADER + solution(b"\x51", [OP_TRUE]))), P2WSH_TRUE, False)
case("P2WSH challenge, witness in the script_sig", Block().serialize(push(SIGNET_HEADER + solution(push(OP_TRUE)))), P2WSH_TRUE, False)
case("witness v1 challenge, empty solution (TAPROOT not checked)", Block().serialize(push(SIGNET_HEADER + solution(b""))), WITNESS_V1, True)
case("witness v1 challenge, no solution", Block().serialize(b""), WITNESS_V1, True)

# The genesis block needs no solution, whatever the challenge.
genesis_cb = bytes.fromhex(
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d"
    "65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062"
    "616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef"
    "38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
genesis_header = (b"\x01\x00\x00\x00" + bytes(32) + sha256d(genesis_cb) + (1598918400).to_bytes(4, "little")
                  + SIGNET_BITS.to_bytes(4, "little") + (52613770).to_bytes(4, "little"))
assert sha256d(genesis_header)[::-1].hex() == "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
case("P2PK challenge, signet genesis block", genesis_header + b"\x01" + genesis_cb, P2PK, True)
case("P2PK challenge, signet genesis block with another nonce", genesis_header[:76] + (52613771).to_bytes(4, "little") + b"\x01" + genesis_cb, P2PK, False)

proc = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
with open(OUT, "w") as out:
    for i, (name, request, intended) in enumerate(cases):
        proc.stdin.write(json.dumps({"id": i, **request}) + "\n")
        proc.stdin.flush()
        answer = json.loads(proc.stdout.readline())
        if answer.get("id") != i or answer.get("ok") is not True:
            sys.exit(f"{name}: {answer}")
        del answer["id"], answer["ok"]
        if answer != {"valid": intended}:
            sys.exit(f"{name}: built to be {'valid' if intended else 'invalid'}, Core says {answer}")
        out.write(json.dumps({"name": name, "request": request, "expect": answer}, separators=(", ", ": ")) + "\n")
proc.stdin.close()
proc.wait()
print(f"{len(cases)} cases written to {OUT}")
