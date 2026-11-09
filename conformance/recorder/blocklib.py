"""Minimal Bitcoin block and transaction codec plus the context-free checks
that Bitcoin Core v32.1 applies before a block reaches contextual validation.

Used by the recorder (to reproduce the bytes Core validated) and by the Core
chain harness (to emulate the P2P delivery path, which differs from the
submitblock RPC in a few places). Everything here mirrors v32.1 source:

- deserialization: primitives/transaction.h (UnserializeTransaction),
  serialize.h (ReadCompactSize with range check)
- merkle roots: consensus/merkle.cpp (ComputeMerkleRoot, mutation flag)
- IsBlockMutated, CheckWitnessMalleation, CheckMerkleRoot, CheckBlock:
  validation.cpp
- CheckTransaction: consensus/tx_check.cpp
- GetSigOpCount(false): script/script.cpp
- SetCompact / GetBlockProof / CheckProofOfWork: arith_uint256.cpp, chain.cpp, pow.cpp
"""

import hashlib
import struct

MAX_SIZE = 0x02000000
MAX_BLOCK_WEIGHT = 4_000_000
WITNESS_SCALE_FACTOR = 4
MAX_BLOCK_SIGOPS_COST = 80_000
MAX_MONEY = 21_000_000 * 100_000_000
MINIMUM_WITNESS_COMMITMENT = 38
WITNESS_COMMITMENT_PREFIX = bytes([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
REGTEST_POW_LIMIT = int("7f" + "ff" * 31, 16)  # kernel/chainparams.cpp, CRegTestParams
U256 = (1 << 256) - 1

# Reject reasons produced by CheckBlock (and the CheckTransaction calls it makes).
CHECKBLOCK_REASONS = {
    "high-hash", "bad-txnmrklroot", "bad-txns-duplicate", "bad-blk-length",
    "bad-cb-missing", "bad-cb-multiple", "bad-blk-sigops",
    "bad-txns-vin-empty", "bad-txns-vout-empty", "bad-txns-oversize",
    "bad-txns-vout-negative", "bad-txns-vout-toolarge", "bad-txns-txouttotal-toolarge",
    "bad-txns-inputs-duplicate", "bad-cb-length", "bad-txns-prevout-null",
}
# Reject reasons Core classifies as BLOCK_MUTATED.
MUTATED_REASONS = {
    "bad-txnmrklroot", "bad-txns-duplicate", "bad-witness-nonce-size",
    "bad-witness-merkle-match", "unexpected-witness",
}


class DecodeError(Exception):
    pass


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_to_hex(h):
    """Raw-order 32-byte hash to display-order hex."""
    return h[::-1].hex()


def hex_to_hash(s):
    """Display-order hex to raw-order 32 bytes."""
    return bytes.fromhex(s)[::-1]


class Reader:
    __slots__ = ("b", "p")

    def __init__(self, b, p=0):
        self.b = b
        self.p = p

    def read(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise DecodeError("end of data")
        r = self.b[self.p:self.p + n]
        self.p += n
        return r

    def u8(self):
        return self.read(1)[0]

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def i32(self):
        return struct.unpack("<i", self.read(4))[0]

    def i64(self):
        return struct.unpack("<q", self.read(8))[0]

    def compact(self):
        c = self.u8()
        if c < 253:
            v = c
        elif c == 253:
            v = struct.unpack("<H", self.read(2))[0]
            if v < 253:
                raise DecodeError("non-canonical ReadCompactSize()")
        elif c == 254:
            v = struct.unpack("<I", self.read(4))[0]
            if v < 0x10000:
                raise DecodeError("non-canonical ReadCompactSize()")
        else:
            v = struct.unpack("<Q", self.read(8))[0]
            if v < 0x100000000:
                raise DecodeError("non-canonical ReadCompactSize()")
        if v > MAX_SIZE:
            raise DecodeError("ReadCompactSize(): size too large")
        return v

    def varbytes(self):
        return self.read(self.compact())


def ser_compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class TxIn:
    __slots__ = ("prev_hash", "prev_n", "script_sig", "sequence", "witness")

    def __init__(self, prev_hash, prev_n, script_sig, sequence):
        self.prev_hash = prev_hash
        self.prev_n = prev_n
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = []


class Tx:
    __slots__ = ("version", "vin", "vout", "locktime")

    def __init__(self):
        self.version = 1
        self.vin = []
        self.vout = []  # list of (value, script_pubkey)
        self.locktime = 0

    def has_witness(self):
        return any(len(i.witness) > 0 for i in self.vin)

    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prev_hash == b"\x00" * 32 and self.vin[0].prev_n == 0xffffffff

    def serialize(self, with_witness=True):
        flags = 1 if (with_witness and self.has_witness()) else 0
        out = [struct.pack("<i", self.version)]
        if flags:
            out.append(b"\x00")
            out.append(bytes([flags]))
        out.append(ser_compact(len(self.vin)))
        for i in self.vin:
            out.append(i.prev_hash)
            out.append(struct.pack("<I", i.prev_n))
            out.append(ser_compact(len(i.script_sig)))
            out.append(i.script_sig)
            out.append(struct.pack("<I", i.sequence))
        out.append(ser_compact(len(self.vout)))
        for value, spk in self.vout:
            out.append(struct.pack("<q", value))
            out.append(ser_compact(len(spk)))
            out.append(spk)
        if flags:
            for i in self.vin:
                out.append(ser_compact(len(i.witness)))
                for item in i.witness:
                    out.append(ser_compact(len(item)))
                    out.append(item)
        out.append(struct.pack("<I", self.locktime))
        return b"".join(out)

    def txid(self):
        return sha256d(self.serialize(with_witness=False))

    def wtxid(self):
        return sha256d(self.serialize(with_witness=True))


def _read_vin(r):
    n = r.compact()
    vin = []
    for _ in range(n):
        h = r.read(32)
        idx = r.u32()
        ss = r.varbytes()
        seq = r.u32()
        vin.append(TxIn(h, idx, ss, seq))
    return vin


def _read_vout(r):
    n = r.compact()
    vout = []
    for _ in range(n):
        v = r.i64()
        spk = r.varbytes()
        vout.append((v, spk))
    return vout


def read_tx(r):
    """UnserializeTransaction with witness allowed (TX_WITH_WITNESS)."""
    tx = Tx()
    tx.version = r.i32()
    flags = 0
    tx.vin = _read_vin(r)
    if len(tx.vin) == 0:
        flags = r.u8()
        if flags != 0:
            tx.vin = _read_vin(r)
            tx.vout = _read_vout(r)
    else:
        tx.vout = _read_vout(r)
    if flags & 1:
        flags ^= 1
        for i in tx.vin:
            n = r.compact()
            i.witness = [r.varbytes() for _ in range(n)]
        if not tx.has_witness():
            raise DecodeError("Superfluous witness record")
    if flags:
        raise DecodeError("Unknown transaction optional data")
    tx.locktime = r.u32()
    return tx


class Header:
    __slots__ = ("version", "prev", "merkle", "time", "bits", "nonce", "raw")

    def __init__(self, raw):
        if len(raw) != 80:
            raise DecodeError("header must be 80 bytes")
        self.raw = raw
        self.version, = struct.unpack("<i", raw[0:4])
        self.prev = raw[4:36]
        self.merkle = raw[36:68]
        self.time, self.bits, self.nonce = struct.unpack("<III", raw[68:80])

    def hash(self):
        return sha256d(self.raw)

    def hash_hex(self):
        return hash_to_hex(self.hash())

    def prev_hex(self):
        return hash_to_hex(self.prev)


class Block:
    __slots__ = ("header", "vtx", "trailing")

    def __init__(self, header, vtx, trailing=0):
        self.header = header
        self.vtx = vtx
        self.trailing = trailing

    def serialize(self, with_witness=True):
        return self.header.raw + ser_compact(len(self.vtx)) + b"".join(t.serialize(with_witness) for t in self.vtx)

    def stripped_size(self):
        return len(self.serialize(with_witness=False))


def parse_block(data, allow_trailing=True):
    r = Reader(data)
    header = Header(r.read(80))
    n = r.compact()
    vtx = [read_tx(r) for _ in range(n)]
    trailing = len(data) - r.p
    if trailing and not allow_trailing:
        raise DecodeError("trailing data")
    return Block(header, vtx, trailing)


# ---------------------------------------------------------------- merkle trees

def compute_merkle_root(hashes):
    """ComputeMerkleRoot: returns (root, mutated)."""
    hashes = list(hashes)
    mutation = False
    while len(hashes) > 1:
        for pos in range(0, len(hashes) - 1, 2):
            if hashes[pos] == hashes[pos + 1]:
                mutation = True
        if len(hashes) & 1:
            hashes.append(hashes[-1])
        hashes = [sha256d(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    if not hashes:
        return b"\x00" * 32, mutation
    return hashes[0], mutation


def block_merkle_root(block):
    return compute_merkle_root([t.txid() for t in block.vtx])


def block_witness_merkle_root(block):
    leaves = [b"\x00" * 32] + [t.wtxid() for t in block.vtx[1:]]
    return compute_merkle_root(leaves)[0]


def witness_commitment_index(block):
    pos = -1
    if block.vtx:
        for o, (_, spk) in enumerate(block.vtx[0].vout):
            if len(spk) >= MINIMUM_WITNESS_COMMITMENT and spk[:6] == WITNESS_COMMITMENT_PREFIX:
                pos = o
    return pos


def check_merkle_root(block):
    """CheckMerkleRoot: None if fine, else the reject reason."""
    root, mutated = block_merkle_root(block)
    if block.header.merkle != root:
        return "bad-txnmrklroot"
    if mutated:
        return "bad-txns-duplicate"
    return None


def check_witness_malleation(block, expect_witness_commitment):
    if expect_witness_commitment:
        pos = witness_commitment_index(block)
        if pos != -1:
            stack = block.vtx[0].vin[0].witness
            if len(stack) != 1 or len(stack[0]) != 32:
                return "bad-witness-nonce-size"
            h = sha256d(block_witness_merkle_root(block) + stack[0])
            if h != block.vtx[0].vout[pos][1][6:38]:
                return "bad-witness-merkle-match"
            return None
    for t in block.vtx:
        if t.has_witness():
            return "unexpected-witness"
    return None


def is_block_mutated(block, check_witness_root):
    """IsBlockMutated (validation.cpp): returns the reason string or None."""
    reason = check_merkle_root(block)
    if reason:
        return reason
    if not block.vtx or not block.vtx[0].is_coinbase():
        for t in block.vtx:
            if len(t.serialize(with_witness=False)) == 64:
                return "64-byte-transaction"
        return None
    return check_witness_malleation(block, check_witness_root)


def update_uncommitted_block_structures(block, segwit_active_after_prev):
    """ChainstateManager::UpdateUncommittedBlockStructures. Returns True if changed."""
    pos = witness_commitment_index(block)
    if pos != -1 and segwit_active_after_prev and not block.vtx[0].has_witness():
        block.vtx[0].vin[0].witness = [b"\x00" * 32]
        return True
    return False


# --------------------------------------------------------- proof of work, work

def set_compact(n):
    """arith_uint256::SetCompact: returns (value, negative, overflow)."""
    size = n >> 24
    word = n & 0x007fffff
    if size <= 3:
        word >>= 8 * (3 - size)
        value = word
    else:
        value = (word << (8 * (size - 3))) & U256
    negative = word != 0 and (n & 0x00800000) != 0
    overflow = word != 0 and (size > 34 or (word > 0xff and size > 33) or (word > 0xffff and size > 32))
    return value, negative, overflow


def derive_target(bits, pow_limit=REGTEST_POW_LIMIT):
    target, neg, ovf = set_compact(bits)
    if neg or target == 0 or ovf or target > pow_limit:
        return None
    return target


def check_proof_of_work(hash_raw, bits, pow_limit=REGTEST_POW_LIMIT):
    target = derive_target(bits, pow_limit)
    if target is None:
        return False
    return int.from_bytes(hash_raw, "little") <= target


def block_proof(bits):
    """GetBlockProof (chain.cpp)."""
    target, neg, ovf = set_compact(bits)
    if neg or ovf or target == 0:
        return 0
    return ((~target & U256) // (target + 1)) + 1


# ------------------------------------------------------ context-free checks

OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY = 0xac, 0xad, 0xae, 0xaf
OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x4c, 0x4d, 0x4e


def legacy_sigop_count(script):
    """CScript::GetSigOpCount(fAccurate=false)."""
    n = 0
    i = 0
    end = len(script)
    while i < end:
        op = script[i]
        i += 1
        if op <= OP_PUSHDATA4:
            if op < OP_PUSHDATA1:
                size = op
            elif op == OP_PUSHDATA1:
                if end - i < 1:
                    break
                size = script[i]
                i += 1
            elif op == OP_PUSHDATA2:
                if end - i < 2:
                    break
                size = int.from_bytes(script[i:i + 2], "little")
                i += 2
            else:
                if end - i < 4:
                    break
                size = int.from_bytes(script[i:i + 4], "little")
                i += 4
            if end - i < size:
                break
            i += size
            continue
        if op in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            n += 1
        elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            n += 20
    return n


def check_transaction(tx):
    """CheckTransaction (consensus/tx_check.cpp): None or reject reason."""
    if not tx.vin:
        return "bad-txns-vin-empty"
    if not tx.vout:
        return "bad-txns-vout-empty"
    if len(tx.serialize(with_witness=False)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        return "bad-txns-oversize"
    total = 0
    for value, _ in tx.vout:
        if value < 0:
            return "bad-txns-vout-negative"
        if value > MAX_MONEY:
            return "bad-txns-vout-toolarge"
        total += value
        if not (0 <= total <= MAX_MONEY):
            return "bad-txns-txouttotal-toolarge"
    seen = set()
    for i in tx.vin:
        k = (i.prev_hash, i.prev_n)
        if k in seen:
            return "bad-txns-inputs-duplicate"
        seen.add(k)
    if tx.is_coinbase():
        if not (2 <= len(tx.vin[0].script_sig) <= 100):
            return "bad-cb-length"
    else:
        for i in tx.vin:
            if i.prev_hash == b"\x00" * 32 and i.prev_n == 0xffffffff:
                return "bad-txns-prevout-null"
    return None


def check_block(block, pow_limit=REGTEST_POW_LIMIT):
    """CheckBlock (validation.cpp) with fCheckPOW and fCheckMerkleRoot: None or reason."""
    if not check_proof_of_work(block.header.hash(), block.header.bits, pow_limit):
        return "high-hash"
    reason = check_merkle_root(block)
    if reason:
        return reason
    if (not block.vtx or len(block.vtx) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
            or block.stripped_size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT):
        return "bad-blk-length"
    if not block.vtx or not block.vtx[0].is_coinbase():
        return "bad-cb-missing"
    for t in block.vtx[1:]:
        if t.is_coinbase():
            return "bad-cb-multiple"
    for t in block.vtx:
        reason = check_transaction(t)
        if reason:
            return reason
    sigops = 0
    for t in block.vtx:
        for i in t.vin:
            sigops += legacy_sigop_count(i.script_sig)
        for _, spk in t.vout:
            sigops += legacy_sigop_count(spk)
    if sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST:
        return "bad-blk-sigops"
    return None


def headers_continuous(headers):
    last = None
    for h in headers:
        if last is not None and h.prev != last:
            return False
        last = h.hash()
    return True
