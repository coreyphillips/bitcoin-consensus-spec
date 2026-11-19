"""Sends the same seeded random requests to two harnesses and reports every answer that differs.

Usage:
  python3 differential.py --a <harness command> --b <harness command>
                          [--domains script,tx,pow,signet] [--cases N] [--seed S]

The usual pair is the reference (`target/release/reference-harness`) and Bitcoin Core's own code
(`conformance/oracle-core/target/release/oracle-core-harness`). Each domain generates `--cases`
requests: fresh random ones and random mutations of the committed vectors. The same seed gives the
same requests. Exit status: 0 if every comparable answer is identical, 1 if any differs, 2 if a
harness fails.
"""

import argparse
import hashlib
import json
import random
import shlex
import subprocess
import sys
from pathlib import Path

VECTORS = Path(__file__).resolve().parent.parent / "vectors"
FLAGS = ["P2SH", "DERSIG", "NULLDUMMY", "CHECKLOCKTIMEVERIFY", "CHECKSEQUENCEVERIFY", "WITNESS", "TAPROOT"]
NETWORKS = ["main", "testnet3", "testnet4", "signet", "regtest"]
POW_LIMIT = {"main": 0x1D00FFFF, "testnet3": 0x1D00FFFF, "testnet4": 0x1D00FFFF, "signet": 0x1E0377AE, "regtest": 0x207FFFFF}
SPACING, TIMESPAN = 600, 14 * 24 * 60 * 60
T0 = 1_600_000_000


class Harness:
    def __init__(self, command):
        self.command = command
        self.proc = subprocess.Popen(shlex.split(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.next_id = 0
        self.ops = set(self.ask({"op": "info"}).get("ops", []))

    def ask(self, request):
        self.next_id += 1
        self.proc.stdin.write(json.dumps({"id": self.next_id, **request}) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            sys.exit(f"harness exited: {self.command}\nlast request: {json.dumps(request)}")
        answer = json.loads(line)
        if answer.pop("id", None) != self.next_id:
            sys.exit(f"harness answered out of order: {self.command}")
        return answer

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def comparable(answer):
    """The fields a conforming harness must agree on, or None if the request was not well formed."""
    if answer.get("ok") is not True:
        return None if answer.get("error") == "bad_request" else {"ok": False, "error": answer.get("error")}
    answer = {k: v for k, v in answer.items() if k != "message"}
    if answer.get("script_error") == "OK":
        del answer["script_error"]
    return answer


# Serialization


def compact_size(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def push(data):
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    return b"\x4d" + n.to_bytes(2, "little") + data


def serialize_tx(version, inputs, outputs, locktime, witnesses=None):
    """inputs: (prevout bytes, script_sig, sequence); outputs: (value, script_pubkey)."""
    out = version.to_bytes(4, "little", signed=True)
    has_witness = witnesses is not None and any(witnesses)
    if has_witness:
        out += b"\x00\x01"
    out += compact_size(len(inputs))
    for prevout, script_sig, sequence in inputs:
        out += prevout + compact_size(len(script_sig)) + script_sig + sequence.to_bytes(4, "little")
    out += compact_size(len(outputs))
    for value, spk in outputs:
        out += value.to_bytes(8, "little", signed=True) + compact_size(len(spk)) + spk
    if has_witness:
        for stack in witnesses:
            out += compact_size(len(stack)) + b"".join(compact_size(len(item)) + item for item in stack)
    return out + locktime.to_bytes(4, "little")


def mutate_bytes(rng, data, max_edits=3):
    data = bytearray(data)
    for _ in range(rng.randint(1, max_edits)):
        kind = rng.randrange(5)
        pos = rng.randrange(len(data) + 1)
        if kind == 0 and data:
            data[min(pos, len(data) - 1)] ^= 1 << rng.randrange(8)
        elif kind == 1 and data:
            data[min(pos, len(data) - 1)] = rng.randrange(256)
        elif kind == 2:
            data[pos:pos] = bytes([rng.randrange(256)])
        elif kind == 3 and data:
            del data[min(pos, len(data) - 1)]
        elif data:
            data = data[:pos]
    return bytes(data)


def random_flags(rng):
    flags = [f for f in FLAGS if rng.random() < 0.6]
    if "WITNESS" in flags and "P2SH" not in flags:
        flags.append("P2SH")
    return [f for f in FLAGS if f in flags]


# Scripts (chapters 02 to 07)

SMALL_OPS = [0x00, 0x4F] + list(range(0x51, 0x61))
OPS = list(range(0x61, 0xBB)) + [0x50, 0x89, 0x8A, 0xBA, 0xBB, 0xFF]
NUMBERS = [b"", b"\x00", b"\x80", b"\x01", b"\x81", b"\x7f", b"\xff", b"\x00\x80", b"\xff\x7f", b"\xff\xff\xff\x7f",
           b"\xff\xff\xff\xff", b"\xff\xff\xff\xff\x7f", b"\x00\x00\x00\x00\x00"]


def random_item(rng):
    r = rng.random()
    if r < 0.4:
        return rng.choice(NUMBERS)
    if r < 0.6:
        return bytes(rng.randrange(256) for _ in range(rng.choice([20, 32, 33, 64, 65, 71, 72])))
    if r < 0.95:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
    return bytes(rng.choice([520, 521]))


def random_script(rng, length):
    out = b""
    for _ in range(length):
        r = rng.random()
        if r < 0.3:
            out += push(random_item(rng))
        elif r < 0.5:
            out += bytes([rng.choice(SMALL_OPS)])
        elif r < 0.6:
            out += bytes([rng.choice([0x63, 0x64, 0x67, 0x68, 0x69])])
        elif r < 0.98:
            out += bytes([rng.choice(OPS)])
        else:
            out += bytes([rng.randrange(1, 0x4F)])  # a push that may run past the end
    return out


def fresh_script_request(rng):
    script_sig = b"".join(push(random_item(rng)) for _ in range(rng.randrange(0, 4)))
    witness = []
    kind = rng.random()
    if kind < 0.5:
        spk = random_script(rng, rng.randrange(1, 12))
    else:
        witness_script = random_script(rng, rng.randrange(1, 12))
        spk = b"\x00\x20" + hashlib.sha256(witness_script).digest()
        witness = [random_item(rng) for _ in range(rng.randrange(0, 4))] + [witness_script]
        if rng.random() < 0.2:
            script_sig = push(random_item(rng))
    sequence = rng.choice([0xFFFFFFFF, 0, 1, 0x00400001, 0x80000000, rng.randrange(1 << 32)])
    tx = serialize_tx(rng.choice([1, 2, -1]), [(bytes(range(32)) + b"\x00\x00\x00\x00", script_sig, sequence)],
                      [(1000, b"\x51")], rng.choice([0, 1, 500_000_000, rng.randrange(1 << 32)]), [witness])
    amount = rng.choice([0, 1000, 5000, 2_100_000_000_000_000])
    return {"op": "script_verify", "tx": tx.hex(), "index": 0,
            "spent_outputs": [{"amount": amount, "script_pubkey": spk.hex()}], "flags": random_flags(rng)}


def mutated_script_request(rng, seeds):
    request = json.loads(json.dumps(rng.choice(seeds)))
    kind = rng.randrange(4)
    if kind == 0:
        request["flags"] = random_flags(rng)
    elif kind == 1:
        request["tx"] = mutate_bytes(rng, bytes.fromhex(request["tx"])).hex()
    elif kind == 2:
        out = rng.choice(request["spent_outputs"])
        out["script_pubkey"] = mutate_bytes(rng, bytes.fromhex(out["script_pubkey"])).hex()
    else:
        out = request["spent_outputs"][request["index"]]
        out["amount"] = rng.choice([0, out["amount"] + 1, out["amount"] - 1])
    return request


def script_requests(rng, count):
    seeds = [json.loads(line)["request"] for name in ["edge-cases.jsonl", "script-versions.jsonl"]
             for line in (VECTORS / "custom" / name).read_text().splitlines() if line.strip()]
    seeds = [s for s in seeds if s["op"] == "script_verify"]
    for _ in range(count):
        yield fresh_script_request(rng) if rng.random() < 0.5 else mutated_script_request(rng, seeds)


# Transactions (chapter 08)


def tx_requests(rng, count):
    seeds = [bytes.fromhex(json.loads(line)["request"]["tx"])
             for line in (VECTORS / "custom" / "script-versions.jsonl").read_text().splitlines() if line.strip()]
    values = [0, 1, -1, 2_100_000_000_000_000, 2_100_000_000_000_001, 1 << 62]
    for _ in range(count):
        if rng.random() < 0.4:
            yield {"op": "tx_check", "tx": mutate_bytes(rng, rng.choice(seeds)).hex()}
            continue
        prevouts = [bytes(rng.randrange(256) for _ in range(32)) + rng.randrange(3).to_bytes(4, "little")
                    for _ in range(rng.randrange(0, 4))]
        if rng.random() < 0.2:
            prevouts.append(rng.choice(prevouts) if prevouts else bytes(32) + b"\xff" * 4)
        if rng.random() < 0.2:
            prevouts = [bytes(32) + b"\xff" * 4] + prevouts[:rng.randrange(2)]
        inputs = [(p, bytes(rng.choice([0, 1, 2, 3, 100, 101])), 0xFFFFFFFF) for p in prevouts]
        outputs = [(rng.choice(values), b"\x51") for _ in range(rng.randrange(0, 4))]
        if len(outputs) > 1 and rng.random() < 0.3:
            outputs = [(1_100_000_000_000_000, b"\x51")] * len(outputs)
        yield {"op": "tx_check", "tx": serialize_tx(rng.choice([1, 2]), inputs, outputs, 0).hex()}


# Proof of work (chapter 09)


def decode(bits):
    size, word = bits >> 24, bits & 0x7FFFFF
    return word >> 8 * (3 - size) if size <= 3 else word << 8 * (size - 3)


def encode(target):
    size = (target.bit_length() + 7) // 8
    compact = target << 8 * (3 - size) if size <= 3 else target >> 8 * (size - 3)
    if compact & 0x800000:
        compact >>= 8
        size += 1
    return compact | size << 24


def random_bits(rng, network):
    r = rng.random()
    limit = decode(POW_LIMIT[network])
    if r < 0.3:
        return rng.randrange(1 << 32)
    if r < 0.6:
        return rng.randrange(0, 0x24) << 24 | rng.randrange(1 << 24)
    return encode(max(1, rng.randrange(1, 2 * limit) >> rng.randrange(0, 60)))


def pow_requests(rng, count):
    for _ in range(count):
        network = rng.choice(NETWORKS)
        interval = 144 if network == "regtest" else TIMESPAN // SPACING
        kind = rng.random()
        if kind < 0.25:
            yield {"op": "pow_compact", "bits": random_bits(rng, network)}
        elif kind < 0.5:
            bits = random_bits(rng, network)
            target = decode(bits) & ((1 << 256) - 1)
            value = max(0, min((1 << 256) - 1, target + rng.choice([-1, 0, 1, rng.randrange(-(1 << 20), 1 << 20)])))
            if rng.random() < 0.3:
                value = rng.randrange(1 << 256)
            yield {"op": "pow_check", "network": network, "hash": f"{value:064x}", "bits": bits}
        else:
            # A chain of runs [count, time, step, bits] from the first block of the parent's period.
            if rng.random() < 0.5:
                parent_height = rng.randrange(1, 300) * interval - 1
            else:
                parent_height = rng.randrange(0, 300 * interval)
            remaining = parent_height % interval + 1
            limit, runs, time = POW_LIMIT[network], [], T0
            normal = encode(decode(limit) >> rng.randrange(0, 40)) or limit
            while remaining:
                n = rng.randint(1, remaining)
                step = rng.choice([0, 1, SPACING, 2 * SPACING, 2 * SPACING + 1, rng.randrange(-3600, 4 * SPACING)])
                bits = rng.choice([limit, normal, random_bits(rng, network)])
                runs.append([n, time, step, bits])
                time += n * step
                remaining -= n
            parent_time = runs[-1][1] + (runs[-1][0] - 1) * runs[-1][2]
            if parent_height % interval == interval - 1 and rng.random() < 0.5:
                # A whole period whose length is chosen, so the retarget clamps are reached.
                span = rng.randrange(-TIMESPAN, 6 * TIMESPAN)
                first, last = rng.choice([limit, normal]), rng.choice([limit, normal, random_bits(rng, network)])
                runs = [[1, T0, 0, first]] + ([[interval - 2, T0 + 1, 0, normal]] if interval > 2 else []) + [[1, T0 + span, 0, last]]
                parent_time = T0 + span
            time = parent_time + rng.choice([-3600, 0, SPACING, 2 * SPACING, 2 * SPACING + 1, rng.randrange(-7200, 7200)])
            yield {"op": "pow_next_work", "network": network, "parent_height": parent_height, "chain": runs, "time": time}


# Signet (chapter 13)


def signet_requests(rng, count):
    seeds = [json.loads(line)["request"] for line in
             (VECTORS / "signet" / "signet-block-solution.jsonl").read_text().splitlines() if line.strip()]
    challenges = sorted({s["challenge"] for s in seeds})
    for _ in range(count):
        request = dict(rng.choice(seeds))
        kind = rng.randrange(4)
        if kind == 0:
            request["challenge"] = rng.choice(challenges)
        elif kind == 1:
            request["challenge"] = mutate_bytes(rng, bytes.fromhex(request["challenge"]), 1).hex()
        elif kind == 2:
            block = bytearray.fromhex(request["block"])
            block[rng.randrange(len(block))] ^= 1 << rng.randrange(8)
            request["block"] = block.hex()
        yield request


DOMAINS = {"script": script_requests, "tx": tx_requests, "pow": pow_requests, "signet": signet_requests}
NEEDS = {"script": "script_verify", "tx": "tx_check", "pow": "pow_next_work", "signet": "signet_check"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", required=True, help="first harness command")
    parser.add_argument("--b", required=True, help="second harness command")
    parser.add_argument("--domains", default=",".join(DOMAINS))
    parser.add_argument("--cases", type=int, default=10_000, help="requests per domain")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--show", type=int, default=10, help="differences to print per domain")
    args = parser.parse_args()

    a, b = Harness(args.a), Harness(args.b)
    print(f"seed {args.seed}, {args.cases} cases per domain")
    differing = 0
    for domain in args.domains.split(","):
        if NEEDS[domain] not in a.ops or NEEDS[domain] not in b.ops:
            sys.exit(f"{domain}: a harness does not list {NEEDS[domain]}")
        rng = random.Random(f"{args.seed}/{domain}")
        compared = skipped = diffs = 0
        for request in DOMAINS[domain](rng, args.cases):
            x, y = comparable(a.ask(request)), comparable(b.ask(request))
            if x is None and y is None:
                skipped += 1
                continue
            compared += 1
            if x != y:
                diffs += 1
                if diffs <= args.show:
                    print(json.dumps({"domain": domain, "request": request, "a": x, "b": y}))
        print(f"{domain}: {compared} compared, {diffs} differ, {skipped} malformed for both")
        differing += diffs
    a.close()
    b.close()
    sys.exit(1 if differing else 0)


if __name__ == "__main__":
    main()
