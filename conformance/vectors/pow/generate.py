"""Writes the pow suite's cases, with the answers of the Core oracle as expectations.

Usage: python3 generate.py <oracle-core-harness> <out.jsonl>
"""

import json
import random
import subprocess
import sys

ORACLE, OUT = sys.argv[1], sys.argv[2]

SPACING = 600
TIMESPAN = 14 * 24 * 60 * 60
INTERVAL = TIMESPAN // SPACING
LIMIT = {"main": 0x1D00FFFF, "testnet3": 0x1D00FFFF, "testnet4": 0x1D00FFFF, "signet": 0x1E0377AE, "regtest": 0x207FFFFF}
NETWORKS = ["main", "testnet3", "testnet4", "signet", "regtest"]
RETARGETING = ["main", "testnet3", "testnet4", "signet"]
MIN_DIFFICULTY = ["testnet3", "testnet4", "regtest"]
T0 = 1_600_000_000

cases = []


def case(name, request):
    cases.append((name, request))


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


def interval(network):
    return 144 if network == "regtest" else INTERVAL


# 9.1 and 9.3: decoding, the canonical re-encoding (its sign step) and the work of a block.
COMPACT = [
    0x00000000, 0x00123456, 0x01003456, 0x01123456, 0x01803456, 0x02000080, 0x02008000, 0x02123456,
    0x03000080, 0x03008000, 0x03123456, 0x03800000, 0x04008000, 0x04800000, 0x04923456, 0x04123456,
    0x05009234, 0x1C7FFFFF, 0x1C800000, 0x1D00FFFF, 0x1D00D86A, 0x1D008000, 0x1D7FFFFF, 0x1E0377AE,
    0x1B0404CB, 0x17053894, 0x170331DB, 0x207FFFFF, 0x20800000, 0x20123456, 0x2100FFFF, 0x21010000,
    0x220000FF, 0x22000100, 0x23000001, 0x23000000, 0xFF000000, 0xFF123456, 0x01FFFFFF, 0x02FFFFFF,
]
rng = random.Random(9)
for _ in range(120):
    COMPACT.append(rng.randrange(0, 37) << 24 | rng.randrange(0, 1 << 24))
for bits in COMPACT:
    case(f"compact {bits:#010x}", {"op": "pow_compact", "bits": bits})

# 9.2: the hash against the target, and the target against the network's limit.
ABOVE_LIMIT = {
    "main": [0x1D010000, 0x1E00FFFF],
    "testnet3": [0x1D010000, 0x1E00FFFF],
    "testnet4": [0x1D010000, 0x1E00FFFF],
    "signet": [0x1E0377AF, 0x1F00FFFF],
    "regtest": [0x2100FFFF, 0x21008000],
}
for network in NETWORKS:
    limit = LIMIT[network]
    t = decode(limit)
    for label, bits, value in [
        ("limit, zero hash", limit, 0),
        ("limit, hash equal to the target", limit, t),
        ("limit, hash one above the target", limit, t + 1),
        ("target just above the limit, zero hash", ABOVE_LIMIT[network][0], 0),
        ("target far above the limit, zero hash", ABOVE_LIMIT[network][1], 0),
        ("half the limit, hash equal", encode(t // 2), decode(encode(t // 2))),
        ("half the limit, hash above", encode(t // 2), decode(encode(t // 2)) + 1),
        ("mainnet block 32256 bits", 0x1D00D86A, 0),
        ("regtest limit", 0x207FFFFF, 0),
        ("signet limit", 0x1E0377AE, 0),
        ("negative", 0x04923456, 0),
        ("zero target", 0x1D000000, 0),
        ("overflow", 0xFF123456, 0),
    ]:
        case(f"check {network}: {label}", {"op": "pow_check", "network": network, "hash": f"{value:064x}", "bits": bits})


def next_work(name, network, parent_height, runs, time):
    assert sum(r[0] for r in runs) == parent_height % interval(network) + 1, name
    case(name, {"op": "pow_next_work", "network": network, "parent_height": parent_height, "chain": runs, "time": time})


def period(first_bits, last_bits, timespan, mid_bits=None):
    """A whole period: its first block at T0, its last `timespan` seconds later."""
    mid = first_bits if mid_bits is None else mid_bits
    return [[1, T0, 0, first_bits], [INTERVAL - 2, T0 + 1, 0, mid], [1, T0 + timespan, 0, last_bits]]


# 9.5, at a retarget: the clamp, the 2015-interval timespan, the base target (BIP94) and the limit.
TIMESPANS = [
    -86400, 0, 1, TIMESPAN // 4 - 1, TIMESPAN // 4, TIMESPAN // 4 + 1, TIMESPAN - SPACING, TIMESPAN - 1,
    TIMESPAN, TIMESPAN + 1, TIMESPAN + SPACING, 2 * TIMESPAN, 4 * TIMESPAN - 1, 4 * TIMESPAN,
    4 * TIMESPAN + 1, 5 * TIMESPAN, 8 * TIMESPAN, 20 * TIMESPAN,
]
for network in RETARGETING:
    limit = LIMIT[network]
    for base in sorted({limit, 0x1D00D86A, 0x1B0404CB, 0x170331DB, encode(decode(limit) // 3)}):
        for span in TIMESPANS:
            for parent_height in [INTERVAL - 1, 16 * INTERVAL - 1]:
                next_work(
                    f"retarget {network}: base {base:#010x}, timespan {span}, height {parent_height + 1}",
                    network, parent_height, period(base, base, span), T0 + span + SPACING,
                )
    # A minimum-difficulty block closing the period, or opening it: BIP94 takes the first one's bits.
    for first, last in [(0x1B0404CB, limit), (limit, 0x1B0404CB), (0x1B0404CB, 0x1C0404CB)]:
        for span in [TIMESPAN // 2, TIMESPAN, 3 * TIMESPAN]:
            next_work(
                f"retarget {network}: first {first:#010x}, last {last:#010x}, timespan {span}",
                network, INTERVAL - 1, period(first, last, span, limit), T0 + span + SPACING,
            )
for span in [0, TIMESPAN, 10 * TIMESPAN]:
    next_work(f"retarget regtest: no retargeting, timespan {span}", "regtest", 143,
              [[1, T0, 0, 0x207FFFFF], [142, T0 + 1, 0, 0x207FFFFF], [1, T0 + span, 0, 0x1D00FFFF]], T0 + span + 1)

# 9.5, between retargets: the 20-minute rule and the walk back over minimum-difficulty blocks.
for network in NETWORKS:
    limit = LIMIT[network]
    n = interval(network)
    normal = 0x1B0404CB if network != "regtest" else 0x1D00FFFF
    start = 5 * n
    chains = {
        "all normal": [[101, T0, SPACING, normal]],
        "last three at the limit": [[98, T0, SPACING, normal], [3, T0 + 98 * SPACING, 1300, limit]],
        "all at the limit after the first": [[1, T0, 0, normal], [100, T0 + SPACING, 1300, limit]],
        "first at the limit too": [[101, T0, SPACING, limit]],
        "limit in the middle only": [[50, T0, SPACING, normal], [10, T0 + 50 * SPACING, 1300, limit], [41, T0 + 70 * SPACING, SPACING, 0x1B0504CB]],
        "parent only at the limit": [[100, T0, SPACING, normal], [1, T0 + 100 * SPACING, 0, limit]],
        "a lower target before the limit": [[60, T0, SPACING, normal], [40, T0 + 60 * SPACING, SPACING, 0x1A0404CB], [1, T0 + 100 * SPACING, 0, limit]],
    }
    for label, runs in chains.items():
        parent_time = runs[-1][1] + (runs[-1][0] - 1) * runs[-1][2]
        for delta in [-3600, 0, SPACING, 2 * SPACING - 1, 2 * SPACING, 2 * SPACING + 1, 7200]:
            next_work(
                f"between retargets {network}: {label}, new block {delta:+d} s after its parent",
                network, start + 100, runs, parent_time + delta,
            )
    # Close to genesis, where the walk back ends at height 0.
    for delta in [0, 2 * SPACING, 2 * SPACING + 1]:
        next_work(f"between retargets {network}: parent is genesis, {delta:+d} s", network, 0, [[1, T0, 0, normal]], T0 + delta)
        next_work(f"between retargets {network}: walk back to genesis, {delta:+d} s", network, 5,
                  [[1, T0, 0, normal], [5, T0 + 1300, 1300, limit]], T0 + 5 * 1300 + delta)
    # The block just before a retarget, so the walk back covers a whole period.
    next_work(f"between retargets {network}: walk back over a whole period", network, 2 * n - 2,
              [[1, T0, 0, normal], [n - 2, T0 + 1300, 1300, limit]], T0 + (n - 2) * 1300 + SPACING)

# Random retargets, as the review that first checked chapter 09 against pow.cpp did.
rng = random.Random(2016)
for i in range(150):
    network = rng.choice(RETARGETING)
    limit = decode(LIMIT[network])
    first = encode(rng.randrange(1, limit + 1) >> rng.randrange(0, 40))
    last = rng.choice([first, LIMIT[network], encode(rng.randrange(1, limit + 1))])
    span = rng.randrange(-TIMESPAN, 6 * TIMESPAN)
    next_work(f"random retarget {i}", network, rng.randrange(1, 400) * INTERVAL - 1,
              period(first, last, span, rng.choice([first, LIMIT[network]])), T0 + span + rng.randrange(0, 3 * SPACING))

proc = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
with open(OUT, "w") as out:
    for i, (name, request) in enumerate(cases):
        proc.stdin.write(json.dumps({"id": i, **request}) + "\n")
        proc.stdin.flush()
        answer = json.loads(proc.stdout.readline())
        if answer.get("id") != i or answer.get("ok") is not True:
            sys.exit(f"{name}: {answer}")
        del answer["id"], answer["ok"]
        out.write(json.dumps({"name": name, "request": request, "expect": answer}, separators=(", ", ": ")) + "\n")
proc.stdin.close()
proc.wait()
print(f"{len(cases)} cases written to {OUT}")
