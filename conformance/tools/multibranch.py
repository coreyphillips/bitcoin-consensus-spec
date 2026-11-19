"""Sends the same seeded random multi-branch regtest scenarios to two chain harnesses and compares
the chain state after every step.

Usage:
  python3 multibranch.py --a <harness command> --b <harness command>
                         [--scenarios N] [--seed S] [--only I] [--log FILE]

The usual pair is the reference (`target/release/reference-harness`) and Bitcoin Core v32.1
(`python3 conformance/recorder/core_chain_harness.py`, with BCS_BITCOIND naming bitcoind). Each
scenario resets a regtest chain, mines a trunk past coinbase maturity, then grows random branches
from it: headers sent before blocks, blocks out of order or unrequested, spends of outputs created
on other branches, invalid blocks, timestamps more than two hours ahead, mutated copies of blocks
and invalidations. After every chain operation (PROTOCOL.md section 4) both harnesses are asked
for the active tip, the chain tip set and the UTXO set hash. The first difference ends the
scenario and is printed with the seed, the scenario and the step.

Scenario I of seed S is the same on every run (`--seed S --only I` repeats it), provided both
harnesses agree up to the step being repeated: invalidations pick their block from the chain tips
both reported. Exit status: 0 if every state matched, 1 if any differed or a harness failed.
"""

import argparse
import hashlib
import json
import random
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "recorder"))
import blocklib  # noqa: E402
from differential import Harness  # noqa: E402

GENESIS_TIME = 1296688602  # regtest, kernel/chainparams.cpp
BITS = 0x207FFFFF
TARGET = blocklib.derive_target(BITS)
MATURITY = 100
HALVING = 150  # regtest nSubsidyHalvingInterval
COIN = 100_000_000
MAX_FUTURE = 2 * 60 * 60
OP_TRUE = b"\x51"
P2WSH_TRUE = b"\x00\x20" + hashlib.sha256(OP_TRUE).digest()
# Kinds of invalid block, each one rule of chapters 10, 11 or 15 broken on purpose.
INVALID = ["other-branch", "double-spend", "immature", "overspend", "cb-amount", "time-too-old",
           "bip34", "bad-witness", "high-hash", "order"]


class Diverged(Exception):
    pass


def script_num(n):
    """CScript() << n for a block height (BIP34)."""
    if n <= 16:
        return bytes([0x50 + n])
    out = n.to_bytes((n.bit_length() + 8) // 8, "little")
    return bytes([len(out)]) + out


def push(data):
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


class Blk:
    """A block the generator made. `view` is the UTXO set after it, as if it were valid:
    outpoint -> (value, script_pubkey, height, is_coinbase)."""

    def __init__(self, hash, prev, height, time, raw, view):
        self.hash, self.prev, self.height, self.time = hash, prev, height, time
        self.raw, self.view = raw, view
        self.children = 0


class Scenario:
    def __init__(self, a, b, seed, index, log):
        self.a, self.b, self.seed, self.index, self.log = a, b, seed, index, log
        self.rng = random.Random(f"{seed}/{index}")
        self.blocks = {}
        self.order = []
        self.outputs = {}  # every output ever created, on any branch
        self.pending = []  # built but not yet delivered in a way that could store it
        self.steps = 0
        self.tips = []
        self.tip = None
        self.reorgs = 0
        self.max_tips = 0

    # ------------------------------------------------------------ talking to the harnesses

    def both(self, request):
        answers = []
        for h in (self.a, self.b):
            answer = h.ask(request)
            if answer.get("ok") is not True:
                raise SystemExit(f"{self.where()}: harness failed: {h.command}\nanswer: {json.dumps(answer)}\n"
                                 f"request: {json.dumps(request)}")
            answers.append(answer)
        return answers

    def where(self):
        return f"seed {self.seed} scenario {self.index} step {self.steps}"

    def state(self, h):
        tip = h.ask({"op": "chain_tip"})
        tips = h.ask({"op": "chain_tips"})
        utxo = h.ask({"op": "utxo_hash"})
        for answer in (tip, tips, utxo):
            if answer.get("ok") is not True:
                raise SystemExit(f"{self.where()}: harness failed: {h.command}\nanswer: {json.dumps(answer)}")
        try:
            return {"tip": tip["tip"], "height": tip["height"], "chainwork": tip["chainwork"],
                    "tips": sorted((t["hash"], t["height"], t["status"]) for t in tips["tips"]),
                    "hash_serialized_3": utxo["hash_serialized_3"], "txouts": utxo["txouts"]}
        except (KeyError, TypeError) as e:
            # Two harnesses that both leave a field out would otherwise compare equal.
            raise SystemExit(f"{self.where()}: harness answer lacks {e}: {h.command}")

    def step(self, request, compare=True):
        """Sends a chain operation to both harnesses, then compares their chain state."""
        self.steps += 1
        answers = self.both(request)
        if self.log:
            self.log.write(json.dumps({"scenario": self.index, "step": self.steps, "request": request,
                                       "a": answers[0], "b": answers[1]}) + "\n")
        if not compare:
            return
        x, y = self.state(self.a), self.state(self.b)
        if x != y:
            lines = [f"{self.where()}: chain state differs after {request['op']}"]
            for key in x:
                if key == "tips" and x[key] != y[key]:
                    lines.append(f"  tips only in a: {sorted(set(x[key]) - set(y[key]))}")
                    lines.append(f"  tips only in b: {sorted(set(y[key]) - set(x[key]))}")
                elif x[key] != y[key]:
                    lines.append(f"  {key}: a {x[key]}, b {y[key]}")
            shown = {k: (v[:160] + "..." if isinstance(v, str) and len(v) > 160 else v) for k, v in request.items()}
            lines.append(f"  request: {json.dumps(shown)}")
            lines.append(f"  answers: a {json.dumps(answers[0])}, b {json.dumps(answers[1])}")
            raise Diverged("\n".join(lines))
        old = self.blocks.get(self.tip)
        if old is not None and x["tip"] != self.tip and not self.descends(x["tip"], self.tip):
            self.reorgs += 1
        self.tip, self.tips = x["tip"], x["tips"]
        self.max_tips = max(self.max_tips, len(x["tips"]))

    def descends(self, h, ancestor):
        b = self.blocks.get(h)
        while b is not None:
            if b.hash == ancestor:
                return True
            b = self.blocks.get(b.prev)
        return False

    # ------------------------------------------------------------ building blocks

    def mtp(self, b):
        times = []
        while b is not None and len(times) < 11:
            times.append(b.time)
            b = self.blocks.get(b.prev)
        return sorted(times)[len(times) // 2]

    def spendable(self, view, height):
        return [op for op, (_, spk, h, cb) in view.items()
                if spk in (OP_TRUE, P2WSH_TRUE) and (not cb or h + MATURITY <= height)]

    def make_tx(self, inputs, view, n_out, fee=None, extra=0):
        """A transaction spending `inputs` (outpoints in `view`), paying `n_out` outputs."""
        rng = self.rng
        tx = blocklib.Tx()
        tx.version = 2
        total = sum(view[op][0] for op in inputs)
        for txid, n in inputs:
            vin = blocklib.TxIn(txid, n, b"", 0xFFFFFFFF)
            if view[(txid, n)][1] == P2WSH_TRUE:
                vin.witness = [OP_TRUE]
            tx.vin.append(vin)
        if fee is None:
            fee = min(total, rng.choice([0, 0, 100, 1000, rng.randrange(10_000)]))
        left = total - fee + extra
        for i in range(n_out):
            value = left if i == n_out - 1 else rng.randint(0, left)
            left -= value
            r = rng.random()
            if r < 0.1:
                tx.vout.append((value, b"\x6a" + push(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20))))))
            else:
                tx.vout.append((value, OP_TRUE if r < 0.6 else P2WSH_TRUE))
        return tx

    def make_block(self, parent, intent=None, time=None):
        """A block on `parent`. `intent` names the rule from INVALID it breaks, None if valid."""
        rng = self.rng
        height = parent.height + 1
        view = dict(parent.view)
        txs = []
        fees = 0
        for _ in range(rng.choice([0, 1, 1, 2, 3, 4])):
            ops = self.spendable(view, height)
            if not ops:
                break
            inputs = rng.sample(ops, min(len(ops), rng.choice([1, 1, 2, 3])))
            tx = self.make_tx(inputs, view, rng.choice([1, 2, 3]))
            fees += sum(view[op][0] for op in inputs) - sum(v for v, _ in tx.vout)
            self.apply(tx, view, height, False)
            txs.append(tx)

        if intent in ("other-branch", "double-spend", "immature", "overspend", "bad-witness", "order"):
            bad = self.bad_tx(intent, parent, view, height, txs)
            if bad is None:
                intent = "cb-amount"
            else:
                txs = bad

        subsidy = (50 * COIN) >> (height // HALVING)
        value = rng.choice([subsidy, subsidy + fees, subsidy - rng.randrange(1000)])
        if intent == "cb-amount":
            value = subsidy + fees + 1
        if time is None:
            time = parent.time + rng.randint(-600, 1200)
            time = min(time, self.now + MAX_FUTURE)
            if rng.random() < 0.05:
                time = self.now + MAX_FUTURE  # the latest time allowed
            time = max(time, self.mtp(parent) + 1)
        if intent == "time-too-old":
            time = self.mtp(parent)

        cb = blocklib.Tx()
        cb.version = 2
        tag = push(rng.randbytes(4))
        cb.vin = [blocklib.TxIn(bytes(32), 0xFFFFFFFF, script_num(height + (intent == "bip34")) + tag, 0xFFFFFFFF)]
        cb.vout = [(value, rng.choice([OP_TRUE, P2WSH_TRUE]))]
        vtx = [cb] + txs
        if any(t.has_witness() for t in txs) or rng.random() < 0.2:
            root = blocklib.compute_merkle_root([bytes(32)] + [t.wtxid() for t in txs])[0]
            cb.vout.append((0, blocklib.WITNESS_COMMITMENT_PREFIX + blocklib.sha256d(root + bytes(32))))
            cb.vin[0].witness = [bytes(32)]
        merkle = blocklib.compute_merkle_root([t.txid() for t in vtx])[0]
        prefix = (0x20000000).to_bytes(4, "little") + bytes.fromhex(parent.hash)[::-1] + merkle
        prefix += time.to_bytes(4, "little") + BITS.to_bytes(4, "little")
        nonce = 0
        while True:
            header = prefix + nonce.to_bytes(4, "little")
            if (int.from_bytes(blocklib.sha256d(header), "little") <= TARGET) != (intent == "high-hash"):
                break
            nonce += 1
        raw = header + blocklib.ser_compact(len(vtx)) + b"".join(t.serialize() for t in vtx)
        h = blocklib.hash_to_hex(blocklib.sha256d(header))
        self.apply(cb, view, height, True)
        b = Blk(h, parent.hash, height, time, raw, view)
        self.blocks[h] = b
        self.order.append(b)
        parent.children += 1
        return b

    def apply(self, tx, view, height, coinbase):
        for vin in tx.vin:
            view.pop((vin.prev_hash, vin.prev_n), None)
        txid = tx.txid()
        for n, (value, spk) in enumerate(tx.vout):
            if spk[:1] != b"\x6a":
                view[(txid, n)] = (value, spk, height, coinbase)
                self.outputs[(txid, n)] = view[(txid, n)]

    def bad_tx(self, intent, parent, view, height, txs):
        """`txs` with one transaction that breaks `intent`, or None if this parent cannot have one."""
        rng = self.rng
        ops = self.spendable(view, height)
        if intent == "other-branch":
            # Created on another branch, or already spent on this one.
            elsewhere = [op for op, (_, spk, h, cb) in self.outputs.items() if op not in parent.view
                         and op not in view and spk in (OP_TRUE, P2WSH_TRUE) and (not cb or h + MATURITY <= height)]
            if not elsewhere:
                return None
            op = rng.choice(elsewhere)
            return txs + [self.make_tx([op], {op: self.outputs[op]}, 1)]
        if intent == "double-spend":
            if not ops:
                return None
            op = rng.choice(ops)
            entry = {op: view[op]}
            return txs + [self.make_tx([op], entry, 1), self.make_tx([op], entry, 2)]
        if intent == "immature":
            young = [op for op, (_, spk, h, cb) in view.items() if cb and h + MATURITY > height
                     and spk in (OP_TRUE, P2WSH_TRUE)]
            if not young:
                return None
            return txs + [self.make_tx([rng.choice(young)], view, 1)]
        if not ops:
            return None
        op = rng.choice(ops)
        if intent == "overspend":
            return txs + [self.make_tx([op], view, rng.choice([1, 2]), fee=0, extra=1)]
        if intent == "bad-witness":
            tx = self.make_tx([op], view, 1)
            tx.vin[0].witness = [b"\x00"] if view[op][1] == P2WSH_TRUE else [OP_TRUE]
            return txs + [tx]
        # order: a transaction placed before the one whose output it spends.
        first = self.make_tx([op], view, 1)
        first.vout[0] = (first.vout[0][0], OP_TRUE)
        out = (first.txid(), 0)
        second = self.make_tx([out], {out: (first.vout[0][0], OP_TRUE, height, False)}, 1)
        return txs + [second, first]

    def mutated(self, b):
        """A copy of `b` with the same header that does not match what the header commits to."""
        rng = self.rng
        blk = blocklib.parse_block(b.raw)
        kinds = ["merkle", "witness"]
        if len(blk.vtx) >= 3 and len(blk.vtx) % 2:
            kinds.append("duplicate")
        kind = rng.choice(kinds)
        if kind == "duplicate":
            blk.vtx.append(blk.vtx[-1])  # the same merkle root (CVE-2012-2459)
        elif kind == "merkle":
            tx = rng.choice(blk.vtx)
            value, spk = tx.vout[0]
            tx.vout[0] = (value ^ 1, spk)
        elif blocklib.witness_commitment_index(blk) != -1:
            blk.vtx[0].vin[0].witness = [bytes([1]) * 32]
        else:
            rng.choice(blk.vtx).vin[0].witness = [OP_TRUE]
        return blk.serialize()

    # ------------------------------------------------------------ delivering

    def send_block(self, b, raw=None, via=None, requested=True):
        rng = self.rng
        via = via or ("rpc" if rng.random() < 0.15 else "p2p")
        request = {"op": "chain_process_block", "block": (raw or b.raw).hex(), "now": self.now, "via": via}
        if via == "p2p" and not requested:
            request["requested"] = False
        self.step(request)
        # Dated too far ahead, or a child of such a block: sent again once the clock moves on.
        held = b.time > self.now + MAX_FUTURE or self.blocks[b.prev] in self.pending
        if raw is None and held and b not in self.pending:
            self.pending.append(b)

    def send_headers(self, run):
        if self.rng.random() < 0.7:
            self.step({"op": "chain_process_headers", "headers": [b.raw[:80].hex() for b in run],
                       "now": self.now, "via": "p2p"})
        else:
            for b in run:
                self.step({"op": "chain_process_headers", "headers": [b.raw[:80].hex()], "now": self.now, "via": "rpc"})

    def pick_parent(self):
        rng = self.rng
        r = rng.random()
        if r < 0.55 and self.tip in self.blocks:
            # The active tip, or a fork a few blocks below it that can overtake it.
            b = self.blocks[self.tip]
            for _ in range(0 if r < 0.3 else rng.randint(1, 4)):
                if b.height > self.trunk - 3:
                    b = self.blocks[b.prev]
            return b
        if r < 0.75:
            return rng.choice([b for b in self.order if not b.children])
        if r < 0.95:
            return rng.choice([b for b in self.order if b.height >= self.trunk - 3])
        return rng.choice(self.order)

    def extend(self):
        """A run of new blocks on one parent, delivered one of several ways."""
        rng = self.rng
        parent = self.pick_parent()
        run = []
        for _ in range(rng.choice([1, 1, 2, 2, 3, 4, 6])):
            r = rng.random()
            intent = rng.choice(INVALID) if r < 0.12 else None
            when = self.now + MAX_FUTURE + rng.randint(1, 3 * 3600) if 0.12 <= r < 0.17 else None
            parent = self.make_block(parent, intent, when)
            run.append(parent)
        mode = rng.choice(["order", "order", "headers", "headers", "shuffled", "reversed", "unrequested", "withheld"])
        if mode in ("headers", "withheld"):
            self.send_headers(run)
            if mode == "withheld":
                self.pending.extend(b for b in run if rng.random() < 0.7)
                return
            run = rng.sample(run, len(run)) if rng.random() < 0.5 else run
        elif mode == "shuffled":
            run = rng.sample(run, len(run))
        elif mode == "reversed":
            run = run[::-1]
        for b in run:
            self.send_block(b, requested=mode != "unrequested")
        if mode in ("shuffled", "reversed"):
            # Children sent before their parents were discarded; send them again, now or later.
            if rng.random() < 0.6:
                for b in sorted(run, key=lambda b: b.height):
                    self.send_block(b)
            else:
                self.pending.extend(b for b in run if b not in self.pending)

    def resend_pending(self):
        ready = sorted(self.pending, key=lambda b: b.height)
        self.pending = []
        for b in ready:
            self.send_block(b)

    def mutate(self):
        rng = self.rng
        if rng.random() < 0.5 or not self.order[1:]:
            b = self.make_block(self.pick_parent())
            for _ in range(rng.choice([1, 1, 2])):
                self.send_block(b, raw=self.mutated(b))
            if rng.random() < 0.7:
                self.send_block(b)
            else:
                self.pending.append(b)
        else:
            b = rng.choice(self.order[1:])
            self.send_block(b, raw=self.mutated(b))

    def invalidate(self):
        """A block both harnesses know: a reported chain tip or one of its ancestors above the trunk."""
        rng = self.rng
        tips = [t for t in self.tips if t[0] in self.blocks and t[1] >= self.trunk - 2]
        if not tips:
            return
        b = self.blocks[rng.choice(tips)[0]]
        for _ in range(rng.choice([0, 0, 1, 2, 4])):
            if self.blocks[b.prev].height < self.trunk - 2:
                break
            b = self.blocks[b.prev]
        self.step({"op": "chain_invalidate", "hash": b.hash, "now": self.now})

    # ------------------------------------------------------------ the scenario

    def run(self):
        rng = self.rng
        genesis = self.both({"op": "chain_reset", "network": "regtest"})
        if genesis[0].get("genesis") != genesis[1].get("genesis"):
            raise Diverged(f"{self.where()}: genesis differs: {genesis[0]} {genesis[1]}")
        g = Blk(genesis[0]["genesis"], None, 0, GENESIS_TIME, None, {})
        self.blocks[g.hash] = g
        self.order.append(g)
        self.tip = g.hash

        # A trunk past coinbase maturity, compared once at its end.
        self.trunk = MATURITY + rng.randint(1, 10)
        b = g
        for height in range(1, self.trunk + 1):
            self.now = b.time + 1200
            b = self.make_block(b, time=b.time + rng.randint(1, 1200))
            self.step({"op": "chain_process_block", "block": b.raw.hex(), "now": self.now}, compare=height == self.trunk)
        self.now = b.time + 600

        actions = [(self.extend, 50), (self.resend_pending, 10), (self.mutate, 10), (self.invalidate, 10),
                   (self.clock, 7), (self.duplicate, 5)]
        for _ in range(rng.randint(25, 50)):
            self.now += rng.choice([0, 0, 30, 600, 1800])
            rng.choices([f for f, _ in actions], [w for _, w in actions])[0]()
        self.clock()

    def clock(self):
        """Moves the clock on, so that blocks dated too far ahead can be delivered again."""
        self.now += self.rng.randint(3600, 4 * 3600)
        self.resend_pending()

    def duplicate(self):
        self.send_block(self.rng.choice(self.order[1:]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", required=True, help="first harness command")
    parser.add_argument("--b", required=True, help="second harness command")
    parser.add_argument("--scenarios", type=int, default=500)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--only", type=int, help="run only this scenario of the seed")
    parser.add_argument("--log", help="write every chain operation and both answers to this file")
    args = parser.parse_args()

    a, b = Harness(args.a), Harness(args.b)
    need = {"chain_reset", "chain_process_block", "chain_process_headers", "chain_invalidate",
            "chain_tip", "chain_tips", "utxo_hash"}
    for h in (a, b):
        if need - h.ops:
            sys.exit(f"harness does not list {', '.join(sorted(need - h.ops))}: {h.command}")
    log = open(args.log, "w") if args.log else None
    indices = [args.only] if args.only is not None else range(args.scenarios)
    print(f"seed {args.seed}, {len(indices)} scenarios", flush=True)
    differing = steps = reorgs = 0
    started = time.time()
    for i in indices:
        s = Scenario(a, b, args.seed, i, log)
        try:
            s.run()
        except Diverged as e:
            differing += 1
            print(e, flush=True)
            continue
        steps += s.steps
        reorgs += s.reorgs
        print(f"scenario {i}: {s.steps} steps, {len(s.order) - 1} blocks, {s.reorgs} reorgs, "
              f"up to {s.max_tips} chain tips, final height {s.blocks[s.tip].height}", flush=True)
    a.close()
    b.close()
    if log:
        log.close()
    print(f"{len(indices) - differing} of {len(indices)} scenarios identical ({steps} steps, {reorgs} reorgs, "
          f"{time.time() - started:.0f} s)")
    sys.exit(1 if differing else 0)


if __name__ == "__main__":
    main()
