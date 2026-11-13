#!/usr/bin/env python3
# Part of the bitcoin-consensus-spec conformance corpus (MIT license).
"""Block validation pitfalls, recorded into the conformance corpus.

Written in the style of Bitcoin Core's functional tests and run by the
recorder against the v32.1 release exactly like Core's own tests. Every part
delivers invalid and valid blocks, over P2P (send_blocks_and_test) and with
submitblock, so that the recorded scenario pins down:

a. BIP68 relative lock-time compares the transaction version as unsigned:
   versions 0xffffffff and 0x80000000 are locked (an unsatisfied height lock
   makes the block bad-txns-nonfinal, one block short of the lock still fails,
   the satisfied lock is valid), version 1 is not locked, and a time-based
   lock on a coin created in the same block is satisfied only by a zero lock.
b. CheckBlock counts sigops the legacy way: OP_1 OP_CHECKMULTISIG counts 20.
   1001 of them exceed 80,000 sigop cost, 1000 are exactly at the limit, one
   OP_CHECKSIG more is over.
c. Block subsidy at the regtest halving height 150: 50 BTC is allowed at
   height 149 but not at 150, where 25 BTC is the most a coinbase may claim.
d. The block version is a signed integer: 0x80000000 and 0xffffffff are below
   2 and rejected as bad-version, 0x20000000 and 4 are accepted.
e. A 64-byte transaction is valid inside a block. The same header with a body
   of a single 64-byte transaction, whose bytes are the block's two txids (so
   the merkle root matches), is a mutated block over P2P and bad-cb-missing
   through submitblock, and the real block is accepted afterwards.
f. A P2SH spend whose scriptSig leaves 1,000 stack elements fails when the
   output script pushes the script hash (stack size limit); 999 is valid.
g. Peer-to-peer anti-DoS work checks (net_processing). The threshold is the
   tip's chain work minus 144 blocks of work. An unsolicited block with a new
   header whose claimed work (parent work plus its own) is below it is dropped
   without storing anything; at the threshold its header is stored (and,
   having less work than the tip, only its header). A headers message whose
   claimed work is below it is ignored entirely, from a peer without the noban
   permission; one more header in the same message reaches the threshold and
   every header is stored.
j. A transaction with 100,001 outputs (zero-value outputs with empty scripts,
   about 900,000 bytes) is valid: nothing but the size rules limits the number
   of outputs.
k. An output created and spent in one block stays spent. A block creates P
   and spends P:0; the next block spends P:0 again and is
   bad-txns-inputs-missingorspent, with both blocks requested and delivered
   together as in initial sync. A different re-spend through submitblock and
   one three blocks above are rejected too. A block that spends P:1 and
   re-spends P:0 is rejected as a whole, and P:1 can then be spent.

Parts a to g, j and k run on node 0 (default regtest parameters). Two more nodes, never
connected to anything but the test, each get their own corpus file:

h. Node 1 activates BIP34 at height 2 and BIP66 and BIP65 only at 300, so the
   version floor is 2 alone: version 0x80000000 is valid at height 1 (before
   BIP34); at height 11 versions 0x80000000, 0xffffffff and 1 are bad-version,
   and version 2 is valid.
i. Node 2 runs with -test=bip94 and blocks 600 seconds apart. A full block at
   the first height of a retarget period (144) whose timestamp is more than
   600 seconds before its parent's is time-timewarp-attack; exactly 600
   seconds before is valid and becomes the tip.
"""

from io import BytesIO

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.descriptors import descsum_create
from test_framework.messages import (
    CBlockHeader,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    SEQUENCE_FINAL,
    hash256,
    msg_generic,
    msg_headers,
    ser_compact_size,
    uint256_from_str,
)
from test_framework.p2p import P2P_SUBVERSION, P2PDataStore
from test_framework.script import (
    CScript,
    OP_0,
    OP_1,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_EQUAL,
    OP_HASH160,
    OP_TRUE,
    hash160,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

ANYONE_CAN_SPEND = CScript([OP_TRUE])
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
HALVING_HEIGHT = 150
RETARGET_INTERVAL = 144  # regtest: one day of 600 second blocks
MAX_TIMEWARP = 600


class SpecPitfallsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            [],
            ["-testactivationheight=bip34@2", "-testactivationheight=dersig@300", "-testactivationheight=cltv@300"],
            ["-test=bip94"],
        ]

    def setup_network(self):
        # Independent nodes: blocks reach each one only from the test.
        self.setup_nodes()

    def mine(self, count):
        self.generatetodescriptor(self.node, count, self.miner, sync_fun=self.no_op)

    def run_test(self):
        self.node = self.nodes[0]
        self.miner = descsum_create("raw(51)")  # coinbases pay to a bare OP_TRUE
        self.next_coinbase_height = 1
        self.mine(110)
        self.bootstrap_p2p()

        self.test_block_version()
        self.test_legacy_sigops()
        self.test_64_byte_transaction()
        self.test_p2sh_stack_size()
        self.test_bip68_unsigned_version()
        self.test_subsidy_halving()
        self.test_anti_dos_work()
        self.test_output_count()
        self.test_respend_of_same_block_spend()

        self.node = self.nodes[1]
        self.test_version_floor_before_dersig()
        self.node = self.nodes[2]
        self.test_timewarp_full_block()

    # ------------------------------------------------------------ helpers

    def bootstrap_p2p(self):
        self.peer = self.node.add_p2p_connection(P2PDataStore())
        # Let the initial getheaders arrive before blocks are stored, so the
        # data store never answers it with headers of blocks under test.
        self.peer.wait_for_getheaders(timeout=10)

    def reconnect_p2p(self):
        self.node.disconnect_p2ps()
        self.bootstrap_p2p()

    def send(self, blocks, *, success=True, reject_reason=None, force_send=False, reconnect=False):
        self.peer.send_blocks_and_test(blocks, self.node, success=success, reject_reason=reject_reason,
                                       force_send=force_send, expect_disconnect=reconnect, timeout=60)
        if reconnect:
            self.reconnect_p2p()

    def submit(self, block, expected):
        assert_equal(self.node.submitblock(block.serialize().hex()), expected)

    def tip(self):
        h = self.node.getbestblockhash()
        header = self.node.getblockheader(h)
        return int(h, 16), header["height"], header["time"]

    def make_block(self, txs=(), *, version=4, coinbase=None, coinbase_value=None):
        prev, height, prev_time = self.tip()
        if coinbase is None:
            coinbase = create_coinbase(height + 1)
        if coinbase_value is not None:
            coinbase.vout[0].nValue = coinbase_value
        block = create_block(prev, coinbase, ntime=prev_time + 1, version=version, txlist=list(txs))
        block.solve()
        return block

    def take_coin(self):
        """A mature coinbase output paying 50 BTC to a bare OP_TRUE."""
        height = self.next_coinbase_height
        self.next_coinbase_height += 1
        txid = self.node.getblock(self.node.getblockhash(height))["tx"][0]
        return COutPoint(int(txid, 16), 0), 50 * COIN

    @staticmethod
    def spend(outpoint, value, *, version=2, sequence=SEQUENCE_FINAL, script_sig=b"", outputs=None):
        tx = CTransaction()
        tx.version = version
        tx.vin = [CTxIn(outpoint, script_sig, sequence)]
        tx.vout = outputs if outputs is not None else [CTxOut(value, ANYONE_CAN_SPEND)]
        return tx

    # ------------------------------------------------------------ d

    def test_block_version(self):
        self.log.info("d. Block versions are signed: 0x80000000 and 0xffffffff are below 2")
        block = self.make_block(version=-0x80000000)
        self.send([block], success=False, force_send=True, reject_reason="bad-version(0x80000000)", reconnect=True)
        block = self.make_block(version=-1)
        self.submit(block, "bad-version(0xffffffff)")
        block = self.make_block(version=0x20000000)
        self.send([block])
        block = self.make_block(version=4)
        self.submit(block, None)

    # ------------------------------------------------------------ b

    def test_legacy_sigops(self):
        self.log.info("b. Legacy sigop counting: OP_1 OP_CHECKMULTISIG counts 20")
        outpoint, value = self.take_coin()

        def sigop_block(script):
            return self.make_block([self.spend(outpoint, value, outputs=[CTxOut(value, script)])])

        block = sigop_block(CScript([OP_1, OP_CHECKMULTISIG] * 1001))  # 20,020 sigops: cost 80,080
        self.send([block], success=False, reject_reason="bad-blk-sigops", reconnect=True)
        block = sigop_block(CScript([OP_1, OP_CHECKMULTISIG] * 1000 + [OP_CHECKSIG]))  # cost 80,004
        self.submit(block, "bad-blk-sigops")
        block = sigop_block(CScript([OP_1, OP_CHECKMULTISIG] * 1000))  # cost exactly 80,000
        self.send([block])

    # ------------------------------------------------------------ e

    def test_64_byte_transaction(self):
        self.log.info("e. A 64-byte transaction is valid in a block; alone under the same header it is a mutation")
        outpoint, value = self.take_coin()
        _, tip_height, _ = self.tip()
        height = tip_height + 1

        # The 64 bytes of a two-transaction block's inner merkle node are
        # txid(coinbase) || txid(tx64). Grind both so those bytes parse as a
        # transaction of exactly 64 bytes: one input (byte 4 is 0x01), a
        # 13-byte scriptSig (byte 41) and no outputs (byte 59).
        tx64 = self.spend(outpoint, value, outputs=[CTxOut(value, CScript([OP_TRUE] * 4))])
        assert_equal(len(tx64.serialize_without_witness()), 64)
        prefix = tx64.serialize_without_witness()[:-4]
        for locktime in range(1 << 24):
            txid = hash256(prefix + locktime.to_bytes(4, "little"))
            if txid[9] == 13 and txid[27] == 0:
                break
        else:
            raise AssertionError("no suitable tx64 locktime")
        tx64.nLockTime = locktime  # every input is final, so any locktime is
        for nonce in range(1 << 16):
            coinbase = create_coinbase(height)
            coinbase.vin[0].scriptSig = CScript(bytes(coinbase.vin[0].scriptSig) + bytes(CScript([nonce.to_bytes(2, "little")])))
            if hash256(coinbase.serialize_without_witness())[4] == 1:
                break
        else:
            raise AssertionError("no suitable coinbase nonce")

        block = self.make_block([tx64], coinbase=coinbase)
        inner = hash256(coinbase.serialize_without_witness()) + hash256(tx64.serialize_without_witness())
        assert_equal(block.hashMerkleRoot, uint256_from_str(hash256(inner)))
        stream = BytesIO(inner)
        fake = CTransaction()
        fake.deserialize(stream)
        assert_equal(stream.read(), b"")
        assert_equal(fake.serialize_without_witness(), inner)
        assert_equal(len(fake.vout), 0)
        fake_block = CBlockHeader(block).serialize() + ser_compact_size(1) + inner

        with self.node.assert_debug_log(expected_msgs=["Received mutated block"]):
            self.peer.send_without_ping(msg_generic(b"block", fake_block))
            self.peer.wait_for_disconnect()
        self.reconnect_p2p()
        self.peer.sync_with_ping()
        assert_equal(self.node.submitblock(fake_block.hex()), "bad-cb-missing")
        self.send([block])
        assert_equal(self.node.getbestblockhash(), block.hash_hex)

    # ------------------------------------------------------------ f

    def test_p2sh_stack_size(self):
        self.log.info("f. P2SH spends with 1,000 and 999 stack elements before the output script")
        outpoint, value = self.take_coin()
        redeem_script = CScript([OP_TRUE])
        p2sh = CScript([OP_HASH160, hash160(redeem_script), OP_EQUAL])
        fund = self.spend(outpoint, value, outputs=[CTxOut(10 * COIN, p2sh), CTxOut(value - 10 * COIN, ANYONE_CAN_SPEND)])
        self.send([self.make_block([fund])])

        def p2sh_spend(elements):
            script_sig = CScript([OP_0] * (elements - 1) + [bytes(redeem_script)])
            return self.spend(COutPoint(fund.txid_int, 0), 10 * COIN, script_sig=script_sig)

        block = self.make_block([p2sh_spend(1000)])
        self.send([block], success=False, reject_reason="Stack size limit exceeded", reconnect=True)
        block = self.make_block([p2sh_spend(999)])
        self.send([block])

    # ------------------------------------------------------------ a

    def test_bip68_unsigned_version(self):
        self.log.info("a. BIP68 compares the transaction version as unsigned")
        outpoint, value = self.take_coin()
        fund = self.spend(outpoint, value, outputs=[CTxOut(10 * COIN, ANYONE_CAN_SPEND) for _ in range(4)] +
                          [CTxOut(value - 40 * COIN, ANYONE_CAN_SPEND)])
        self.send([self.make_block([fund])])
        _, coin_height, _ = self.tip()

        def locked(version, n):
            return self.spend(COutPoint(fund.txid_int, n), 10 * COIN, version=version, sequence=10)

        tx_ffffffff = locked(0xffffffff, 0)
        tx_80000000 = locked(0x80000000, 1)
        tx_v1 = locked(1, 2)

        # One confirmation of a ten-block lock.
        self.send([self.make_block([tx_ffffffff])], success=False, reject_reason="bad-txns-nonfinal", reconnect=True)
        self.submit(self.make_block([tx_80000000]), "bad-txns-nonfinal")
        self.send([self.make_block([tx_v1])])

        # Nine confirmations still fail, ten pass.
        _, height, _ = self.tip()
        self.mine(coin_height + 8 - height)
        self.submit(self.make_block([tx_ffffffff, tx_80000000]), "bad-txns-nonfinal")
        self.mine(1)
        block = self.make_block([tx_ffffffff, tx_80000000])
        assert_equal(self.tip()[1] + 1, coin_height + 10)
        self.send([block])

        # A time-based lock on a coin created earlier in the same block.
        parent = self.spend(COutPoint(fund.txid_int, 3), 10 * COIN)

        def child(lock):
            return self.spend(COutPoint(parent.txid_int, 0), 10 * COIN, version=0xffffffff,
                              sequence=SEQUENCE_LOCKTIME_TYPE_FLAG | lock)

        self.send([self.make_block([parent, child(1)])], success=False, reject_reason="bad-txns-nonfinal", reconnect=True)
        self.send([self.make_block([parent, child(0)])])

    # ------------------------------------------------------------ c

    def test_subsidy_halving(self):
        self.log.info("c. Subsidy at the regtest halving height")
        _, height, _ = self.tip()
        self.mine(HALVING_HEIGHT - 2 - height)
        assert_equal(self.tip()[1], HALVING_HEIGHT - 2)
        self.send([self.make_block(coinbase_value=50 * COIN)])
        assert_equal(self.tip()[1], HALVING_HEIGHT - 1)
        self.submit(self.make_block(coinbase_value=50 * COIN), "bad-cb-amount")
        self.send([self.make_block(coinbase_value=25 * COIN + 1)], success=False, reject_reason="bad-cb-amount", reconnect=True)
        self.send([self.make_block(coinbase_value=25 * COIN)])
        assert_equal(self.tip()[1], HALVING_HEIGHT)

    # ------------------------------------------------------------ g

    def fork(self, parent_height, count):
        """count blocks on top of the active chain block at parent_height."""
        parent = self.node.getblockhash(parent_height)
        prev, prev_time = int(parent, 16), self.node.getblockheader(parent)["time"]
        blocks = []
        for i in range(count):
            block = create_block(prev, create_coinbase(parent_height + 1 + i), ntime=prev_time + 1 + i, version=4)
            block.solve()
            blocks.append(block)
            prev = block.hash_int
        return blocks

    def chain_tip_entry(self, block_hash):
        return next((t for t in self.node.getchaintips() if t["hash"] == block_hash), None)

    def test_anti_dos_work(self):
        self.log.info("g. Peer-to-peer anti-DoS work checks")
        # Core bypasses the headers check for peers with the noban permission;
        # this test's peer has none.
        peers = [p for p in self.node.getpeerinfo() if p["subver"] == P2P_SUBVERSION]
        assert_equal(len(peers), 1)
        assert_equal(peers[0]["permissions"], [])

        _, height, _ = self.tip()
        self.mine(200 - height)
        _, tip_height, _ = self.tip()
        # Every regtest block has work 2, so the threshold (tip work minus
        # 144 blocks of work) is the chain work at height tip_height - 144: a
        # new block or headers chain ending at or above that height passes.
        lowest = tip_height - 144

        self.log.info("g1. An unsolicited block whose parent is 146 blocks below the tip stores nothing")
        [block] = self.fork(lowest - 2, 1)
        self.send([block], success=False, force_send=True, reject_reason="too-little-chainwork")
        assert_equal(self.chain_tip_entry(block.hash_hex), None)

        self.log.info("g2. At 145 blocks below the tip only the header is stored")
        [block] = self.fork(lowest - 1, 1)
        self.send([block], success=False, force_send=True)
        assert_equal(self.chain_tip_entry(block.hash_hex),
                     {"height": lowest, "hash": block.hash_hex, "branchlen": 1, "status": "headers-only"})

        self.log.info("g3. Closer to the tip as well")
        [block] = self.fork(tip_height - 100, 1)
        self.send([block], success=False, force_send=True)
        assert_equal(self.chain_tip_entry(block.hash_hex)["status"], "headers-only")

        self.log.info("g4. A headers message ending below the threshold is ignored")
        blocks = self.fork(lowest - 27, 27)
        with self.node.assert_debug_log(expected_msgs=["Ignoring low-work chain (height=%d)" % (lowest - 1)]):
            self.peer.send_and_ping(msg_headers([CBlockHeader(b) for b in blocks[:26]]))
        assert all(self.chain_tip_entry(b.hash_hex) is None for b in blocks)

        self.log.info("g5. The same headers and one more reach the threshold: all are stored")
        self.peer.send_and_ping(msg_headers([CBlockHeader(b) for b in blocks]))
        assert_equal(self.chain_tip_entry(blocks[-1].hash_hex),
                     {"height": lowest, "hash": blocks[-1].hash_hex, "branchlen": 27, "status": "headers-only"})

        self.log.info("g6. A short headers message forking near the tip is stored")
        blocks = self.fork(tip_height - 80, 3)
        self.peer.send_and_ping(msg_headers([CBlockHeader(b) for b in blocks]))
        assert_equal(self.chain_tip_entry(blocks[-1].hash_hex)["status"], "headers-only")
        assert_equal(self.tip()[1], tip_height)

    # ------------------------------------------------------------ j

    def test_output_count(self):
        self.log.info("j. A transaction with 100,001 outputs is valid")
        outpoint, value = self.take_coin()
        outputs = [CTxOut(value, ANYONE_CAN_SPEND)] + [CTxOut(0, b"")] * 100_000
        block = self.make_block([self.spend(outpoint, value, outputs=outputs)])
        assert_equal(len(block.vtx[1].vout), 100_001)
        self.send([block])
        assert_equal(self.node.getbestblockhash(), block.hash_hex)

    # ------------------------------------------------------------ k

    def test_respend_of_same_block_spend(self):
        self.log.info("k. An output created and spent in one block stays spent")
        outpoint, value = self.take_coin()
        parent = self.spend(outpoint, value, outputs=[CTxOut(10 * COIN, ANYONE_CAN_SPEND),
                                                      CTxOut(value - 10 * COIN, ANYONE_CAN_SPEND)])
        spent, other = COutPoint(parent.txid_int, 0), COutPoint(parent.txid_int, 1)
        first = self.spend(spent, 10 * COIN)

        def respend(amount):
            return self.spend(spent, amount)  # a different transaction for each amount

        self.log.info("k1. The next block spends it again; both blocks are requested and sent together")
        _, height, _ = self.tip()
        block = self.make_block([parent, first])
        child = create_block(block.hash_int, create_coinbase(height + 2), ntime=block.nTime + 1, version=4,
                             txlist=[respend(9 * COIN)])
        child.solve()
        self.send([block, child], success=False, reject_reason="bad-txns-inputs-missingorspent", reconnect=True)
        assert_equal(self.node.getbestblockhash(), block.hash_hex)

        self.log.info("k2. A different re-spend through submitblock")
        self.submit(self.make_block([respend(8 * COIN)]), "bad-txns-inputs-missingorspent")

        self.log.info("k3. A re-spend three blocks above")
        self.mine(2)
        self.send([self.make_block([respend(7 * COIN)])], success=False,
                  reject_reason="bad-txns-inputs-missingorspent", reconnect=True)

        self.log.info("k4. A block that also spends P:1 is rejected as a whole; P:1 is then spendable")
        spend_other = self.spend(other, value - 10 * COIN)
        self.submit(self.make_block([spend_other, respend(6 * COIN)]), "bad-txns-inputs-missingorspent")
        block = self.make_block([spend_other, self.spend(COutPoint(first.txid_int, 0), 10 * COIN)])
        self.send([block])
        assert_equal(self.node.getbestblockhash(), block.hash_hex)

    # ------------------------------------------------------------ h (node 1)

    def test_version_floor_before_dersig(self):
        self.log.info("h. Node 1, BIP34 at 2 but BIP66 and BIP65 at 300: the version floor is 2, compared as signed")
        self.log.info("h1. Before the BIP34 height a negative version is valid")
        block = self.make_block(version=-0x80000000)
        self.submit(block, None)
        assert_equal(self.tip()[1], 1)
        self.mine(9)
        self.bootstrap_p2p()

        self.log.info("h2. After it, 0x80000000, 0xffffffff and 1 are below 2")
        self.send([self.make_block(version=-0x80000000)], success=False, force_send=True,
                  reject_reason="bad-version(0x80000000)", reconnect=True)
        self.submit(self.make_block(version=-1), "bad-version(0xffffffff)")
        self.submit(self.make_block(version=1), "bad-version(0x00000001)")
        assert_equal(self.tip()[1], 10)

        self.log.info("h3. Version 2 is valid until BIP66 activates")
        block = self.make_block(version=2)
        self.send([block])
        assert_equal(self.node.getbestblockhash(), block.hash_hex)

    # ------------------------------------------------------------ i (node 2)

    def test_timewarp_full_block(self):
        self.log.info("i. Node 2, -test=bip94: full blocks at a retarget boundary")
        node = self.node
        genesis_time = node.getblockheader(node.getblockhash(0))["time"]
        for height in range(1, RETARGET_INTERVAL):
            node.setmocktime(genesis_time + 600 * height)
            self.mine(1)
        prev_hash, prev_height, prev_time = self.tip()
        assert_equal(prev_height, RETARGET_INTERVAL - 1)
        assert_equal(prev_time, genesis_time + 600 * prev_height)
        self.bootstrap_p2p()

        def boundary_block(ntime):
            block = create_block(prev_hash, create_coinbase(RETARGET_INTERVAL), ntime=ntime, version=4)
            block.solve()
            return block

        self.log.info("i1. More than 600 seconds before the parent: time-timewarp-attack")
        self.send([boundary_block(prev_time - MAX_TIMEWARP - 1)], success=False, force_send=True,
                  reject_reason="time-timewarp-attack", reconnect=True)
        self.submit(boundary_block(prev_time - 2 * MAX_TIMEWARP), "time-timewarp-attack")
        assert_equal(self.tip()[1], RETARGET_INTERVAL - 1)

        self.log.info("i2. Exactly 600 seconds before the parent is valid and becomes the tip")
        block = boundary_block(prev_time - MAX_TIMEWARP)
        self.send([block])
        assert_equal(node.getbestblockhash(), block.hash_hex)
        assert_equal(self.tip()[1], RETARGET_INTERVAL)


if __name__ == '__main__':
    SpecPitfallsTest(__file__).main()
