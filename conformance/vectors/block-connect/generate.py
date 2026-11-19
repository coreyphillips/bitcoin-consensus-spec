"""Writes the block-connect suite's cases: historic blocks with the coins they spend, and
constructed blocks around the BIP34-implies-BIP30 limit.

Usage: [ELECTRUM=host:port,...] python3 -I generate.py <cache-dir> <out.jsonl.gz>

Blocks and ancestor timestamps come from a public Esplora API (mempool.space), and so do the
transactions they spend unless ELECTRUM names Electrum servers (SSL ports) for mainnet. Esplora
serves one spent transaction per request and slows down after a few thousand, so the large blocks
need ELECTRUM: those servers answer pipelined requests, and also give the ancestor timestamps.
Everything is cached in <cache-dir>, so a second run reads nothing from the network. Every
historic block is on the chain Bitcoin Core v32.1 accepts, so its verdict is valid.
The constructed cases at heights 1,983,701 and 1,983,702 cannot come from a chain; their verdicts
follow `ConnectBlock` in Core's `src/validation.cpp` (see README.md).
"""

import concurrent.futures
import gzip
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request

CACHE, OUT = sys.argv[1], sys.argv[2]
API = {"main": "https://mempool.space/api", "testnet3": "https://mempool.space/testnet/api"}
CSV_HEIGHT = {"main": 419328, "testnet3": 770112}
BIP34 = {"main": (227931, "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),
         "testnet3": (21111, "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8")}

# (network, height, hash, name). The hashes are checked against what the API serves.
HISTORIC = [
    ("main", 91722, "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e", "coinbase that block 91880 repeats"),
    ("main", 91812, "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f", "coinbase that block 91842 repeats"),
    ("main", 91842, "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec", "BIP30 exempt, repeats the coinbase of 91812"),
    ("main", 91880, "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721", "BIP30 exempt, repeats the coinbase of 91722"),
    ("main", 170060, "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22", "script flag exception: no P2SH"),
    ("testnet3", 394, "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105", "testnet3 script flag exception: no P2SH"),
    ("main", 363724, "00000000000000000fb32e0d606a42615d44d93449a36ba64ee018de6009f898", "below the BIP66 height"),
    ("main", 363725, "00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931", "BIP66 height"),
    ("main", 210000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e", "first halving"),
    ("main", 227930, "0000000000000251b3834c8d5b9c041bfaa0fedb93c0f16099d0072ed6b629d6", "below the BIP34 height"),
    ("main", 227931, "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8", "BIP34 height"),
    ("main", 388380, "000000000000000009f886db2c7c12a497603e86378bace3ead93d350be3f38c", "below the BIP65 height"),
    ("main", 388381, "000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0", "BIP65 height"),
    ("main", 419327, "0000000000000000051804b4c2da5298c4573386bf1d4242bf0e26a49ec32e42", "below the CSV height"),
    ("main", 419328, "000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5", "CSV height"),
    ("main", 481823, "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80", "below the segwit height"),
    ("main", 481824, "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893", "segwit height"),
    ("main", 692261, "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad",
     "script flag exception: no taproot"),
]

# The coinbase a BIP30 exempt block repeats: it is still unspent when the repeat is connected.
OVERWRITTEN = {91842: 91812, 91880: 91722}


def fetch(network, path, binary=False):
    """GET <api><path>, cached under CACHE."""
    key = os.path.join(CACHE, network, path.strip("/").replace("/", "_"))
    if os.path.exists(key):
        with open(key, "rb") as f:
            data = f.read()
    else:
        for attempt in range(8):
            try:
                with urllib.request.urlopen(API[network] + path, timeout=60) as r:
                    data = r.read()
                break
            except Exception as e:
                if attempt == 7:
                    raise RuntimeError(f"{network} {path}: {e}")
                time.sleep(2 ** attempt)
        os.makedirs(os.path.dirname(key), exist_ok=True)
        with open(key + ".tmp", "wb") as f:
            f.write(data)
        os.replace(key + ".tmp", key)
    return data if binary else json.loads(data) if path.startswith(("/tx/", "/block/")) else data.decode()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def display(h):
    return h[::-1].hex()


class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        out = self.b[self.i:self.i + n]
        if len(out) != n:
            raise ValueError("truncated")
        self.i += n
        return out

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def varint(self):
        n = self.take(1)[0]
        if n < 0xfd:
            return n
        return int.from_bytes(self.take({0xfd: 2, 0xfe: 4, 0xff: 8}[n]), "little")


def parse_tx(r):
    """Returns (txid, version, inputs [(prev_txid_display, vout, sequence)],
    outputs [(amount, script_pubkey hex)])."""
    start = r.i
    version = r.u32()
    segwit = r.b[r.i] == 0 and r.b[r.i + 1] == 1
    if segwit:
        r.take(2)
    body_start = r.i
    inputs = []
    for _ in range(r.varint()):
        prev = r.take(32)
        vout = r.u32()
        r.take(r.varint())
        inputs.append((display(prev), vout, r.u32()))
    outputs = []
    for _ in range(r.varint()):
        amount = struct.unpack("<q", r.take(8))[0]
        outputs.append((amount, r.take(r.varint()).hex()))
    body_end = r.i
    if segwit:
        for _ in inputs:
            for _ in range(r.varint()):
                r.take(r.varint())
    lock = r.take(4)
    stripped = r.b[start:start + 4] + r.b[body_start:body_end] + lock
    return display(sha256d(stripped)), version, inputs, outputs


def parse_block(raw):
    r = Reader(raw)
    header = r.take(80)
    txs = [parse_tx(r) for _ in range(r.varint())]
    if r.i != len(raw):
        raise ValueError("trailing bytes")
    return header, txs


def block_mtp(network, block_hash):
    return fetch(network, f"/block/{block_hash}")["mediantime"]


ELECTRUM = [s for s in os.environ.get("ELECTRUM", "").split(",") if s]
_connections = threading.local()


def electrum(requests):
    """Sends [(method, params)] down one connection to an Electrum server, pipelined, and returns
    the results in order. A failed batch is sent again, to the next server."""
    conns = _connections.__dict__.setdefault("conns", {})
    for attempt in range(3 * len(ELECTRUM)):
        server = ELECTRUM[(attempt + threading.get_ident()) % len(ELECTRUM)]
        try:
            if server not in conns:
                host, port = server.rsplit(":", 1)
                # Public servers mostly have self-signed certificates. Nothing they send is taken
                # on trust beyond what Esplora would be: transactions are checked against their
                # txids, and heights against the hash of the header at that height.
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                sock = socket.create_connection((host, int(port)), timeout=20)
                conns[server] = ctx.wrap_socket(sock, server_hostname=host).makefile("rwb")
                requests = [("server.version", ["bcs-generate", "1.4"])] + requests
            f = conns[server]
            for i, (method, params) in enumerate(requests):
                f.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}).encode() + b"\n")
            f.flush()
            results = {}
            while len(results) < len(requests):
                line = f.readline()
                if not line:
                    raise ConnectionError("connection closed")
                msg = json.loads(line)
                if msg.get("id") is None:
                    continue  # a subscription notification
                if msg.get("error"):
                    raise RuntimeError(msg["error"])
                results[msg["id"]] = msg["result"]
            out = [results[i] for i in range(len(requests))]
            return out[1:] if requests[0][0] == "server.version" else out
        except Exception as e:
            conns.pop(server, None)
            requests = [r for r in requests if r[0] != "server.version"]
            error = f"{server}: {e}"
            print(f"electrum {error}, sending again", file=sys.stderr)
            time.sleep(min(2 ** attempt, 30))
    raise RuntimeError(f"electrum: {error}")


def cached(network, kind, name, compute):
    key = os.path.join(CACHE, network, kind, name)
    if os.path.exists(key):
        with open(key) as f:
            return json.load(f)
    value = compute()
    os.makedirs(os.path.dirname(key), exist_ok=True)
    with open(key + ".tmp", "w") as f:
        json.dump(value, f)
    os.replace(key + ".tmp", key)
    return value


def electrum_headers(start, count):
    """`count` headers from `start`, each linked to the one before it."""
    raw = bytes.fromhex(electrum([("blockchain.block.headers", [start, count])])[0]["hex"])
    headers = [raw[i:i + 80] for i in range(0, len(raw), 80)]
    if len(headers) != count or any(headers[i][4:36] != sha256d(headers[i - 1]) for i in range(1, count)):
        raise ValueError(f"electrum: headers {start} to {start + count - 1} do not form a chain")
    return headers


def electrum_txs(txids):
    """{txid: {"hex", "height"}} for transactions in blocks."""
    replies = electrum([("blockchain.headers.subscribe", [])]
                       + [("blockchain.transaction.get", [t, True]) for t in txids])
    tip = replies[0]["height"]
    out = {}
    for txid, reply in zip(txids, replies[1:]):
        raw = bytes.fromhex(reply["hex"])
        r = Reader(raw)
        if parse_tx(r)[0] != txid or r.i != len(raw):
            raise ValueError(f"electrum: {txid}: the served transaction has another txid")
        out[txid] = {"hex": reply["hex"], "height": tip - reply["confirmations"] + 1, "block": reply["blockhash"]}
    # A block found during the batch makes a height one too low.
    heights = sorted({h for tx in out.values() for h in (tx["height"], tx["height"] + 1)})
    headers = electrum([("blockchain.block.header", [h]) for h in heights])
    hashes = {display(sha256d(bytes.fromhex(header))): h for h, header in zip(heights, headers)}
    for txid, tx in out.items():
        if hashes.get(tx["block"]) not in (tx["height"], tx["height"] + 1):
            raise ValueError(f"electrum: {txid}: no block {tx['block']} at height {tx['height']}")
        tx["height"] = hashes[tx["block"]]
    return {t: {"hex": tx["hex"], "height": tx["height"]} for t, tx in out.items()}


def spent_txs(network, txids, pool):
    """{txid: (outputs [(amount, script_pubkey hex)], height, coinbase)}."""
    if ELECTRUM and network == "main":
        todo = [t for t in txids if not os.path.exists(os.path.join(CACHE, network, "electrum-tx", t))]
        batches = [todo[i:i + 50] for i in range(0, len(todo), 50)]

        # Cached by the worker, so a batch that fails does not lose those that finished after it.
        def fetch_batch(batch):
            for t, tx in electrum_txs(batch).items():
                cached(network, "electrum-tx", t, lambda: tx)
        list(pool.map(fetch_batch, batches))
        out = {}
        for t in txids:
            tx = cached(network, "electrum-tx", t, None)
            _, _, ins, outputs = parse_tx(Reader(bytes.fromhex(tx["hex"])))
            out[t] = (outputs, tx["height"], ins[0][:2] == ("00" * 32, 0xffffffff))
        return out
    out = {}
    for t, tx in zip(txids, pool.map(lambda t: fetch(network, f"/tx/{t}"), txids)):
        out[t] = ([(o["value"], o["scriptpubkey"]) for o in tx["vout"]], tx["status"]["block_height"],
                  tx["vin"][0]["is_coinbase"])
    return out


def ancestor(network, height):
    """(hash, median time past) of the block at `height`."""
    if ELECTRUM and network == "main":
        def compute():
            headers = electrum_headers(height - 10, 11)
            return [display(sha256d(headers[-1])), sorted(struct.unpack("<I", h[68:72])[0] for h in headers)[5]]
        return tuple(cached(network, "electrum-ancestor", str(height), compute))
    block_hash = fetch(network, f"/block-height/{height}")
    return block_hash, block_mtp(network, block_hash)


def historic_case(network, height, block_hash, name, pool):
    raw = fetch(network, f"/block/{block_hash}/raw", binary=True)
    header, txs = parse_block(raw)
    if display(sha256d(header)) != block_hash:
        raise ValueError(f"{block_hash}: the served block has another hash")
    info = fetch(network, f"/block/{block_hash}")
    if info["height"] != height:
        raise ValueError(f"{block_hash}: height {info['height']}, not {height}")
    created = {txid for txid, _, _, _ in txs}
    prev_txids = sorted({p for _, _, ins, _ in txs[1:] for p, _, _ in ins if p not in created})
    prev = spent_txs(network, prev_txids, pool)

    coins = {}
    bip68_heights = set()
    for txid, version, ins, _ in txs[1:]:
        for p, vout, sequence in ins:
            if p in created:
                continue
            outputs, coin_height, coinbase = prev[p]
            amount, script_pubkey = outputs[vout]
            coins[(p, vout)] = {"txid": p, "vout": vout, "amount": amount,
                                "script_pubkey": script_pubkey, "height": coin_height,
                                "coinbase": coinbase}
            # Chapter 08 calculate_sequence_locks reads the median time past before the coin's block.
            if height >= CSV_HEIGHT[network] and version >= 2 and not sequence & (1 << 31):
                bip68_heights.add(max(coin_height - 1, 0))
    if height in OVERWRITTEN:
        old_hash = next(h for n, ht, h, _ in HISTORIC if ht == OVERWRITTEN[height])
        old_raw = fetch(network, f"/block/{old_hash}/raw", binary=True)
        _, old_txs = parse_block(old_raw)
        if old_txs[0][0] != txs[0][0]:
            raise ValueError(f"{height}: the coinbase does not repeat that of {OVERWRITTEN[height]}")
        for vout, (amount, script_pubkey) in enumerate(old_txs[0][3]):
            coins[(old_txs[0][0], vout)] = {"txid": old_txs[0][0], "vout": vout, "amount": amount,
                                           "script_pubkey": script_pubkey,
                                           "height": OVERWRITTEN[height], "coinbase": True}

    parent = display(header[4:36])
    ancestors = {height - 1: (parent, block_mtp(network, parent))}
    bip34_height, bip34_hash = BIP34[network]
    if height > bip34_height:
        ancestors[bip34_height] = (bip34_hash, block_mtp(network, bip34_hash))
    missing = sorted(bip68_heights - set(ancestors))
    ancestors.update(zip(missing, pool.map(lambda h: ancestor(network, h), missing)))
    request = {
        "op": "block_connect",
        "network": network,
        "height": height,
        "block": raw.hex(),
        "ancestors": [{"height": h, "hash": a[0], "median_time_past": a[1]}
                      for h, a in sorted(ancestors.items(), reverse=True)],
        "coins": sorted(coins.values(), key=lambda c: (c["txid"], c["vout"])),
    }
    return {"name": f"{network} {height} {name}", "request": request, "expect": {"valid": True}}


def push_int(n):
    if n == 0:
        return b"\x00"
    if n <= 16:
        return bytes([0x50 + n])
    body = n.to_bytes((n.bit_length() + 8) // 8, "little")
    return bytes([len(body)]) + body


def constructed_case(height, bip34_hash, name, expect, conflict=True):
    """A mainnet block whose coinbase has the txid of a pre-BIP34 coinbase that starts with a push
    of `height`. With `conflict`, that coinbase's output is unspent. The header has no valid proof
    of work: the operation does not check it."""
    subsidy = (50 * 100_000_000) >> (height // 210_000)
    coinbase = (struct.pack("<I", 1) + b"\x01" + b"\x00" * 32 + b"\xff" * 4
                 + bytes([len(push_int(height)) + 2]) + push_int(height) + b"\x00\x00" + b"\xff" * 4
                 + b"\x01" + struct.pack("<q", subsidy) + b"\x01\x51" + b"\x00" * 4)
    txid = sha256d(coinbase)
    parent = hashlib.sha256(f"parent of {height}".encode()).digest()
    header = (struct.pack("<I", 0x20000000) + parent + txid
              + struct.pack("<III", 2_000_000_000, 0x1d00ffff, 0))
    block = header + b"\x01" + coinbase
    request = {
        "op": "block_connect",
        "network": "main",
        "height": height,
        "block": block.hex(),
        "ancestors": [{"height": height - 1, "hash": display(parent), "median_time_past": 1_999_999_000},
                      {"height": 227931, "hash": bip34_hash, "median_time_past": 1_363_934_779}],
        "coins": [{"txid": display(txid), "vout": 0, "amount": subsidy, "script_pubkey": "51",
                   "height": 164384, "coinbase": True}] if conflict else [],
    }
    return {"name": f"main {height} {name}", "request": request, "expect": expect}


def bip30_wrong_height_case(cases):
    """Block 91842 sent as height 91843: the exemption names the height and the hash together."""
    case = json.loads(json.dumps(next(c for c in cases if c["request"]["height"] == 91842)))
    case["name"] = "main 91842 sent as height 91843: not BIP30 exempt"
    case["request"]["height"] = 91843
    case["request"]["ancestors"][0]["height"] = 91842
    case["expect"] = {"valid": False, "reason": "bad-txns-BIP30"}
    return case


def main():
    os.makedirs(CACHE, exist_ok=True)
    only = os.environ.get("ONLY")
    cases = []
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        for network, height, block_hash, name in HISTORIC:
            if only and str(height) not in only.split(","):
                continue
            started = time.time()
            cases.append(historic_case(network, height, block_hash, name, pool))
            print(f"{network} {height}: {len(cases[-1]['request']['coins'])} coins, "
                  f"{time.time() - started:.0f}s", file=sys.stderr)
    if any(c["request"]["height"] == 91842 for c in cases):
        cases.append(bip30_wrong_height_case(cases))
    main_bip34 = BIP34["main"][1]
    other = "000000000000000000000000000000000000000000000000000000000000beef"
    # Below the limit on the BIP34 chain no such coin can be unspent (chapter 10.7), and a
    # conforming implementation may check BIP30 anyway, so this case has no conflict.
    cases.append(constructed_case(1_983_701, main_bip34, "below BIP34_IMPLIES_BIP30_LIMIT, no conflicting coin",
                                  {"valid": True}, conflict=False))
    cases.append(constructed_case(1_983_702, main_bip34, "at BIP34_IMPLIES_BIP30_LIMIT: BIP30 applies",
                                  {"valid": False, "reason": "bad-txns-BIP30"}))
    cases.append(constructed_case(1_983_701, other, "another block at the BIP34 height: BIP30 applies",
                                  {"valid": False, "reason": "bad-txns-BIP30"}))
    with gzip.GzipFile(OUT, "wb", mtime=0) as out:
        for case in cases:
            out.write((json.dumps(case, separators=(", ", ": ")) + "\n").encode())
    print(f"{len(cases)} cases written to {OUT}", file=sys.stderr)


main()
