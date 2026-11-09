# 14. Peer-to-peer protocol

Nodes exchange headers and blocks over TCP. Nothing in this chapter affects which blocks are valid, but a node that cannot talk to Bitcoin Core cannot follow the chain, and a node that misbehaves gets disconnected. This chapter specifies the subset of the protocol a validating node needs to synchronize from, and stay in sync with, Bitcoin Core v32.1 over the **version 1** (unencrypted) transport. Bitcoin Core also offers the encrypted version 2 transport (BIP324) and falls back to version 1 when the connecting side speaks it; version 2, transaction relay, compact blocks (BIP152), address relay and block filters are outside this specification.

The reference implements the protocol in this chapter's code, and the conformance suite's interop test runs it against a real Bitcoin Core node.

## 14.1 Message framing

Every message is a 24-byte header followed by a payload:

```text
magic:4 | command:12 | length:u32 | checksum:4 | payload:length
```

- `magic` is the network's message start (chapter 12). A message with the wrong magic means the peer is on another network; disconnect.
- `command` is an ASCII name, padded with zero bytes to 12 bytes.
- `checksum` is the first 4 bytes of `sha256d(payload)`. Bitcoin Core drops messages with a wrong checksum.
- `length` must not exceed 4,000,000 (Core: `MAX_PROTOCOL_MESSAGE_LENGTH`); Bitcoin Core disconnects a peer that announces a longer message.

Payload fields use the serializations of chapter 03. Bitcoin Core ignores unknown commands and ignores bytes left over after the fields it reads.

```rust
/// Core: `MAX_PROTOCOL_MESSAGE_LENGTH`, `src/net.h`.
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 4_000_000;

/// One decoded message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub command: String,
    pub payload: Vec<u8>,
}

/// Frames a message. Core: `V1Transport`, `src/net.cpp`.
pub fn encode_message(magic: [u8; 4], command: &str, payload: &[u8]) -> Vec<u8> {
    assert!(command.len() <= 12);
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&magic);
    let mut name = [0u8; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

/// Reads one message. Errors on the wrong magic, an oversized payload, or a bad checksum.
pub fn read_message(stream: &mut dyn std::io::Read, magic: [u8; 4]) -> std::io::Result<Message> {
    use std::io::{Error, ErrorKind};
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;
    if header[..4] != magic {
        return Err(Error::new(ErrorKind::InvalidData, "wrong network magic"));
    }
    let name_end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&header[4..4 + name_end]).to_string();
    let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if length > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(Error::new(ErrorKind::InvalidData, "message too large"));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    if sha256d(&payload)[..4] != header[20..24] {
        return Err(Error::new(ErrorKind::InvalidData, "bad checksum"));
    }
    Ok(Message { command, payload })
}
```

## 14.2 Handshake

The connecting side sends `version` first. Each side answers the other's `version` with its own (if it has not sent one yet) and then `verack`; the connection is established when both have received `verack`. Bitcoin Core's order when it receives a `version` from a peer that connected to it is: its own `version`, `wtxidrelay` (if the peer's version is at least 70016), `sendaddrv2`, possibly `sendtxrcncl`, then `verack`.

Rules Bitcoin Core enforces (Core: `PeerManagerImpl::ProcessMessage`, `src/net_processing.cpp`):

- The peer's protocol version must be at least 31800, and its nonce must not equal one Bitcoin Core sent (self-connection).
- Before `verack`, only `version`, `verack`, `wtxidrelay`, `sendaddrv2`, `sendtxrcncl` and `feature` are processed; anything else is ignored.
- `wtxidrelay`, `sendaddrv2` and `feature` received **after** `verack` cause a disconnect. A node that sends them must send them between its `version` and its `verack`.
- `ping` must be answered with `pong` echoing the 8-byte nonce. Bitcoin Core pings every two minutes and disconnects a peer that has not answered for 20 minutes.

The `version` payload is:

| Field | Encoding | Value to send |
|---|---|---|
| version | i32 | 70016. (Bitcoin Core v32.1 speaks 70017, which adds `feature` messages; advertising 70016 avoids them.) |
| services | u64 | Service bits offered. A node that does not serve blocks sends `NODE_WITNESS` (8); a node that serves all blocks adds `NODE_NETWORK` (1). |
| timestamp | i64 | Current Unix time |
| receiver | services:u64, IPv6 address:16, port:u16 **big-endian** | The peer's address, IPv4 mapped as `::ffff:a.b.c.d`; zeros are accepted |
| sender | the same 26 bytes | Ignored by Bitcoin Core; zeros |
| nonce | u64 | Random, to detect connecting to oneself |
| user agent | var_bytes, at most 256 bytes | For example `/bitcoin-consensus-spec:0.1/` |
| start height | i32 | Height of the active tip |
| relay | u8 (0 or 1) | 0 to receive no transaction announcements |

```rust
pub const PROTOCOL_VERSION: i32 = 70016;
/// Core: `MIN_PEER_PROTO_VERSION`.
pub const MIN_PEER_PROTO_VERSION: i32 = 31800;
pub const NODE_NETWORK: u64 = 1;
pub const NODE_WITNESS: u64 = 1 << 3;
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;

/// The fields of a `version` message that a node acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub nonce: u64,
    pub user_agent: Vec<u8>,
    pub start_height: i32,
    pub relay: bool,
}

pub fn encode_version(message: &VersionMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&message.version.to_le_bytes());
    out.extend_from_slice(&message.services.to_le_bytes());
    out.extend_from_slice(&message.timestamp.to_le_bytes());
    out.extend_from_slice(&[0u8; 26]); // receiver: services, address, port
    out.extend_from_slice(&[0u8; 26]); // sender
    out.extend_from_slice(&message.nonce.to_le_bytes());
    write_var_bytes(&mut out, &message.user_agent);
    out.extend_from_slice(&message.start_height.to_le_bytes());
    out.push(message.relay as u8);
    out
}

/// Decodes a `version` payload the way Bitcoin Core does: fields after the timestamp and receiver are
/// optional, and trailing bytes are ignored.
pub fn decode_version(payload: &[u8]) -> Result<VersionMessage, DecodeError> {
    let mut reader = Reader::new(payload);
    let version = reader.read_i32()?;
    let services = reader.read_u64()?;
    let timestamp = reader.read_i64()?;
    reader.read_bytes(26)?;
    let mut message = VersionMessage { version, services, timestamp, nonce: 1, user_agent: Vec::new(), start_height: -1, relay: true };
    if reader.remaining() > 0 {
        reader.read_bytes(26)?;
        message.nonce = reader.read_u64()?;
    }
    if reader.remaining() > 0 {
        message.user_agent = reader.read_var_bytes()?;
    }
    if reader.remaining() > 0 {
        message.start_height = reader.read_i32()?;
    }
    if reader.remaining() > 0 {
        message.relay = reader.read_u8()? != 0;
    }
    Ok(message)
}
```

## 14.3 Headers synchronization

A node learns the header chain with `getheaders` and `headers`:

- `getheaders` payload: `version:u32` (ignored by Bitcoin Core), a CompactSize count and that many 32-byte hashes (the *locator*, at most 101 entries, else Bitcoin Core disconnects), and a 32-byte stop hash (zero for "as many as possible").
- The answering node finds the first locator hash on its active chain and returns up to 2,000 headers of its active chain after it (`MAX_HEADERS_RESULTS`). Bitcoin Core v32.1 answers with an empty `headers` message while its own chain has less work than its minimum chain work, unless the requesting peer has the `download` permission (for example through `-whitelist`).
- `headers` payload: a CompactSize count (at most 2,000, else Bitcoin Core penalizes the sender) and, for each header, the 80 header bytes followed by a CompactSize transaction count, which Bitcoin Core ignores and senders set to 0.

A node keeps sending `getheaders` with a locator ending in the last header received until a `headers` message has fewer than 2,000 entries. Headers are processed with `process_headers` (chapter 11) in order, and processing stops at the first one that fails.

The locator is the hashes of the active tip and its ancestors at decreasing heights: the first 10 one apart, then doubling the step each time, always ending with genesis. (Core: `LocatorEntries`, `src/chain.cpp`.)

```rust
/// Core: `MAX_HEADERS_RESULTS`.
pub const MAX_HEADERS_RESULTS: usize = 2000;
/// Core: `MAX_LOCATOR_SZ`.
pub const MAX_LOCATOR_SZ: usize = 101;

/// Core: `LocatorEntries`.
pub fn block_locator(tree: &BlockTree, from: &Hash256) -> Vec<Hash256> {
    let mut have = Vec::new();
    let mut step = 1;
    let mut entry = tree.get(from);
    while let Some(current) = entry {
        have.push(current.hash);
        if current.height == 0 {
            break;
        }
        let height = (current.height - step).max(0);
        entry = tree.ancestor(&current.hash, height);
        if have.len() > 10 {
            step *= 2;
        }
    }
    have
}

pub fn encode_getheaders(locator: &[Hash256], stop: &Hash256) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(PROTOCOL_VERSION as u32).to_le_bytes());
    write_compact_size(&mut out, locator.len() as u64);
    for hash in locator {
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(stop);
    out
}

pub fn decode_getheaders(payload: &[u8]) -> Result<(Vec<Hash256>, Hash256), DecodeError> {
    let mut reader = Reader::new(payload);
    reader.read_u32()?;
    let count = reader.read_compact_size()?;
    let mut locator = Vec::new();
    for _ in 0..count {
        locator.push(reader.read_hash()?);
    }
    Ok((locator, reader.read_hash()?))
}

pub fn encode_headers(headers: &[BlockHeader]) -> Vec<u8> {
    let mut out = Vec::new();
    write_compact_size(&mut out, headers.len() as u64);
    for header in headers {
        out.extend_from_slice(&header.serialize());
        out.push(0);
    }
    out
}

pub fn decode_headers(payload: &[u8]) -> Result<Vec<BlockHeader>, DecodeError> {
    let mut reader = Reader::new(payload);
    let count = reader.read_compact_size()? as usize;
    if count > MAX_HEADERS_RESULTS {
        return Err(DecodeError("too many headers"));
    }
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        headers.push(read_block_header(&mut reader)?);
        reader.read_compact_size()?;
    }
    Ok(headers)
}

/// Whether a received `headers` message is processed at all. Bitcoin Core drops the whole message,
/// processing none of it, if any header fails its own proof of work, if the headers do not form a
/// continuous chain, or if the first header's parent is unknown. (It then also applies an anti-denial-
/// of-service threshold to chains with little work, which never triggers for honest peers near the
/// tip.) Core: `PeerManagerImpl::ProcessHeadersMessage`, `CheckHeadersPoW`.
pub fn headers_message_acceptable(state: &ChainState, headers: &[BlockHeader]) -> bool {
    if headers.is_empty() {
        return true;
    }
    let pow_limit = state.params.consensus.pow_limit;
    if headers.iter().any(|header| !check_proof_of_work(&header.hash(), header.bits, pow_limit)) {
        return false;
    }
    if headers.windows(2).any(|pair| pair[1].prev_block != pair[0].hash()) {
        return false;
    }
    state.tree.get(&headers[0].prev_block).is_some()
}

/// The headers to send in answer to `getheaders`. Core: the `GETHEADERS` case of `ProcessMessage`.
pub fn answer_getheaders(tree: &BlockTree, locator: &[Hash256], stop: &Hash256) -> Vec<BlockHeader> {
    let start = locator
        .iter()
        .filter_map(|hash| tree.get(hash))
        .find(|entry| tree.is_active(entry))
        .map(|entry| entry.height + 1)
        .unwrap_or(0);
    let mut headers = Vec::new();
    for height in start..tree.active.len() as i32 {
        let entry = &tree.entries[&tree.active[height as usize]];
        headers.push(entry.header);
        if headers.len() >= MAX_HEADERS_RESULTS || entry.hash == *stop {
            break;
        }
    }
    headers
}
```

Bitcoin Core's own `FindForkInGlobalIndex` also accepts a locator hash that is on a side branch it knows, by taking that block's fork point with the active chain; the simpler rule above returns more headers in that case, which the requester simply finds it already has.

## 14.4 Block download

Blocks are requested with `getdata`, whose payload is a CompactSize count followed by inventory entries `type:u32 | hash:32`. To receive witness data a node MUST request blocks with the type `MSG_WITNESS_BLOCK` (`0x40000002`). A plain `MSG_BLOCK` (2) request returns the block without witnesses, which fails validation after segwit activation (the witness commitment check of chapter 10, with `Mutated` failures). The answer is a `block` message carrying the block, or `notfound`.

Blocks are requested along the best header chain, oldest first. Bitcoin Core itself keeps at most 16 blocks in flight per peer; a node downloading from Bitcoin Core should do the same, because Bitcoin Core answers `getdata` requests one at a time and large batches only delay other messages.

Bitcoin Core announces new blocks with `inv` entries of type `MSG_BLOCK`, or with `headers` messages after the peer has sent `sendheaders` (empty payload). On an `inv` for an unknown block, send `getheaders`; on new headers, request the blocks.

Blocks received from a peer are first checked with `is_block_mutated` (chapter 11) when their parent is known, and then given to `process_block` as *requested* if the node asked for them.

```rust
pub const MSG_TX: u32 = 1;
pub const MSG_BLOCK: u32 = 2;
pub const MSG_WITNESS_FLAG: u32 = 1 << 30;
pub const MSG_WITNESS_BLOCK: u32 = MSG_BLOCK | MSG_WITNESS_FLAG;
/// Core: `MAX_BLOCKS_IN_TRANSIT_PER_PEER`.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;

pub fn encode_inv(items: &[(u32, Hash256)]) -> Vec<u8> {
    let mut out = Vec::new();
    write_compact_size(&mut out, items.len() as u64);
    for (kind, hash) in items {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(hash);
    }
    out
}

pub fn decode_inv(payload: &[u8]) -> Result<Vec<(u32, Hash256)>, DecodeError> {
    let mut reader = Reader::new(payload);
    let count = reader.read_compact_size()?;
    let mut items = Vec::new();
    for _ in 0..count {
        items.push((reader.read_u32()?, reader.read_hash()?));
    }
    Ok(items)
}
```

## 14.5 A minimal synchronizing peer

The function below connects to one peer, performs the handshake, downloads headers and blocks until the active tip equals `stop_at` (or the peer has nothing more to give), and answers `ping` and `getheaders` along the way. It is deliberately simple: one peer, one connection, blocking input and output. It is the reference behaviour the conformance suite's interop test exercises against Bitcoin Core; a production node adds multiple peers, peer discovery, timeouts and persistence.

```rust
/// Outcome of a synchronization run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEnd {
    /// The active tip reached the requested block.
    ReachedTarget,
    /// The peer had nothing more to offer and no request was outstanding for `idle_limit` seconds.
    Idle,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Synchronizes `state` from the peer at `address` (host:port). With `download_blocks` false, only
/// headers are synchronized.
pub fn sync_from_peer(state: &mut ChainState, address: &str, stop_at: Option<Hash256>, idle_limit: u64, download_blocks: bool) -> std::io::Result<SyncEnd> {
    use std::io::Write;
    let magic = state.params.magic;
    let mut stream = std::net::TcpStream::connect(address)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    let send = |stream: &mut std::net::TcpStream, command: &str, payload: &[u8]| -> std::io::Result<()> {
        stream.write_all(&encode_message(magic, command, payload))
    };

    let nonce = sha256(&unix_now().to_le_bytes());
    let version = VersionMessage {
        version: PROTOCOL_VERSION,
        services: NODE_WITNESS,
        timestamp: unix_now(),
        nonce: u64::from_le_bytes(nonce[..8].try_into().unwrap()),
        user_agent: b"/bitcoin-consensus-spec:0.1/".to_vec(),
        start_height: state.tip().height,
        relay: false,
    };
    send(&mut stream, "version", &encode_version(&version))?;

    let mut buffer: Vec<u8> = Vec::new();
    let mut handshake_done = false;
    let mut requested_headers = false;
    // True once the peer has answered `getheaders` with fewer than the maximum number of headers.
    let mut headers_synced = false;
    let mut in_flight: Vec<Hash256> = Vec::new();
    let mut last_activity = std::time::Instant::now();

    loop {
        if let Some(target) = stop_at {
            if state.tip().hash == target {
                return Ok(SyncEnd::ReachedTarget);
            }
        }
        // Read whatever is available and decode complete messages.
        let mut chunk = [0u8; 65536];
        match std::io::Read::read(&mut stream, &mut chunk) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "peer closed the connection")),
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
        let mut messages = Vec::new();
        loop {
            if buffer.len() < 24 {
                break;
            }
            let length = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]) as usize;
            if buffer.len() < 24 + length {
                break;
            }
            let frame: Vec<u8> = buffer.drain(..24 + length).collect();
            messages.push(read_message(&mut &frame[..], magic)?);
        }

        for message in messages {
            last_activity = std::time::Instant::now();
            match message.command.as_str() {
                "version" => {
                    let theirs = decode_version(&message.payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.0))?;
                    if theirs.version < MIN_PEER_PROTO_VERSION {
                        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "peer version too old"));
                    }
                    send(&mut stream, "verack", &[])?;
                }
                "verack" => {
                    handshake_done = true;
                    send(&mut stream, "sendheaders", &[])?;
                }
                "ping" => send(&mut stream, "pong", &message.payload)?,
                "getheaders" => {
                    if let Ok((locator, stop)) = decode_getheaders(&message.payload) {
                        let headers = answer_getheaders(&state.tree, &locator, &stop);
                        send(&mut stream, "headers", &encode_headers(&headers))?;
                    }
                }
                "headers" => {
                    requested_headers = false;
                    let headers = decode_headers(&message.payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.0))?;
                    let full_batch = headers.len() == MAX_HEADERS_RESULTS;
                    headers_synced = !full_batch;
                    if headers_message_acceptable(state, &headers) {
                        let _ = state.process_headers(&headers, unix_now());
                    }
                    if full_batch {
                        let last = headers.last().unwrap().hash();
                        let locator = block_locator(&state.tree, &last);
                        send(&mut stream, "getheaders", &encode_getheaders(&locator, &ZERO_HASH))?;
                        requested_headers = true;
                    }
                }
                "inv" => {
                    if let Ok(items) = decode_inv(&message.payload) {
                        if items.iter().any(|(kind, hash)| *kind & !MSG_WITNESS_FLAG == MSG_BLOCK && state.tree.get(hash).is_none()) {
                            headers_synced = false;
                            let best = state.best_header().hash;
                            send(&mut stream, "getheaders", &encode_getheaders(&block_locator(&state.tree, &best), &ZERO_HASH))?;
                            requested_headers = true;
                        }
                    }
                }
                "block" => {
                    if let Ok(block) = deserialize_block(&message.payload) {
                        let hash = block.hash();
                        in_flight.retain(|h| *h != hash);
                        let segwit_active = state.tree.get(&block.header.prev_block).map(|p| p.height + 1 >= state.params.consensus.segwit_height);
                        let is_mutated = segwit_active.map_or(false, |active| is_block_mutated(&block, active));
                        if !is_mutated {
                            state.process_block(block, unix_now(), true);
                        }
                    }
                }
                _ => {}
            }
        }

        if !handshake_done {
            continue;
        }
        let want_headers = !headers_synced || stop_at.map_or(false, |t| state.tree.get(&t).is_none());
        if !requested_headers && in_flight.is_empty() && want_headers && (!headers_synced || last_activity.elapsed().as_secs() >= idle_limit) {
            // Ask for headers when the target is not known yet.
            let best = state.best_header().hash;
            send(&mut stream, "getheaders", &encode_getheaders(&block_locator(&state.tree, &best), &ZERO_HASH))?;
            requested_headers = true;
        }
        // Request missing blocks along the best header chain, oldest first.
        if download_blocks && in_flight.len() < MAX_BLOCKS_IN_TRANSIT_PER_PEER {
            let best = state.best_header().hash;
            let tip_height = state.tip().height;
            let best_height = state.tree.entries[&best].height;
            let mut wanted = Vec::new();
            let fork_height = state.tree.entries[&state.find_fork(&best)].height;
            let start = fork_height.min(tip_height) + 1;
            for height in start..=best_height {
                if in_flight.len() + wanted.len() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER {
                    break;
                }
                let entry = state.tree.ancestor(&best, height).unwrap();
                if entry.block.is_none() && !in_flight.contains(&entry.hash) && !entry.failed {
                    wanted.push(entry.hash);
                }
            }
            if !wanted.is_empty() {
                let items: Vec<(u32, Hash256)> = wanted.iter().map(|h| (MSG_WITNESS_BLOCK, *h)).collect();
                send(&mut stream, "getdata", &encode_inv(&items))?;
                in_flight.extend(wanted);
            }
        }
        if !download_blocks && headers_synced && !requested_headers {
            return Ok(SyncEnd::Idle);
        }
        if !requested_headers && in_flight.is_empty() && headers_synced && last_activity.elapsed().as_secs() >= idle_limit {
            return Ok(SyncEnd::Idle);
        }
    }
}
```

## 14.6 DNS seeds and ports

To find peers on mainnet, Bitcoin Core v32.1 queries these DNS seeds: `dnsseed.bluematt.me`, `seed.bitcoin.jonasschnelli.ch`, `seed.btc.petertodd.net`, `seed.bitcoin.sprovoost.nl`, `dnsseed.emzy.de`, `seed.bitcoin.wiz.biz`, `seed.mainnet.achownodes.xyz`. Testnet4 uses `seed.testnet4.bitcoin.sprovoost.nl` and `seed.testnet4.wiz.biz`. Default ports are in chapter 12. Peer discovery is not part of consensus; any source of honest peers works, and a node SHOULD connect to several, because a single peer can withhold the best chain.
