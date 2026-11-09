# 14. Peer-to-peer protocol

Nodes exchange headers and blocks over TCP. Nothing in this chapter affects which blocks are valid, but a node that cannot talk to Bitcoin Core cannot follow the chain, and a node that misbehaves gets disconnected. This chapter specifies the subset of the protocol a validating node needs to *download* headers and blocks from Bitcoin Core v32.1 and stay in sync with it, over the **version 1** (unencrypted) transport, and to answer the requests Bitcoin Core sends to its peers. Serving blocks to other nodes, the encrypted version 2 transport (BIP324), transaction relay, compact blocks (BIP152), address relay and block filters are outside this specification.

The reference implements the protocol in this chapter's code, and the conformance suite's interop test runs it against a real Bitcoin Core node.

## 14.1 Message framing

Every message is a 24-byte header followed by a payload:

```text
magic:4 | command:12 | length:u32 | checksum:4 | payload:length
```

- `magic` is the network's message start (chapter 12). A message with the wrong magic means the peer is on another network; disconnect.
- `command` is an ASCII name, padded with zero bytes to 12 bytes. Bitcoin Core drops a message whose command field is malformed (a non-zero byte after a zero byte, or non-printable characters).
- `checksum` is the first 4 bytes of `sha256d(payload)`. Bitcoin Core drops a message with a wrong checksum and keeps the connection.
- `length` must not exceed 4,000,000 (Core: `MAX_PROTOCOL_MESSAGE_LENGTH`). Bitcoin Core checks the magic and the length as soon as the 24-byte header has arrived, before reading any payload, and disconnects a peer that sends the wrong magic or an oversized length. A receiver MUST do the same, or a peer can make it buffer gigabytes.

Payload fields use the serializations of chapter 03. Bitcoin Core ignores unknown commands, and ignores bytes left over after the fields it reads (except in a `feature` message, section 14.2).

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

/// Checks a 24-byte message header as soon as it has arrived, before the payload is read.
/// Returns the command and the payload length. Core: `V1Transport::ProcessReceivedHeaderBytes`.
pub fn check_frame_header(header: &[u8], magic: [u8; 4]) -> std::io::Result<(String, usize)> {
    use std::io::{Error, ErrorKind};
    assert!(header.len() >= 24);
    if header[..4] != magic {
        return Err(Error::new(ErrorKind::InvalidData, "wrong network magic"));
    }
    let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if length > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(Error::new(ErrorKind::InvalidData, "message too large"));
    }
    let name_end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
    Ok((String::from_utf8_lossy(&header[4..4 + name_end]).to_string(), length))
}

/// Decodes one complete frame. `Ok(None)` means the checksum was wrong and the message must be
/// dropped (the connection stays open).
pub fn decode_frame(frame: &[u8], magic: [u8; 4]) -> std::io::Result<Option<Message>> {
    let (command, length) = check_frame_header(frame, magic)?;
    let payload = &frame[24..24 + length];
    if sha256d(payload)[..4] != frame[20..24] {
        return Ok(None);
    }
    Ok(Some(Message { command, payload: payload.to_vec() }))
}
```

## 14.2 Handshake

The connecting side sends `version` first. Each side answers the other's `version` with its own (if it has not sent one yet) and then `verack`; the connection is established when both have received `verack`. Bitcoin Core's order when it receives a `version` from a peer that connected to it is: its own `version`, `wtxidrelay` (if the common version is at least 70016), `sendaddrv2` (likewise), possibly `sendtxrcncl`, then `verack`; after the handshake it typically sends `sendcmpct`, `ping` and `feefilter`.

Rules Bitcoin Core v32.1 enforces (Core: `PeerManagerImpl::ProcessMessage`, `src/net_processing.cpp`; `CConnman`, `src/net.cpp`):

- The first bytes on a connection decide the transport: Bitcoin Core treats a connection whose first message is not a version 1 `version` message as a version 2 (BIP324) handshake. The first message MUST be `version`.
- The peer's protocol version must be at least 31800, and its nonce must not equal one Bitcoin Core sent (that would be a connection to itself).
- Before `verack`, only `version`, `verack`, `wtxidrelay`, `sendaddrv2`, `sendtxrcncl`, `feature`, `sendheaders` and `sendcmpct` are processed; anything else is ignored.
- `wtxidrelay`, `sendaddrv2` and `feature` received **after** `verack` cause a disconnect. A node that sends them must send them between its `version` and its `verack`.
- A `feature` message (protocol version 70017) from a peer whose negotiated version is below 70017, or with a malformed payload, causes a disconnect. A node that advertises 70016 MUST NOT send `feature`.
- The handshake must complete within 60 seconds. A connection on which nothing has been sent or received for 20 minutes is closed.
- `ping` must be answered with `pong` echoing the 8-byte nonce. Bitcoin Core pings every two minutes and disconnects a peer that has not answered for 20 minutes.
- *Misbehaviour* (for example a `headers` message with more than 2,000 headers, an `inv` or `getdata` with more than 50,000 entries, headers with invalid proof of work, or a locator with more than 101 hashes) makes Bitcoin Core disconnect the peer and *discourage* its address (lower priority for future connections). Peers with the `noban` permission are only logged; peers on the local machine are disconnected but not discouraged.

The `version` payload is:

| Field | Encoding | Value to send |
|---|---|---|
| version | i32 | 70016. (Bitcoin Core v32.1 speaks 70017, which adds `feature` messages; advertising 70016 avoids them.) |
| services | u64 | Service bits offered. A node that does not serve blocks sends `NODE_WITNESS` (8); a node that serves all blocks adds `NODE_NETWORK` (1). |
| timestamp | i64 | Current Unix time |
| receiver | services:u64, IPv6 address:16, port:u16 **big-endian** | The peer's address, IPv4 mapped as `::ffff:a.b.c.d`; zeros are accepted |
| sender | the same 26 bytes | Ignored by Bitcoin Core; zeros |
| nonce | u64 | A value unlikely to repeat (random), used to detect connecting to oneself. The reference derives it from the clock. |
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
/// Core: `MAX_INV_SZ`. More entries in one `inv` or `getdata` is misbehaviour.
pub const MAX_INV_SZ: usize = 50_000;

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

- `getheaders` payload: `version:u32` (ignored by Bitcoin Core), a CompactSize count and that many 32-byte hashes (the *locator*, at most 101 entries), and a 32-byte stop hash (zero for "as many as possible").
- `headers` payload: a CompactSize count (at most 2,000) and, for each header, the 80 header bytes followed by a CompactSize transaction count, which Bitcoin Core ignores and senders set to 0.

How Bitcoin Core answers `getheaders` (Core: the `GETHEADERS` case of `ProcessMessage`, `Chainstate::FindForkInGlobalIndex`, `src/validation.cpp`):

- While its own active chain has less work than its minimum chain work, it answers with an empty `headers` message, unless the requester has the `download` permission (for example through `-whitelist`). A node synchronizing from a Bitcoin Core node that is itself still synchronizing therefore gets headers only up to that node's active tip, or none at all.
- With an **empty locator**, it sends exactly one header, the stop hash's, if it knows that block and is willing to serve it (on its active chain, or a recent valid fork); otherwise it sends **nothing at all**.
- Otherwise it takes the first locator hash that it knows and that is on its active chain, or that is a descendant of its active tip (then it uses the tip); hashes it does not know, and hashes on side branches, are skipped; if none qualifies it uses genesis. It then sends the headers of its active chain after that block, up to 2,000, stopping early after the stop hash.

A node keeps sending `getheaders`, with a locator starting from the last header received, until a `headers` message has fewer than 2,000 entries. A received `headers` message is first checked as a whole (`headers_message_acceptable` below), and then processed with `process_headers` (chapter 11) in order, stopping at the first header that fails.

The locator is the hashes of a block and its ancestors at decreasing heights: the first 12 entries are consecutive heights, after which the step doubles at each entry; the list always ends with genesis. Bitcoin Core builds it from its best header when synchronizing headers. (Core: `LocatorEntries`, `src/chain.cpp`.)

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
/// processing none of it:
/// - if any header fails its own proof of work, or the headers do not form a continuous chain
///   (the peer is misbehaving);
/// - if the first header's parent is unknown (Core asks the peer for headers again);
/// - if the chain's claimed work (the parent's chain work plus each header's proof) is below
///   `anti_dos_work_threshold`, unless the last header is already known and is an ancestor of the
///   best header or on the active chain. Core then ignores a message of fewer than 2,000 headers and
///   starts a *low-work headers synchronization* for a full one: it downloads the peer's headers
///   once without storing them, and only if they reach the threshold downloads them again and
///   stores them. The reference does not implement that synchronization; for a peer near the tip,
///   or whose chain has enough work, the stored result is the same. Core skips this check for peers
///   with the `noban` permission.
/// Core: `PeerManagerImpl::ProcessHeadersMessage`, `CheckHeadersPoW`, `TryLowWorkHeadersSync`,
/// `IsAncestorOfBestHeaderOrTip`.
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
    let parent = match state.tree.get(&headers[0].prev_block) {
        Some(parent) => parent,
        None => return false,
    };
    let last = headers.last().expect("not empty").hash();
    let last_already_on_best = state.tree.get(&last).map_or(false, |entry| {
        state.tree.ancestor(&state.best_header().hash, entry.height).map(|a| a.hash) == Some(last) || state.tree.is_active(entry)
    });
    if last_already_on_best {
        return true;
    }
    let claimed_work = headers.iter().fold(parent.chain_work, |work, header| work.wrapping_add(block_proof(header.bits)));
    claimed_work >= anti_dos_work_threshold(state)
}

/// The answer to `getheaders`, or `None` for no answer at all. The reference serves only blocks on its
/// active chain. Core: the `GETHEADERS` case of `ProcessMessage`, `FindForkInGlobalIndex`.
pub fn answer_getheaders(tree: &BlockTree, locator: &[Hash256], stop: &Hash256) -> Option<Vec<BlockHeader>> {
    if locator.is_empty() {
        let entry = tree.get(stop)?;
        if !tree.is_active(entry) {
            return None;
        }
        return Some(vec![entry.header]);
    }
    let tip_height = tree.active.len() as i32 - 1;
    let tip_hash = *tree.active.last().expect("chain has genesis");
    let mut fork_height = 0;
    for hash in locator {
        if let Some(entry) = tree.get(hash) {
            if tree.is_active(entry) {
                fork_height = entry.height;
                break;
            }
            if tree.ancestor(hash, tip_height).map(|a| a.hash) == Some(tip_hash) {
                fork_height = tip_height;
                break;
            }
        }
    }
    let mut headers = Vec::new();
    for height in fork_height + 1..=tip_height {
        let entry = &tree.entries[&tree.active[height as usize]];
        headers.push(entry.header);
        if headers.len() >= MAX_HEADERS_RESULTS || entry.hash == *stop {
            break;
        }
    }
    Some(headers)
}
```

## 14.4 Block download

Blocks are requested with `getdata`, whose payload is a CompactSize count (at most 50,000) followed by inventory entries `type:u32 | hash:32`. To receive witness data a node MUST request blocks with the type `MSG_WITNESS_BLOCK` (`0x40000002`). A plain `MSG_BLOCK` (2) request returns the block without witnesses; for a block that has witness data, that copy fails validation after segwit activation (the witness commitment check of chapter 10, a `Mutated` failure).

Bitcoin Core answers a block request with a `block` message, or **not at all**: it never sends `notfound` for blocks. It stays silent for a block it does not know, does not have the data for, or will not serve (an old block on a side branch), and it disconnects a peer that asks for pruned blocks or historical blocks beyond what it is willing to serve. A requester MUST therefore time out every block request and ask another peer. Bitcoin Core's own downloader gives a peer 2 seconds, doubling up to 64 seconds, before it considers the peer stalling (Core: `BLOCK_STALLING_TIMEOUT_DEFAULT`, `BLOCK_STALLING_TIMEOUT_MAX`).

Blocks are requested along the best header chain, oldest first. Bitcoin Core itself keeps at most 16 blocks in flight per peer; a node downloading from Bitcoin Core should do the same, because Bitcoin Core answers `getdata` requests one at a time and large batches only delay other messages.

Bitcoin Core announces new blocks with `inv` entries of type `MSG_BLOCK`, or with `headers` messages if the peer sent `sendheaders` (empty payload; Bitcoin Core accepts it before or after `verack`). On an `inv` for an unknown block, send `getheaders`; on new headers, request the blocks.

A block received from a peer is first checked with `is_block_mutated` (chapter 11) when its parent is known; a mutated block is dropped and the peer is misbehaving. Then, if the block's header is new and its parent is known, Bitcoin Core drops the block (reason `too-little-chainwork`, nothing stored) when the parent's chain work plus the block's own proof is below an anti-denial-of-service threshold: the active tip's work minus 144 blocks of work at the tip's difficulty, but at least the minimum chain work (`p2p_block_work_acceptable`). Core reports this only after the context-free block checks and the header checks have passed; nothing is stored in either case. Blocks the node requested always have known headers, so the check matters only for unrequested blocks. Finally the block goes to `process_block`, as *requested* if the node had asked for it and as unrequested otherwise. A peer that sends a block that fails validation is misbehaving (section 14.2).

```rust
pub const MSG_TX: u32 = 1;
pub const MSG_BLOCK: u32 = 2;
pub const MSG_WITNESS_FLAG: u32 = 1 << 30;
pub const MSG_WITNESS_BLOCK: u32 = MSG_BLOCK | MSG_WITNESS_FLAG;
/// Core: `MAX_BLOCKS_IN_TRANSIT_PER_PEER`.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;
/// How long the reference waits for one requested block before giving up on the peer.
pub const BLOCK_REQUEST_TIMEOUT_SECS: u64 = 64;

/// Core: `PeerManagerImpl::GetAntiDoSWorkThreshold`. Multiplication wraps, as in Core.
pub fn anti_dos_work_threshold(state: &ChainState) -> U256 {
    let tip = state.tip();
    let buffer = block_proof(tip.header.bits).wrapping_mul(U256::from_u64(144));
    let near_tip = if buffer > tip.chain_work { U256::from_u64(0) } else { tip.chain_work.wrapping_sub(buffer) };
    std::cmp::max(near_tip, state.minimum_chain_work)
}

/// Whether a block that arrived in a `block` message may be processed. Core: the `BLOCK` case of
/// `ProcessMessage` (`min_pow_checked`) and `AcceptBlockHeader` (`too-little-chainwork`).
pub fn p2p_block_work_acceptable(state: &ChainState, header: &BlockHeader) -> bool {
    if state.tree.get(&header.hash()).is_some() {
        return true;
    }
    match state.tree.get(&header.prev_block) {
        // An orphan; `process_block` discards it.
        None => true,
        Some(parent) => parent.chain_work.wrapping_add(block_proof(header.bits)) >= anti_dos_work_threshold(state),
    }
}

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

The function below connects to one peer, performs the handshake, downloads headers and blocks until the active tip equals `stop_at` (in headers-only mode, until the header `stop_at` is known), and answers `ping` and `getheaders` along the way. Without `stop_at`, it stops when the peer has no more headers (headers-only mode) or when nothing has happened for `idle_limit` seconds. It fails with an error when it makes no progress for `idle_limit` seconds with a target still unreached, when a requested block does not arrive within `BLOCK_REQUEST_TIMEOUT_SECS`, when the peer sends a block that cannot be decoded or that fails validation, and when the peer breaks the framing rules. While a target is unknown it asks for headers again every 10 seconds, because a peer that is itself still synchronizing does not announce new blocks. It is deliberately simple: one peer, one connection, blocking input and output. It is the reference behaviour the conformance suite's interop test exercises against Bitcoin Core; a production node adds multiple peers, peer discovery, retries elsewhere and persistence.

```rust
/// Outcome of a successful synchronization run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEnd {
    /// The active tip reached the requested block.
    ReachedTarget,
    /// No target was given and the peer had nothing more to offer.
    Idle,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Synchronizes `state` from the peer at `address` (host:port). With `download_blocks` false, only
/// headers are synchronized.
pub fn sync_from_peer(state: &mut ChainState, address: &str, stop_at: Option<Hash256>, idle_limit: u64, download_blocks: bool) -> std::io::Result<SyncEnd> {
    use std::io::{Error, ErrorKind, Write};
    use std::time::Instant;
    let magic = state.params.magic;
    let mut stream = std::net::TcpStream::connect(address)?;
    stream.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
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
    // A getheaders request is outstanding.
    let mut requested_headers = false;
    // The peer answered getheaders with fewer than the maximum number of headers.
    let mut headers_synced = false;
    let mut last_headers_request = Instant::now();
    let mut in_flight: Vec<(Hash256, Instant)> = Vec::new();
    // Last time the best header or the active tip changed.
    let mut last_progress = Instant::now();
    let request_headers = |state: &ChainState, stream: &mut std::net::TcpStream| -> std::io::Result<()> {
        let best = state.best_header().hash;
        stream.write_all(&encode_message(magic, "getheaders", &encode_getheaders(&block_locator(&state.tree, &best), &ZERO_HASH)))
    };

    loop {
        if let Some(target) = stop_at {
            let reached = if download_blocks { state.tip().hash == target } else { state.tree.get(&target).is_some() };
            if reached {
                return Ok(SyncEnd::ReachedTarget);
            }
        }
        let progress_before = (state.best_header().hash, state.tip().hash);
        // Read what is available; check each frame header as soon as it is complete.
        let mut chunk = [0u8; 65536];
        match std::io::Read::read(&mut stream, &mut chunk) {
            Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "peer closed the connection")),
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
        let mut messages = Vec::new();
        while buffer.len() >= 24 {
            let (_, length) = check_frame_header(&buffer[..24], magic)?;
            if buffer.len() < 24 + length {
                break;
            }
            let frame: Vec<u8> = buffer.drain(..24 + length).collect();
            if let Some(message) = decode_frame(&frame, magic)? {
                messages.push(message);
            }
        }

        for message in messages {
            match message.command.as_str() {
                "version" => {
                    let theirs = decode_version(&message.payload).map_err(|e| Error::new(ErrorKind::InvalidData, e.0))?;
                    if theirs.version < MIN_PEER_PROTO_VERSION {
                        return Err(Error::new(ErrorKind::InvalidData, "peer version too old"));
                    }
                    send(&mut stream, "sendheaders", &[])?;
                    send(&mut stream, "verack", &[])?;
                }
                "verack" => {
                    handshake_done = true;
                    request_headers(state, &mut stream)?;
                    requested_headers = true;
                    last_headers_request = Instant::now();
                }
                "ping" => send(&mut stream, "pong", &message.payload)?,
                "getheaders" => {
                    if let Ok((locator, stop)) = decode_getheaders(&message.payload) {
                        if let Some(headers) = answer_getheaders(&state.tree, &locator, &stop) {
                            send(&mut stream, "headers", &encode_headers(&headers))?;
                        }
                    }
                }
                "headers" => {
                    requested_headers = false;
                    let headers = decode_headers(&message.payload).map_err(|e| Error::new(ErrorKind::InvalidData, e.0))?;
                    let full_batch = headers.len() == MAX_HEADERS_RESULTS;
                    if headers_message_acceptable(state, &headers) {
                        let _ = state.process_headers(&headers, unix_now());
                    }
                    if full_batch {
                        request_headers(state, &mut stream)?;
                        requested_headers = true;
                        last_headers_request = Instant::now();
                    } else {
                        headers_synced = true;
                    }
                }
                "inv" => {
                    if let Ok(items) = decode_inv(&message.payload) {
                        // `!` on an integer is bitwise NOT: this clears the witness flag.
                        if items.iter().any(|(kind, hash)| (*kind & !MSG_WITNESS_FLAG) == MSG_BLOCK && state.tree.get(hash).is_none()) {
                            request_headers(state, &mut stream)?;
                            requested_headers = true;
                            last_headers_request = Instant::now();
                        }
                    }
                }
                "block" => {
                    let block = deserialize_block(&message.payload).map_err(|e| Error::new(ErrorKind::InvalidData, format!("undecodable block: {}", e.0)))?;
                    let hash = block.hash();
                    let was_requested = in_flight.iter().any(|(h, _)| *h == hash);
                    in_flight.retain(|(h, _)| *h != hash);
                    let segwit_active = state.tree.get(&block.header.prev_block).map(|p| p.height + 1 >= state.params.consensus.segwit_height);
                    let failure = if segwit_active.map_or(false, |active| is_block_mutated(&block, active)) {
                        Some("mutated block".to_string())
                    } else if !p2p_block_work_acceptable(state, &block.header) {
                        None
                    } else {
                        match state.process_block(block, unix_now(), was_requested) {
                            BlockOutcome::Rejected(failure) => Some(failure.reason),
                            _ => None,
                        }
                    };
                    // Bitcoin Core disconnects a peer that sends an invalid block; so does the reference.
                    if let Some(reason) = failure {
                        return Err(Error::new(ErrorKind::InvalidData, format!("peer sent an invalid block {}: {reason}", hash_to_display(&hash))));
                    }
                }
                _ => {}
            }
        }

        if (state.best_header().hash, state.tip().hash) != progress_before {
            last_progress = Instant::now();
        }
        if !handshake_done {
            if last_progress.elapsed().as_secs() >= 60 {
                return Err(Error::new(ErrorKind::TimedOut, "handshake did not complete"));
            }
            continue;
        }
        // Headers-only mode without a target ends once the peer has no more headers.
        if !download_blocks && headers_synced && !requested_headers && stop_at.is_none() {
            return Ok(SyncEnd::Idle);
        }
        // While the target is unknown, ask again from time to time.
        if let Some(target) = stop_at {
            if headers_synced && !requested_headers && state.tree.get(&target).is_none() && last_headers_request.elapsed().as_secs() >= 10 {
                request_headers(state, &mut stream)?;
                requested_headers = true;
                last_headers_request = Instant::now();
            }
        }
        // Give up on a peer that does not deliver a requested block.
        if in_flight.iter().any(|(_, since)| since.elapsed().as_secs() >= BLOCK_REQUEST_TIMEOUT_SECS) {
            return Err(Error::new(ErrorKind::TimedOut, "requested block not delivered"));
        }
        // Request missing blocks along the best header chain, oldest first.
        if download_blocks && in_flight.len() < MAX_BLOCKS_IN_TRANSIT_PER_PEER {
            let best = state.best_header().hash;
            let best_height = state.tree.entries[&best].height;
            let start = state.tree.entries[&state.find_fork(&best)].height + 1;
            let mut wanted = Vec::new();
            for height in start..=best_height {
                if in_flight.len() + wanted.len() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER {
                    break;
                }
                let entry = state.tree.ancestor(&best, height).unwrap();
                if entry.block.is_none() && !entry.failed && !in_flight.iter().any(|(h, _)| *h == entry.hash) {
                    wanted.push(entry.hash);
                }
            }
            if !wanted.is_empty() {
                let items: Vec<(u32, Hash256)> = wanted.iter().map(|h| (MSG_WITNESS_BLOCK, *h)).collect();
                send(&mut stream, "getdata", &encode_inv(&items))?;
                in_flight.extend(wanted.into_iter().map(|h| (h, Instant::now())));
            }
        }
        // Nothing outstanding and no progress for `idle_limit` seconds: done without a target, stuck with one.
        if headers_synced && in_flight.is_empty() && last_progress.elapsed().as_secs() >= idle_limit {
            return match stop_at {
                None => Ok(SyncEnd::Idle),
                Some(_) => Err(Error::new(ErrorKind::TimedOut, "no progress towards the target block")),
            };
        }
    }
}
```

## 14.6 DNS seeds and ports

To find peers, Bitcoin Core v32.1 queries these DNS seeds (Core: `vSeeds`, `src/kernel/chainparams.cpp`):

| Network | Seeds |
|---|---|
| main | `dnsseed.bluematt.me`, `seed.bitcoin.jonasschnelli.ch`, `seed.btc.petertodd.net`, `seed.bitcoin.sprovoost.nl`, `dnsseed.emzy.de`, `seed.bitcoin.wiz.biz`, `seed.mainnet.achownodes.xyz` |
| testnet3 | `testnet-seed.bitcoin.jonasschnelli.ch`, `seed.tbtc.petertodd.net`, `testnet-seed.bluematt.me`, `seed.testnet.achownodes.xyz` |
| testnet4 | `seed.testnet4.bitcoin.sprovoost.nl`, `seed.testnet4.wiz.biz` |
| signet (default challenge) | `seed.signet.bitcoin.sprovoost.nl`, `seed.signet.achownodes.xyz` |

Default ports are in chapter 12. Peer discovery is not part of consensus; any source of honest peers works, and a node SHOULD connect to several, because a single peer can withhold the best chain.
