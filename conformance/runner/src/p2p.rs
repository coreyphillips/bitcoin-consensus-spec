//! A minimal peer-to-peer client (version 1 transport, specification chapter 14): handshake,
//! `ping`/`pong`, `getheaders`/`headers`. Used by the headers-live suite; the message helpers also
//! serve the peer-sync suite (`listen.rs`).

use crate::hex;
use crate::tx::{sha256d, write_compact_size};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Version advertised in `version` (spec chapter 14: 70016 avoids `feature` messages).
pub const PROTOCOL_VERSION: i32 = 70016;
/// Core's `MIN_PEER_PROTO_VERSION`.
pub const MIN_PEER_PROTO_VERSION: i32 = 31800;
/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH`.
pub const MAX_MESSAGE_LENGTH: usize = 4_000_000;
/// Core's `MAX_HEADERS_RESULTS`.
pub const MAX_HEADERS_RESULTS: usize = 2000;
const NODE_WITNESS: u64 = 1 << 3;

/// Message start, default port, genesis block and its `nBits` (Core's chainparams).
#[derive(Clone, Debug)]
pub struct Network {
    pub name: &'static str,
    pub magic: [u8; 4],
    pub port: u16,
    /// Display order.
    pub genesis: &'static str,
    pub genesis_bits: u32,
}

/// The default signet challenge (BIP325); the message start is the first four bytes of the
/// double SHA-256 of the serialized challenge.
const SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

pub fn signet_magic(challenge: &[u8]) -> [u8; 4] {
    let mut data = Vec::new();
    write_compact_size(&mut data, challenge.len() as u64);
    data.extend_from_slice(challenge);
    sha256d(&data)[..4].try_into().unwrap()
}

pub fn network(name: &str) -> Option<Network> {
    Some(match name {
        "main" => Network {
            name: "main",
            magic: [0xf9, 0xbe, 0xb4, 0xd9],
            port: 8333,
            genesis: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            genesis_bits: 0x1d00ffff,
        },
        "testnet3" => Network {
            name: "testnet3",
            magic: [0x0b, 0x11, 0x09, 0x07],
            port: 18333,
            genesis: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            genesis_bits: 0x1d00ffff,
        },
        "testnet4" => Network {
            name: "testnet4",
            magic: [0x1c, 0x16, 0x3f, 0x28],
            port: 48333,
            genesis: "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            genesis_bits: 0x1d00ffff,
        },
        "signet" => Network {
            name: "signet",
            magic: signet_magic(&hex::decode(SIGNET_CHALLENGE).unwrap()),
            port: 38333,
            genesis: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            genesis_bits: 0x1e0377ae,
        },
        "regtest" => Network {
            name: "regtest",
            magic: [0xfa, 0xbf, 0xb5, 0xda],
            port: 18444,
            genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            genesis_bits: 0x207fffff,
        },
        _ => return None,
    })
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug)]
pub struct Message {
    pub command: String,
    pub payload: Vec<u8>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn read_compact_size(data: &[u8], pos: &mut usize) -> io::Result<u64> {
    let take = |pos: &mut usize, n: usize| -> io::Result<u64> {
        if data.len() < *pos + n {
            return Err(invalid("truncated message"));
        }
        let mut v = 0u64;
        for i in 0..n {
            v |= (data[*pos + i] as u64) << (8 * i);
        }
        *pos += n;
        Ok(v)
    };
    match take(pos, 1)? {
        253 => take(pos, 2),
        254 => take(pos, 4),
        255 => take(pos, 8),
        n => Ok(n),
    }
}

/// A `version` payload: protocol 70016, the given services and start height, no relay.
pub fn version_payload(services: u64, start_height: i32) -> Vec<u8> {
    let mut version = Vec::new();
    version.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    version.extend_from_slice(&services.to_le_bytes());
    version.extend_from_slice(&unix_now().to_le_bytes());
    version.extend_from_slice(&[0u8; 26]); // receiver: services, address, port
    version.extend_from_slice(&[0u8; 26]); // sender
    let nonce = sha256d(&format!("{:?}{}", Instant::now(), std::process::id()).into_bytes());
    version.extend_from_slice(&nonce[..8]);
    let agent = format!("/bcs-conformance:{}/", env!("CARGO_PKG_VERSION"));
    write_compact_size(&mut version, agent.len() as u64);
    version.extend_from_slice(agent.as_bytes());
    version.extend_from_slice(&start_height.to_le_bytes());
    version.push(0); // relay: no transaction announcements
    version
}

/// A connected peer after a completed handshake.
pub struct Peer {
    stream: TcpStream,
    magic: [u8; 4],
    buffer: Vec<u8>,
    pub version: i32,
    pub user_agent: String,
    pub start_height: i32,
}

impl Peer {
    /// Connects and performs the version handshake.
    pub fn connect(addr: SocketAddr, magic: [u8; 4], timeout: Duration) -> io::Result<Peer> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_millis(250)))?;
        let mut peer = Peer {
            stream,
            magic,
            buffer: Vec::new(),
            version: 0,
            user_agent: String::new(),
            start_height: -1,
        };
        peer.send("version", &version_payload(NODE_WITNESS, 0))?;

        let deadline = Instant::now() + timeout;
        let (mut got_version, mut got_verack) = (false, false);
        while !(got_version && got_verack) {
            let m = peer.recv(deadline)?;
            match m.command.as_str() {
                "version" => {
                    let p = &m.payload;
                    if p.len() < 20 {
                        return Err(invalid("short version message"));
                    }
                    peer.version = i32::from_le_bytes(p[0..4].try_into().unwrap());
                    if peer.version < MIN_PEER_PROTO_VERSION {
                        return Err(invalid(format!(
                            "peer protocol version {} is too old",
                            peer.version
                        )));
                    }
                    // services 8, time 8, receiver 26, sender 26, nonce 8, then the user agent.
                    let mut pos = 4 + 8 + 8 + 26 + 26 + 8;
                    if p.len() > pos {
                        if let Ok(n) = read_compact_size(p, &mut pos) {
                            let end = (pos + n as usize).min(p.len());
                            peer.user_agent = String::from_utf8_lossy(&p[pos..end]).to_string();
                            pos = end;
                            if p.len() >= pos + 4 {
                                peer.start_height =
                                    i32::from_le_bytes(p[pos..pos + 4].try_into().unwrap());
                            }
                        }
                    }
                    peer.send("verack", &[])?;
                    got_version = true;
                }
                "verack" => got_verack = true,
                _ => {}
            }
        }
        Ok(peer)
    }

    pub fn send(&mut self, command: &str, payload: &[u8]) -> io::Result<()> {
        let mut msg = Vec::with_capacity(24 + payload.len());
        msg.extend_from_slice(&self.magic);
        let mut name = [0u8; 12];
        name[..command.len()].copy_from_slice(command.as_bytes());
        msg.extend_from_slice(&name);
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&sha256d(payload)[..4]);
        msg.extend_from_slice(payload);
        self.stream.write_all(&msg)
    }

    fn try_parse(&mut self) -> io::Result<Option<Message>> {
        if self.buffer.len() < 24 {
            return Ok(None);
        }
        if self.buffer[..4] != self.magic {
            return Err(invalid(
                "wrong network magic (is the peer on another network?)",
            ));
        }
        let length = u32::from_le_bytes(self.buffer[16..20].try_into().unwrap()) as usize;
        if length > MAX_MESSAGE_LENGTH {
            return Err(invalid("message too large"));
        }
        if self.buffer.len() < 24 + length {
            return Ok(None);
        }
        let frame: Vec<u8> = self.buffer.drain(..24 + length).collect();
        let payload = frame[24..].to_vec();
        if sha256d(&payload)[..4] != frame[20..24] {
            return Err(invalid("bad message checksum"));
        }
        let end = frame[4..16].iter().position(|&b| b == 0).unwrap_or(12);
        let command = String::from_utf8_lossy(&frame[4..4 + end]).to_string();
        Ok(Some(Message { command, payload }))
    }

    /// The next message, waiting until `deadline`. `ping` is answered automatically.
    pub fn recv(&mut self, deadline: Instant) -> io::Result<Message> {
        let mut chunk = [0u8; 65536];
        loop {
            while let Some(m) = self.try_parse()? {
                if m.command == "ping" {
                    self.send("pong", &m.payload)?;
                    continue;
                }
                return Ok(m);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for the peer",
                ));
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the peer closed the connection",
                    ))
                }
                Ok(n) => self.buffer.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Sends `getheaders` with the given locator (raw-order hashes) and no stop hash.
    pub fn request_headers(&mut self, locator: &[[u8; 32]]) -> io::Result<()> {
        let mut p = Vec::new();
        p.extend_from_slice(&(PROTOCOL_VERSION as u32).to_le_bytes());
        write_compact_size(&mut p, locator.len() as u64);
        for h in locator {
            p.extend_from_slice(h);
        }
        p.extend_from_slice(&[0u8; 32]);
        self.send("getheaders", &p)
    }

    /// Waits for the next `headers` message. Other messages are ignored; `getheaders` from the
    /// peer is answered with an empty `headers` message.
    pub fn wait_headers(&mut self, deadline: Instant) -> io::Result<Vec<[u8; 80]>> {
        loop {
            let m = self.recv(deadline)?;
            match m.command.as_str() {
                "headers" => return decode_headers(&m.payload),
                "getheaders" => self.send("headers", &[0])?,
                _ => {}
            }
        }
    }
}

/// Decodes a `headers` payload: 80-byte headers each followed by a transaction count.
pub fn decode_headers(payload: &[u8]) -> io::Result<Vec<[u8; 80]>> {
    let mut pos = 0;
    let n = read_compact_size(payload, &mut pos)? as usize;
    if n > MAX_HEADERS_RESULTS {
        return Err(invalid(format!("headers message with {n} headers")));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if payload.len() < pos + 80 {
            return Err(invalid("truncated headers message"));
        }
        out.push(payload[pos..pos + 80].try_into().unwrap());
        pos += 80;
        read_compact_size(payload, &mut pos)?;
    }
    Ok(out)
}

/// Hash of an 80-byte header, raw order.
pub fn header_hash(h: &[u8; 80]) -> [u8; 32] {
    sha256d(h)
}

/// The previous block hash of a header, raw order.
pub fn header_prev(h: &[u8; 80]) -> [u8; 32] {
    h[4..36].try_into().unwrap()
}

pub fn header_bits(h: &[u8; 80]) -> u32 {
    u32::from_le_bytes(h[72..76].try_into().unwrap())
}

/// Core's `LocatorEntries` over a list of hashes indexed by height: the last ten one apart, then
/// doubling the step, always ending with the first entry.
pub fn locator(hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if hashes.is_empty() {
        return out;
    }
    let mut height = hashes.len() as i64 - 1;
    let mut step = 1i64;
    loop {
        out.push(hashes[height as usize]);
        if height == 0 {
            break;
        }
        height = (height - step).max(0);
        if out.len() > 10 {
            step *= 2;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_signet_magic() {
        assert_eq!(network("signet").unwrap().magic, [0x0a, 0x03, 0xcf, 0x40]);
    }

    #[test]
    fn locator_shape() {
        let hashes: Vec<[u8; 32]> = (0..100u8).map(|i| [i; 32]).collect();
        let l = locator(&hashes);
        let heights: Vec<u8> = l.iter().map(|h| h[0]).collect();
        // Core's LocatorEntries: the step doubles once more than ten entries were collected.
        assert_eq!(
            heights,
            vec![99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 86, 82, 74, 58, 26, 0]
        );
    }
}
