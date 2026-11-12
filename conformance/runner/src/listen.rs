//! The runner as the peer a node connects to (the peer-sync suite). A listener accepts inbound
//! connections, tells the version 1 transport (specification chapter 14) from BIP324 version 2 by
//! the first 16 bytes as Bitcoin Core does, and runs one reader thread per connection. Every
//! message, connection and disconnection becomes an [`Event`] on one channel, which the suite also
//! uses for the node's standard output, so its loop waits on a single receiver.

use crate::p2p::{Message, MAX_MESSAGE_LENGTH};
use crate::tx::sha256d;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

/// BIP324 message type IDs 1 to 28 (one byte instead of the 12-byte command).
const SHORT_IDS: [&str; 28] = [
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
];

/// Core's `V1_PREFIX_LEN`: the network magic and the 12-byte command `version`.
const V1_PREFIX_LEN: usize = 16;

/// How long a new connection may take to show its transport and finish the BIP324 handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub enum Event {
    /// A connection completed its transport handshake (`v1` or `v2`).
    Connected(u64, Writer, &'static str),
    Message(u64, Message),
    /// The connection ended; the text says why.
    Closed(u64, String),
    /// One line of the node's standard output.
    NodeLine(String),
    /// The node closed its standard output.
    NodeEof,
}

enum Sink {
    V1 { stream: TcpStream, magic: [u8; 4] },
    V2(bip324::io::ProtocolWriter<TcpStream>),
}

/// The sending half of one connection.
pub struct Writer {
    sink: Sink,
    stream: TcpStream,
}

impl Writer {
    pub fn send(&mut self, command: &str, payload: &[u8]) -> io::Result<()> {
        let mut name = [0u8; 12];
        name[..command.len()].copy_from_slice(command.as_bytes());
        match &mut self.sink {
            Sink::V1 { stream, magic } => {
                let mut msg = Vec::with_capacity(24 + payload.len());
                msg.extend_from_slice(magic);
                msg.extend_from_slice(&name);
                msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                msg.extend_from_slice(&sha256d(payload)[..4]);
                msg.extend_from_slice(payload);
                stream.write_all(&msg)
            }
            Sink::V2(writer) => {
                // Always the long form: a zero byte, then the 12-byte command.
                let mut contents = Vec::with_capacity(13 + payload.len());
                contents.push(0);
                contents.extend_from_slice(&name);
                contents.extend_from_slice(payload);
                writer
                    .write(&bip324::io::Payload::genuine(contents))
                    .map_err(|e| io::Error::other(e.to_string()))
            }
        }
    }

    /// Closes the connection in both directions.
    pub fn close(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Accepts connections on `listener` until `stop` is set. Each connection gets the next id.
pub fn accept_loop(
    listener: TcpListener,
    magic: [u8; 4],
    events: Sender<Event>,
    stop: Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    let mut next_id = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                next_id += 1;
                let id = next_id;
                let events = events.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve(stream, id, magic, &events) {
                        let _ = events.send(Event::Closed(id, e));
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// One connection: transport detection and handshake, then the reader loop.
fn serve(stream: TcpStream, id: u64, magic: [u8; 4], events: &Sender<Event>) -> Result<(), String> {
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut prefix = [0u8; V1_PREFIX_LEN];
    let mut reader = stream.try_clone().map_err(|e| e.to_string())?;
    reader
        .read_exact(&mut prefix)
        .map_err(|e| format!("no transport prefix: {e}"))?;
    let mut v1 = [0u8; V1_PREFIX_LEN];
    v1[..4].copy_from_slice(&magic);
    v1[4..11].copy_from_slice(b"version");
    let chained = Cursor::new(prefix.to_vec()).chain(reader);
    if prefix == v1 {
        stream.set_read_timeout(None).map_err(|e| e.to_string())?;
        let writer = Writer {
            sink: Sink::V1 {
                stream: stream.try_clone().map_err(|e| e.to_string())?,
                magic,
            },
            stream: stream.try_clone().map_err(|e| e.to_string())?,
        };
        if events.send(Event::Connected(id, writer, "v1")).is_err() {
            return Ok(());
        }
        read_v1(BufReader::new(chained), magic, id, events)
    } else {
        let protocol = bip324::io::Protocol::new(
            magic,
            bip324::Role::Responder,
            None,
            None,
            BufReader::new(chained),
            stream.try_clone().map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("BIP324 handshake: {e}"))?;
        stream.set_read_timeout(None).map_err(|e| e.to_string())?;
        let (mut reader, writer) = protocol.into_split();
        let writer = Writer {
            sink: Sink::V2(writer),
            stream,
        };
        if events.send(Event::Connected(id, writer, "v2")).is_err() {
            return Ok(());
        }
        loop {
            let payload = reader.read().map_err(|e| e.to_string())?;
            if payload.packet_type() == bip324::PacketType::Decoy {
                continue;
            }
            let message = decode_v2(payload.contents())?;
            if events.send(Event::Message(id, message)).is_err() {
                return Ok(());
            }
        }
    }
}

fn read_v1<R: Read>(
    mut reader: R,
    magic: [u8; 4],
    id: u64,
    events: &Sender<Event>,
) -> Result<(), String> {
    loop {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header).map_err(|e| e.to_string())?;
        if header[..4] != magic {
            return Err("wrong network magic".into());
        }
        let length = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if length > MAX_MESSAGE_LENGTH {
            return Err(format!("message of {length} bytes"));
        }
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).map_err(|e| e.to_string())?;
        if sha256d(&payload)[..4] != header[20..24] {
            return Err("bad message checksum".into());
        }
        let end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
        let command = String::from_utf8_lossy(&header[4..4 + end]).to_string();
        if events
            .send(Event::Message(id, Message { command, payload }))
            .is_err()
        {
            return Ok(());
        }
    }
}

/// A BIP324 message: one byte, either a short message type ID or zero followed by the 12-byte
/// command, then the payload.
fn decode_v2(contents: &[u8]) -> Result<Message, String> {
    let (&first, rest) = contents.split_first().ok_or("empty BIP324 message")?;
    if first == 0 {
        if rest.len() < 12 {
            return Err("truncated BIP324 command".into());
        }
        let end = rest[..12].iter().position(|&b| b == 0).unwrap_or(12);
        return Ok(Message {
            command: String::from_utf8_lossy(&rest[..end]).to_string(),
            payload: rest[12..].to_vec(),
        });
    }
    let command = SHORT_IDS
        .get(first as usize - 1)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("unknown-short-id-{first}"));
    Ok(Message {
        command,
        payload: rest.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip324_message_types() {
        let long = [&[0u8][..], b"version\0\0\0\0\0", &[1, 2, 3]].concat();
        let m = decode_v2(&long).unwrap();
        assert_eq!(
            (m.command.as_str(), m.payload.as_slice()),
            ("version", &[1u8, 2, 3][..])
        );
        let m = decode_v2(&[13, 0]).unwrap();
        assert_eq!(
            (m.command.as_str(), m.payload.as_slice()),
            ("headers", &[0u8][..])
        );
        assert_eq!(decode_v2(&[28]).unwrap().command, "addrv2");
        assert_eq!(decode_v2(&[2]).unwrap().command, "block");
        assert!(decode_v2(&[]).is_err());
        assert!(decode_v2(&[0, b'a']).is_err());
    }
}
