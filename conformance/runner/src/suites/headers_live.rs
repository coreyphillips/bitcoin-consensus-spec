//! The `headers-live` suite: the runner downloads the complete header chain from a live peer over
//! the version 1 peer-to-peer protocol (specification chapter 14) and feeds it to the harness.
//!
//! The harness gets `chain_reset` for the network, then `chain_process_headers` (with `via: p2p`
//! and the current time as `now`) for every `headers` message of at most 2,000 headers, in the
//! order received. The suite passes when every message is accepted, the harness's final
//! `best_header` is the last header the peer sent, and the peer sent at least one header and a
//! chain at least as high as the start height it announced in `version`. It reports the height and
//! the chain work of that header (computed by the runner from the headers' `nBits`).
//!
//! A connection that replaces a failed one asks for the headers after the parent of the last header
//! received, so the new peer sends that header again or its own chain from an earlier fork. One that
//! sends no header has neither, and is replaced in turn.

use crate::check::Ctx;
use crate::hex;
use crate::p2p::{self, Peer};
use crate::work::U256;
use serde_json::Value;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

pub struct Config {
    /// `host:port`, or `host` for the network's default port.
    pub peer: String,
    pub network: String,
    /// How long to wait for each `headers` answer.
    pub response_timeout: Duration,
    /// How many times to reconnect (to the same or the next address) after a failure.
    pub max_reconnects: u32,
}

fn resolve(peer: &str, default_port: u16) -> Result<Vec<SocketAddr>, String> {
    let with_port = if peer.parse::<SocketAddr>().is_ok()
        || peer
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
    {
        peer.to_string()
    } else if peer.contains(':') && !peer.starts_with('[') {
        format!("[{peer}]:{default_port}")
    } else {
        format!("{peer}:{default_port}")
    };
    let addrs: Vec<SocketAddr> = with_port
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {with_port}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{with_port} resolves to no address"));
    }
    Ok(addrs)
}

/// Why a download that ended at `height` is too short to pass, given the start height the peer
/// announced in `version` (-1 when it sent none).
fn short_download(height: usize, start_height: i32) -> Option<String> {
    if height == 0 {
        // Bitcoin Core answers `getheaders` with an empty `headers` message while its chain has
        // less work than `-minimumchainwork`.
        return Some(format!(
            "the peer sent no header (it announced start height {start_height}), so no header was checked"
        ));
    }
    if (height as i64) < i64::from(start_height) {
        return Some(format!(
            "the peer's header chain ends at height {height}, below the start height {start_height} it announced"
        ));
    }
    None
}

pub fn run(ctx: &mut Ctx, cfg: &Config) -> Result<(), String> {
    run_with(ctx, cfg, resolve)
}

/// `run`, with the peer's addresses given by `resolve` (the tests' local peers).
fn run_with(
    ctx: &mut Ctx,
    cfg: &Config,
    resolve: impl Fn(&str, u16) -> Result<Vec<SocketAddr>, String>,
) -> Result<(), String> {
    let net =
        p2p::network(&cfg.network).ok_or_else(|| format!("unknown network {}", cfg.network))?;
    for op in ["chain_reset", "chain_process_headers"] {
        if !ctx.supports(op) {
            return Err(format!("the harness does not list {op}"));
        }
    }
    let started = Instant::now();

    // Fresh chain; the harness's genesis must be the network's.
    let reset = ctx
        .harness
        .call("chain_reset", &format!("\"network\":\"{}\"", net.name))
        .map_err(|e| format!("chain_reset: {e}"))?;
    let genesis = reset.get("genesis").and_then(Value::as_str).unwrap_or("");
    if genesis == net.genesis {
        ctx.pass();
    } else {
        ctx.fail(
            "chain_reset",
            &format!("genesis {genesis}, expected {}", net.genesis),
        );
        return Ok(());
    }

    let addrs = resolve(&cfg.peer, net.port)?;
    let mut genesis_raw = hex::decode32(net.genesis)?;
    genesis_raw.reverse();
    // Header chain received so far, indexed by height, with the cumulative chain work.
    let mut hashes: Vec<[u8; 32]> = vec![genesis_raw];
    let mut work: Vec<U256> = vec![U256::proof(net.genesis_bits)];
    let mut last_bits = (0u32, U256::ZERO);
    let mut messages = 0u64;
    let mut best_header = net.genesis.to_string();
    let mut connections = 0u32;
    let mut addr_index = 0usize;
    let mut last_error = String::new();
    let mut peer_text = String::new();
    // Of the connection that ends the download.
    let mut start_height = -1i32;
    let mut synced = false;

    'connections: while connections <= cfg.max_reconnects && !synced {
        if connections > 0 {
            // A short pause before trying again, for peers that are briefly overloaded.
            std::thread::sleep(Duration::from_secs(2));
        }
        let addr = addrs[addr_index % addrs.len()];
        addr_index += 1;
        connections += 1;
        let mut peer = match Peer::connect(addr, net.magic, Duration::from_secs(20)) {
            Ok(p) => p,
            Err(e) => {
                last_error = format!("{addr}: {e}");
                eprintln!("headers-live: cannot connect to {addr}: {e}");
                continue;
            }
        };
        peer_text = format!(
            "{} ({}, protocol {}, start height {})",
            addr, peer.user_agent, peer.version, peer.start_height
        );
        start_height = peer.start_height;
        eprintln!("headers-live: connected to {peer_text}");
        // The headers kept from an earlier connection are only this peer's chain once it sends
        // the last of them again, or headers that replace it. An empty answer to a locator that
        // starts at that header would also come from a peer whose chain ends below it.
        let mut unconfirmed = hashes.len() > 1;
        let from = &hashes[..hashes.len() - usize::from(unconfirmed)];
        if let Err(e) = peer.request_headers(&p2p::locator(from)) {
            last_error = format!("{addr}: {e}");
            continue;
        }
        loop {
            let deadline = Instant::now() + cfg.response_timeout;
            let headers = match peer.wait_headers(deadline) {
                Ok(h) => h,
                Err(e) => {
                    last_error = format!("{addr}: {e}");
                    eprintln!("headers-live: {last_error}; reconnecting");
                    continue 'connections;
                }
            };
            if headers.is_empty() && unconfirmed {
                let height = hashes.len() - 1;
                last_error = format!(
                    "{addr}: the peer sent no header after height {}, so its chain does not reach \
                     the header at height {height} received from an earlier connection",
                    height - 1
                );
                eprintln!("headers-live: {last_error}; reconnecting");
                continue 'connections;
            }
            if headers.is_empty() {
                synced = true;
                break;
            }
            unconfirmed = false;
            // Connect the message to the chain received so far (a peer that reorganized may
            // continue from an earlier block).
            let first_prev = p2p::header_prev(&headers[0]);
            let Some(pos) = hashes.iter().rposition(|h| *h == first_prev) else {
                ctx.fail(
                    &format!("headers message {}", messages + 1),
                    "the peer sent headers that do not connect to the chain it sent before",
                );
                return Ok(());
            };
            hashes.truncate(pos + 1);
            work.truncate(pos + 1);
            let first_height = hashes.len();
            let mut prev = first_prev;
            for h in &headers {
                if p2p::header_prev(h) != prev {
                    ctx.fail(
                        &format!("headers message {}", messages + 1),
                        "the peer sent a discontinuous headers message",
                    );
                    return Ok(());
                }
                prev = p2p::header_hash(h);
                let bits = p2p::header_bits(h);
                if bits != last_bits.0 || last_bits.1.is_zero() {
                    last_bits = (bits, U256::proof(bits));
                }
                let total = work.last().unwrap().add(&last_bits.1);
                work.push(total);
                hashes.push(prev);
            }
            let full = headers.len() == p2p::MAX_HEADERS_RESULTS;
            // Ask for the next message before the harness works on this one.
            let mut request_failed = None;
            if full {
                if let Err(e) = peer.request_headers(&p2p::locator(&hashes)) {
                    request_failed = Some(format!("{addr}: {e}"));
                }
            }
            messages += 1;
            let list: Vec<String> = headers
                .iter()
                .map(|h| format!("\"{}\"", hex::encode(h)))
                .collect();
            let body = format!(
                "\"headers\":[{}],\"now\":{},\"via\":\"p2p\"",
                list.join(","),
                p2p::unix_now()
            );
            let loc = format!(
                "headers message {messages} (heights {} to {})",
                first_height,
                first_height + headers.len() - 1
            );
            match ctx.harness.call("chain_process_headers", &body) {
                Err(e) => {
                    ctx.call_failed(&loc, &e);
                    return Ok(());
                }
                Ok(a) => {
                    let result = a.get("result").and_then(Value::as_str).unwrap_or("");
                    if result != "accepted" {
                        let reason = a.get("reason").and_then(Value::as_str).unwrap_or("");
                        let index = a
                            .get("index")
                            .and_then(Value::as_i64)
                            .map_or(String::new(), |i| format!(" at index {i}"));
                        ctx.fail(
                            &loc,
                            &format!("expected accepted, got {result} ({reason}){index}"),
                        );
                        return Ok(());
                    }
                    ctx.pass();
                    best_header = a
                        .get("best_header")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                }
            }
            if messages.is_multiple_of(50) {
                eprintln!(
                    "headers-live: height {} after {} messages, {:.0} s",
                    hashes.len() - 1,
                    messages,
                    started.elapsed().as_secs_f64()
                );
            }
            if !full {
                synced = true;
                break;
            }
            if let Some(e) = request_failed {
                last_error = e;
                eprintln!("headers-live: {last_error}; reconnecting");
                continue 'connections;
            }
        }
    }
    if !synced {
        ctx.fail(
            "download",
            &format!(
                "could not download the header chain from {}: {last_error}",
                cfg.peer
            ),
        );
        return Ok(());
    }

    let height = hashes.len() - 1;
    let last = hex::encode_reversed(hashes.last().unwrap());
    match short_download(height, start_height) {
        None => ctx.pass(),
        Some(why) => ctx.fail("chain height", &why),
    }
    if best_header == last {
        ctx.pass();
    } else {
        ctx.fail(
            "final best header",
            &format!("expected {last} (height {height}), the harness reports {best_header}"),
        );
    }
    ctx.stats.details.push(format!(
        "headers-live: network {}, peer {peer_text}",
        net.name
    ));
    ctx.stats.details.push(format!(
        "headers-live: {} headers in {} messages, last header {} at height {height}, chainwork {}, {:.0} s",
        height,
        messages,
        last,
        work.last().unwrap().to_hex(),
        started.elapsed().as_secs_f64()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run_with, short_download, Config};
    use crate::check::{Ctx, Stats};
    use crate::harness::Harness;
    use crate::hex;
    use crate::p2p::{self, MAX_HEADERS_RESULTS};
    use crate::tx::{sha256d, write_compact_size};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    fn send(s: &mut TcpStream, command: &str, payload: &[u8]) -> std::io::Result<()> {
        let mut m = p2p::network("regtest").unwrap().magic.to_vec();
        let mut name = [0u8; 12];
        name[..command.len()].copy_from_slice(command.as_bytes());
        m.extend_from_slice(&name);
        m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        m.extend_from_slice(&sha256d(payload)[..4]);
        m.extend_from_slice(payload);
        s.write_all(&m)
    }

    fn recv(s: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
        let mut head = [0u8; 24];
        s.read_exact(&mut head)?;
        let mut payload = vec![0; u32::from_le_bytes(head[16..20].try_into().unwrap()) as usize];
        s.read_exact(&mut payload)?;
        let end = head[4..16].iter().position(|&b| b == 0).unwrap_or(12);
        Ok((String::from_utf8_lossy(&head[4..4 + end]).into(), payload))
    }

    /// Serves one connection as a peer whose chain is `hashes`/`headers` up to `tip`. It
    /// announces `tip` as its start height, answers `answers` `getheaders` as Core does (the
    /// headers after the first locator entry it has) and closes the connection at the next one.
    fn serve(
        listener: TcpListener,
        (tip, answers): (usize, usize),
        hashes: &[[u8; 32]],
        headers: &[[u8; 80]],
    ) -> std::io::Result<()> {
        let (mut s, _) = listener.accept()?;
        drop(listener);
        recv(&mut s)?;
        send(&mut s, "version", &p2p::version_payload(0, tip as i32))?;
        send(&mut s, "verack", &[])?;
        let mut answered = 0;
        loop {
            let (command, payload) = recv(&mut s)?;
            if command != "getheaders" {
                continue;
            }
            if answered == answers {
                return Ok(());
            }
            answered += 1;
            let mut pos = 4;
            let n = p2p::read_compact_size(&payload, &mut pos)? as usize;
            let fork = (0..n)
                .map(|i| &payload[pos + 32 * i..pos + 32 * (i + 1)])
                .find_map(|h| hashes[..=tip].iter().position(|x| x == h))
                .unwrap_or(0);
            let sent = &headers[fork + 1..=tip.min(fork + MAX_HEADERS_RESULTS)];
            let mut reply = Vec::new();
            write_compact_size(&mut reply, sent.len() as u64);
            for h in sent {
                reply.extend_from_slice(h);
                reply.push(0);
            }
            send(&mut s, "headers", &reply)?;
        }
    }

    /// Runs the suite against `peers` (each `(tip, answers)` as in `serve`), each on its own local
    /// address and each accepting one connection, tried in turn. The stub harness accepts every message and reports the header at
    /// height `best` as its best header. Returns the statistics and the peers' addresses.
    fn download(
        name: &str,
        peers: &[(usize, usize)],
        max_reconnects: u32,
        best: usize,
    ) -> (Stats, Vec<SocketAddr>) {
        let net = p2p::network("regtest").unwrap();
        let tip = peers.iter().map(|p| p.0).max().unwrap();
        let mut hashes = vec![hex::decode32(net.genesis).unwrap()];
        hashes[0].reverse();
        let mut headers = vec![[0u8; 80]];
        for height in 1..=tip {
            let mut h = [0u8; 80];
            h[0] = 4;
            h[4..36].copy_from_slice(&hashes[height - 1]);
            h[72..76].copy_from_slice(&net.genesis_bits.to_le_bytes());
            h[76..80].copy_from_slice(&(height as u32).to_le_bytes());
            hashes.push(p2p::header_hash(&h));
            headers.push(h);
        }
        let mut addrs = Vec::new();
        for &peer in peers {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            addrs.push(listener.local_addr().unwrap());
            let (hashes, headers) = (hashes.clone(), headers.clone());
            std::thread::spawn(move || serve(listener, peer, &hashes, &headers));
        }

        let dir = std::env::temp_dir().join(format!(
            "bcs-headers-live-test-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("harness.sh");
        let reply = |op: &str, fields: &str| {
            format!("    *'\"op\":\"{op}\"'*) printf '{{\"id\":%s,\"ok\":true,{fields}}}\\n' \"$id\";;\n")
        };
        let script = format!(
            "while IFS= read -r line; do\n  id=${{line#*'\"id\":'}}; id=${{id%%[,\\}}]*}}\n  case \"$line\" in\n{}{}{}  esac\ndone\n",
            reply(
                "info",
                r#""name":"stub","version":"0","spec_version":"0","ops":["info","chain_reset","chain_process_headers"]"#
            ),
            reply("chain_reset", &format!(r#""genesis":"{}""#, net.genesis)),
            reply(
                "chain_process_headers",
                &format!(
                    r#""result":"accepted","best_header":"{}""#,
                    hex::encode_reversed(&hashes[best])
                )
            ),
        );
        std::fs::write(&stub, script).unwrap();
        let mut harness =
            Harness::start(&format!("sh '{}'", stub.display()), Duration::from_secs(10)).unwrap();
        let mut ctx = Ctx::new(&mut harness, "headers-live", false);
        let cfg = Config {
            peer: "peers".into(),
            network: "regtest".into(),
            response_timeout: Duration::from_secs(10),
            max_reconnects,
        };
        let listed = addrs.clone();
        run_with(&mut ctx, &cfg, |_, _| Ok(listed.clone())).unwrap();
        let stats = std::mem::take(&mut ctx.stats);
        let _ = std::fs::remove_dir_all(&dir);
        (stats, addrs)
    }

    /// The first peer announces 2,001, sends 2,000 headers and leaves; the second has 1,999 blocks
    /// and so has nothing after the parent of the header at 2,000.
    #[test]
    fn a_replacement_peer_without_the_last_header_does_not_end_the_download() {
        let peers = [(2001, 1), (1999, usize::MAX)];
        let (stats, _) = download("short-replacement", &peers, 1, 2000);
        // chain_reset and the first message pass; the download fails.
        assert_eq!((stats.passed, stats.failed), (2, 1), "{stats:?}");
        assert!(stats.details.is_empty(), "{stats:?}");
    }

    #[test]
    fn a_replacement_peer_that_sends_the_last_header_again_ends_the_download() {
        for tip in [2000, 2001] {
            let peers = [(2001, 1), (tip, usize::MAX)];
            let (stats, addrs) = download(&format!("replacement-{tip}"), &peers, 1, tip);
            assert_eq!((stats.passed, stats.failed), (5, 0), "{stats:?}");
            assert!(
                stats.details[0].contains(&addrs[1].to_string()),
                "{stats:?}"
            );
            assert!(
                stats.details[1].starts_with(&format!("headers-live: {tip} headers in 2 messages")),
                "{stats:?}"
            );
        }
    }

    /// A chain of exactly 2,000 headers ends with an empty answer to the next `getheaders`.
    #[test]
    fn an_empty_answer_after_a_full_message_on_the_same_connection_ends_the_download() {
        let (stats, _) = download("same-connection", &[(2000, usize::MAX)], 0, 2000);
        assert_eq!((stats.passed, stats.failed), (4, 0), "{stats:?}");
        assert!(stats.details[1].contains("at height 2000"), "{stats:?}");
    }

    #[test]
    fn a_download_with_no_header_fails() {
        // A regtest Core node with 50 blocks below its minimum chain work.
        assert!(short_download(0, 50).is_some());
        // A peer whose chain is only the genesis block still leaves nothing checked.
        assert!(short_download(0, 0).is_some());
        assert!(short_download(0, -1).is_some());
    }

    #[test]
    fn a_download_below_the_announced_start_height_fails() {
        assert!(short_download(49, 50).is_some());
        assert_eq!(short_download(50, 50), None);
        // The peer's chain may have grown since it connected.
        assert_eq!(short_download(51, 50), None);
        // A peer that announced no start height.
        assert_eq!(short_download(1, -1), None);
    }
}
