//! The `headers-live` suite: the runner downloads the complete header chain from a live peer over
//! the version 1 peer-to-peer protocol (specification chapter 14) and feeds it to the harness.
//!
//! The harness gets `chain_reset` for the network, then `chain_process_headers` (with `via: p2p`
//! and the current time as `now`) for every `headers` message of at most 2,000 headers, in the
//! order received. The suite passes when every message is accepted and the harness's final
//! `best_header` is the last header the peer sent. It reports the height and the chain work of
//! that header (computed by the runner from the headers' `nBits`).

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

pub fn run(ctx: &mut Ctx, cfg: &Config) -> Result<(), String> {
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
        eprintln!("headers-live: connected to {peer_text}");
        if let Err(e) = peer.request_headers(&p2p::locator(&hashes)) {
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
            if headers.is_empty() {
                synced = true;
                break;
            }
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
