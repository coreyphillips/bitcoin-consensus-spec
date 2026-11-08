//! Live node mode for the interop suite (conformance/PROTOCOL.md section 5).
//!
//! Usage: reference-node --network regtest --connect 127.0.0.1:18444 --stop-at <hash> [--idle 30]
//! Tooling, not specification: it parses arguments and calls `sync_from_peer` from spec/14.

use bcs::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let network = match get("--network").as_deref().unwrap_or("regtest") {
        "main" => Network::Main,
        "testnet3" => Network::Testnet3,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    };
    let peer = get("--connect").expect("--connect host:port is required");
    let stop_at = get("--stop-at").map(|h| hash_from_display(&h).expect("--stop-at must be a block hash"));
    let idle: u64 = get("--idle").and_then(|v| v.parse().ok()).unwrap_or(30);
    let headers_only = args.iter().any(|a| a == "--headers-only");
    let mut state = ChainState::new(network_params(network, &NetworkOptions::default()));
    let result = sync_from_peer(&mut state, &peer, stop_at, idle, !headers_only);
    if headers_only {
        let best = state.best_header();
        println!(
            "{{\"event\":\"headers\",\"best_header\":\"{}\",\"height\":{},\"chainwork\":\"{}\",\"result\":\"{:?}\"}}",
            hash_to_display(&best.hash),
            best.height,
            hex_encode(&best.chain_work.to_be_bytes()),
            result
        );
        return;
    }
    let tip = state.tip();
    let (utxo_hash, _) = utxo_hash_serialized_3(&state.utxo);
    match result {
        Ok(end) => {
            println!(
                "{{\"event\":\"stopped\",\"tip\":\"{}\",\"height\":{},\"hash_serialized_3\":\"{}\",\"end\":\"{:?}\"}}",
                hash_to_display(&tip.hash),
                tip.height,
                hash_to_display(&utxo_hash),
                end
            );
        }
        Err(error) => {
            eprintln!("sync failed: {error}");
            println!("{{\"event\":\"error\",\"tip\":\"{}\",\"height\":{}}}", hash_to_display(&tip.hash), tip.height);
            std::process::exit(1);
        }
    }
}
