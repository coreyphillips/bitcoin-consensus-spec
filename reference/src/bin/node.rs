//! Live node mode for the interop suite (conformance/PROTOCOL.md section 5).
//!
//! Usage:
//!   reference-node --network regtest --connect 127.0.0.1:18444 [--stop-at <hash>] [--options <json>]
//!                  [--datadir <dir>] [--idle <seconds>] [--headers-only]
//!
//! `--options` takes the network options object of PROTOCOL.md section 4.8. `--datadir` is accepted
//! and ignored: the reference keeps its state in memory. Tooling, not specification: it parses
//! arguments and calls `sync_from_peer` from spec/14.

use bcs::*;

#[path = "../tooling.rs"]
#[allow(dead_code)]
mod tooling;
use tooling::*;

fn fail(message: &str, state: Option<&ChainState>) -> ! {
    let mut line = format!("{{\"event\":\"error\",\"message\":\"{}\"", message.replace('\\', "\\\\").replace('"', "\\\""));
    if let Some(state) = state {
        let tip = state.tip();
        line.push_str(&format!(",\"tip\":\"{}\",\"height\":{}", hash_to_display(&tip.hash), tip.height));
    }
    line.push('}');
    println!("{line}");
    eprintln!("reference-node: {message}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let network = parse_network(get("--network").as_deref().unwrap_or("regtest")).unwrap_or_else(|e| fail(&e, None));
    let options = match get("--options") {
        None => NetworkOptions::default(),
        Some(text) => {
            let value = parse_json(&text).unwrap_or_else(|e| fail(&format!("--options: {e}"), None));
            parse_network_options(Some(&value)).unwrap_or_else(|e| fail(&format!("--options: {e}"), None))
        }
    };
    let peer = get("--connect").unwrap_or_else(|| fail("--connect host:port is required", None));
    let stop_at = get("--stop-at").map(|h| hash_from_display(&h).unwrap_or_else(|| fail("--stop-at must be a block hash", None)));
    let idle: u64 = get("--idle").and_then(|v| v.parse().ok()).unwrap_or(30);
    let headers_only = args.iter().any(|a| a == "--headers-only");

    let mut state = ChainState::new(network_params(network, &options));
    let result = sync_from_peer(&mut state, &peer, stop_at, idle, !headers_only);
    if let Err(error) = &result {
        fail(&format!("sync failed: {error}"), Some(&state));
    }
    if headers_only {
        let best = state.best_header();
        println!(
            "{{\"event\":\"x_headers\",\"best_header\":\"{}\",\"height\":{},\"chainwork\":\"{}\"}}",
            hash_to_display(&best.hash),
            best.height,
            hex_encode(&best.chain_work.to_be_bytes())
        );
        return;
    }
    let tip = state.tip();
    let (utxo_hash, _) = utxo_hash_serialized_3(&state.utxo);
    println!(
        "{{\"event\":\"stopped\",\"tip\":\"{}\",\"height\":{},\"hash_serialized_3\":\"{}\"}}",
        hash_to_display(&tip.hash),
        tip.height,
        hash_to_display(&utxo_hash)
    );
}
