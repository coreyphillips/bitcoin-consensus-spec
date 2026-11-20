//! Live node mode for the interop suite (conformance/PROTOCOL.md section 5).
//!
//! Usage:
//!   reference-node --network regtest --connect 127.0.0.1:18444 [--stop-at <hash>] [--options <json>]
//!                  [--datadir <dir>] [--idle <seconds>] [--headers-only]
//!
//! `--options` takes the network options object of PROTOCOL.md section 4.8. `--datadir` is accepted
//! and ignored: the reference keeps its state in memory. Tooling, not specification: it parses
//! arguments and calls `sync_from_peer` from spec/14.
//!
//! Exit status: 0 after the `stopped` (or `x_headers`) line, 1 when the sync fails, 2 for arguments
//! it cannot run with. Both failures write one `error` line first.

use bcs::*;
use std::collections::BTreeMap;

#[path = "../tooling.rs"]
#[allow(dead_code)]
mod tooling;
use tooling::*;

const SYNC_FAILED: i32 = 1;
const BAD_ARGUMENTS: i32 = 2;

/// Every option but `--headers-only` takes a value.
const VALUE_OPTIONS: [&str; 6] = ["--network", "--connect", "--stop-at", "--options", "--datadir", "--idle"];

fn fail(message: &str, state: Option<&ChainState>, status: i32) -> ! {
    let mut line = String::from("{\"event\":\"error\",\"message\":");
    write_json(&Json::Str(message.to_string()), &mut line);
    if let Some(state) = state {
        let tip = state.tip();
        line.push_str(&format!(",\"tip\":\"{}\",\"height\":{}", hash_to_display(&tip.hash), tip.height));
    }
    line.push('}');
    println!("{line}");
    eprintln!("reference-node: {message}");
    std::process::exit(status);
}

fn usage_error(message: &str) -> ! {
    fail(message, None, BAD_ARGUMENTS)
}

/// The value of each option given, and whether `--headers-only` is.
fn parse_arguments() -> (BTreeMap<&'static str, String>, bool) {
    let mut args = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().unwrap_or_else(|a| usage_error(&format!("argument {a:?} is not UTF-8"))));
    let mut values = BTreeMap::new();
    let mut headers_only = false;
    while let Some(arg) = args.next() {
        if arg == "--headers-only" {
            headers_only = true;
            continue;
        }
        let Some(&name) = VALUE_OPTIONS.iter().find(|&&name| name == arg) else {
            usage_error(&format!("unknown argument {arg}"))
        };
        // An empty placeholder in a `sh -c` template leaves the next option where the value belongs.
        let value = match args.next() {
            Some(value) if !value.starts_with("--") => value,
            _ => usage_error(&format!("{name} needs a value")),
        };
        if values.insert(name, value).is_some() {
            usage_error(&format!("{name} is given more than once"));
        }
    }
    (values, headers_only)
}

fn main() {
    let (args, headers_only) = parse_arguments();
    let get = |name: &str| args.get(name).map(String::as_str);
    let network = parse_network(get("--network").unwrap_or("regtest")).unwrap_or_else(|e| usage_error(&e));
    let options = match get("--options") {
        None => NetworkOptions::default(),
        Some(text) => {
            let value = parse_json(text).unwrap_or_else(|e| usage_error(&format!("--options: {e}")));
            parse_network_options(Some(&value)).unwrap_or_else(|e| usage_error(&format!("--options: {e}")))
        }
    };
    let peer = get("--connect").unwrap_or_else(|| usage_error("--connect host:port is required"));
    let stop_at = get("--stop-at").map(|h| hash_from_display(h).unwrap_or_else(|| usage_error("--stop-at must be a block hash")));
    let idle: u64 = match get("--idle") {
        None => 30,
        Some(text) => text.parse().unwrap_or_else(|_| usage_error(&format!("--idle must be a whole number of seconds, not {text}"))),
    };

    let params = network_params(network, &options).unwrap_or_else(|e| usage_error(&format!("--options: {e}")));
    let mut state = ChainState::new(params);
    let result = sync_from_peer(&mut state, peer, stop_at, idle, !headers_only);
    if let Err(error) = &result {
        fail(&format!("sync failed: {error}"), Some(&state), SYNC_FAILED);
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
