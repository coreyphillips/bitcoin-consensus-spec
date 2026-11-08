//! Conformance harness for the executable reference (conformance/PROTOCOL.md).
//!
//! This file is tooling, not specification: it parses JSON requests, calls the functions defined in
//! spec/*.md, and prints JSON responses. It has no dependencies beyond the standard library.

use bcs::*;
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

// ---------------------------------------------------------------------------------------------
// Minimal JSON

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] as char).is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn parse(&mut self) -> Result<Json, String> {
        self.ws();
        if self.i >= self.s.len() {
            return Err("unexpected end".into());
        }
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut map = BTreeMap::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(map));
                }
                loop {
                    self.ws();
                    let key = match self.parse()? {
                        Json::Str(k) => k,
                        _ => return Err("object key must be a string".into()),
                    };
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return Err("expected ':'".into());
                    }
                    self.i += 1;
                    let value = self.parse()?;
                    map.insert(key, value);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(map));
                        }
                        _ => return Err("expected ',' or '}'".into()),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.parse()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err("expected ',' or ']'".into()),
                    }
                }
            }
            b'"' => {
                self.i += 1;
                let mut out = String::new();
                loop {
                    let c = *self.s.get(self.i).ok_or("unterminated string")?;
                    self.i += 1;
                    match c {
                        b'"' => return Ok(Json::Str(out)),
                        b'\\' => {
                            let e = *self.s.get(self.i).ok_or("bad escape")?;
                            self.i += 1;
                            match e {
                                b'"' => out.push('"'),
                                b'\\' => out.push('\\'),
                                b'/' => out.push('/'),
                                b'n' => out.push('\n'),
                                b't' => out.push('\t'),
                                b'r' => out.push('\r'),
                                b'b' => out.push('\u{8}'),
                                b'f' => out.push('\u{c}'),
                                b'u' => {
                                    let hex = std::str::from_utf8(self.s.get(self.i..self.i + 4).ok_or("bad \\u")?)
                                        .map_err(|_| "bad \\u")?;
                                    let code = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u")?;
                                    self.i += 4;
                                    out.push(char::from_u32(code).unwrap_or('?'));
                                }
                                _ => return Err("bad escape".into()),
                            }
                        }
                        _ => {
                            let start = self.i - 1;
                            let mut end = self.i;
                            while end < self.s.len() && (self.s[end] & 0xc0) == 0x80 {
                                end += 1;
                            }
                            out.push_str(std::str::from_utf8(&self.s[start..end]).map_err(|_| "bad utf8")?);
                            self.i = end;
                        }
                    }
                }
            }
            b't' if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Json::Bool(true))
            }
            b'f' if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Json::Bool(false))
            }
            b'n' if self.s[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(Json::Null)
            }
            _ => {
                let start = self.i;
                while self.i < self.s.len() && b"+-0123456789.eE".contains(&self.s[self.i]) {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| "bad number")?;
                if text.is_empty() {
                    return Err(format!("unexpected character at {}", start));
                }
                if let Ok(v) = text.parse::<i128>() {
                    Ok(Json::Int(v))
                } else {
                    text.parse::<f64>().map(Json::Float).map_err(|_| format!("bad number {text}"))
                }
            }
        }
    }
}

fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    let v = p.parse()?;
    p.ws();
    if p.i != p.s.len() {
        return Err("trailing characters".into());
    }
    Ok(v)
}

fn write_json(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::Float(f) => out.push_str(&f.to_string()),
        Json::Str(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Json::Arr(items) => {
            out.push('[');
            for (k, item) in items.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Json::Obj(map) => {
            out.push('{');
            for (k, (key, value)) in map.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                write_json(&Json::Str(key.clone()), out);
                out.push(':');
                write_json(value, out);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Request helpers

type Fields = BTreeMap<String, Json>;

struct BadRequest(String);

fn field<'a>(req: &'a Fields, name: &str) -> Result<&'a Json, BadRequest> {
    req.get(name).ok_or_else(|| BadRequest(format!("missing field {name}")))
}

fn get_str<'a>(req: &'a Fields, name: &str) -> Result<&'a str, BadRequest> {
    match field(req, name)? {
        Json::Str(s) => Ok(s),
        _ => Err(BadRequest(format!("{name} must be a string"))),
    }
}

fn get_hex(req: &Fields, name: &str) -> Result<Vec<u8>, BadRequest> {
    hex_decode(get_str(req, name)?).ok_or_else(|| BadRequest(format!("{name} is not hex")))
}

fn get_int(req: &Fields, name: &str) -> Result<i128, BadRequest> {
    match field(req, name)? {
        Json::Int(i) => Ok(*i),
        _ => Err(BadRequest(format!("{name} must be an integer"))),
    }
}

fn opt_hex(req: &Fields, name: &str) -> Result<Option<Vec<u8>>, BadRequest> {
    match req.get(name) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Str(s)) => hex_decode(s).map(Some).ok_or_else(|| BadRequest(format!("{name} is not hex"))),
        _ => Err(BadRequest(format!("{name} must be a hex string"))),
    }
}

fn get_tx(req: &Fields, name: &str) -> Result<Transaction, BadRequest> {
    let bytes = get_hex(req, name)?;
    deserialize_transaction(&bytes).map_err(|e| BadRequest(format!("{name} does not decode: {}", e.0)))
}

fn get_spent_outputs(req: &Fields) -> Result<Vec<TxOut>, BadRequest> {
    let items = match field(req, "spent_outputs")? {
        Json::Arr(items) => items,
        _ => return Err(BadRequest("spent_outputs must be an array".into())),
    };
    let mut out = Vec::new();
    for item in items {
        let obj = match item {
            Json::Obj(o) => o,
            _ => return Err(BadRequest("spent output must be an object".into())),
        };
        let value = get_int(obj, "amount")? as i64;
        let script_pubkey = get_hex(obj, "script_pubkey")?;
        out.push(TxOut { value, script_pubkey });
    }
    Ok(out)
}

fn get_flags(req: &Fields) -> Result<ScriptFlags, BadRequest> {
    let items = match field(req, "flags")? {
        Json::Arr(items) => items,
        _ => return Err(BadRequest("flags must be an array".into())),
    };
    let mut flags = 0;
    for item in items {
        let name = match item {
            Json::Str(s) => s,
            _ => return Err(BadRequest("flag must be a string".into())),
        };
        match FLAG_NAMES.iter().find(|(n, _)| n == name) {
            Some((_, bit)) => flags |= bit,
            None => return Err(BadRequest(format!("unknown flag {name}"))),
        }
    }
    Ok(flags)
}

fn obj(pairs: Vec<(&str, Json)>) -> Fields {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// ---------------------------------------------------------------------------------------------
// Operations

const OPS: &[&str] = &[
    "info",
    "script_verify",
    "tx_check",
    "sighash_legacy",
    "sighash_taproot",
    "taproot_commitment_verify",
    "schnorr_verify",
    "chain_reset",
    "chain_process_block",
    "chain_process_headers",
    "chain_invalidate",
    "chain_tip",
    "chain_tips",
    "utxo_hash",
];

fn handle(op: &str, req: &Fields, chain: &mut Option<ChainState>) -> Result<Option<Fields>, BadRequest> {
    let result = match op {
        "info" => obj(vec![
            ("name", Json::Str("bitcoin-consensus-spec reference".into())),
            ("version", Json::Str(env!("CARGO_PKG_VERSION").into())),
            ("spec_version", Json::Str("v32.1-1".into())),
            ("ops", Json::Arr(OPS.iter().map(|s| Json::Str(s.to_string())).collect())),
        ]),
        "script_verify" => {
            let tx = get_tx(req, "tx")?;
            let index = get_int(req, "index")? as usize;
            let spent = get_spent_outputs(req)?;
            let flags = get_flags(req)?;
            if index >= tx.inputs.len() || spent.len() != tx.inputs.len() {
                return Err(BadRequest("index or spent_outputs do not match the transaction".into()));
            }
            let pre = PrecomputedTx::new(&tx, &spent);
            match verify_input(&tx, index, &spent, &pre, flags) {
                Ok(()) => obj(vec![("valid", Json::Bool(true)), ("script_error", Json::Str("OK".into()))]),
                Err(e) => obj(vec![("valid", Json::Bool(false)), ("script_error", Json::Str(e.name().into()))]),
            }
        }
        "tx_check" => {
            let bytes = get_hex(req, "tx")?;
            match deserialize_transaction(&bytes) {
                Err(_) => obj(vec![("valid", Json::Bool(false)), ("reason", Json::Str("tx-decode".into()))]),
                Ok(tx) => match check_transaction(&tx) {
                    Ok(()) => obj(vec![("valid", Json::Bool(true))]),
                    Err(reason) => obj(vec![("valid", Json::Bool(false)), ("reason", Json::Str(reason.into()))]),
                },
            }
        }
        "sighash_legacy" => {
            let tx = get_tx(req, "tx")?;
            let script_code = get_hex(req, "script_code")?;
            let index = get_int(req, "index")? as usize;
            let hash_type = get_int(req, "hash_type")? as i32;
            if index >= tx.inputs.len() {
                return Err(BadRequest("index out of range".into()));
            }
            let pre = PrecomputedTx::new(&tx, &[]);
            let hash = signature_hash(&script_code, &tx, index, hash_type, 0, SigVersion::Base, &pre);
            obj(vec![("sighash", Json::Str(hex_encode(&hash)))])
        }
        "sighash_taproot" => {
            let tx = get_tx(req, "tx")?;
            let index = get_int(req, "index")? as usize;
            let spent = get_spent_outputs(req)?;
            let hash_type = get_int(req, "hash_type")?;
            if index >= tx.inputs.len() || spent.len() != tx.inputs.len() || !(0..=255).contains(&hash_type) {
                return Err(BadRequest("bad index, spent_outputs or hash_type".into()));
            }
            let mut execdata = ExecData::default();
            execdata.codeseparator_pos = 0xffff_ffff;
            if let Some(annex) = opt_hex(req, "annex")? {
                let mut serialized = Vec::new();
                write_var_bytes(&mut serialized, &annex);
                execdata.annex_hash = Some(sha256(&serialized));
            }
            let mut sigversion = SigVersion::Taproot;
            if let Some(leaf) = opt_hex(req, "leaf_hash")? {
                if leaf.len() != 32 {
                    return Err(BadRequest("leaf_hash must be 32 bytes".into()));
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&leaf);
                execdata.tapleaf_hash = Some(h);
                sigversion = SigVersion::Tapscript;
            }
            if let Some(Json::Int(pos)) = req.get("codesep_pos") {
                execdata.codeseparator_pos = *pos as u32;
            }
            let pre = PrecomputedTx::new(&tx, &spent);
            match signature_hash_schnorr(&execdata, &tx, index, hash_type as u8, sigversion, &spent, &pre) {
                Some(hash) => obj(vec![("valid", Json::Bool(true)), ("sighash", Json::Str(hex_encode(&hash)))]),
                None => obj(vec![("valid", Json::Bool(false))]),
            }
        }
        "taproot_commitment_verify" => {
            let control = get_hex(req, "control_block")?;
            let script = get_hex(req, "script")?;
            let output_key = get_hex(req, "output_key")?;
            let valid = output_key.len() == 32 && control_block_size_valid(&control) && {
                let leaf = tapleaf_hash(control[0] & TAPROOT_LEAF_MASK, &script);
                verify_taproot_commitment(&control, &output_key, &leaf)
            };
            obj(vec![("valid", Json::Bool(valid))])
        }
        "schnorr_verify" => {
            let pubkey = get_hex(req, "pubkey")?;
            let msg = get_hex(req, "msg")?;
            let sig = get_hex(req, "sig")?;
            obj(vec![("valid", Json::Bool(schnorr_verify(&pubkey, &msg, &sig)))])
        }
        "chain_reset" => {
            let network = match get_str(req, "network")? {
                "main" => Network::Main,
                "testnet3" => Network::Testnet3,
                "testnet4" => Network::Testnet4,
                "signet" => Network::Signet,
                "regtest" => Network::Regtest,
                other => return Err(BadRequest(format!("unknown network {other}"))),
            };
            let mut options = NetworkOptions::default();
            if let Some(Json::Obj(opts)) = req.get("options") {
                if let Some(Json::Obj(heights)) = opts.get("testactivationheight") {
                    for (name, height) in heights {
                        match height {
                            Json::Int(h) => options.activation_heights.push((name.clone(), *h as i32)),
                            _ => return Err(BadRequest("activation height must be an integer".into())),
                        }
                    }
                }
                if let Some(Json::Arr(tests)) = opts.get("test") {
                    for t in tests {
                        if t == &Json::Str("bip94".into()) {
                            options.enforce_bip94 = true;
                        }
                    }
                }
                if let Some(Json::Str(challenge)) = opts.get("signetchallenge") {
                    options.signet_challenge = Some(hex_decode(challenge).ok_or_else(|| BadRequest("bad signetchallenge".into()))?);
                }
            }
            let params = network_params(network, &options);
            let genesis = hash_to_display(&params.consensus.genesis_hash);
            *chain = Some(ChainState::new(params));
            obj(vec![("genesis", Json::Str(genesis))])
        }
        "chain_process_block" | "chain_process_headers" | "chain_invalidate" | "chain_tip" | "chain_tips" | "utxo_hash" => {
            let state = chain.as_mut().ok_or_else(|| BadRequest("chain_reset first".into()))?;
            match op {
                "chain_process_block" => {
                    let bytes = get_hex(req, "block")?;
                    let now = get_int(req, "now")? as i64;
                    let via = match req.get("via") {
                        Some(Json::Str(v)) => v.clone(),
                        _ => "p2p".to_string(),
                    };
                    let requested = !matches!(req.get("requested"), Some(Json::Bool(false)));
                    let (result, reason) = match deserialize_block(&bytes) {
                        Err(e) => ("mutated", e.0.to_string()),
                        Ok(block) => {
                            let parent_height = state.tree.get(&block.header.prev_block).map(|p| p.height);
                            let segwit = parent_height.map(|h| h + 1 >= state.params.consensus.segwit_height);
                            if via == "p2p" && segwit.is_some() && is_block_mutated(&block, segwit.unwrap()) {
                                ("mutated", "block-mutated".to_string())
                            } else {
                                match state.process_block(block, now, requested) {
                                    BlockOutcome::Accepted => ("accepted", String::new()),
                                    BlockOutcome::Duplicate => ("duplicate", String::new()),
                                    BlockOutcome::Orphan => ("orphan", "prev-blk-not-found".to_string()),
                                    BlockOutcome::Rejected(f) => (
                                        match f.kind {
                                            FailureKind::Invalid => "invalid",
                                            FailureKind::Mutated => "mutated",
                                            FailureKind::Temporary => "temporary",
                                        },
                                        f.reason,
                                    ),
                                }
                            }
                        }
                    };
                    let tip = state.tip();
                    let mut fields = obj(vec![
                        ("result", Json::Str(result.into())),
                        ("tip", Json::Str(hash_to_display(&tip.hash))),
                        ("height", Json::Int(tip.height as i128)),
                    ]);
                    if !reason.is_empty() {
                        fields.insert("reason".into(), Json::Str(reason));
                    }
                    fields
                }
                "chain_process_headers" => {
                    let now = get_int(req, "now")? as i64;
                    let items = match field(req, "headers")? {
                        Json::Arr(items) => items.clone(),
                        _ => return Err(BadRequest("headers must be an array".into())),
                    };
                    let mut headers = Vec::new();
                    for item in &items {
                        let bytes = match item {
                            Json::Str(h) => hex_decode(h).ok_or_else(|| BadRequest("bad header hex".into()))?,
                            _ => return Err(BadRequest("header must be hex".into())),
                        };
                        if bytes.len() < 80 {
                            return Err(BadRequest("header must be 80 bytes".into()));
                        }
                        headers.push(read_block_header(&mut Reader::new(&bytes)).map_err(|_| BadRequest("bad header".into()))?);
                    }
                    let mut fields = match state.process_headers(&headers, now) {
                        Ok(()) => obj(vec![("result", Json::Str("accepted".into()))]),
                        Err((index, HeaderError::Orphan)) => obj(vec![
                            ("result", Json::Str("orphan".into())),
                            ("reason", Json::Str("prev-blk-not-found".into())),
                            ("index", Json::Int(index as i128)),
                        ]),
                        Err((index, HeaderError::Failed(f))) => obj(vec![
                            ("result", Json::Str(if f.kind == FailureKind::Temporary { "temporary" } else { "invalid" }.into())),
                            ("reason", Json::Str(f.reason)),
                            ("index", Json::Int(index as i128)),
                        ]),
                    };
                    fields.insert("best_header".into(), Json::Str(hash_to_display(&state.best_header().hash)));
                    fields
                }
                "chain_invalidate" => {
                    let hash = hash_from_display(get_str(req, "hash")?).ok_or_else(|| BadRequest("bad hash".into()))?;
                    state.invalidate_block(&hash);
                    let tip = state.tip();
                    obj(vec![("tip", Json::Str(hash_to_display(&tip.hash))), ("height", Json::Int(tip.height as i128))])
                }
                "chain_tip" => {
                    let tip = state.tip();
                    obj(vec![
                        ("tip", Json::Str(hash_to_display(&tip.hash))),
                        ("height", Json::Int(tip.height as i128)),
                        ("chainwork", Json::Str(hex_encode(&tip.chain_work.to_be_bytes()))),
                    ])
                }
                "chain_tips" => {
                    let tips = state
                        .chain_tips()
                        .into_iter()
                        .map(|(hash, height, status)| {
                            Json::Obj(obj(vec![
                                ("hash", Json::Str(hash_to_display(&hash))),
                                ("height", Json::Int(height as i128)),
                                ("status", Json::Str(status.into())),
                            ]))
                        })
                        .collect();
                    obj(vec![("tips", Json::Arr(tips))])
                }
                _ => {
                    let (hash, count) = utxo_hash_serialized_3(&state.utxo);
                    obj(vec![
                        ("hash_serialized_3", Json::Str(hash_to_display(&hash))),
                        ("txouts", Json::Int(count as i128)),
                    ])
                }
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut chain: Option<ChainState> = None;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let mut response: Fields = BTreeMap::new();
        match parse_json(&line) {
            Ok(Json::Obj(req)) => {
                response.insert("id".into(), req.get("id").cloned().unwrap_or(Json::Null));
                let op = match req.get("op") {
                    Some(Json::Str(s)) => s.clone(),
                    _ => String::new(),
                };
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(&op, &req, &mut chain)));
                match outcome {
                    Ok(Ok(Some(fields))) => {
                        response.insert("ok".into(), Json::Bool(true));
                        response.extend(fields);
                    }
                    Ok(Ok(None)) => {
                        response.insert("ok".into(), Json::Bool(false));
                        response.insert("error".into(), Json::Str("unsupported_op".into()));
                        response.insert("message".into(), Json::Str(format!("operation {op} is not supported")));
                    }
                    Ok(Err(BadRequest(message))) => {
                        response.insert("ok".into(), Json::Bool(false));
                        response.insert("error".into(), Json::Str("bad_request".into()));
                        response.insert("message".into(), Json::Str(message));
                    }
                    Err(_) => {
                        response.insert("ok".into(), Json::Bool(false));
                        response.insert("error".into(), Json::Str("internal".into()));
                        response.insert("message".into(), Json::Str("panic in reference".into()));
                    }
                }
            }
            _ => {
                response.insert("id".into(), Json::Null);
                response.insert("ok".into(), Json::Bool(false));
                response.insert("error".into(), Json::Str("bad_request".into()));
                response.insert("message".into(), Json::Str("request is not a JSON object".into()));
            }
        }
        let mut text = String::new();
        write_json(&Json::Obj(response), &mut text);
        text.push('\n');
        if out.write_all(text.as_bytes()).is_err() || out.flush().is_err() {
            break;
        }
    }
}
