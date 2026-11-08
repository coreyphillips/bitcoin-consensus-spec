//! `oracle-core-harness`: a conformance harness (see `conformance/PROTOCOL.md`) whose answers come
//! from Bitcoin Core v32.1's own consensus code, compiled from source by `build.rs`.
//!
//! It reads one JSON request per line on standard input and writes one JSON response per line on
//! standard output. Chain operations are not provided (`unsupported_op`).

mod ffi;

use ffi::{CoreError, SpentOutput, FLAG_NAMES};
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, BufWriter, Write};

const NAME: &str = "oracle-core";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const CORE_COMMIT: &str = env!("ORACLE_CORE_COMMIT");
const CORE_VERSION: &str = env!("ORACLE_CORE_VERSION");
const BUILD: &str = env!("ORACLE_BUILD");

const OPS: &[&str] = &[
    "info",
    "script_verify",
    "tx_check",
    "sighash_legacy",
    "sighash_taproot",
    "taproot_commitment_verify",
    "schnorr_verify",
];

/// Operations outside PROTOCOL.md, listed under `extensions` in `info` (not under `ops`).
/// `x_core_script_verify` is `script_verify` with any of Core's flag names, policy flags
/// included; `bcs-conformance derive` uses it to replay Core's own tests with their original
/// flags.
const EXTENSIONS: &[&str] = &["x_core_script_verify"];

enum Failure {
    Unsupported(String),
    BadRequest(String),
    Internal(String),
}

impl From<CoreError> for Failure {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::BadRequest(m) => Failure::BadRequest(m),
            CoreError::Internal(m) => Failure::Internal(m),
        }
    }
}

type Fields = Map<String, Value>;

fn main() {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut out = BufWriter::new(io::stdout().lock());
    let mut line = String::new();
    loop {
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("oracle-core-harness: cannot read standard input: {e}");
                std::process::exit(1);
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(line.trim_end_matches(['\n', '\r']));
        let written = out
            .write_all(response.as_bytes())
            .and_then(|_| out.write_all(b"\n"))
            .and_then(|_| out.flush());
        if let Err(e) = written {
            eprintln!("oracle-core-harness: cannot write standard output: {e}");
            std::process::exit(1);
        }
    }
}

fn handle_line(line: &str) -> String {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return failure(
                &Value::Null,
                Failure::BadRequest(format!("invalid JSON: {e}")),
            )
        }
    };
    let Some(obj) = request.as_object() else {
        return failure(
            &Value::Null,
            Failure::BadRequest("request is not a JSON object".into()),
        );
    };
    let id = obj.get("id").cloned().unwrap_or(Value::Null);
    if !id.is_i64() && !id.is_u64() {
        return failure(&id, Failure::BadRequest("missing or non-integer id".into()));
    }
    let Some(op) = obj.get("op").and_then(Value::as_str) else {
        return failure(&id, Failure::BadRequest("missing op".into()));
    };
    let result = match op {
        "info" => Ok(info()),
        "script_verify" => script_verify(obj),
        "x_core_script_verify" => x_core_script_verify(obj),
        "tx_check" => tx_check(obj),
        "sighash_legacy" => sighash_legacy(obj),
        "sighash_taproot" => sighash_taproot(obj),
        "taproot_commitment_verify" => taproot_commitment_verify(obj),
        "schnorr_verify" => schnorr_verify(obj),
        other => Err(Failure::Unsupported(format!(
            "oracle-core only provides the context-free operations, not {other}"
        ))),
    };
    match result {
        Ok(mut fields) => {
            let mut resp = Map::new();
            resp.insert("id".into(), id);
            resp.insert("ok".into(), Value::Bool(true));
            resp.append(&mut fields);
            Value::Object(resp).to_string()
        }
        Err(f) => failure(&id, f),
    }
}

fn failure(id: &Value, f: Failure) -> String {
    let (code, message) = match f {
        Failure::Unsupported(m) => ("unsupported_op", m),
        Failure::BadRequest(m) => ("bad_request", m),
        Failure::Internal(m) => ("internal", m),
    };
    json!({"id": id, "ok": false, "error": code, "message": message}).to_string()
}

fn fields(v: Value) -> Fields {
    match v {
        Value::Object(m) => m,
        _ => unreachable!("fields() takes an object"),
    }
}

fn info() -> Fields {
    fields(json!({
        "name": NAME,
        "version": VERSION,
        "spec_version": CORE_VERSION,
        "ops": OPS,
        "extensions": EXTENSIONS,
        "core_version": CORE_VERSION,
        "core_commit": CORE_COMMIT,
        "build": BUILD,
    }))
}

// ----- request field helpers -------------------------------------------------------------------

fn bad(msg: impl Into<String>) -> Failure {
    Failure::BadRequest(msg.into())
}

/// Lowercase, even-length hexadecimal (protocol section 3).
fn decode_hex(s: &str, field: &str) -> Result<Vec<u8>, Failure> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(bad(format!("{field}: odd-length hex")));
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(bad(format!("{field}: not lowercase hex"))),
    };
    bytes
        .chunks(2)
        .map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

fn hex_field(req: &Fields, field: &str) -> Result<Vec<u8>, Failure> {
    match req.get(field) {
        Some(Value::String(s)) => decode_hex(s, field),
        Some(_) => Err(bad(format!("{field} must be a hex string"))),
        None => Err(bad(format!("missing field {field}"))),
    }
}

fn optional_hex_field(req: &Fields, field: &str) -> Result<Option<Vec<u8>>, Failure> {
    match req.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => hex_field(req, field).map(Some),
    }
}

fn fixed_hex<const N: usize>(req: &Fields, field: &str) -> Result<[u8; N], Failure> {
    let v = hex_field(req, field)?;
    v.try_into()
        .map_err(|_| bad(format!("{field} must be exactly {N} bytes")))
}

fn int_field(req: &Fields, field: &str) -> Result<i64, Failure> {
    match req.get(field) {
        Some(v) => v
            .as_i64()
            .ok_or_else(|| bad(format!("{field} must be an integer"))),
        None => Err(bad(format!("missing field {field}"))),
    }
}

fn u32_field(req: &Fields, field: &str) -> Result<u32, Failure> {
    let v = int_field(req, field)?;
    u32::try_from(v).map_err(|_| bad(format!("{field} out of range")))
}

fn spent_outputs(req: &Fields) -> Result<Vec<SpentOutput>, Failure> {
    let Some(Value::Array(items)) = req.get("spent_outputs") else {
        return Err(bad("spent_outputs must be an array"));
    };
    items
        .iter()
        .map(|item| {
            let obj = item
                .as_object()
                .ok_or_else(|| bad("spent_outputs entries must be objects"))?;
            Ok(SpentOutput {
                amount: int_field(obj, "amount")?,
                script_pubkey: hex_field(obj, "script_pubkey")?,
            })
        })
        .collect()
}

fn flag_bits(req: &Fields) -> Result<u32, Failure> {
    let Some(Value::Array(names)) = req.get("flags") else {
        return Err(bad("flags must be an array of strings"));
    };
    let mut bits = 0u32;
    for name in names {
        let name = name
            .as_str()
            .ok_or_else(|| bad("flags must be an array of strings"))?;
        let pos = FLAG_NAMES
            .iter()
            .position(|f| *f == name)
            .ok_or_else(|| bad(format!("unknown flag {name}")))?;
        bits |= 1 << pos;
    }
    Ok(bits)
}

// ----- operations ------------------------------------------------------------------------------

fn script_verify(req: &Fields) -> Result<Fields, Failure> {
    let tx = hex_field(req, "tx")?;
    let index = u32_field(req, "index")?;
    let spent = spent_outputs(req)?;
    let flags = flag_bits(req)?;
    let (valid, error) = ffi::script_verify(&tx, index, &spent, flags)?;
    Ok(fields(json!({"valid": valid, "script_error": error})))
}

fn x_core_script_verify(req: &Fields) -> Result<Fields, Failure> {
    let tx = hex_field(req, "tx")?;
    let index = u32_field(req, "index")?;
    let spent = spent_outputs(req)?;
    let Some(Value::Array(names)) = req.get("flags") else {
        return Err(bad("flags must be an array of strings"));
    };
    let names = names
        .iter()
        .map(|n| {
            n.as_str()
                .map(str::to_string)
                .ok_or_else(|| bad("flags must be an array of strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (valid, error) = ffi::script_verify_named(&tx, index, &spent, &names)?;
    Ok(fields(json!({"valid": valid, "script_error": error})))
}

fn tx_check(req: &Fields) -> Result<Fields, Failure> {
    let tx = hex_field(req, "tx")?;
    Ok(match ffi::tx_check(&tx)? {
        None => fields(json!({"valid": true})),
        Some(reason) => fields(json!({"valid": false, "reason": reason})),
    })
}

fn sighash_legacy(req: &Fields) -> Result<Fields, Failure> {
    let tx = hex_field(req, "tx")?;
    let script = hex_field(req, "script_code")?;
    let index = u32_field(req, "index")?;
    let hash_type = int_field(req, "hash_type")?;
    let hash_type =
        i32::try_from(hash_type).map_err(|_| bad("hash_type must be a signed 32-bit integer"))?;
    let hash = ffi::sighash_legacy(&tx, &script, index, hash_type)?;
    Ok(fields(json!({"sighash": encode_hex(&hash)})))
}

fn sighash_taproot(req: &Fields) -> Result<Fields, Failure> {
    let tx = hex_field(req, "tx")?;
    let index = u32_field(req, "index")?;
    let spent = spent_outputs(req)?;
    let hash_type = int_field(req, "hash_type")?;
    if !(0..=255).contains(&hash_type) {
        return Err(bad("hash_type must be between 0 and 255"));
    }
    let annex = optional_hex_field(req, "annex")?;
    let leaf_hash: Option<[u8; 32]> = match optional_hex_field(req, "leaf_hash")? {
        None => None,
        Some(v) => Some(
            v.try_into()
                .map_err(|_| bad("leaf_hash must be exactly 32 bytes"))?,
        ),
    };
    // Only meaningful for script path spends; ignored on the key path.
    let codesep_pos = match req.get("codesep_pos") {
        None | Some(Value::Null) => u32::MAX,
        Some(_) => u32_field(req, "codesep_pos")?,
    };
    let hash = ffi::sighash_taproot(
        &tx,
        index,
        &spent,
        hash_type as u32,
        annex.as_deref(),
        leaf_hash.as_ref(),
        codesep_pos,
    )?;
    Ok(match hash {
        Some(h) => fields(json!({"valid": true, "sighash": encode_hex(&h)})),
        None => fields(json!({"valid": false})),
    })
}

fn taproot_commitment_verify(req: &Fields) -> Result<Fields, Failure> {
    let control = hex_field(req, "control_block")?;
    let script = hex_field(req, "script")?;
    let output_key: [u8; 32] = fixed_hex(req, "output_key")?;
    let valid = ffi::taproot_commitment_verify(&control, &script, &output_key)?;
    Ok(fields(json!({"valid": valid})))
}

fn schnorr_verify(req: &Fields) -> Result<Fields, Failure> {
    let pubkey: [u8; 32] = fixed_hex(req, "pubkey")?;
    let msg = hex_field(req, "msg")?;
    let sig: [u8; 64] = fixed_hex(req, "sig")?;
    let valid = ffi::schnorr_verify(&pubkey, &msg, &sig)?;
    Ok(fields(json!({"valid": valid})))
}
