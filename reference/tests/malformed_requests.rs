//! Malformed requests get a `bad_request` response (PROTOCOL.md section 2) and the harness keeps
//! answering. The runner never sends these, so only this test covers them.

use std::io::Write;
use std::process::{Command, Stdio};

#[allow(dead_code)]
#[path = "../src/tooling.rs"]
mod tooling;
use tooling::{parse_json, Json};

/// One input and one output, an empty scriptSig: valid against an `OP_1` output.
fn tx() -> String {
    format!("01000000 01 {} 00000000 00 ffffffff 01 0000000000000000 00 00000000", "00".repeat(32)).replace(' ', "")
}

fn script_verify(id: u32, index: &str, amount: &str) -> Vec<u8> {
    let spent = format!(r#"[{{"amount":{amount},"script_pubkey":"51"}}]"#);
    format!(r#"{{"id":{id},"op":"script_verify","tx":"{}","index":{index},"spent_outputs":{spent},"flags":[]}}"#, tx()).into_bytes()
}

#[test]
fn malformed_requests_get_bad_request() {
    const TWO_POW_64: &str = "18446744073709551616";
    let unknown = "11".repeat(32);
    // (request line, expected id, expected `error`, or None for a successful response)
    let cases: Vec<(Vec<u8>, Json, Option<&str>)> = vec![
        (br#"{"id":1}"#.to_vec(), Json::Int(1), Some("bad_request")),
        (br#"{"id":2,"op":7}"#.to_vec(), Json::Int(2), Some("bad_request")),
        (br#"{"id":3,"op":"x_unknown"}"#.to_vec(), Json::Int(3), Some("unsupported_op")),
        (
            br#"{"id":4,"op":"chain_reset","network":"regtest","options":{"testactivationheight":{"taproot":5}}}"#.to_vec(),
            Json::Int(4),
            Some("bad_request"),
        ),
        (
            br#"{"id":5,"op":"chain_reset","network":"main","options":{"testactivationheight":{"segwit":5}}}"#.to_vec(),
            Json::Int(5),
            Some("bad_request"),
        ),
        (br#"{"id":6,"op":"chain_reset","network":"regtest"}"#.to_vec(), Json::Int(6), None),
        (format!(r#"{{"id":7,"op":"chain_invalidate","hash":"{unknown}","now":0}}"#).into_bytes(), Json::Int(7), Some("bad_request")),
        (br#"{"id":8,"op":"chain_process_headers","headers":[],"now":18446744073709551616}"#.to_vec(), Json::Int(8), Some("bad_request")),
        (script_verify(9, "0", "0"), Json::Int(9), None),
        (script_verify(10, TWO_POW_64, "0"), Json::Int(10), Some("bad_request")),
        (script_verify(11, "0", TWO_POW_64), Json::Int(11), Some("bad_request")),
        (b"{\"id\":12,\"op\":\"info\",\"x\":\"\xff\"}".to_vec(), Json::Null, Some("bad_request")),
        (vec![b'['; 400_000], Json::Null, Some("bad_request")),
        (br#"{"id":14,"op":"info"}"#.to_vec(), Json::Int(14), None),
        // Without an integer id nothing runs: the regtest chain from id 6 must survive these resets.
        (br#"{"op":"chain_reset","network":"main"}"#.to_vec(), Json::Null, Some("bad_request")),
        (br#"{"id":null,"op":"chain_reset","network":"main"}"#.to_vec(), Json::Null, Some("bad_request")),
        (br#"{"id":"15","op":"chain_reset","network":"main"}"#.to_vec(), Json::Null, Some("bad_request")),
        (br#"{"id":15.5,"op":"chain_reset","network":"main"}"#.to_vec(), Json::Null, Some("bad_request")),
        (br#"{"id":9223372036854775808,"op":"chain_reset","network":"main"}"#.to_vec(), Json::Null, Some("bad_request")),
        (br#"{"id":1e400,"op":"info"}"#.to_vec(), Json::Null, Some("bad_request")),
        (br#"{"id":-16,"op":"chain_tip"}"#.to_vec(), Json::Int(-16), None),
    ];

    let mut child = Command::new(env!("CARGO_BIN_EXE_reference-harness"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start reference-harness");
    let mut stdin = child.stdin.take().unwrap();
    // A harness that exits early closes the pipe; the response count below reports that.
    let _ = cases.iter().try_for_each(|(line, _, _)| stdin.write_all(line).and_then(|_| stdin.write_all(b"\n")));
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "harness exited with {}", output.status);

    let text = String::from_utf8(output.stdout).unwrap();
    let responses: Vec<&str> = text.lines().collect();
    assert_eq!(responses.len(), cases.len(), "one response per request:\n{text}");
    let mut by_id = std::collections::BTreeMap::new();
    for ((_, id, error), response) in cases.iter().zip(responses) {
        let fields = match parse_json(response) {
            Ok(Json::Obj(fields)) => fields,
            other => panic!("not a JSON object: {response} ({other:?})"),
        };
        assert_eq!(fields.get("id"), Some(id), "{response}");
        assert_eq!(fields.get("ok"), Some(&Json::Bool(error.is_none())), "{response}");
        if let Some(error) = error {
            assert_eq!(fields.get("error"), Some(&Json::Str(error.to_string())), "{response}");
        }
        if let Json::Int(id) = id {
            by_id.insert(*id, fields);
        }
    }
    assert_eq!(by_id[&-16].get("tip"), by_id[&6].get("genesis"), "the chain changed after the regtest reset");
}
