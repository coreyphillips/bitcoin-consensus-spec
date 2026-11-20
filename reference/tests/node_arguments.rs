//! reference-node refuses arguments it cannot run with (exit status 2) before it connects, and its
//! `error` line stays one valid JSON object whatever the message holds.

use std::process::Command;

#[allow(dead_code)]
#[path = "../src/tooling.rs"]
mod tooling;
use tooling::{parse_json, Json};

/// Runs reference-node and returns its exit status and the `message` of its one output line.
fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_reference-node")).args(args).output().expect("start reference-node");
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?} should write one line:\n{text}");
    let fields = match parse_json(lines[0]) {
        Ok(Json::Obj(fields)) => fields,
        other => panic!("{args:?}: not a JSON object: {} ({other:?})", lines[0]),
    };
    assert_eq!(fields.get("event"), Some(&Json::Str("error".into())), "{args:?}: {}", lines[0]);
    let Some(Json::Str(message)) = fields.get("message") else { panic!("{args:?}: no message: {}", lines[0]) };
    (output.status.code(), message.clone())
}

/// A local address nothing listens on, so a node given good arguments fails to connect at once.
fn closed_port() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

#[test]
fn bad_arguments_exit_with_status_2() {
    let peer = closed_port();
    let hash = "11".repeat(32);
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["--connect", &peer, "--stop-al", &hash], "unknown argument --stop-al"),
        (vec!["--connect", &peer, "extra"], "unknown argument extra"),
        (vec!["--connect", &peer, "--idle", "abc"], "--idle must be a whole number of seconds, not abc"),
        (vec!["--connect", &peer, "--idle", "-1"], "--idle must be a whole number of seconds, not -1"),
        (vec!["--connect", &peer, "--stop-at"], "--stop-at needs a value"),
        (vec!["--connect", &peer, "--stop-at", "--options", "{}"], "--stop-at needs a value"),
        (vec!["--connect", &peer, "--stop-at", "zz"], "--stop-at must be a block hash"),
        (vec!["--connect", &peer, "--connect", &peer], "--connect is given more than once"),
        (vec!["--stop-at", &hash], "--connect host:port is required"),
        (vec!["--connect", &peer, "--options", "{"], "--options: "),
        // A newline and a control character in the message must not break the JSON line.
        (vec!["--connect", &peer, "--network", "reg\n\u{1}\"test"], "unknown network reg\n\u{1}\"test"),
    ];
    for (args, expected) in cases {
        let (status, message) = run(&args);
        assert_eq!(status, Some(2), "{args:?}: {message}");
        assert!(message.starts_with(expected), "{args:?}: {message:?} should start with {expected:?}");
    }
}

#[test]
fn good_arguments_reach_the_sync() {
    let peer = closed_port();
    let hash = "11".repeat(32);
    let args = [
        "--network", "regtest", "--connect", &peer, "--stop-at", &hash, "--options", "{}", "--datadir", "/nonexistent", "--idle", "5",
        "--headers-only",
    ];
    let (status, message) = run(&args);
    assert_eq!(status, Some(1), "{message}");
    assert!(message.starts_with("sync failed: "), "{message}");
}
