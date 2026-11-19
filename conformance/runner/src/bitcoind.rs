//! A regtest `bitcoind` started by the runner (interop suite): process management and a minimal
//! JSON-RPC client (HTTP/1.1 with the cookie credentials).

use crate::process::{self, Group};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Picks `count` distinct TCP ports in `range` that nothing listens on (127.0.0.1), starting at
/// an offset derived from the process id so concurrent runs rarely collide.
pub fn free_ports(range: (u16, u16), count: usize, avoid: &[u16]) -> Result<Vec<u16>, String> {
    let (lo, hi) = range;
    let span = (hi - lo) as u32 + 1;
    let start = std::process::id() % span;
    let mut ports = Vec::new();
    for i in 0..span {
        let port = lo + ((start + i * 7) % span) as u16;
        if avoid.contains(&port) || ports.contains(&port) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_ok()
            && TcpStream::connect(("127.0.0.1", port)).is_err()
        {
            ports.push(port);
            if ports.len() == count {
                return Ok(ports);
            }
        }
    }
    Err(format!("no {count} free ports in {lo}-{hi}"))
}

/// The Bitcoin Core release the corpus was recorded from, `core.version` in
/// conformance/recorder/pins.json.
pub fn pinned_version() -> String {
    let pins: Value =
        serde_json::from_str(include_str!("../../recorder/pins.json")).expect("pins.json is JSON");
    pins["core"]["version"]
        .as_str()
        .expect("pins.json has core.version")
        .to_string()
}

/// Checks that `binary -version` is the pinned release. The suites take its verdicts as the
/// expected ones, and another release can differ from the one the corpus was recorded from.
pub fn check_version(binary: &Path) -> Result<(), String> {
    let pinned = pinned_version();
    // An empty data directory, so that no bitcoin.conf of the user's is read.
    let datadir = std::env::temp_dir().join(format!("bcs-version-{}", std::process::id()));
    std::fs::create_dir_all(&datadir)
        .map_err(|e| format!("cannot create {}: {e}", datadir.display()))?;
    let out = Command::new(binary)
        .arg("-version")
        .arg(format!("-datadir={}", datadir.display()))
        .stdin(Stdio::null())
        .output();
    let _ = std::fs::remove_dir_all(&datadir);
    let out = out.map_err(|e| format!("cannot run {} -version: {e}", binary.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().unwrap_or("").trim();
    if version_matches(first, &pinned) {
        Ok(())
    } else {
        Err(format!(
            "--bitcoind {} is not Bitcoin Core {pinned}, the release the corpus was recorded from: its -version says {:?}",
            binary.display(),
            shorten_line(first)
        ))
    }
}

/// Whether the first line of `bitcoind -version` names release `pinned` ("v32.1"). A release
/// build says "v32.1.0", a build at the tag "v32.1"; a release candidate or a build of another
/// commit says more, and does not match.
fn version_matches(line: &str, pinned: &str) -> bool {
    line.starts_with("Bitcoin Core")
        && line
            .split_whitespace()
            .any(|t| t == pinned || t == format!("{pinned}.0"))
}

fn shorten_line(s: &str) -> String {
    s.chars().take(120).collect()
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub struct Bitcoind {
    /// Registered with [`process::spawn`], so a signal that ends the runner ends bitcoind too.
    child: Option<Group>,
    pub p2p_port: u16,
    pub rpc_port: u16,
    auth: String,
}

impl Bitcoind {
    /// Starts `bitcoind -regtest` with an empty data directory and waits for its RPC server.
    /// `v2transport` is bitcoind's `-v2transport`: with it, inbound peers may use BIP324 version 2
    /// or version 1; without it, only version 1.
    pub fn start(
        binary: &Path,
        datadir: &Path,
        p2p_port: u16,
        rpc_port: u16,
        v2transport: bool,
        extra: &[String],
    ) -> Result<Bitcoind, String> {
        std::fs::create_dir_all(datadir)
            .map_err(|e| format!("cannot create {}: {e}", datadir.display()))?;
        let mut args: Vec<String> = vec![
            "-regtest".into(),
            format!("-datadir={}", datadir.display()),
            format!("-port={p2p_port}"),
            format!("-rpcport={rpc_port}"),
            "-bind=127.0.0.1".into(),
            "-rpcbind=127.0.0.1".into(),
            "-rpcallowip=127.0.0.1".into(),
            "-listen=1".into(),
            // No whitelist: a peer with `noban` is never disconnected for misbehaviour, which would
            // hide it. `-debug=net` makes bitcoind log every `Misbehaving` call.
            "-debug=net".into(),
            "-server=1".into(),
            "-connect=0".into(),
            "-dnsseed=0".into(),
            "-fixedseeds=0".into(),
            "-listenonion=0".into(),
            "-discover=0".into(),
            "-natpmp=0".into(),
            format!("-v2transport={}", u8::from(v2transport)),
            "-printtoconsole=0".into(),
            "-daemon=0".into(),
        ];
        args.extend_from_slice(extra);
        let stderr_path = datadir.join("stderr.log");
        let stderr = std::fs::File::create(&stderr_path)
            .map_err(|e| format!("cannot create {}: {e}", stderr_path.display()))?;
        let child = process::spawn(
            Command::new(binary)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(stderr),
        )
        .map_err(|e| format!("cannot start {}: {e}", binary.display()))?;
        let mut node = Bitcoind {
            child: Some(child),
            p2p_port,
            rpc_port,
            auth: String::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        let cookie = datadir.join("regtest/.cookie");
        loop {
            if let Some(child) = node.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    let err = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                    process::end(child);
                    node.child = None;
                    return Err(format!(
                        "bitcoind exited at startup ({status}): {}",
                        err.trim()
                    ));
                }
            }
            if node.auth.is_empty() {
                if let Ok(c) = std::fs::read_to_string(&cookie) {
                    node.auth = base64(c.trim().as_bytes());
                }
            }
            if !node.auth.is_empty() {
                match node.rpc("getblockchaininfo", json!([])) {
                    Ok(_) => return Ok(node),
                    Err(e) if Instant::now() > deadline => {
                        return Err(format!("bitcoind RPC not ready: {e}"))
                    }
                    Err(_) => {}
                }
            } else if Instant::now() > deadline {
                return Err("bitcoind did not create its RPC cookie".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// One JSON-RPC call. Returns the `result`, or the error message.
    pub fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut stream = TcpStream::connect(("127.0.0.1", self.rpc_port))
            .map_err(|e| format!("{method}: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(1800)))
            .ok();
        let request = format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.rpc_port,
            self.auth,
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("{method}: {e}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("{method}: {e}"))?;
        let text = String::from_utf8_lossy(&response);
        let (head, payload) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("{method}: malformed HTTP response"))?;
        let status = head.split_whitespace().nth(1).unwrap_or("");
        let v: Value = serde_json::from_str(payload.trim()).map_err(|_| {
            format!(
                "{method}: HTTP {status}: {}",
                payload.trim().chars().take(200).collect::<String>()
            )
        })?;
        if !v["error"].is_null() {
            return Err(format!(
                "{method}: {}",
                v["error"]["message"]
                    .as_str()
                    .unwrap_or(&v["error"].to_string())
            ));
        }
        Ok(v["result"].clone())
    }

    /// Stops the node: RPC `stop`, then [`process::end`] if it still runs 60 seconds later.
    pub fn stop(&mut self) {
        let _ = self.rpc("stop", json!([]));
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + Duration::from_secs(60);
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            // Also when it exited: this is what unregisters the group.
            process::end(&mut child);
        }
    }
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Writes the regtest RPC cookie and answers every JSON-RPC call with `null`, exiting on `stop`.
    const FAKE_BITCOIND: &str = r#"#!/usr/bin/env python3
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
args = dict(a[1:].split("=", 1) for a in sys.argv[1:] if "=" in a)
class Rpc(BaseHTTPRequestHandler):
    def do_POST(self):
        method = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["method"]
        body = json.dumps({"result": None, "error": None, "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if method == "stop":
            os._exit(0)
    def log_message(self, *a):
        pass
server = HTTPServer(("127.0.0.1", int(args["rpcport"])), Rpc)
os.makedirs(os.path.join(args["datadir"], "regtest"), exist_ok=True)
with open(os.path.join(args["datadir"], "regtest", ".cookie"), "w") as f:
    f.write("__cookie__:test")
server.serve_forever()
"#;

    /// A fresh directory for one test, holding `script` as the executable `bitcoind`.
    fn fake(name: &str, script: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bcs-bitcoind-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("bitcoind");
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    /// bitcoind runs in a process group of its own that is registered while it runs, so a signal
    /// to the runner ends it, and that is unregistered once it stopped.
    #[test]
    fn bitcoind_runs_in_a_registered_group() {
        if !Command::new("python3")
            .args(["-c", ""])
            .status()
            .is_ok_and(|s| s.success())
        {
            eprintln!("skipped: no python3");
            return;
        }
        let dir = fake("registered", FAKE_BITCOIND);
        let ports = free_ports((29000, 29999), 2, &[]).unwrap();
        let mut node = Bitcoind::start(
            &dir.join("bitcoind"),
            &dir.join("data"),
            ports[0],
            ports[1],
            false,
            &[],
        )
        .unwrap();
        let pid = node.child.as_ref().unwrap().id() as i32;
        // SAFETY: getpgid only reads the process's group.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        assert!(process::registered(pid));
        node.stop();
        assert!(!process::registered(pid));
        // SAFETY: signal 0 only checks that the process exists.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "bitcoind left");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bitcoind that exits at startup is reported with its standard error and leaves no group
    /// registered.
    #[test]
    fn bitcoind_that_exits_at_startup_is_unregistered() {
        let dir = fake(
            "exits",
            "#!/bin/sh\necho $$ > \"$0.pid\"\necho 'cannot obtain a lock' >&2\nexit 3\n",
        );
        let e = Bitcoind::start(&dir.join("bitcoind"), &dir.join("data"), 1, 2, false, &[])
            .err()
            .unwrap();
        assert!(e.starts_with("bitcoind exited at startup"), "{e}");
        assert!(e.ends_with(": cannot obtain a lock"), "{e}");
        let pid: i32 = std::fs::read_to_string(dir.join("bitcoind.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!process::registered(pid));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_line() {
        assert_eq!(pinned_version(), "v32.1");
        assert!(version_matches(
            "Bitcoin Core daemon version v32.1.0",
            "v32.1"
        ));
        assert!(version_matches(
            "Bitcoin Core daemon version v32.1.0 bitcoind",
            "v32.1"
        ));
        assert!(version_matches("Bitcoin Core version v32.1", "v32.1"));
        assert!(!version_matches(
            "Bitcoin Core daemon version v32.0.0",
            "v32.1"
        ));
        assert!(!version_matches(
            "Bitcoin Core daemon version v32.1.0rc1",
            "v32.1"
        ));
        assert!(!version_matches(
            "Bitcoin Core daemon version v32.10.0",
            "v32.1"
        ));
        assert!(!version_matches(
            "Bitcoin Core daemon version v32.99.0-abc123",
            "v32.1"
        ));
        assert!(!version_matches("", "v32.1"));
    }

    /// A binary that prints another release is refused, with what it printed.
    #[test]
    fn another_release_is_refused() {
        let dir = fake(
            "version",
            "#!/bin/sh\necho 'Bitcoin Core daemon version v31.0.0'\n",
        );
        let e = check_version(&dir.join("bitcoind")).unwrap_err();
        assert!(e.contains("is not Bitcoin Core v32.1"), "{e}");
        assert!(e.contains("v31.0.0"), "{e}");
        std::fs::write(
            dir.join("bitcoind"),
            "#!/bin/sh\necho 'Bitcoin Core daemon version v32.1.0'\n",
        )
        .unwrap();
        check_version(&dir.join("bitcoind")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
