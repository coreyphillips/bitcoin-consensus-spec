//! A regtest `bitcoind` started by the runner (interop suite): process management and a minimal
//! JSON-RPC client (HTTP/1.1 with the cookie credentials).

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
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
    child: Option<Child>,
    pub p2p_port: u16,
    pub rpc_port: u16,
    auth: String,
}

impl Bitcoind {
    /// Starts `bitcoind -regtest` with an empty data directory and waits for its RPC server.
    pub fn start(
        binary: &Path,
        datadir: &Path,
        p2p_port: u16,
        rpc_port: u16,
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
            "-v2transport=0".into(),
            "-printtoconsole=0".into(),
            "-daemon=0".into(),
        ];
        args.extend_from_slice(extra);
        let stderr_path = datadir.join("stderr.log");
        let stderr = std::fs::File::create(&stderr_path)
            .map_err(|e| format!("cannot create {}: {e}", stderr_path.display()))?;
        let child = Command::new(binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
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

    /// Stops the node (RPC `stop`, then kill after 60 seconds).
    pub fn stop(&mut self) {
        let _ = self.rpc("stop", json!([]));
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(100))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                }
            }
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

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
