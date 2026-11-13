//! The harness child process and the JSON-lines protocol of conformance/PROTOCOL.md.

use serde_json::{Map, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

/// How many times the runner restarts a harness that died before giving up.
const MAX_RESTARTS: u32 = 5;

/// The harness's answer to `info`.
#[derive(Clone, Debug)]
pub struct Info {
    pub name: String,
    pub version: String,
    pub spec_version: String,
    pub ops: Vec<String>,
    /// The complete response, for provenance records.
    pub raw: Map<String, Value>,
}

/// Why a call produced no result.
#[derive(Debug)]
pub enum CallError {
    /// `ok: false` with `unsupported_op`.
    Unsupported(String),
    /// `ok: false` with `bad_request` (always a runner or harness bug).
    BadRequest(String),
    /// `ok: false` with `internal`.
    Internal(String),
    /// The response violates the protocol (not JSON, wrong id, missing fields).
    Protocol(String),
    /// The harness exited, closed its output or did not answer in time.
    Died(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Unsupported(m) => write!(f, "unsupported_op: {m}"),
            CallError::BadRequest(m) => write!(f, "bad_request: {m}"),
            CallError::Internal(m) => write!(f, "internal: {m}"),
            CallError::Protocol(m) => write!(f, "protocol violation: {m}"),
            CallError::Died(m) => write!(f, "harness died: {m}"),
        }
    }
}

struct Process {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
}

pub struct Harness {
    command: String,
    process: Option<Process>,
    next_id: u64,
    timeout: Duration,
    restarts: u32,
    pub info: Info,
}

fn spawn(command: &str) -> Result<Process, String> {
    let mut child = crate::process::spawn(
        crate::process::shell(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    )
    .map_err(|e| format!("cannot start harness `{command}`: {e}"))?;
    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                    break;
                }
            }
        }
    });
    Ok(Process {
        child,
        stdin,
        lines: rx,
    })
}

impl Harness {
    /// Starts the harness and performs `info`.
    pub fn start(command: &str, timeout: Duration) -> Result<Harness, String> {
        let mut h = Harness {
            command: command.to_string(),
            process: Some(spawn(command)?),
            next_id: 1,
            timeout,
            restarts: 0,
            info: Info {
                name: String::new(),
                version: String::new(),
                spec_version: String::new(),
                ops: Vec::new(),
                raw: Map::new(),
            },
        };
        h.info = h.fetch_info().map_err(|e| format!("info failed: {e}"))?;
        Ok(h)
    }

    fn fetch_info(&mut self) -> Result<Info, CallError> {
        let r = self.call_once("info", "")?;
        let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let ops = r
            .get("ops")
            .and_then(Value::as_array)
            .ok_or_else(|| CallError::Protocol("info response has no ops array".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        Ok(Info {
            name: s("name"),
            version: s("version"),
            spec_version: s("spec_version"),
            ops,
            raw: r,
        })
    }

    pub fn supports(&self, op: &str) -> bool {
        self.info.ops.iter().any(|o| o == op)
    }

    pub fn restarts(&self) -> u32 {
        self.restarts
    }

    /// Sends one request and returns the result fields of a successful response. `body` is the
    /// list of request fields after `id` and `op`, already JSON encoded (for example
    /// `"tx":"00","index":0`), or empty. A harness that died is restarted for the next call.
    pub fn call(&mut self, op: &str, body: &str) -> Result<Map<String, Value>, CallError> {
        let r = self.call_once(op, body);
        if let Err(CallError::Died(_)) = &r {
            self.kill();
            if self.restarts < MAX_RESTARTS {
                self.restarts += 1;
                eprintln!(
                    "bcs-conformance: restarting harness (restart {} of at most {MAX_RESTARTS})",
                    self.restarts
                );
                if let Ok(p) = spawn(&self.command) {
                    self.process = Some(p);
                    if let Ok(info) = self.fetch_info() {
                        self.info = info;
                    }
                }
            }
        }
        r
    }

    fn call_once(&mut self, op: &str, body: &str) -> Result<Map<String, Value>, CallError> {
        let id = self.next_id;
        self.next_id += 1;
        let line = if body.is_empty() {
            format!("{{\"id\":{id},\"op\":\"{op}\"}}\n")
        } else {
            format!("{{\"id\":{id},\"op\":\"{op}\",{body}}}\n")
        };
        let timeout = self.timeout;
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| CallError::Died("harness is not running".into()))?;
        process
            .stdin
            .write_all(line.as_bytes())
            .and_then(|_| process.stdin.flush())
            .map_err(|e| CallError::Died(format!("cannot write request: {e}")))?;
        let text = match process.lines.recv_timeout(timeout) {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => return Err(CallError::Died(format!("cannot read response: {e}"))),
            Err(RecvTimeoutError::Timeout) => {
                return Err(CallError::Died(format!(
                    "no response within {} s",
                    timeout.as_secs()
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                let status = process.child.try_wait().ok().flatten();
                return Err(CallError::Died(match status {
                    Some(s) => format!("harness exited ({s})"),
                    None => "harness closed its standard output".into(),
                }));
            }
        };
        let value: Value = serde_json::from_str(text.trim_end()).map_err(|e| {
            CallError::Protocol(format!("response is not JSON ({e}): {}", text.trim_end()))
        })?;
        let Value::Object(mut obj) = value else {
            return Err(CallError::Protocol("response is not a JSON object".into()));
        };
        if obj.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(CallError::Protocol(format!(
                "response id {:?} does not match request id {id}",
                obj.get("id")
            )));
        }
        match obj.get("ok").and_then(Value::as_bool) {
            Some(true) => {
                obj.remove("id");
                obj.remove("ok");
                Ok(obj)
            }
            Some(false) => {
                let code = obj.get("error").and_then(Value::as_str).unwrap_or("");
                let message = obj
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                Err(match code {
                    "unsupported_op" => CallError::Unsupported(message),
                    "bad_request" => CallError::BadRequest(message),
                    "internal" => CallError::Internal(message),
                    other => {
                        CallError::Protocol(format!("unknown error code {other:?}: {message}"))
                    }
                })
            }
            None => Err(CallError::Protocol("response has no boolean ok".into())),
        }
    }

    /// Ends the harness and every process it started ([`crate::process::end`]).
    fn kill(&mut self) {
        if let Some(mut p) = self.process.take() {
            crate::process::end(&mut p.child);
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(p) = self.process.take() {
            // Closing standard input asks the harness to exit (PROTOCOL.md section 1).
            let Process {
                mut child, stdin, ..
            } = p;
            drop(stdin);
            for _ in 0..50 {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            // Then whatever is left, the harness itself or a process it started.
            crate::process::end(&mut child);
        }
    }
}
