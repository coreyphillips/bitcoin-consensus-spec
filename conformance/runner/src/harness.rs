//! The harness child process and the JSON-lines protocol of conformance/PROTOCOL.md.

use serde_json::{Map, Value};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::process::{ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// How many times the runner restarts a harness that died before giving up.
const MAX_RESTARTS: u32 = 5;

/// The longest line of the harness's output the runner holds. Every response of PROTOCOL.md is far
/// shorter. A longer line is read to its end, but only its start is kept.
const MAX_LINE: usize = 4 << 20;

/// How many lines the reader holds that the runner has not taken. Past that the harness blocks
/// on its output pipe, so output nobody asked for cannot fill the runner's memory.
const QUEUED_LINES: usize = 4;

/// How much of a line an error or warning shows.
const SHOWN: usize = 200;

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
    /// A process in the harness's process group is stopped, most likely by a read of the
    /// terminal ([`crate::process::stopped`]). A restarted harness would stop again, so the
    /// harness is ended for good.
    Stopped(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Unsupported(m) => write!(f, "unsupported_op: {m}"),
            CallError::BadRequest(m) => write!(f, "bad_request: {m}"),
            CallError::Internal(m) => write!(f, "internal: {m}"),
            CallError::Protocol(m) => write!(f, "protocol violation: {m}"),
            CallError::Died(m) => write!(f, "harness died: {m}"),
            CallError::Stopped(m) => write!(f, "the harness command {m}"),
        }
    }
}

/// A line of the harness's output, without its `\n`.
struct Line {
    /// The whole line, or its first [`SHOWN`] bytes when `cut`.
    bytes: Vec<u8>,
    /// The line was longer than [`MAX_LINE`].
    cut: bool,
}

impl Line {
    /// The line for an error or a warning.
    fn shown(&self) -> String {
        let text = crate::check::shorten(&String::from_utf8_lossy(&self.bytes), SHOWN);
        if self.cut {
            format!("{text} (a line longer than {MAX_LINE} bytes)")
        } else {
            text
        }
    }
}

/// Reads one line of the harness's output, or `None` at its end.
fn read_line(reader: &mut impl BufRead) -> io::Result<Option<Line>> {
    let mut bytes = Vec::new();
    // One byte over the limit tells a line of exactly MAX_LINE bytes from a longer one.
    if reader
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut bytes)?
        == 0
    {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    } else if bytes.len() > MAX_LINE {
        bytes.truncate(SHOWN);
        bytes.shrink_to_fit();
        let mut rest = Vec::new();
        loop {
            rest.clear();
            let n = reader.take(MAX_LINE as u64).read_until(b'\n', &mut rest)?;
            if n == 0 || rest.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(Line { bytes, cut: true }));
    }
    Ok(Some(Line { bytes, cut: false }))
}

/// The response to request `id` in `line`, or `None` for a line that is not one: a line that does
/// not start with `{` (a debug print), or the answer to an earlier request (a second answer, or
/// one that came after a stray line was taken for it). Skipping these keeps one stray line from
/// putting every later response a line behind. Any other line is taken as this request's
/// response, so a wrong one fails the call at once instead of at the timeout.
fn response(line: &Line, id: u64) -> Option<Result<Map<String, Value>, CallError>> {
    let text = line.bytes.trim_ascii();
    if text.first() != Some(&b'{') {
        return None;
    }
    if line.cut {
        return Some(Err(CallError::Protocol(format!(
            "response is too long: {}",
            line.shown()
        ))));
    }
    let mut obj: Map<String, Value> = match serde_json::from_slice(text) {
        Ok(obj) => obj,
        Err(e) => {
            return Some(Err(CallError::Protocol(format!(
                "response is not a JSON object ({e}): {}",
                line.shown()
            ))))
        }
    };
    match obj.get("id").and_then(Value::as_u64) {
        Some(got) if got == id => {}
        // Request ids start at 1.
        Some(got) if (1..id).contains(&got) => return None,
        _ => {
            return Some(Err(CallError::Protocol(format!(
                "response id {:?} does not match request id {id}",
                obj.get("id")
            ))))
        }
    }
    Some(match obj.get("ok").and_then(Value::as_bool) {
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
                other => CallError::Protocol(format!("unknown error code {other:?}: {message}")),
            })
        }
        None => Err(CallError::Protocol("response has no boolean ok".into())),
    })
}

struct Process {
    child: crate::process::Group,
    stdin: ChildStdin,
    lines: Receiver<io::Result<Line>>,
}

pub struct Harness {
    command: String,
    process: Option<Process>,
    next_id: u64,
    timeout: Duration,
    restarts: u32,
    /// Lines of output that were not responses ([`response`]), over every restart.
    skipped: u64,
    /// Set once a call found the harness stopped: every later call fails the same way.
    stopped: Option<String>,
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
    if let Err(e) = set_nonblocking(&stdin) {
        crate::process::end(&mut child);
        return Err(format!("cannot set up harness `{command}`: {e}"));
    }
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::sync_channel(QUEUED_LINES);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_line(&mut reader) {
                Ok(None) => break,
                Ok(Some(line)) => {
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

/// Makes writes to the harness return instead of blocking when its input pipe is full, so that a
/// harness that stops reading in the middle of a large request cannot hold the runner past its
/// timeout or its stop check ([`send`]).
fn set_nonblocking(stdin: &ChildStdin) -> std::io::Result<()> {
    let fd = stdin.as_raw_fd();
    // SAFETY: fcntl(2) on a descriptor the runner owns; it only reads and sets its status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Writes `line` to the harness. While its input pipe is full, this waits for the harness to read
/// until `deadline`, looking for a stopped process every [`crate::process::STOP_CHECK`].
fn send(
    process: &mut Process,
    line: &[u8],
    deadline: Instant,
    timeout: Duration,
) -> Result<(), CallError> {
    let mut rest = line;
    while !rest.is_empty() {
        match process.stdin.write(rest) {
            Ok(0) => {
                return Err(CallError::Died(
                    "cannot write request: no byte taken".into(),
                ))
            }
            Ok(n) => {
                rest = &rest[n..];
                continue;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(CallError::Died(format!("cannot write request: {e}"))),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(CallError::Died(format!(
                "request not read within {} s",
                timeout.as_secs()
            )));
        }
        let wait = left.min(crate::process::STOP_CHECK).as_millis().max(1) as libc::c_int;
        let mut fd = libc::pollfd {
            fd: process.stdin.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll(2) on one pollfd the runner owns. A closed pipe also ends the wait, and the
        // next write reports it.
        if unsafe { libc::poll(&mut fd, 1, wait) } == 0 {
            if let Some(stop) = crate::process::stopped(&process.child) {
                return Err(CallError::Stopped(stop.to_string()));
            }
        }
    }
    Ok(())
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
            skipped: 0,
            stopped: None,
            info: Info {
                name: String::new(),
                version: String::new(),
                spec_version: String::new(),
                ops: Vec::new(),
                raw: Map::new(),
            },
        };
        match h.fetch_info() {
            Ok(info) => h.info = info,
            Err(e) => {
                if let CallError::Stopped(_) = e {
                    // It cannot exit when its input closes, so Drop's wait would be wasted.
                    h.kill();
                }
                return Err(format!("info failed: {e}"));
            }
        }
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

    /// How many lines of the harness's output were skipped as not responses.
    pub fn skipped_lines(&self) -> u64 {
        self.skipped
    }

    /// Sends one request and returns the result fields of a successful response. `body` is the
    /// list of request fields after `id` and `op`, already JSON encoded (for example
    /// `"tx":"00","index":0`), or empty. A harness that died is restarted for the next call; one
    /// that was stopped is not.
    pub fn call(&mut self, op: &str, body: &str) -> Result<Map<String, Value>, CallError> {
        if let Some(m) = &self.stopped {
            return Err(CallError::Stopped(m.clone()));
        }
        let r = self.call_once(op, body);
        match &r {
            Err(CallError::Died(_)) => {
                self.kill();
                if self.restarts < MAX_RESTARTS {
                    self.restarts += 1;
                    eprintln!(
                        "bcs-conformance: restarting harness (restart {} of at most {MAX_RESTARTS})",
                        self.restarts
                    );
                    if let Ok(p) = spawn(&self.command) {
                        self.process = Some(p);
                        match self.fetch_info() {
                            Ok(info) => self.info = info,
                            Err(CallError::Stopped(m)) => self.give_up(m),
                            Err(_) => {}
                        }
                    }
                }
            }
            Err(CallError::Stopped(m)) => self.give_up(m.clone()),
            _ => {}
        }
        r
    }

    /// Ends a stopped harness for good.
    fn give_up(&mut self, why: String) {
        eprintln!("bcs-conformance: the harness command {why}");
        self.stopped = Some(why);
        self.kill();
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
        let deadline = Instant::now() + timeout;
        send(process, line.as_bytes(), deadline, timeout)?;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match process
                .lines
                .recv_timeout(left.min(crate::process::STOP_CHECK))
            {
                Ok(Ok(line)) => {
                    if let Some(r) = response(&line, id) {
                        return r;
                    }
                    self.skipped += 1;
                    if self.skipped == 1 {
                        eprintln!(
                            "bcs-conformance: the harness printed a line that is not a response \
                             to request {id}, skipped (later ones are skipped without a message): {}",
                            line.shown()
                        );
                    }
                }
                Ok(Err(e)) => return Err(CallError::Died(format!("cannot read response: {e}"))),
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(stop) = crate::process::stopped(&process.child) {
                        return Err(CallError::Stopped(stop.to_string()));
                    }
                    if Instant::now() >= deadline {
                        return Err(CallError::Died(format!(
                            "no response within {} s",
                            timeout.as_secs()
                        )));
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = process.child.try_wait().ok().flatten();
                    return Err(CallError::Died(match status {
                        Some(s) => format!("harness exited ({s})"),
                        None => "harness closed its standard output".into(),
                    }));
                }
            }
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
                mut child,
                stdin,
                lines,
            } = p;
            // The reader may be waiting for room for a line, and the harness for it to read.
            drop(lines);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A harness stopped before it answers `info` fails the start at once, not after the timeout.
    #[test]
    fn start_fails_at_once_when_the_harness_is_stopped() {
        let started = Instant::now();
        let e = Harness::start("kill -STOP $$", Duration::from_secs(60))
            .err()
            .expect("start succeeded");
        assert!(
            e.starts_with("info failed: the harness command was stopped"),
            "{e}"
        );
        assert!(e.contains("SIGSTOP"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A harness stopped after `info` is not restarted, and later calls fail without waiting.
    #[test]
    fn a_stopped_harness_is_not_restarted() {
        let mut h = Harness::start(
            r#"read l; echo '{"id":1,"ok":true,"ops":["x"]}'; kill -STOP $$"#,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(matches!(h.call("x", ""), Err(CallError::Stopped(_))));
        assert_eq!(h.restarts(), 0);
        assert!(h.process.is_none());
        let started = Instant::now();
        assert!(matches!(h.call("x", ""), Err(CallError::Stopped(_))));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    /// Starts `command`, which answers `info` and then reads nothing more, and sends it a request
    /// far larger than a pipe holds. Returns the result, the time it took, and the harness. Fails
    /// rather than hangs if the write blocks.
    fn call_large(command: &str, timeout: Duration) -> (CallError, Duration, Harness) {
        let mut h = Harness::start(command, timeout).unwrap();
        let body = format!("\"tx\":\"{}\"", "00".repeat(1 << 20));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let r = h.call("x", &body);
            let _ = tx.send((r, started.elapsed(), h));
        });
        let (r, took, h) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the request write blocked");
        (r.expect_err("the call succeeded"), took, h)
    }

    /// A harness stopped after `info` is found while a large request waits to be read, and is
    /// ended without a restart.
    #[test]
    fn a_large_request_to_a_stopped_harness_fails_at_once() {
        let (e, took, h) = call_large(
            r#"read l; echo '{"id":1,"ok":true,"ops":["x"]}'; kill -STOP $$"#,
            Duration::from_secs(60),
        );
        assert!(matches!(e, CallError::Stopped(_)), "{e}");
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(h.restarts(), 0);
        assert!(h.process.is_none());
    }

    /// A harness that stops reading in the middle of a request fails at the timeout.
    #[test]
    fn a_large_request_the_harness_does_not_read_times_out() {
        let (e, took, h) = call_large(
            r#"read l; echo '{"id":1,"ok":true,"ops":["x"]}'; exec sleep 30"#,
            Duration::from_secs(1),
        );
        assert!(
            matches!(&e, CallError::Died(m) if m == "request not read within 1 s"),
            "{e}"
        );
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert_eq!(h.restarts(), 1);
    }

    /// Lines end at `\n`, and the last may lack one. A line of [`MAX_LINE`] bytes is kept whole;
    /// of a longer one only the start is kept, and the next line is read after it.
    #[test]
    fn read_line_caps_long_lines() {
        let mut input = Vec::new();
        input.extend_from_slice(b"a\r\n");
        input.extend(std::iter::repeat_n(b'x', MAX_LINE));
        input.push(b'\n');
        input.extend(std::iter::repeat_n(b'y', 3 * MAX_LINE));
        input.extend_from_slice(b"\n{}\nlast");
        let mut reader = BufReader::new(input.as_slice());
        let mut lines = Vec::new();
        while let Some(line) = read_line(&mut reader).unwrap() {
            lines.push((line.bytes, line.cut));
        }
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], (b"a\r".to_vec(), false));
        assert_eq!(lines[1], (vec![b'x'; MAX_LINE], false));
        assert_eq!(lines[2], (vec![b'y'; SHOWN], true));
        assert_eq!(lines[3], (b"{}".to_vec(), false));
        assert_eq!(lines[4], (b"last".to_vec(), false));
    }

    /// The shell code a stub harness runs for each request: `$id` is the request's id, and the
    /// response carries it again as `n`, so a test sees which request a result answers.
    const RESPOND: &str = r#"id=${l#*'"id":'}; id=${id%%[,\}]*}; respond() { printf '{"id":%s,"ok":true,"ops":["x"],"n":%s}\n' "$id" "$id"; }"#;

    /// Starts a stub harness that runs `body` for each request (after [`RESPOND`]).
    fn stub(body: &str) -> Harness {
        Harness::start(
            &format!("while read -r l; do {RESPOND}; {body}; done"),
            Duration::from_secs(10),
        )
        .unwrap()
    }

    fn n(r: Result<Map<String, Value>, CallError>) -> u64 {
        r.unwrap()["n"].as_u64().unwrap()
    }

    /// A debug print before every response is skipped, and every call gets its own response.
    #[test]
    fn lines_that_are_not_responses_are_skipped() {
        let mut h = stub(r#"echo "debug: $l"; respond"#);
        assert_eq!(n(h.call("x", "")), 2);
        assert_eq!(n(h.call("x", "")), 3);
        assert_eq!(n(h.call("x", "")), 4);
        assert_eq!(h.skipped_lines(), 4);
        assert_eq!(h.restarts(), 0);
    }

    /// A request answered twice does not put the responses to later requests a line behind.
    #[test]
    fn a_second_answer_is_skipped() {
        let mut h = stub(r#"respond; if [ "$id" = 2 ]; then respond; fi"#);
        assert_eq!(n(h.call("x", "")), 2);
        assert_eq!(n(h.call("x", "")), 3);
        assert_eq!(n(h.call("x", "")), 4);
        assert_eq!(h.skipped_lines(), 1);
    }

    /// A stray line that starts with `{` fails the call it came in, and only that call: its own
    /// response, which comes after it, is skipped.
    #[test]
    fn a_stray_object_fails_one_call() {
        let mut h = stub(r#"if [ "$id" = 2 ]; then echo '{"log":"x"}'; fi; respond"#);
        assert!(
            matches!(h.call("x", ""), Err(CallError::Protocol(m)) if m == "response id None does not match request id 2")
        );
        assert_eq!(n(h.call("x", "")), 3);
        assert_eq!(n(h.call("x", "")), 4);
        assert_eq!(h.skipped_lines(), 1);
        assert_eq!(h.restarts(), 0);
    }

    /// A line too long to hold is skipped, unless it starts with `{`: then it fails its call.
    #[test]
    fn long_lines_are_dropped() {
        let long = format!("head -c {} /dev/zero | tr '\\0' x; echo", 3 * MAX_LINE);
        let mut h = stub(&format!(
            r#"case $id in 2) {long};; 3) printf '{{'; {long};; esac; respond"#
        ));
        assert_eq!(n(h.call("x", "")), 2);
        assert!(
            matches!(h.call("x", ""), Err(CallError::Protocol(m)) if m.starts_with("response is too long: {xxx") && m.ends_with(&format!("(a line longer than {MAX_LINE} bytes)")))
        );
        assert_eq!(n(h.call("x", "")), 4);
        assert_eq!(h.skipped_lines(), 2);
        assert_eq!(h.restarts(), 0);
    }

    /// A harness that writes without end, and never the response, fails the call at the timeout.
    #[test]
    fn endless_output_times_out() {
        let mut h = Harness::start(
            r#"read -r l; echo '{"id":1,"ok":true,"ops":["x"]}'; exec yes"#,
            Duration::from_secs(1),
        )
        .unwrap();
        let started = Instant::now();
        assert!(
            matches!(h.call("x", ""), Err(CallError::Died(m)) if m == "no response within 1 s")
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(h.skipped_lines() > 0);
    }
}
