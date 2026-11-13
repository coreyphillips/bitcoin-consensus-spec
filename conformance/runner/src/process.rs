//! The commands the runner starts through `sh -c`: the harness (`--impl`, PROTOCOL.md section 1)
//! and the node commands of the interop and peer-sync suites (sections 5 and 5.1). Each runs in a
//! process group of its own, so ending one reaches every process it started: a wrapper killed
//! while its node runs on leaves nothing behind.
//!
//! A process group of its own is also out of the terminal's reach, so a Ctrl-C or Ctrl-\ would no
//! longer stop it. While a group runs it is registered, and SIGINT, SIGQUIT, SIGTERM or SIGHUP to
//! the runner sends SIGTERM to every registered group before the runner exits by the same signal.
//! A signal the runner was started ignoring (a shell's background job ignores SIGINT and SIGQUIT)
//! stays ignored.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

/// How long a group has after SIGTERM before SIGKILL.
pub const GRACE: Duration = Duration::from_secs(10);

/// The registered groups: a process group id, or 0 for a free slot. The signal handler reads
/// them, so they are atomics in a fixed array.
const SLOTS: usize = 256;
static GROUPS: [AtomicI32; SLOTS] = [const { AtomicI32::new(0) }; SLOTS];

/// `sh -c command`, to start in a process group of its own with [`spawn`].
pub fn shell(command: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(command).process_group(0);
    c
}

/// Starts `command` (from [`shell`]) and registers its process group.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    install_handlers();
    let child = command.spawn()?;
    let group = child.id() as i32;
    for slot in &GROUPS {
        if slot
            .compare_exchange(0, group, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            break;
        }
    }
    Ok(child)
}

/// Ends `child`'s process group and reaps `child`: SIGTERM to every process left in the group,
/// then SIGKILL to whatever is left [`GRACE`] later. A group with no process left is only
/// reaped, so this may be called again, and after `child` exited on its own.
pub fn end(child: &mut Child) {
    let group = child.id() as i32;
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let _ = child.try_wait();
        if !group_alive(group) {
            break;
        }
        // SAFETY: kill(2) with a negative pid signals that process group; no memory is involved.
        unsafe { libc::kill(-group, signal) };
        let deadline = Instant::now() + GRACE;
        while Instant::now() < deadline {
            let _ = child.try_wait();
            if !group_alive(group) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let _ = child.wait();
    for slot in &GROUPS {
        let _ = slot.compare_exchange(group, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Whether any process of the group `group` is left (an exited child not yet reaped counts).
fn group_alive(group: i32) -> bool {
    // SAFETY: signal 0 only checks that the group exists.
    unsafe { libc::kill(-group, 0) == 0 }
}

extern "C" fn on_signal(signal: libc::c_int) {
    for slot in &GROUPS {
        let group = slot.load(Ordering::SeqCst);
        if group > 0 {
            // SAFETY: kill(2) is async-signal-safe.
            unsafe { libc::kill(-group, libc::SIGTERM) };
        }
    }
    // SAFETY: signal(2) and raise(3) are async-signal-safe. The default action, delivered once
    // this handler returns, ends the runner as the signal would have.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

fn install_handlers() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let handler: extern "C" fn(libc::c_int) = on_signal;
        for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: the handler only touches atomics and async-signal-safe calls.
            let previous = unsafe { libc::signal(signal, handler as libc::sighandler_t) };
            if previous == libc::SIG_IGN {
                // SAFETY: as above; this puts back what the runner was started with.
                unsafe { libc::signal(signal, libc::SIG_IGN) };
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// A command whose own process exits while a process it started runs on: ending it ends both.
    #[test]
    fn end_reaches_the_whole_group() {
        let dir = std::env::temp_dir().join(format!("bcs-process-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("pid");
        let mut child = spawn(
            shell(&format!(
                "sleep 300 & echo $! > {}; exec sleep 300",
                pid_file.display()
            ))
            .stdin(Stdio::null()),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let orphan: i32 = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "no pid file");
            std::thread::sleep(Duration::from_millis(20));
        };
        let group = child.id() as i32;
        assert!(GROUPS.iter().any(|s| s.load(Ordering::SeqCst) == group));
        end(&mut child);
        // SAFETY: signal 0 only checks that the process exists.
        assert_ne!(
            unsafe { libc::kill(orphan, 0) },
            0,
            "background process left"
        );
        assert!(!group_alive(group));
        assert!(GROUPS.iter().all(|s| s.load(Ordering::SeqCst) != group));
        end(&mut child);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
