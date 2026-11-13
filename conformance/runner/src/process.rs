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
//!
//! Started from a terminal, such a group is a background group of that terminal, and a process in
//! it that reads the terminal (a password prompt) is stopped by SIGTTIN. Nothing would ever
//! continue it, so the runner looks for a stopped process while it waits ([`stopped`]) and fails
//! at once instead of waiting for its timeout.

use std::fmt;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

/// How long a group has after SIGTERM before SIGKILL.
pub const GRACE: Duration = Duration::from_secs(10);

/// How often a wait for a command looks for a stopped process in its group ([`stopped`]).
pub const STOP_CHECK: Duration = Duration::from_millis(500);

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
        if signal == libc::SIGTERM {
            // A stopped process acts on SIGTERM only once it is continued.
            // SAFETY: as above.
            unsafe { libc::kill(-group, libc::SIGCONT) };
        }
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

/// A stopped process in a command's process group. Displayed as the rest of a sentence that
/// starts with the command: "the harness command {stop}".
#[derive(Debug)]
pub struct Stop {
    pub pid: i32,
    /// The signal that stopped it, known only when it is the command's own process.
    pub signal: Option<i32>,
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pid = self.pid;
        match self.signal {
            Some(libc::SIGTTIN) => write!(
                f,
                "was stopped (process {pid}, SIGTTIN): it tried to read the terminal"
            )?,
            Some(libc::SIGTTOU) => write!(
                f,
                "was stopped (process {pid}, SIGTTOU): it tried to set up or write to the terminal"
            )?,
            Some(libc::SIGTSTP) => write!(f, "was stopped (process {pid}, SIGTSTP)")?,
            Some(libc::SIGSTOP) => write!(f, "was stopped (process {pid}, SIGSTOP)")?,
            Some(signal) => write!(f, "was stopped (process {pid}, signal {signal})")?,
            None => write!(f, "was stopped (process {pid})")?,
        }
        f.write_str(
            ". It runs in a background process group, where reading the terminal (a password \
             prompt, for example) stops a process (PROTOCOL.md section 1)",
        )
    }
}

/// A stopped process in `child`'s process group, if there is one. Takes nothing away from
/// `child`: its exit status is still there for [`Child::try_wait`].
pub fn stopped(child: &Child) -> Option<Stop> {
    let pid = child.id() as i32;
    // SAFETY: an all-zero siginfo_t is valid, and waitid only writes to it. Without WEXITED it
    // neither reports nor reaps an exit, and WNOWAIT leaves a stop to be reported again.
    let (r, info) = unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
        );
        (r, info)
    };
    // SAFETY: the fields of a child state change, which is all waitid reports.
    if r == 0 && info.si_code == libc::CLD_STOPPED && unsafe { info.si_pid() } == pid {
        return Some(Stop {
            pid,
            signal: Some(unsafe { info.si_status() }),
        });
    }
    // A process the command started is not the runner's child, so waitid cannot see it.
    group_stopped(pid).map(|pid| Stop { pid, signal: None })
}

/// A stopped process in the process group `group`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn group_stopped(group: i32) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // After the command name, which is in parentheses and may hold anything: the state, the
        // parent and the process group.
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let state = fields.next();
        let pgrp = fields.nth(1).and_then(|s| s.parse::<i32>().ok());
        if state == Some("T") && pgrp == Some(group) {
            return Some(pid);
        }
    }
    None
}

/// A stopped process in the process group `group`.
#[cfg(target_os = "macos")]
fn group_stopped(group: i32) -> Option<i32> {
    let mut pids: Vec<libc::pid_t> = vec![0; 1024];
    let size = std::mem::size_of_val(pids.as_slice()) as libc::c_int;
    // SAFETY: the buffer holds `size` bytes. The result is a number of pids.
    let n = unsafe { libc::proc_listpgrppids(group, pids.as_mut_ptr().cast(), size) };
    pids.truncate(usize::try_from(n).ok()?);
    pids.into_iter().find(|&pid| {
        // The short form, unlike PROC_PIDTBSDINFO, may be read for a process of another user,
        // such as sudo.
        // SAFETY: an all-zero proc_bsdshortinfo is valid, and proc_pidinfo writes at most `len`
        // bytes to it.
        let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
        let len = std::mem::size_of_val(&info) as libc::c_int;
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDT_SHORTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdshortinfo).cast(),
                len,
            )
        };
        pid > 0 && got == len && info.pbsi_status == libc::SSTOP && info.pbsi_pgid == group as u32
    })
}

/// Other systems: only the command's own process is checked, by [`stopped`].
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn group_stopped(_group: i32) -> Option<i32> {
    None
}

extern "C" fn on_signal(signal: libc::c_int) {
    for slot in &GROUPS {
        let group = slot.load(Ordering::SeqCst);
        if group > 0 {
            // SAFETY: kill(2) is async-signal-safe.
            unsafe {
                libc::kill(-group, libc::SIGTERM);
                libc::kill(-group, libc::SIGCONT);
            }
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

    /// Waits up to 10 seconds for [`stopped`] to find a stopped process in `child`'s group.
    fn wait_stopped(child: &Child) -> Option<Stop> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(stop) = stopped(child) {
                return Some(stop);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// A process stopped by a signal is found, the signal named when it is the command's own
    /// process, and ending the group does not wait for SIGKILL.
    #[test]
    fn stopped_finds_the_command_stopped() {
        let mut child = spawn(shell("kill -STOP $$; exec sleep 300").stdin(Stdio::null())).unwrap();
        let stop = wait_stopped(&child).expect("stop not found");
        assert_eq!(stop.pid, child.id() as i32);
        assert_eq!(stop.signal, Some(libc::SIGSTOP));
        assert!(stop.to_string().starts_with("was stopped (process "));
        // Nothing was reaped.
        assert!(child.try_wait().unwrap().is_none());
        let started = Instant::now();
        end(&mut child);
        assert!(
            started.elapsed() < GRACE,
            "ending a stopped group waited for SIGKILL"
        );
    }

    /// A stopped process the command started is found too, without its signal.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn stopped_finds_a_process_the_command_started() {
        let mut child =
            spawn(shell("sh -c 'kill -STOP $$'; exec sleep 300").stdin(Stdio::null())).unwrap();
        let stop = wait_stopped(&child).expect("stop not found");
        assert_ne!(stop.pid, child.id() as i32);
        assert_eq!(stop.signal, None);
        let started = Instant::now();
        end(&mut child);
        assert!(
            started.elapsed() < GRACE,
            "ending a stopped group waited for SIGKILL"
        );
    }

    /// A running command is not stopped, and one that exited keeps its exit status.
    #[test]
    fn stopped_leaves_running_and_exited_commands_alone() {
        let mut running = spawn(shell("exec sleep 300").stdin(Stdio::null())).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(stopped(&running).is_none());
        end(&mut running);

        let mut exited = spawn(shell("exit 3").stdin(Stdio::null())).unwrap();
        let pid = exited.id() as i32;
        let deadline = Instant::now() + Duration::from_secs(10);
        // On Linux an unreaped child keeps its group alive, so the exit is watched with waitid,
        // which with WNOWAIT leaves it unreaped.
        loop {
            // SAFETY: as in `stopped`.
            let info = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                );
                info
            };
            // SAFETY: as in `stopped`.
            if unsafe { info.si_pid() } == pid {
                break;
            }
            assert!(Instant::now() < deadline, "the command did not exit");
            assert!(stopped(&exited).is_none());
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(stopped(&exited).is_none());
        assert_eq!(exited.wait().unwrap().code(), Some(3));
        end(&mut exited);
    }
}
