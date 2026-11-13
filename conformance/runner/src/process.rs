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
//!
//! On Linux a zombie keeps its process group alive for `kill`. A process a command left behind is
//! handed, once its parent exits, to process 1, which in a container started without an init
//! never reaps it, so its group would never look empty. The runner makes itself a child
//! subreaper instead, is handed those processes, and reaps them when it ends their group.

use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
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

/// A command started by [`spawn`]: its own process, the leader of its process group. It derefs to
/// that process's [`Child`].
pub struct Group {
    child: Child,
    /// Set by [`end`]. The group's id may since belong to another group, so it is not used again.
    ended: bool,
}

impl Deref for Group {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for Group {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Group {
    /// Whether any process of the group is left. The command's own process is reaped first, then
    /// any other process of the group that exited after it was handed to the runner.
    fn alive(&mut self) -> bool {
        let group = self.child.id() as i32;
        // Only once `child` is reaped: waitpid could otherwise take its exit status from it.
        if let Ok(Some(_)) = self.child.try_wait() {
            // SAFETY: waitpid with a null status pointer only reaps.
            while unsafe { libc::waitpid(-group, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        }
        // SAFETY: signal 0 only checks that the group exists.
        unsafe { libc::kill(-group, 0) == 0 }
    }
}

/// Starts `command` (from [`shell`]) and registers its process group.
pub fn spawn(command: &mut Command) -> io::Result<Group> {
    setup();
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
    Ok(Group {
        child,
        ended: false,
    })
}

/// Ends the command's process group and reaps its processes: SIGTERM to every process left in
/// the group, then SIGKILL to whatever is left [`GRACE`] later. A group with no process left is
/// only reaped, so this may be called after the command exited on its own. Calling it again does
/// nothing.
pub fn end(child: &mut Group) {
    if child.ended {
        return;
    }
    let group = child.id() as i32;
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        if !child.alive() {
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
            if !child.alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let _ = child.wait();
    child.ended = true;
    for slot in &GROUPS {
        let _ = slot.compare_exchange(group, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
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
    if let Some(signal) = stop_signal(pid) {
        return Some(Stop {
            pid,
            signal: Some(signal),
        });
    }
    // Then the rest of the group, since waitid was only asked about the command's own process.
    let found = group_stopped(pid)?;
    // The command's own process may have stopped since waitid looked.
    let signal = if found == pid { stop_signal(pid) } else { None };
    Some(Stop { pid: found, signal })
}

/// The signal that stopped the runner's child `pid`, if it is stopped.
fn stop_signal(pid: i32) -> Option<i32> {
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
    (r == 0 && info.si_code == libc::CLD_STOPPED && unsafe { info.si_pid() } == pid)
        .then(|| unsafe { info.si_status() })
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

fn setup() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        install_handlers();
        become_subreaper();
    });
}

fn install_handlers() {
    let handler: extern "C" fn(libc::c_int) = on_signal;
    for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only touches atomics and async-signal-safe calls.
        let previous = unsafe { libc::signal(signal, handler as libc::sighandler_t) };
        if previous == libc::SIG_IGN {
            // SAFETY: as above; this puts back what the runner was started with.
            unsafe { libc::signal(signal, libc::SIG_IGN) };
        }
    }
}

/// Has the processes the runner's commands leave behind handed to the runner when their parent
/// exits, so that [`end`] can reap them. Should it fail, they are handed to process 1 as before.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn become_subreaper() {
    // SAFETY: this only sets an attribute of the runner's process.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong) };
}

/// Other systems: the processes are handed to process 1 as before. On macOS `kill` does not
/// count a zombie as a member of its group.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn become_subreaper() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// Starts `sleep 300 &` followed by `rest`, and returns the command with that `sleep`'s pid.
    fn spawn_with_background(name: &str, rest: &str) -> (Group, i32) {
        let pid_file =
            std::env::temp_dir().join(format!("bcs-process-{name}-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&pid_file);
        let child = spawn(
            shell(&format!(
                "sleep 300 & echo $! > {}; {rest}",
                pid_file.display()
            ))
            .stdin(Stdio::null()),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "no pid file");
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = std::fs::remove_file(&pid_file);
        (child, pid)
    }

    /// Ends `child` as the runner does and checks that nothing of its group is left, `background`
    /// included, and that this did not wait for SIGKILL.
    fn end_all(child: &mut Group, background: i32) {
        let group = child.id() as i32;
        assert!(GROUPS.iter().any(|s| s.load(Ordering::SeqCst) == group));
        let started = Instant::now();
        end(child);
        assert!(
            started.elapsed() < GRACE,
            "ending the group waited for SIGKILL"
        );
        // On Linux the runner reaped it. Elsewhere process 1 reaps it, a moment later: `end` does
        // not wait for that, since a zombie does not count as a member of its group there.
        let linux = cfg!(any(target_os = "linux", target_os = "android"));
        let deadline = Instant::now() + Duration::from_secs(if linux { 0 } else { 5 });
        // SAFETY: signal 0 only checks that the process or group exists.
        while unsafe { libc::kill(background, 0) } == 0 {
            assert!(Instant::now() < deadline, "background process left");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ne!(unsafe { libc::kill(-group, 0) }, 0, "group left");
        assert!(GROUPS.iter().all(|s| s.load(Ordering::SeqCst) != group));
        // Ended already: nothing is probed or signalled again.
        end(child);
    }

    /// A command and a process it started in the background: ending the command ends both.
    #[test]
    fn end_reaches_the_whole_group() {
        let (mut child, background) = spawn_with_background("whole", "exec sleep 300");
        end_all(&mut child, background);
    }

    /// A command that exited while a process it started runs on (a wrapper and its node): ending
    /// it ends that process. On Linux the process was handed to the runner, so it is reaped even
    /// where process 1 reaps nothing.
    #[test]
    fn end_reaches_what_an_exited_command_left() {
        let (mut child, background) = spawn_with_background("exited", "exit 0");
        assert!(child.wait().unwrap().success());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let stat = std::fs::read_to_string(format!("/proc/{background}/stat")).unwrap();
            let parent = stat.rsplit_once(')').unwrap().1.split_whitespace().nth(1);
            assert_eq!(parent, Some(std::process::id().to_string().as_str()));
        }
        end_all(&mut child, background);
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
