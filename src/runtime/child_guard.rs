//! Track OpenSSH session children so brokre exit (especially SIGTERM from timeouts)
//! does not leave orphan `ssh` processes.
//!
//! Mux masters started with `ssh -N -f` fork into the background; we only track
//! the direct session client brokre spawned. Per-call [`SessionTracker`] scopes
//! kills so MCP `brokre_list` timeout cannot terminate a concurrent `brokre_exec`.

use crate::utils::errors::{BrokreError, Result};
use std::collections::HashSet;
use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output};
#[cfg(unix)]
use std::sync::Once;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SessionWaitError {
    TimedOut { after: Duration },
    Io(io::Error),
    Runtime(String),
}

impl From<SessionWaitError> for BrokreError {
    fn from(err: SessionWaitError) -> Self {
        match err {
            SessionWaitError::TimedOut { after } => {
                BrokreError::Runtime(format!("bastion rpc timed out after {}s", after.as_secs()))
            }
            SessionWaitError::Io(e) => BrokreError::Io(e),
            SessionWaitError::Runtime(msg) => BrokreError::Runtime(msg),
        }
    }
}

#[derive(Clone, Default)]
pub struct SessionTracker {
    pgids: Arc<Mutex<HashSet<i32>>>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, pgid: i32) {
        if pgid <= 0 {
            return;
        }
        if let Ok(mut set) = self.pgids.lock() {
            set.insert(pgid);
        }
    }

    fn remove(&self, pgid: i32) {
        if let Ok(mut set) = self.pgids.lock() {
            set.remove(&pgid);
        }
    }

    /// SIGTERM then SIGKILL only the process groups registered in this tracker.
    pub fn terminate(&self) {
        let pgids: Vec<i32> = self
            .pgids
            .lock()
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        for pgid in pgids {
            terminate_pgid(pgid);
            unregister_pgid(pgid);
        }
        if let Ok(mut set) = self.pgids.lock() {
            set.clear();
        }
    }
}

thread_local! {
    static CURRENT_TRACKER: std::cell::RefCell<Option<SessionTracker>> =
        const { std::cell::RefCell::new(None) };
}

fn all_pgids() -> &'static Mutex<HashSet<i32>> {
    static ALL_PGIDS: OnceLock<Mutex<HashSet<i32>>> = OnceLock::new();
    ALL_PGIDS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(unix)]
static HANDLERS: Once = Once::new();

pub fn with_session_tracker<R>(tracker: SessionTracker, f: impl FnOnce() -> R) -> R {
    CURRENT_TRACKER.with(|slot| {
        let prev = slot.replace(Some(tracker));
        let result = f();
        slot.replace(prev);
        result
    })
}

fn register_pgid(pgid: i32) {
    if pgid <= 0 {
        return;
    }
    if let Ok(mut set) = all_pgids().lock() {
        set.insert(pgid);
    }
    CURRENT_TRACKER.with(|slot| {
        if let Some(tracker) = slot.borrow().as_ref() {
            tracker.insert(pgid);
        }
    });
}

fn unregister_pgid(pgid: i32) {
    if pgid <= 0 {
        return;
    }
    if let Ok(mut set) = all_pgids().lock() {
        set.remove(&pgid);
    }
    CURRENT_TRACKER.with(|slot| {
        if let Some(tracker) = slot.borrow().as_ref() {
            tracker.remove(pgid);
        }
    });
}

#[cfg(unix)]
fn terminate_pgid(pgid: i32) {
    if pgid <= 0 {
        return;
    }
    unsafe {
        let _ = libc::kill(-pgid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        unsafe {
            if libc::kill(-pgid, 0) != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    unsafe {
        let _ = libc::kill(-pgid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn terminate_pgid(_pgid: i32) {}

/// Kill every session this process registered. For `brokre mcp` / `brokre ssh` SIGTERM only —
/// never use this as MCP `brokre_list` timeout (that would kill concurrent exec).
pub fn terminate_process_sessions() {
    let pgids: Vec<i32> = all_pgids()
        .lock()
        .map(|set| set.iter().copied().collect())
        .unwrap_or_default();
    for pgid in pgids {
        terminate_pgid(pgid);
        unregister_pgid(pgid);
    }
}

#[cfg(unix)]
fn prune_askpass_owned_by_current_process() {
    let pid = std::process::id();
    let dir = crate::utils::paths::run_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("askpass_") || !name.ends_with(".owner") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        if raw.trim().parse::<u32>().ok() != Some(pid) {
            continue;
        }
        let state = path.with_extension("");
        let _ = std::fs::remove_file(&state);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(unix)]
extern "C" fn on_sigterm(_: libc::c_int) {
    terminate_process_sessions();
    prune_askpass_owned_by_current_process();
    unsafe {
        libc::_exit(128 + 15);
    }
}

pub fn ensure_signal_handlers() {
    #[cfg(unix)]
    HANDLERS.call_once(|| unsafe {
        let _ = signal_hook::low_level::register(libc::SIGTERM, || {
            on_sigterm(libc::SIGTERM);
        });
    });
}

#[cfg(unix)]
pub fn configure_session_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    ensure_signal_handlers();
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
pub fn configure_session_process_group(_cmd: &mut Command) {}

/// After portable-pty spawn: put the child in its own process group and track it.
pub fn register_pty_child_pid(pid: u32) {
    ensure_signal_handlers();
    let pgid = pid as i32;
    #[cfg(unix)]
    unsafe {
        if libc::setpgid(pgid, pgid) != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) && err.raw_os_error() != Some(libc::EACCES) {
                let _ = err;
            }
        }
    }
    register_pgid(pgid);
}

pub fn unregister_session_pid(pid: u32) {
    unregister_pgid(pid as i32);
}

pub fn terminate_session_pid(pid: u32) {
    let pgid = pid as i32;
    terminate_pgid(pgid);
    unregister_pgid(pgid);
}

pub struct SessionChildGuard {
    child: Option<Child>,
    pgid: i32,
    reaped: bool,
}

impl SessionChildGuard {
    pub fn spawn(mut cmd: Command) -> Result<Self> {
        configure_session_process_group(&mut cmd);
        let child = cmd
            .spawn()
            .map_err(|e| BrokreError::Runtime(format!("spawn: {e}")))?;
        let pgid = child.id() as i32;
        #[cfg(unix)]
        unsafe {
            if libc::setpgid(pgid, pgid) != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EPERM)
                    && err.raw_os_error() != Some(libc::EACCES)
                {
                    let _ = err;
                }
            }
        }
        register_pgid(pgid);
        Ok(Self {
            child: Some(child),
            pgid,
            reaped: false,
        })
    }

    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.as_mut()?.stderr.take()
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "session child missing"))?
            .try_wait()
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
        unregister_pgid(self.pgid);
    }

    pub fn wait(mut self) -> Result<ExitStatus> {
        let status = self
            .child
            .take()
            .ok_or_else(|| BrokreError::Runtime("session child missing".into()))?
            .wait()
            .map_err(BrokreError::Io)?;
        self.mark_reaped();
        Ok(status)
    }

    pub fn wait_with_output_timeout(
        mut self,
        timeout: Duration,
    ) -> std::result::Result<Output, SessionWaitError> {
        let stdout = self.take_stdout();
        let stderr = self.take_stderr();
        let out_h = stdout.map(|mut r| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = r.read_to_end(&mut buf);
                buf
            })
        });
        let err_h = stderr.map(|mut r| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = r.read_to_end(&mut buf);
                buf
            })
        });

        let deadline = Instant::now() + timeout;
        let status = loop {
            match self.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    terminate_pgid(self.pgid);
                    if let Some(child) = self.child.as_mut() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    self.mark_reaped();
                    let _ = out_h.map(|h| h.join());
                    let _ = err_h.map(|h| h.join());
                    return Err(SessionWaitError::TimedOut { after: timeout });
                }
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(SessionWaitError::Io(e)),
            }
        };

        self.mark_reaped();
        let stdout = out_h
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        let stderr = err_h
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for SessionChildGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        terminate_pgid(self.pgid);
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        unregister_pgid(self.pgid);
        self.reaped = true;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn session_guard_reaps_sleeping_child_on_drop() {
        let mut cmd = Command::new("sleep");
        cmd.arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = SessionChildGuard::spawn(cmd).unwrap();
        let pid = guard.pid().unwrap() as i32;
        drop(guard);
        std::thread::sleep(Duration::from_millis(200));
        unsafe {
            assert_eq!(libc::kill(pid, 0), -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        }
    }

    #[test]
    fn session_guard_reaps_sleep_and_grandchild_on_drop() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & exec sleep 30"]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let g = SessionChildGuard::spawn(cmd).unwrap();
        let pid = g.pid().unwrap() as i32;
        drop(g);
        std::thread::sleep(Duration::from_millis(200));
        unsafe {
            assert_eq!(libc::kill(pid, 0), -1);
        }
    }

    #[test]
    fn tracker_timeout_does_not_kill_sibling_scope() {
        let keep = SessionTracker::new();
        let kill = SessionTracker::new();
        let keep2 = keep.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            with_session_tracker(keep2, || {
                let mut cmd = Command::new("sleep");
                cmd.arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let g = SessionChildGuard::spawn(cmd).unwrap();
                let pid = g.pid().unwrap() as i32;
                tx.send(pid).unwrap();
                std::thread::sleep(Duration::from_millis(600));
                let alive = unsafe { libc::kill(pid, 0) == 0 };
                drop(g);
                alive
            })
        });
        let _keep_pid = rx.recv().unwrap();
        with_session_tracker(kill, || {
            let mut cmd = Command::new("sleep");
            cmd.arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let g = SessionChildGuard::spawn(cmd).unwrap();
            let _ = g.wait_with_output_timeout(Duration::from_millis(50));
        });
        let sibling_alive = h.join().unwrap();
        assert!(sibling_alive);
    }

    #[test]
    fn wait_with_output_timeout_kills_sleep() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let g = SessionChildGuard::spawn(cmd).unwrap();
        let pid = g.pid().unwrap() as i32;
        let err = g
            .wait_with_output_timeout(Duration::from_millis(80))
            .err()
            .expect("timeout");
        assert!(matches!(err, SessionWaitError::TimedOut { .. }));
        std::thread::sleep(Duration::from_millis(200));
        unsafe {
            assert_eq!(libc::kill(pid, 0), -1);
        }
    }
}
