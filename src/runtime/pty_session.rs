//! Long-lived PTY session for MCP elevated shell reuse (Unix).

use crate::runtime::prompts::{
    is_remote_su_password_prompt, is_remote_sudo_password_prompt, patterns_for,
};
use crate::runtime::session_markers;
use crate::utils::errors::{BrokreError, Result};
use portable_pty::{CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use regex::bytes::Regex;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::RawFd;

use uuid::Uuid;

fn tail_snapshot(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    s[s.len().saturating_sub(max)..].to_string()
}

fn field_for_prompt(window: &[u8], available: &[String]) -> Option<String> {
    if available.is_empty() {
        return None;
    }
    let lower: Vec<u8> = window.iter().map(|b| b.to_ascii_lowercase()).collect();
    let text = String::from_utf8_lossy(&lower);
    if text.contains("passphrase") && available.iter().any(|f| f == "key_passphrase") {
        return Some("key_passphrase".into());
    }
    if text.contains("password") && available.iter().any(|f| f == "password") {
        return Some("password".into());
    }
    if available.len() == 1 {
        return Some(available[0].clone());
    }
    None
}

fn ssh_post_auth_indicated(buf: &[u8]) -> bool {
    let lower: Vec<u8> = buf.iter().map(|b| b.to_ascii_lowercase()).collect();
    let text = String::from_utf8_lossy(&lower);
    text.contains("last login") || text.contains("welcome to ")
}

pub const SESSION_PTY_COLS: u16 = 1024;
pub const SESSION_PTY_ROWS: u16 = 24;

pub struct PtySession {
    _master: Box<dyn MasterPty + Send>,
    #[cfg(unix)]
    master_fd: RawFd,
    writer: Mutex<Box<dyn Write + Send>>,
    output: Arc<Mutex<String>>,
    child_alive: Arc<AtomicBool>,
    #[allow(dead_code)]
    reader_thread: Option<thread::JoinHandle<()>>,
    #[allow(dead_code)]
    injector_thread: Option<thread::JoinHandle<()>>,
}

impl PtySession {
    /// Spawn `binary` with vault password injection; output accumulates in memory (not stdout).
    #[cfg(unix)]
    pub fn spawn_ssh(
        record_id: Uuid,
        binary: &str,
        args: &[String],
        expect_su: bool,
    ) -> Result<Self> {
        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: SESSION_PTY_ROWS,
                cols: SESSION_PTY_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| BrokreError::Runtime(format!("openpty: {}", e)))?;

        let master = pair.master;
        let master_raw_fd: RawFd = MasterPty::as_raw_fd(&*master)
            .ok_or_else(|| BrokreError::Runtime("pty session: no master fd".into()))?;

        let mut cmd = CommandBuilder::new(binary);
        for a in args {
            cmd.arg(a);
        }
        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| BrokreError::Runtime(format!("spawn: {}", e)))?;
        drop(pair.slave);

        let output = Arc::new(Mutex::new(String::new()));
        let child_alive = Arc::new(AtomicBool::new(true));
        let done = Arc::new(AtomicBool::new(false));

        let mut reader = master
            .try_clone_reader()
            .map_err(|e| BrokreError::Runtime(format!("clone reader: {}", e)))?;
        let writer = master
            .take_writer()
            .map_err(|e| BrokreError::Runtime(format!("take writer: {}", e)))?;

        let inject_fields: Arc<Vec<String>> = Arc::new(
            crate::vault::store::VaultStore::open()
                .ok()
                .and_then(|s| s.get_by_id(&record_id).ok().flatten())
                .map(|r| crate::runtime::ssh_identity::injectable_field_names(&r))
                .unwrap_or_else(|| vec!["password".into()]),
        );

        let patterns: Vec<Regex> = patterns_for("ssh");
        let pending_inject = Arc::new(AtomicBool::new(false));
        let pending_field: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let injected_fields: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let inject_done_count = Arc::new(AtomicUsize::new(0));
        let inject_completed = Arc::new(AtomicBool::new(false));
        let post_auth = Arc::new(AtomicBool::new(false));

        let output_reader = output.clone();
        let done_reader = done.clone();
        let child_alive_reader = child_alive.clone();
        let reader_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = String::from_utf8_lossy(&buf[..n]);
                        if let Ok(mut g) = output_reader.lock() {
                            g.push_str(&chunk);
                        }
                    }
                    Err(_) => break,
                }
            }
            done_reader.store(true, Ordering::Release);
            child_alive_reader.store(false, Ordering::Release);
        });

        let pending_inj = pending_inject.clone();
        let done_inj = done.clone();
        let pending_field_inj = pending_field.clone();
        let injected_fields_inj = injected_fields.clone();
        let inject_fields_inj = inject_fields.clone();
        let inject_done_count_inj = inject_done_count.clone();
        let inject_completed_inj = inject_completed.clone();
        let output_inj = output.clone();
        let post_auth_inj = post_auth.clone();

        let injector_thread = thread::spawn(move || {
            while !done_inj.load(Ordering::Acquire) {
                if pending_inj.swap(false, Ordering::AcqRel) {
                    thread::sleep(Duration::from_millis(80));
                    let field = pending_field_inj
                        .lock()
                        .ok()
                        .and_then(|mut g| g.take())
                        .unwrap_or_else(|| "password".into());
                    if let Ok((0, _, _, _)) = crate::runtime::injector_child::spawn_injector_child(
                        record_id,
                        master_raw_fd,
                        &field,
                    ) {
                        if let Ok(mut g) = injected_fields_inj.lock() {
                            g.insert(field);
                        }
                        let n = inject_done_count_inj.fetch_add(1, Ordering::AcqRel) + 1;
                        if n >= inject_fields_inj.len() {
                            inject_completed_inj.store(true, Ordering::Release);
                        }
                    }
                }

                if let Ok(g) = output_inj.lock() {
                    let window = g.as_bytes();
                    if !post_auth_inj.load(Ordering::Acquire) && ssh_post_auth_indicated(window) {
                        post_auth_inj.store(true, Ordering::Release);
                    }

                    if !pending_inj.load(Ordering::Acquire) {
                        for re in &patterns {
                            if re.is_match(window) {
                                let is_sudo = is_remote_sudo_password_prompt(window);
                                let is_su = expect_su && is_remote_su_password_prompt(window);
                                let is_elevation = is_sudo || is_su;
                                if let Some(field) = field_for_prompt(window, &inject_fields_inj) {
                                    let already = injected_fields_inj
                                        .lock()
                                        .map(|g| g.contains(&field))
                                        .unwrap_or(true);
                                    let allow_reinject =
                                        already && field == "password" && is_elevation;
                                    if !already || allow_reinject {
                                        if let Ok(mut pf) = pending_field_inj.lock() {
                                            *pf = Some(field);
                                        }
                                        pending_inj.store(true, Ordering::Release);
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                thread::sleep(Duration::from_millis(25));
            }
        });

        // Reap child in background
        let child_alive_reap = child_alive.clone();
        thread::spawn(move || {
            let _ = child.wait();
            child_alive_reap.store(false, Ordering::Release);
            done.store(true, Ordering::Release);
        });

        Ok(Self {
            _master: master,
            master_fd: master_raw_fd,
            writer: Mutex::new(writer),
            output,
            child_alive,
            reader_thread: Some(reader_thread),
            injector_thread: Some(injector_thread),
        })
    }

    #[cfg(not(unix))]
    pub fn spawn_ssh(
        _record_id: Uuid,
        _binary: &str,
        _args: &[String],
        _expect_su: bool,
    ) -> Result<Self> {
        Err(BrokreError::Runtime(
            "persistent PTY sessions require Unix".into(),
        ))
    }

    pub fn is_alive(&self) -> bool {
        self.child_alive.load(Ordering::Acquire)
    }

    /// Disable local PTY echo after password injection / READY.
    pub fn set_echo_off(&self) {
        #[cfg(unix)]
        crate::runtime::pty_drain::ensure_pty_echo_off(self.master_fd);
    }

    pub fn output_snapshot(&self) -> String {
        self.output.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn clear_output(&self) {
        if let Ok(mut g) = self.output.lock() {
            g.clear();
        }
    }

    pub fn write_line(&self, line: &str) -> Result<()> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| BrokreError::Runtime("pty writer lock poisoned".into()))?;
        w.write_all(line.as_bytes())
            .map_err(|e| BrokreError::Runtime(format!("pty write: {}", e)))?;
        if !line.ends_with('\n') {
            w.write_all(b"\n")
                .map_err(|e| BrokreError::Runtime(format!("pty write: {}", e)))?;
        }
        w.flush()
            .map_err(|e| BrokreError::Runtime(format!("pty flush: {}", e)))
    }

    pub fn wait_for_substring(&self, needle: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !self.is_alive() {
                return Err(BrokreError::Runtime(
                    "pty session child exited during bootstrap".into(),
                ));
            }
            if self.output_snapshot().contains(needle) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(BrokreError::Runtime(format!(
            "pty session timed out waiting for {:?}; tail: {:?}",
            needle,
            tail_snapshot(self.output_snapshot(), 800)
        )))
    }

    pub fn run_command(&self, command: &str, timeout: Duration) -> Result<(String, i32)> {
        self.clear_output();
        let wrapped = session_markers::wrap_command(command);
        self.write_line(&wrapped.line)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !self.is_alive() {
                return Err(BrokreError::Runtime(
                    "pty session child exited during command".into(),
                ));
            }
            let snap = self.output_snapshot();
            if let Some((stdout, code)) = wrapped.parse(&snap) {
                return Ok((stdout, code));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(BrokreError::Runtime(format!(
            "command timed out after {}s",
            timeout.as_secs()
        )))
    }

    pub fn kill(&mut self) {
        self.child_alive.store(false, Ordering::Release);
        let _ = self.write_line("exit");
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_pty_is_wide_enough_to_avoid_wrap() {
        assert!(SESSION_PTY_COLS >= 1024);
        assert_eq!(SESSION_PTY_ROWS, 24);
    }
}
