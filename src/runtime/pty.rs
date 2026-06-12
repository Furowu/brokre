//! Transparent PTY pass-through with optional password capture / injection.
//!
//! Cross-platform implementation using portable-pty + crossterm.
//! On Unix, saved credentials use a short-lived `brokr --internal-injector` child
//! so the parent never holds decrypted passwords (T1 mitigation).

use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use crossterm::terminal;
use portable_pty::{CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use regex::bytes::Regex;
use std::io::{Read, Write};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::RawFd;

#[cfg(unix)]
use uuid::Uuid;

/// How to satisfy a password prompt for the wrapped CLI.
#[derive(Clone, Copy)]
pub enum PtyCredential<'a> {
    None,
    /// Decrypt in a short-lived child and write once to the PTY (Unix only).
    #[cfg(unix)]
    VaultRecord(Uuid),
    /// In-process injection (Windows always; Unix only with `--features in_proc_inject`).
    #[cfg(any(not(unix), feature = "in_proc_inject"))]
    Secret(&'a SecretString),
    /// Binds `'a` when Unix builds omit `Secret` (e.g. `--no-default-features`).
    #[cfg(all(unix, not(feature = "in_proc_inject")))]
    #[doc(hidden)]
    _Reserved(std::marker::PhantomData<&'a ()>),
}

impl<'a> PtyCredential<'a> {
    fn should_scan(&self, stdin_is_tty: bool) -> bool {
        let inject = match self {
            PtyCredential::None => false,
            #[cfg(unix)]
            PtyCredential::VaultRecord(_) => true,
            #[cfg(any(not(unix), feature = "in_proc_inject"))]
            PtyCredential::Secret(_) => true,
            #[cfg(all(unix, not(feature = "in_proc_inject")))]
            PtyCredential::_Reserved(_) => false,
        };
        inject || stdin_is_tty
    }

    fn preset_injection(&self) -> bool {
        match self {
            PtyCredential::None => false,
            #[cfg(unix)]
            PtyCredential::VaultRecord(_) => true,
            #[cfg(any(not(unix), feature = "in_proc_inject"))]
            PtyCredential::Secret(_) => true,
            #[cfg(all(unix, not(feature = "in_proc_inject")))]
            PtyCredential::_Reserved(_) => false,
        }
    }
}

/// After SSH prints a normal post-login banner, MOTD / help text may contain lines
/// that end with `password:` and would otherwise re-trigger the prompt scanner,
/// wiping an already-captured password buffer before `PtyRunResult` is assembled.
fn ssh_post_auth_indicated(buf: &[u8]) -> bool {
    contains_ascii_case_insensitive(buf, b"last login")
        || contains_ascii_case_insensitive(buf, b"welcome to ")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|win| {
        win.iter()
            .zip(needle_lower.iter())
            .all(|(b, n)| b.to_ascii_lowercase() == *n)
    })
}

/// Map PTY output to the vault field that should be injected.
fn field_for_prompt(window: &[u8], available: &[String]) -> Option<String> {
    if available.is_empty() {
        return None;
    }
    let lower = window
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect::<Vec<_>>();
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

#[derive(Default)]
pub struct PtyRunResult {
    pub exit_code: i32,
    pub captured_password: Option<SecretString>,
    pub had_prompt: bool,
    pub injector_pid: Option<u32>,
    pub injector_dur_ms: Option<u64>,
    pub injector_outcome: Option<String>,
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Self {
        let _ = terminal::enable_raw_mode();
        Self
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

pub fn run(
    binary: &str,
    args: &[String],
    cred: PtyCredential<'_>,
    prompt_patterns: &[Regex],
) -> Result<PtyRunResult> {
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| BrokrError::Runtime(format!("openpty: {}", e)))?;

    let master = pair.master;
    #[cfg(unix)]
    let master_raw_fd: Option<RawFd> = MasterPty::as_raw_fd(&*master);
    #[cfg(not(unix))]
    let master_raw_fd: Option<i32> = None;

    let mut cmd = CommandBuilder::new(binary);
    for a in args {
        cmd.arg(a);
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| BrokrError::Runtime(format!("spawn: {}", e)))?;

    drop(pair.slave);

    let mut reader = master
        .try_clone_reader()
        .map_err(|e| BrokrError::Runtime(format!("clone reader: {}", e)))?;
    let mut writer = master
        .take_writer()
        .map_err(|e| BrokrError::Runtime(format!("take writer: {}", e)))?;

    let stdin_is_tty = crate::security::tty::stdin_is_real_tty();
    let stdin_is_pipe = crate::security::tty::stdin_is_pipe();
    let _raw_guard = if stdin_is_tty {
        Some(RawModeGuard::enable())
    } else {
        None
    };

    // Shared state for password capture / injection.
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let pending_capture = Arc::new(AtomicBool::new(false));
    let pending_inject = Arc::new(AtomicBool::new(false));
    let had_prompt = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let inject_completed = Arc::new(AtomicBool::new(false));

    #[cfg(unix)]
    let inject_fields: Arc<Vec<String>> = match cred {
        PtyCredential::VaultRecord(id) => Arc::new(
            crate::vault::store::VaultStore::open()
                .ok()
                .and_then(|s| s.get_by_id(&id).ok().flatten())
                .map(|r| crate::runtime::ssh_identity::injectable_field_names(&r))
                .unwrap_or_else(|| vec!["password".into()]),
        ),
        _ => Arc::new(Vec::new()),
    };
    #[cfg(not(unix))]
    let inject_fields: Arc<Vec<String>> = Arc::new(Vec::new());

    let pending_field: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let injected_fields: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let inject_done_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let should_scan = cred.should_scan(stdin_is_tty);
    let preset_some = cred.preset_injection();

    // Gate stdin -> PTY forwarding so pipe data cannot arrive before password injection.
    let stdin_forward_enabled = Arc::new(AtomicBool::new(
        stdin_is_tty && !preset_some,
    ));
    let stdin_forward_a = stdin_forward_enabled.clone();

    let bin_base = binary
        .rsplit('/')
        .next()
        .unwrap_or(binary)
        .to_ascii_lowercase();
    let track_ssh_post_auth = matches!(bin_base.as_str(), "ssh" | "scp" | "sftp");

    // ---- thread A: PTY -> stdout + optional prompt scanner ----
    let patterns: Vec<Regex> = prompt_patterns.to_vec();
    let cap_a = captured.clone();
    let pending_cap_a = pending_capture.clone();
    let pending_inj_a = pending_inject.clone();
    let had_a = had_prompt.clone();
    let done_a = done.clone();
    let post_auth = Arc::new(AtomicBool::new(false));
    let post_auth_a = post_auth.clone();
    let inject_fields_a = inject_fields.clone();
    let pending_field_a = pending_field.clone();
    let injected_fields_a = injected_fields.clone();

    let scanner = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut window: Vec<u8> = Vec::with_capacity(2048);
        let stdout = std::io::stdout();
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = &buf[..n];
                    {
                        let mut out = stdout.lock();
                        let _ = out.write_all(data);
                        let _ = out.flush();
                    }

                    if should_scan {
                        window.extend_from_slice(data);
                        if window.len() > 4096 {
                            let drop_n = window.len() - 2048;
                            window.drain(..drop_n);
                        }

                        if track_ssh_post_auth
                            && !post_auth_a.load(Ordering::Acquire)
                            && ssh_post_auth_indicated(&window)
                        {
                            post_auth_a.store(true, Ordering::Release);
                            stdin_forward_a.store(true, Ordering::Release);
                        }

                        if !pending_cap_a.load(Ordering::Acquire)
                            && !pending_inj_a.load(Ordering::Acquire)
                        {
                            'prompt_scan: for re in &patterns {
                                if re.is_match(&window) {
                                    // Do not re-arm password capture after we're clearly past
                                    // SSH authentication — later "…password:" lines are usually MOTD.
                                    if !preset_some
                                        && track_ssh_post_auth
                                        && post_auth_a.load(Ordering::Acquire)
                                    {
                                        window.clear();
                                        break 'prompt_scan;
                                    }
                                    had_a.store(true, Ordering::Release);
                                    if preset_some {
                                        if let Some(field) =
                                            field_for_prompt(&window, &inject_fields_a)
                                        {
                                            let already = injected_fields_a
                                                .lock()
                                                .map(|g| g.contains(&field))
                                                .unwrap_or(true);
                                            if !already {
                                                if let Ok(mut pf) = pending_field_a.lock() {
                                                    *pf = Some(field);
                                                }
                                                pending_inj_a.store(true, Ordering::Release);
                                            }
                                        }
                                    } else {
                                        pending_cap_a.store(true, Ordering::Release);
                                        let mut g = cap_a.lock().unwrap();
                                        *g = Some(String::new());
                                    }
                                    window.clear();
                                    break 'prompt_scan;
                                }
                            }
                        }
                    }
                }
                Err(_e) => break,
            }
        }
        done_a.store(true, Ordering::Release);
    });

    // ---- thread B: handle password injection (vault subprocess or in-proc secret) ----
    let pending_inj_b = pending_inject.clone();
    let done_b = done.clone();
    #[cfg_attr(all(unix, not(feature = "in_proc_inject")), allow(unused_variables))]
    let (inject_tx, inject_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    let inject_meta: Arc<Mutex<Option<(u32, u64, String)>>> = Arc::new(Mutex::new(None));

    #[cfg(unix)]
    let vault_id: Option<Uuid> = match cred {
        PtyCredential::VaultRecord(id) => Some(id),
        PtyCredential::None => None,
        #[cfg(feature = "in_proc_inject")]
        PtyCredential::Secret(_) => None,
        #[cfg(all(unix, not(feature = "in_proc_inject")))]
        PtyCredential::_Reserved(_) => None,
    };

    #[cfg_attr(all(unix, not(feature = "in_proc_inject")), allow(unused_variables))]
    let preset_for_inj: Option<String> = match cred {
        PtyCredential::None => None,
        #[cfg(unix)]
        PtyCredential::VaultRecord(_) => None,
        #[cfg(any(not(unix), feature = "in_proc_inject"))]
        PtyCredential::Secret(s) => Some(s.expose().to_string()),
        #[cfg(all(unix, not(feature = "in_proc_inject")))]
        PtyCredential::_Reserved(_) => None,
    };

    let meta_for_thread = inject_meta.clone();
    let inject_completed_b = inject_completed.clone();
    let stdin_forward_b = stdin_forward_enabled.clone();
    let pending_field_b = pending_field.clone();
    let injected_fields_b = injected_fields.clone();
    let inject_fields_b = inject_fields.clone();
    let inject_done_count_b = inject_done_count.clone();
    let injector = thread::spawn(move || {
        while !done_b.load(Ordering::Acquire) {
            if pending_inj_b.swap(false, Ordering::AcqRel) {
                thread::sleep(Duration::from_millis(80));
                #[cfg(unix)]
                if let (Some(rid), Some(fd)) = (vault_id, master_raw_fd) {
                    let field = pending_field_b
                        .lock()
                        .ok()
                        .and_then(|mut g| g.take())
                        .unwrap_or_else(|| "password".into());
                    match crate::runtime::injector_child::spawn_injector_child(
                        rid, fd, &field,
                    ) {
                        Ok((code, dur, pid, out)) => {
                            if let Ok(mut g) = meta_for_thread.lock() {
                                *g = Some((pid.unwrap_or(0), dur, out.clone()));
                            }
                            if code == 0 {
                                if let Ok(mut g) = injected_fields_b.lock() {
                                    g.insert(field.clone());
                                }
                                let n =
                                    inject_done_count_b.fetch_add(1, Ordering::AcqRel) + 1;
                                if n >= inject_fields_b.len() {
                                    inject_completed_b.store(true, Ordering::Release);
                                }
                                stdin_forward_b.store(true, Ordering::Release);
                            } else {
                                let _ = std::io::stderr().write_all(
                                    format!("brokr: injector exited {} ({})\n", code, out)
                                        .as_bytes(),
                                );
                            }
                        }
                        Err(e) => {
                            let _ = std::io::stderr()
                                .write_all(format!("brokr: injector failed: {}\n", e).as_bytes());
                        }
                    }
                    continue;
                }

                #[cfg(any(not(unix), feature = "in_proc_inject"))]
                if let Some(ref pw) = preset_for_inj {
                    let mut payload = pw.as_bytes().to_vec();
                    payload.push(b'\r');
                    let _ = inject_tx.send(payload);
                    inject_completed_b.store(true, Ordering::Release);
                    stdin_forward_b.store(true, Ordering::Release);
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    // ---- thread C: stdin -> channel (TTY or pipe) ----
    const STDIN_CHANNEL_CAP: usize = 8;
    let pipe_eof = Arc::new(AtomicBool::new(false));
    let pipe_eof_sent = Arc::new(AtomicBool::new(false));
    let stdin_rx: Option<std::sync::mpsc::Receiver<Vec<u8>>> =
        if stdin_is_tty || stdin_is_pipe {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(STDIN_CHANNEL_CAP);
            let pipe_eof_reader = pipe_eof.clone();
            let stdin_is_pipe_reader = stdin_is_pipe;
            thread::spawn(move || {
                let mut buf = [0u8; 65536];
                loop {
                    match std::io::stdin().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                if stdin_is_pipe_reader {
                    pipe_eof_reader.store(true, Ordering::Release);
                }
            });
            Some(rx)
        } else {
            None
        };

    let cap_main = captured.clone();
    let pending_cap_main = pending_capture.clone();
    let stdin_forward_main = stdin_forward_enabled.clone();
    let post_auth_main = post_auth.clone();
    let spawn_instant = Instant::now();

    loop {
        while let Ok(payload) = inject_rx.try_recv() {
            let _ = writer.write_all(&payload);
            let _ = writer.flush();
        }

        // Open stdin forwarding once injection succeeded or SSH post-auth is visible.
        if !stdin_forward_main.load(Ordering::Acquire)
            && (inject_completed.load(Ordering::Acquire)
                || (preset_some && post_auth_main.load(Ordering::Acquire))
                || (!preset_some
                    && !pending_capture.load(Ordering::Acquire)
                    && !pending_inject.load(Ordering::Acquire)
                    && spawn_instant.elapsed() >= Duration::from_secs(1)))
        {
            stdin_forward_main.store(true, Ordering::Release);
        }

        if stdin_forward_main.load(Ordering::Acquire) {
            if let Some(ref rx) = stdin_rx {
                while let Ok(data) = rx.try_recv() {
                    if stdin_is_tty {
                        for &b in &data {
                            if pending_cap_main.load(Ordering::Acquire) {
                                if b == b'\r' || b == b'\n' {
                                    pending_cap_main.store(false, Ordering::Release);
                                } else if b == 0x7f || b == 0x08 {
                                    let mut g = cap_main.lock().unwrap();
                                    if let Some(s) = g.as_mut() {
                                        s.pop();
                                    }
                                } else if b >= 0x20 {
                                    let mut g = cap_main.lock().unwrap();
                                    if let Some(s) = g.as_mut() {
                                        s.push(b as char);
                                    }
                                }
                            }
                        }
                    }
                    let _ = writer.write_all(&data);
                    let _ = writer.flush();
                }
                // Pipe EOF: signal EOT to PTY so remote readers (cat, tar) terminate.
                if stdin_is_pipe
                    && pipe_eof.load(Ordering::Acquire)
                    && !pipe_eof_sent.load(Ordering::Acquire)
                    && matches!(
                        rx.try_recv(),
                        Err(std::sync::mpsc::TryRecvError::Disconnected)
                    )
                {
                    pipe_eof_sent.store(true, Ordering::Release);
                    let _ = writer.write_all(&[0x04]);
                    let _ = writer.flush();
                }
            }
        }

        match child.try_wait() {
            Ok(Some(_status)) => {
                let deadline = std::time::Instant::now() + Duration::from_millis(150);
                while !done.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    while let Ok(payload) = inject_rx.try_recv() {
                        let _ = writer.write_all(&payload);
                        let _ = writer.flush();
                    }
                    if stdin_forward_main.load(Ordering::Acquire) {
                        if let Some(ref rx) = stdin_rx {
                            while let Ok(data) = rx.try_recv() {
                                let _ = writer.write_all(&data);
                                let _ = writer.flush();
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }

        thread::sleep(Duration::from_millis(15));
    }

    let exit_status = child
        .wait()
        .map_err(|e| BrokrError::Runtime(format!("child wait: {}", e)))?;
    let exit_code = exit_status.exit_code() as i32;

    done.store(true, Ordering::Release);
    drop(master);
    // scanner thread may be stuck in a blocking read() after master is dropped;
    // don't wait forever — cap at 500 ms.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while !scanner.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let _ = injector.join();
    // stdin thread intentionally not joined — it may be blocked on stdin read.
    // The process (or test) will terminate and reap it.

    let captured_pw = captured.lock().unwrap().take().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(SecretString::new(s))
        }
    });
    let had = had_prompt.load(Ordering::Acquire);

    let (inj_pid, inj_dur, inj_out) = inject_meta
        .lock()
        .unwrap()
        .take()
        .map(|(p, d, o)| (Some(p), Some(d), Some(o)))
        .unwrap_or((None, None, None));

    Ok(PtyRunResult {
        exit_code,
        captured_password: captured_pw,
        had_prompt: had,
        injector_pid: inj_pid,
        injector_dur_ms: inj_dur,
        injector_outcome: inj_out,
    })
}

#[cfg(test)]
mod tests {
    use super::{contains_ascii_case_insensitive, ssh_post_auth_indicated};

    #[test]
    fn post_auth_detects_ubuntu_welcome() {
        assert!(ssh_post_auth_indicated(
            b" * Documentation:  https://help.ubuntu.com\nWelcome to Ubuntu 25.10 (GNU/Linux)\n"
        ));
    }

    #[test]
    fn post_auth_detects_last_login() {
        assert!(ssh_post_auth_indicated(
            b"Last login: Mon May 18 08:41:12 2026 from 198.51.100.1\n"
        ));
    }

    #[test]
    fn motd_line_ending_password_not_post_auth_alone() {
        let line = b"Configure your account password: ";
        assert!(!ssh_post_auth_indicated(line));
        assert!(contains_ascii_case_insensitive(line, b"password"));
    }
}
