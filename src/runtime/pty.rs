//! Transparent PTY pass-through with optional password capture / injection.
//!
//! Cross-platform implementation using portable-pty + crossterm.
//! No platform-specific syscalls (no forkpty/fcntl) — stdin is handled by a
//! dedicated thread that blocks on `std::io::stdin().read()` and forwards
//! bytes over a channel. This works identically on Linux, macOS, and Windows.

use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use crossterm::terminal;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use regex::bytes::Regex;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

#[derive(Default)]
pub struct PtyRunResult {
    pub exit_code: i32,
    pub captured_password: Option<SecretString>,
    pub had_prompt: bool,
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
    preset_password: Option<&SecretString>,
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

    let master = pair.master;
    let mut reader = master
        .try_clone_reader()
        .map_err(|e| BrokrError::Runtime(format!("clone reader: {}", e)))?;
    let mut writer = master
        .take_writer()
        .map_err(|e| BrokrError::Runtime(format!("take writer: {}", e)))?;

    let stdin_is_tty = crate::security::tty::stdin_is_real_tty();
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

    let should_scan = preset_password.is_some() || stdin_is_tty;

    let bin_base = binary
        .rsplit('/')
        .next()
        .unwrap_or(binary)
        .to_ascii_lowercase();
    let track_ssh_post_auth =
        matches!(bin_base.as_str(), "ssh" | "scp" | "sftp");

    // ---- thread A: PTY -> stdout + optional prompt scanner ----
    let patterns: Vec<Regex> = prompt_patterns.to_vec();
    let preset_some = preset_password.is_some();
    let cap_a = captured.clone();
    let pending_cap_a = pending_capture.clone();
    let pending_inj_a = pending_inject.clone();
    let had_a = had_prompt.clone();
    let done_a = done.clone();
    let post_auth = Arc::new(AtomicBool::new(false));
    let post_auth_a = post_auth.clone();

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

                        if track_ssh_post_auth && !post_auth_a.load(Ordering::Acquire) {
                            if ssh_post_auth_indicated(&window) {
                                post_auth_a.store(true, Ordering::Release);
                            }
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
                                        pending_inj_a.store(true, Ordering::Release);
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

    // ---- thread B: handle password injection ----
    let preset_for_inj: Option<String> = preset_password.map(|s| s.expose().to_string());
    let pending_inj_b = pending_inject.clone();
    let done_b = done.clone();
    let (inject_tx, inject_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    let injector = thread::spawn(move || {
        while !done_b.load(Ordering::Acquire) {
            if pending_inj_b.swap(false, Ordering::AcqRel) {
                if let Some(ref pw) = preset_for_inj {
                    thread::sleep(Duration::from_millis(80));
                    let mut payload = pw.as_bytes().to_vec();
                    payload.push(b'\r');
                    let _ = inject_tx.send(payload);
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    // ---- thread C: stdin -> PTY (only when stdin is a real TTY) ----
    let stdin_rx: Option<std::sync::mpsc::Receiver<Vec<u8>>> = if stdin_is_tty {
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
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
        });
        Some(rx)
    } else {
        None
    };

    let cap_main = captured.clone();
    let pending_cap_main = pending_capture.clone();

    loop {
        while let Ok(payload) = inject_rx.try_recv() {
            let _ = writer.write_all(&payload);
            let _ = writer.flush();
        }

        if let Some(ref rx) = stdin_rx {
            while let Ok(data) = rx.try_recv() {
                for &b in &data {
                    if pending_cap_main.load(Ordering::Acquire) {
                        if b == b'\r' || b == b'\n' {
                            pending_cap_main.store(false, Ordering::Release);
                        } else if b == 0x7f || b == 0x08 {
                            let mut g = cap_main.lock().unwrap();
                            if let Some(s) = g.as_mut() { s.pop(); }
                        } else if b >= 0x20 {
                            let mut g = cap_main.lock().unwrap();
                            if let Some(s) = g.as_mut() { s.push(b as char); }
                        }
                    }
                }
                let _ = writer.write_all(&data);
                let _ = writer.flush();
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
        if s.is_empty() { None } else { Some(SecretString::new(s)) }
    });
    let had = had_prompt.load(Ordering::Acquire);

    Ok(PtyRunResult {
        exit_code,
        captured_password: captured_pw,
        had_prompt: had,
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
