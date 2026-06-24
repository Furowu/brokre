//! Fork/exec short-lived `brokre --internal-injector` to write a vault password to a PTY fd.

use crate::utils::errors::{BrokreError, Result};
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Instant;
use uuid::Uuid;

use crate::security::hardening;

/// Disable PTY echo while injecting so secrets are not reflected to the user terminal.
///
/// Only toggles the ECHO bit on the current termios — never restores a full stale snapshot,
/// which could leave the remote shell with echo permanently off after SSH adjusts termios.
#[cfg(unix)]
fn with_pty_echo_off<T>(fd: libc::c_int, f: impl FnOnce() -> Result<T>) -> Result<T> {
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return f();
        }
        term.c_lflag &= !libc::ECHO;
        let echo_off = libc::tcsetattr(fd, libc::TCSANOW, &term) == 0;
        let result = f();
        if echo_off {
            crate::runtime::pty_drain::ensure_pty_echo_on(fd);
            crate::runtime::pty_drain::drain_pty_master(fd);
        }
        result
    }
}

#[cfg(not(unix))]
fn with_pty_echo_off<T>(_fd: libc::c_int, f: impl FnOnce() -> Result<T>) -> Result<T> {
    f()
}

/// Spawn injector, write token to child's fd 4, wait for exit.
pub fn spawn_injector_child(
    record_id: Uuid,
    pty_master_raw: libc::c_int,
    field: &str,
) -> Result<(i32, u64, Option<u32>, String)> {
    if hardening::hardening_disabled_by_env() {
        return Err(BrokreError::Runtime(
            "BROKRE_DISABLE_HARDENING=1 — cannot inject password".into(),
        ));
    }

    let mut pipe_fds: [libc::c_int; 2] = [0, 0];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(BrokreError::Io(std::io::Error::last_os_error()));
    }
    let r_tok = pipe_fds[0];
    let w_tok = pipe_fds[1];

    let pty_dup = unsafe { libc::dup(pty_master_raw) };
    if pty_dup < 0 {
        unsafe {
            libc::close(r_tok);
            libc::close(w_tok);
        }
        return Err(BrokreError::Io(std::io::Error::last_os_error()));
    }
    let tok_dup = unsafe { libc::dup(r_tok) };
    if tok_dup < 0 {
        unsafe {
            libc::close(pty_dup);
            libc::close(r_tok);
            libc::close(w_tok);
        }
        return Err(BrokreError::Io(std::io::Error::last_os_error()));
    }
    unsafe {
        libc::close(r_tok);
    }

    let exe: std::path::PathBuf = std::env::var_os("BROKRE_INJECTOR_EXE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| BrokreError::Runtime("cannot resolve injector binary path".into()))?;
    let ppid = std::process::id();

    let mut cmd = Command::new(exe);
    cmd.arg("--internal-injector")
        .arg(record_id.to_string())
        .arg(ppid.to_string())
        .arg(field)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(pty_dup, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(tok_dup, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::close(pty_dup);
            libc::close(tok_dup);
            Ok(())
        });
    }

    let start = Instant::now();
    let (status, cid) = with_pty_echo_off(pty_master_raw, || {
        let mut child = cmd
            .spawn()
            .map_err(|e| BrokreError::Runtime(format!("injector spawn: {}", e)))?;
        let cid = child.id();

        unsafe {
            libc::close(pty_dup);
            libc::close(tok_dup);
        }

        let token = format!("{}\n", Uuid::new_v4());
        {
            let mut w = unsafe { std::fs::File::from_raw_fd(w_tok) };
            w.write_all(token.as_bytes()).map_err(BrokreError::Io)?;
            w.flush().map_err(BrokreError::Io)?;
        }

        let status = child.wait().map_err(BrokreError::Io)?;
        Ok((status, cid))
    })?;

    let dur_ms = start.elapsed().as_millis() as u64;
    let code = status.code().unwrap_or(-1);
    let outcome = if code == 0 {
        "ok".into()
    } else {
        format!("exit_{}", code)
    };
    Ok((code, dur_ms, Some(cid), outcome))
}
