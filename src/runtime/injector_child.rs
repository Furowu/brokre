//! Fork/exec short-lived `brokr --internal-injector` to write a vault password to a PTY fd.

use crate::utils::errors::{BrokrError, Result};
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Instant;
use uuid::Uuid;

use crate::security::hardening;

/// Spawn injector, write token to child's fd 4, wait for exit.
pub fn spawn_injector_child(
    record_id: Uuid,
    pty_master_raw: libc::c_int,
    field: &str,
) -> Result<(i32, u64, Option<u32>, String)> {
    if hardening::hardening_disabled_by_env() {
        return Err(BrokrError::Runtime(
            "BROKR_DISABLE_HARDENING=1 — cannot inject password".into(),
        ));
    }

    let mut pipe_fds: [libc::c_int; 2] = [0, 0];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(BrokrError::Io(std::io::Error::last_os_error()));
    }
    let r_tok = pipe_fds[0];
    let w_tok = pipe_fds[1];

    let pty_dup = unsafe { libc::dup(pty_master_raw) };
    if pty_dup < 0 {
        unsafe {
            libc::close(r_tok);
            libc::close(w_tok);
        }
        return Err(BrokrError::Io(std::io::Error::last_os_error()));
    }
    let tok_dup = unsafe { libc::dup(r_tok) };
    if tok_dup < 0 {
        unsafe {
            libc::close(pty_dup);
            libc::close(r_tok);
            libc::close(w_tok);
        }
        return Err(BrokrError::Io(std::io::Error::last_os_error()));
    }
    unsafe {
        libc::close(r_tok);
    }

    let exe: std::path::PathBuf = std::env::var_os("BROKR_INJECTOR_EXE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| BrokrError::Runtime("cannot resolve injector binary path".into()))?;
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
    let mut child = cmd
        .spawn()
        .map_err(|e| BrokrError::Runtime(format!("injector spawn: {}", e)))?;
    let cid = child.id();

    unsafe {
        libc::close(pty_dup);
        libc::close(tok_dup);
    }

    let token = format!("{}\n", Uuid::new_v4());
    {
        let mut w = unsafe { std::fs::File::from_raw_fd(w_tok) };
        w.write_all(token.as_bytes())
            .map_err(BrokrError::Io)?;
        w.flush().map_err(BrokrError::Io)?;
    }

    let status = child.wait().map_err(BrokrError::Io)?;
    let dur_ms = start.elapsed().as_millis() as u64;
    let code = status.code().unwrap_or(-1);
    let outcome = if code == 0 {
        "ok".into()
    } else {
        format!("exit_{}", code)
    };
    Ok((code, dur_ms, Some(cid), outcome))
}
