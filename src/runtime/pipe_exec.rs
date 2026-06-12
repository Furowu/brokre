//! Binary-safe OpenSSH execution without a PTY.
//!
//! `scp` and `ssh … < file` must not use a pseudo-terminal: PTY line discipline
//! corrupts binary streams and echoes payload bytes to the terminal.

use crate::runtime::pty::PtyRunResult;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use uuid::Uuid;

/// True when the CLI must run without a PTY (pipe-safe).
pub fn should_use_pipe_mode(profile: &str, stdin_is_pipe: bool) -> bool {
    let bin = profile.rsplit('/').next().unwrap_or(profile).to_ascii_lowercase();
    if matches!(bin.as_str(), "scp" | "sftp") {
        return true;
    }
    stdin_is_pipe && bin == "ssh"
}

/// Run OpenSSH with `SSH_ASKPASS` for vault injection and optional stdin pipe forwarding.
#[cfg(unix)]
pub fn run(
    binary: &str,
    args: &[String],
    record_id: Uuid,
) -> Result<PtyRunResult> {
    if std::env::var_os("BROKRE_DISABLE_HARDENING").is_some() {
        return Err(BrokreError::Runtime(
            "BROKRE_DISABLE_HARDENING=1 — cannot inject password in pipe mode".into(),
        ));
    }

    let exe = std::env::var_os("BROKRE_INJECTOR_EXE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| BrokreError::Runtime("cannot resolve brokre binary path".into()))?;

    let token = Uuid::new_v4().to_string();
    let state_path = run_dir().join(format!("askpass_{}_{}", record_id, token));
    std::fs::write(&state_path, "0").map_err(BrokreError::Io)?;

    let owner_pid = std::process::id().to_string();
    let stdin_is_pipe = crate::security::tty::stdin_is_pipe();

    let bin = which::which(binary).map_err(|_| {
        BrokreError::Runtime(format!("{}: command not found", binary))
    })?;
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.current_dir(cwd);
    }

    cmd.env("SSH_ASKPASS", &exe);
    cmd.env("SSH_ASKPASS_REQUIRE", "force");
    cmd.env("DISPLAY", ":0");
    cmd.env("BROKRE_INTERNAL_ASKPASS", "1");
    cmd.env("BROKRE_ASKPASS_RECORD_ID", record_id.to_string());
    cmd.env("BROKRE_ASKPASS_TOKEN", &token);
    cmd.env("BROKRE_ASKPASS_STATE", &state_path);
    cmd.env("BROKRE_ASKPASS_OWNER", &owner_pid);

    if stdin_is_pipe {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| BrokreError::Runtime(format!("spawn {}: {}", binary, e)))?;

    if stdin_is_pipe {
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| BrokreError::Runtime("child stdin missing".into()))?;
        thread::spawn(move || {
            let mut src = std::io::stdin();
            let mut buf = [0u8; 65536];
            loop {
                match src.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if child_stdin.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = child_stdin.flush();
        });
    }

    let status = child.wait().map_err(BrokreError::Io)?;
    let _ = std::fs::remove_file(&state_path);

    Ok(PtyRunResult {
        exit_code: status.code().unwrap_or(-1),
        captured_password: None,
        had_prompt: true,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: Some("askpass".into()),
    })
}

#[cfg(not(unix))]
pub fn run(_binary: &str, _args: &[String], _record_id: Uuid) -> Result<PtyRunResult> {
    Err(BrokreError::Runtime(
        "pipe mode is only supported on Unix".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_mode_for_scp_and_piped_ssh() {
        assert!(should_use_pipe_mode("scp", false));
        assert!(should_use_pipe_mode("sftp", false));
        assert!(should_use_pipe_mode("ssh", true));
        assert!(!should_use_pipe_mode("ssh", false));
        assert!(!should_use_pipe_mode("mysql", true));
    }
}
