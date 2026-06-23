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
///
/// `remote_trailing` is the remote command slice (argv after the connection target)
/// when known — used by MCP to pick PTY only for `sudo` / `su` one-shots.
pub fn should_use_pipe_mode(
    profile: &str,
    stdin_is_pipe: bool,
    remote_trailing: Option<&[String]>,
) -> bool {
    let bin = profile
        .rsplit('/')
        .next()
        .unwrap_or(profile)
        .to_ascii_lowercase();
    if matches!(bin.as_str(), "scp" | "sftp") {
        return true;
    }
    if bin == "ssh" {
        // Interactive bastion routes need a PTY end-to-end (`ssh -tt hop brokre ssh -tt inner`).
        if remote_trailing.is_some_and(crate::runtime::ssh_identity::is_routed_interactive_trailing)
        {
            return false;
        }
        // Remote sudo/su always needs a PTY for password injection — even when stdin
        // is a pipe (CI, IDE agents, scripts). MCP sets BROKRE_MCP_EXEC for the same rule.
        if remote_trailing.is_some_and(crate::runtime::ssh_identity::remote_command_needs_tty) {
            return false;
        }
        if std::env::var_os("BROKRE_MCP_EXEC").is_some() {
            return true;
        }
        return stdin_is_pipe;
    }
    false
}

/// Run OpenSSH with `SSH_ASKPASS` for vault injection and optional stdin pipe forwarding.
#[cfg(unix)]
pub fn run(binary: &str, args: &[String], record_id: Uuid) -> Result<PtyRunResult> {
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

    let bin = which::which(binary)
        .map_err(|_| BrokreError::Runtime(format!("{}: command not found", binary)))?;
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

/// Policy for bastion inner interactive login (TTY check applied separately).
pub fn routed_inner_inherited_ssh(
    profile: &str,
    routed_inner_passive: bool,
    trailing_empty: bool,
) -> bool {
    let bin = profile
        .rsplit('/')
        .next()
        .unwrap_or(profile)
        .to_ascii_lowercase();
    bin == "ssh" && routed_inner_passive && trailing_empty
}

/// Bastion inner hop (`BROKRE_ROUTED_INNER=1`): inherit the SSH session TTY instead of
/// wrapping OpenSSH in another PTY (breaks arrow keys / line editing).
#[cfg(unix)]
pub fn should_use_inherited_tty_mode(
    profile: &str,
    routed_inner_passive: bool,
    trailing_empty: bool,
) -> bool {
    routed_inner_inherited_ssh(profile, routed_inner_passive, trailing_empty)
        && crate::security::tty::stdin_is_real_tty()
}

#[cfg(unix)]
pub fn run_inherited_tty(binary: &str, args: &[String]) -> Result<PtyRunResult> {
    let bin = which::which(binary)
        .map_err(|_| BrokreError::Runtime(format!("{}: command not found", binary)))?;
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd
        .spawn()
        .map_err(|e| BrokreError::Runtime(format!("spawn {}: {}", binary, e)))?
        .wait()
        .map_err(BrokreError::Io)?;
    Ok(PtyRunResult {
        exit_code: status.code().unwrap_or(-1),
        captured_password: None,
        had_prompt: false,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
    })
}

#[cfg(not(unix))]
pub fn run_inherited_tty(_binary: &str, _args: &[String]) -> Result<PtyRunResult> {
    Err(BrokreError::Runtime(
        "inherited TTY mode is only supported on Unix".into(),
    ))
}

#[cfg(not(unix))]
pub fn should_use_inherited_tty_mode(
    _profile: &str,
    _routed_inner_passive: bool,
    _trailing_empty: bool,
) -> bool {
    false
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
    fn inherited_tty_for_routed_inner_interactive_ssh() {
        assert!(routed_inner_inherited_ssh("ssh", true, true));
        assert!(!routed_inner_inherited_ssh("ssh", false, true));
        assert!(!routed_inner_inherited_ssh("ssh", true, false));
        assert!(!routed_inner_inherited_ssh("mysql", true, true));
    }

    #[test]
    fn pipe_mode_for_scp_and_piped_ssh() {
        assert!(should_use_pipe_mode("scp", false, None));
        assert!(should_use_pipe_mode("sftp", false, None));
        assert!(should_use_pipe_mode("ssh", true, None));
        assert!(!should_use_pipe_mode("ssh", false, None));
        assert!(!should_use_pipe_mode("mysql", true, None));
    }

    #[test]
    fn mcp_exec_pipe_mode_for_normal_remote_command() {
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        assert!(should_use_pipe_mode("ssh", true, Some(&["uptime".into()]),));
        std::env::remove_var("BROKRE_MCP_EXEC");
    }

    #[test]
    fn mcp_exec_pty_mode_for_sudo_remote_command() {
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        assert!(!should_use_pipe_mode(
            "ssh",
            true,
            Some(&["sudo".into(), "whoami".into()]),
        ));
        std::env::remove_var("BROKRE_MCP_EXEC");
    }

    #[test]
    fn cli_sudo_forces_pty_even_when_stdin_is_pipe() {
        assert!(!should_use_pipe_mode(
            "ssh",
            true,
            Some(&["sudo".into(), "whoami".into()]),
        ));
    }

    #[test]
    fn cli_quoted_sudo_script_forces_pty_when_stdin_is_pipe() {
        assert!(!should_use_pipe_mode(
            "ssh",
            true,
            Some(&["sudo -i whoami".into()]),
        ));
    }
}
