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
use std::time::Duration;
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
        // Interactive bastion routes: mux pre-auth (askpass) + inherited TTY (native multi-hop).
        if remote_trailing.is_some_and(crate::runtime::ssh_identity::is_routed_interactive_trailing)
        {
            return false;
        }
        // Outer hop of bastion::inner: Mac must watch the PTY stream and inject the inner
        // SSH login from the local vault. Pipe mode breaks nested inject and leaves commands
        // on the bastion host (same machine-id as the hop).
        if remote_trailing
            .is_some_and(crate::runtime::ssh_identity::is_routed_bastion_outer_trailing)
        {
            return false;
        }
        // Tunnel SessionRelay runs the inner brokre locally on the bastion. Non-interactive
        // commands can use ASKPASS pipe mode; only interactive/elevation paths need a PTY.
        if std::env::var_os("BROKRE_ROUTED_INNER").is_some()
            && std::env::var_os("BROKRE_TUNNEL_AGENT_INNER").is_some()
            && remote_trailing.is_some_and(|t| {
                !t.is_empty() && !crate::runtime::ssh_identity::remote_command_needs_tty(t)
            })
        {
            return true;
        }
        // Inner brokre on a bastion (`BROKRE_ROUTED_INNER=1`) is usually spawned headless from the
        // outer SSH remote command; it still needs vault/ASKPASS inject to reach the inner host.
        if std::env::var_os("BROKRE_ROUTED_INNER").is_some() {
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
fn configure_askpass(cmd: &mut Command, record_id: Uuid) -> Result<std::path::PathBuf> {
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
    cmd.env("SSH_ASKPASS", &exe);
    cmd.env("SSH_ASKPASS_REQUIRE", "force");
    cmd.env("DISPLAY", ":0");
    cmd.env("BROKRE_INTERNAL_ASKPASS", "1");
    cmd.env("BROKRE_ASKPASS_RECORD_ID", record_id.to_string());
    cmd.env("BROKRE_ASKPASS_TOKEN", &token);
    cmd.env("BROKRE_ASKPASS_STATE", &state_path);
    cmd.env("BROKRE_ASKPASS_OWNER", &owner_pid);
    Ok(state_path)
}

/// Run OpenSSH with `SSH_ASKPASS` for vault injection and optional stdin pipe forwarding.
#[cfg(unix)]
pub fn run(binary: &str, args: &[String], record_id: Uuid) -> Result<PtyRunResult> {
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

    let state_path = configure_askpass(&mut cmd, record_id)?;

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

/// Policy for Mac-side interactive bastion routes (TTY check applied separately).
pub fn routed_interactive_native_tty(profile: &str, remote_trailing: Option<&[String]>) -> bool {
    let bin = profile
        .rsplit('/')
        .next()
        .unwrap_or(profile)
        .to_ascii_lowercase();
    bin == "ssh"
        && std::env::var_os("BROKRE_ROUTED_INNER").is_none()
        && remote_trailing.is_some_and(crate::runtime::ssh_identity::is_routed_interactive_trailing)
}

/// Interactive `bastion::inner` on the Mac: mux pre-auth + inherited TTY (same as native `ssh` multi-hop).
#[cfg(unix)]
pub fn should_use_mux_inherited_tty_mode(
    profile: &str,
    remote_trailing: Option<&[String]>,
) -> bool {
    routed_interactive_native_tty(profile, remote_trailing)
        && crate::security::tty::stdin_is_real_tty()
}

/// Askpass mux master, then run OpenSSH on the real terminal (no local PTY wrapper).
#[cfg(unix)]
pub fn run_interactive_routed_mux_tty(
    binary: &str,
    args: &[String],
    record_id: Uuid,
    prompt_patterns: &[regex::bytes::Regex],
) -> Result<PtyRunResult> {
    ensure_ssh_mux_master(binary, args, record_id, prompt_patterns)?;
    let master_argv = crate::runtime::ssh_identity::build_mux_master_argv(args);
    if !crate::runtime::ssh_identity::wait_mux_master_alive(binary, &master_argv, Duration::ZERO)? {
        return Err(BrokreError::Runtime(
            "ssh multiplex master unavailable after pre-authentication".into(),
        ));
    }
    let session_argv = crate::runtime::ssh_identity::build_mux_session_argv(args);
    let mut result = run_inherited_tty(binary, &session_argv)?;
    result.had_prompt = true;
    result.injector_outcome = Some("mux+inherited".into());
    Ok(result)
}

/// Establish mux master: short PTY inject for outer-hop auth, then inherited TTY for the session.
#[cfg(unix)]
fn ensure_ssh_mux_master(
    binary: &str,
    argv: &[String],
    record_id: Uuid,
    prompt_patterns: &[regex::bytes::Regex],
) -> Result<()> {
    use crate::runtime::pty::{run as pty_run, PtyCredential, PtyRunOptions};

    let master_argv = crate::runtime::ssh_identity::build_mux_master_argv(argv);
    if crate::runtime::ssh_identity::wait_mux_master_alive(binary, &master_argv, Duration::ZERO)? {
        return Ok(());
    }
    let preflight_opts = PtyRunOptions {
        skip_interactive_raw: true,
        ..PtyRunOptions::default()
    };
    for attempt in 0..2 {
        crate::runtime::ssh_identity::prune_stale_mux_sockets(binary, &master_argv)?;
        let result = pty_run(
            binary,
            &master_argv,
            PtyCredential::VaultRecord(record_id),
            prompt_patterns,
            preflight_opts.clone(),
        )?;
        if crate::runtime::ssh_identity::wait_mux_master_alive(
            binary,
            &master_argv,
            Duration::from_secs(3),
        )? {
            return Ok(());
        }
        if attempt == 1 {
            return Err(BrokreError::Runtime(format!(
                "ssh multiplex pre-authentication failed (exit {})",
                result.exit_code
            )));
        }
    }
    Ok(())
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
pub fn should_use_mux_inherited_tty_mode(
    _profile: &str,
    _remote_trailing: Option<&[String]>,
) -> bool {
    false
}

#[cfg(not(unix))]
pub fn run_interactive_routed_mux_tty(
    _binary: &str,
    _args: &[String],
    _record_id: Uuid,
    _prompt_patterns: &[regex::bytes::Regex],
) -> Result<PtyRunResult> {
    Err(BrokreError::Runtime(
        "mux inherited TTY mode is only supported on Unix".into(),
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
    fn routed_interactive_native_tty_policy() {
        std::env::remove_var("BROKRE_ROUTED_INNER");
        let token = crate::utils::paths::remote_brokre_shell_token().to_string();
        let trailing = vec![token, "ssh".into(), "-tt".into(), "db".into()];
        assert!(routed_interactive_native_tty("ssh", Some(&trailing)));
        assert!(!routed_interactive_native_tty(
            "ssh",
            Some(&["uptime".into()])
        ));
    }

    #[test]
    fn inherited_tty_for_routed_inner_interactive_ssh() {
        assert!(routed_inner_inherited_ssh("ssh", true, true));
        assert!(!routed_inner_inherited_ssh("ssh", false, true));
        assert!(!routed_inner_inherited_ssh("ssh", true, false));
        assert!(!routed_inner_inherited_ssh("mysql", true, true));
    }

    #[test]
    fn pipe_mode_for_scp_and_piped_ssh() {
        std::env::remove_var("BROKRE_ROUTED_INNER");
        std::env::remove_var("BROKRE_MCP_EXEC");
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
    fn mcp_exec_pty_mode_for_routed_bastion_outer_hop() {
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        let token = crate::utils::paths::remote_brokre_shell_token().to_string();
        let trailing = vec![
            token,
            "ssh".into(),
            "db".into(),
            "sh".into(),
            "-c".into(),
            "hostname".into(),
        ];
        assert!(!should_use_pipe_mode("ssh", true, Some(&trailing)));
        std::env::remove_var("BROKRE_MCP_EXEC");
    }

    #[test]
    fn mcp_exec_pipe_mode_for_manual_remote_ssh_chain() {
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        std::env::remove_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV);
        let trailing = vec![
            "ssh".into(),
            "-tt".into(),
            "root@10.0.0.195".into(),
            "hostname".into(),
        ];
        assert!(should_use_pipe_mode("ssh", true, Some(&trailing)));
        std::env::remove_var("BROKRE_MCP_EXEC");
    }

    #[test]
    fn mcp_exec_pty_mode_for_routed_direct_inner() {
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        std::env::set_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV, "db");
        let trailing = vec![
            "ssh".into(),
            "-tt".into(),
            "root@10.0.0.195".into(),
            "hostname".into(),
        ];
        assert!(!should_use_pipe_mode("ssh", true, Some(&trailing)));
        std::env::remove_var("BROKRE_MCP_EXEC");
        std::env::remove_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV);
    }

    #[test]
    fn routed_inner_forces_pty_even_when_stdin_is_pipe() {
        std::env::set_var("BROKRE_ROUTED_INNER", "1");
        assert!(!should_use_pipe_mode(
            "ssh",
            true,
            Some(&["hostname".into()])
        ));
        std::env::remove_var("BROKRE_ROUTED_INNER");
    }

    #[test]
    fn tunnel_agent_inner_noninteractive_uses_pipe_mode() {
        std::env::set_var("BROKRE_ROUTED_INNER", "1");
        std::env::set_var("BROKRE_TUNNEL_AGENT_INNER", "1");
        assert!(should_use_pipe_mode(
            "ssh",
            false,
            Some(&["hostname".into()])
        ));
        assert!(!should_use_pipe_mode(
            "ssh",
            false,
            Some(&["sudo".into(), "whoami".into()])
        ));
        std::env::remove_var("BROKRE_ROUTED_INNER");
        std::env::remove_var("BROKRE_TUNNEL_AGENT_INNER");
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
