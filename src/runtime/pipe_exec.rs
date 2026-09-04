//! Binary-safe OpenSSH execution without a PTY.
//!
//! `scp` and `ssh … < file` must not use a pseudo-terminal: PTY line discipline
//! corrupts binary streams and echoes payload bytes to the terminal.

use crate::runtime::child_guard::SessionChildGuard;
use crate::runtime::pty::PtyRunResult;
use crate::runtime::ssh_identity::{BrokreSshStdinFlags, should_disconnect_stdin};
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// True when the CLI must run without a PTY (pipe-safe).
///
/// `remote_trailing` is the remote command slice (argv after the connection target)
/// when known — used by MCP to pick PTY only for `sudo` / `su` one-shots.
pub fn should_use_pipe_mode(
    profile: &str,
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
        // Non-interactive remote commands: pipe mode (ASKPASS, no PTY stdout suppression).
        if remote_trailing.is_some_and(|t| {
            !t.is_empty() && !crate::runtime::ssh_identity::remote_command_needs_tty(t)
        }) {
            return true;
        }
        if std::env::var_os("BROKRE_MCP_EXEC").is_some() {
            return true;
        }
        return crate::security::tty::stdin_should_forward_to_child();
    }
    false
}

#[cfg(unix)]
pub(crate) struct AskpassGuard {
    state_path: PathBuf,
    owner_path: PathBuf,
}

#[cfg(unix)]
impl Drop for AskpassGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.state_path);
        let _ = std::fs::remove_file(&self.owner_path);
    }
}

/// Run OpenSSH with `SSH_ASKPASS` for vault injection and optional stdin pipe forwarding.
#[cfg(unix)]
fn configure_askpass(cmd: &mut Command, record_id: Uuid) -> Result<AskpassGuard> {
    if std::env::var_os("BROKRE_DISABLE_HARDENING").is_some() {
        return Err(BrokreError::Runtime(
            "BROKRE_DISABLE_HARDENING=1 — cannot inject password in pipe mode".into(),
        ));
    }

    let exe = std::env::var_os("BROKRE_INJECTOR_EXE")
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| BrokreError::Runtime("cannot resolve brokre binary path".into()))?;

    let token = Uuid::new_v4().to_string();
    let state_path = run_dir().join(format!("askpass_{}_{}", record_id, token));
    std::fs::write(&state_path, "0").map_err(BrokreError::Io)?;
    let owner_path = state_path.with_extension("owner");
    std::fs::write(&owner_path, std::process::id().to_string()).map_err(BrokreError::Io)?;

    let owner_pid = std::process::id().to_string();
    cmd.env("SSH_ASKPASS", &exe);
    cmd.env("SSH_ASKPASS_REQUIRE", "force");
    cmd.env("DISPLAY", ":0");
    cmd.env("BROKRE_INTERNAL_ASKPASS", "1");
    cmd.env("BROKRE_ASKPASS_RECORD_ID", record_id.to_string());
    cmd.env("BROKRE_ASKPASS_TOKEN", &token);
    cmd.env("BROKRE_ASKPASS_STATE", &state_path);
    cmd.env("BROKRE_ASKPASS_OWNER", &owner_pid);
    Ok(AskpassGuard {
        state_path,
        owner_path,
    })
}

#[cfg(unix)]
#[allow(dead_code)] // used by ssh_pool daemon when that module is wired
pub(crate) fn configure_askpass_for_command(
    cmd: &mut Command,
    record_id: Uuid,
) -> Result<AskpassGuard> {
    configure_askpass(cmd, record_id)
}

fn owner_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if pid == 0 {
            return false;
        }
        unsafe {
            if libc::kill(pid as i32, 0) == 0 {
                return true;
            }
            io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

fn askpass_mtime_older_than(path: &Path, age: Duration) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|d| d > age)
        .unwrap_or(false)
}

/// Remove askpass state files whose owner process is dead (or unowned files older than 24h).
pub fn prune_stale_askpass_files() {
    let dir = run_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("askpass_") || name.ends_with(".owner") {
            continue;
        }
        let owner_path = path.with_extension("owner");
        if owner_path.is_file() {
            let dead = std::fs::read_to_string(&owner_path)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .map(|pid| !owner_pid_alive(pid))
                .unwrap_or(true);
            if dead {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(&owner_path);
            }
            continue;
        }
        if askpass_mtime_older_than(&path, Duration::from_secs(24 * 3600)) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Run OpenSSH with `SSH_ASKPASS` for vault injection and optional stdin forwarding.
#[cfg(unix)]
pub fn run(
    profile: &str,
    binary: &str,
    args: &[String],
    record_id: Uuid,
    remote_trailing: Option<&[String]>,
    brokre_flags: &BrokreSshStdinFlags,
) -> Result<PtyRunResult> {
    let disconnect = should_disconnect_stdin(profile, args, remote_trailing, brokre_flags);
    let result = run_once(binary, args, record_id, disconnect)?;
    if result.exit_code != 0 && scp_legacy_mode_requested(binary, args) {
        let retry_args = scp_args_without_legacy_mode(args);
        return run_once(binary, &retry_args, record_id, disconnect);
    }
    Ok(result)
}

#[cfg(unix)]
fn run_once(
    binary: &str,
    args: &[String],
    record_id: Uuid,
    disconnect_stdin: bool,
) -> Result<PtyRunResult> {
    let bin = which::which(binary)
        .map_err(|_| BrokreError::Runtime(format!("{}: command not found", binary)))?;
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(a);
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.current_dir(cwd);
    }

    let _askpass = configure_askpass(&mut cmd, record_id)?;

    if disconnect_stdin {
        cmd.stdin(Stdio::null());
    } else {
        cmd.stdin(Stdio::inherit());
    }
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let guard = SessionChildGuard::spawn(cmd)?;
    let status = guard.wait()?;
    drop(_askpass);

    Ok(PtyRunResult {
        exit_code: status.code().unwrap_or(-1),
        captured_password: None,
        had_prompt: true,
        ssh_authenticated: false,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: Some("askpass".into()),
    })
}

fn scp_legacy_mode_requested(binary: &str, args: &[String]) -> bool {
    binary.rsplit('/').next().unwrap_or(binary) == "scp" && args.iter().any(|arg| arg == "-O")
}

fn scp_args_without_legacy_mode(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| arg.as_str() != "-O")
        .cloned()
        .collect()
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

#[cfg(unix)]
#[allow(dead_code)] // used by ssh_pool daemon when that module is wired
pub(crate) fn ensure_ssh_mux_master_for_argv(
    binary: &str,
    argv: &[String],
    record_id: Uuid,
    prompt_patterns: &[regex::bytes::Regex],
) -> Result<()> {
    ensure_ssh_mux_master(binary, argv, record_id, prompt_patterns)
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
    let status = SessionChildGuard::spawn(cmd)?.wait()?;
    Ok(PtyRunResult {
        exit_code: status.code().unwrap_or(-1),
        captured_password: None,
        had_prompt: false,
        ssh_authenticated: false,
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
pub fn run(
    _profile: &str,
    _binary: &str,
    _args: &[String],
    _record_id: Uuid,
    _remote_trailing: Option<&[String]>,
    _brokre_flags: &BrokreSshStdinFlags,
) -> Result<PtyRunResult> {
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
        assert!(should_use_pipe_mode("scp", None));
        assert!(should_use_pipe_mode("sftp", None));
        assert!(!should_use_pipe_mode("ssh", None));
        assert!(!should_use_pipe_mode("mysql", None));
    }

    #[test]
    fn pipe_mode_for_noninteractive_remote_command_without_piped_stdin() {
        std::env::remove_var("BROKRE_ROUTED_INNER");
        std::env::remove_var("BROKRE_MCP_EXEC");
        assert!(should_use_pipe_mode(
            "ssh",
            Some(&["true".into()])
        ));
    }

    #[test]
    fn scp_legacy_retry_removes_only_standalone_o_flag() {
        let args = vec![
            "-O".into(),
            "-P".into(),
            "2222".into(),
            "/tmp/local".into(),
            "dev-host:/tmp/remote".into(),
        ];
        assert!(scp_legacy_mode_requested("scp", &args));
        assert_eq!(
            scp_args_without_legacy_mode(&args),
            vec![
                "-P".to_string(),
                "2222".to_string(),
                "/tmp/local".to_string(),
                "dev-host:/tmp/remote".to_string()
            ]
        );
        assert!(!scp_legacy_mode_requested("ssh", &args));
    }

    #[test]
    fn mcp_exec_pipe_mode_for_normal_remote_command() {
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        assert!(should_use_pipe_mode("ssh", Some(&["uptime".into()]),));
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
        assert!(!should_use_pipe_mode("ssh", Some(&trailing)));
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
        assert!(should_use_pipe_mode("ssh", Some(&trailing)));
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
        assert!(!should_use_pipe_mode("ssh", Some(&trailing)));
        std::env::remove_var("BROKRE_MCP_EXEC");
        std::env::remove_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV);
    }

    #[test]
    fn routed_inner_forces_pty_even_when_stdin_is_pipe() {
        std::env::set_var("BROKRE_ROUTED_INNER", "1");
        assert!(!should_use_pipe_mode("ssh", Some(&["hostname".into()])));
        std::env::remove_var("BROKRE_ROUTED_INNER");
    }

    #[test]
    fn tunnel_agent_inner_noninteractive_uses_pipe_mode() {
        std::env::set_var("BROKRE_ROUTED_INNER", "1");
        std::env::set_var("BROKRE_TUNNEL_AGENT_INNER", "1");
        assert!(should_use_pipe_mode("ssh", Some(&["hostname".into()])));
        assert!(!should_use_pipe_mode(
            "ssh",
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
            Some(&["sudo".into(), "whoami".into()]),
        ));
        std::env::remove_var("BROKRE_MCP_EXEC");
    }

    #[test]
    fn cli_sudo_forces_pty_even_when_stdin_is_pipe() {
        assert!(!should_use_pipe_mode(
            "ssh",
            Some(&["sudo".into(), "whoami".into()]),
        ));
    }

    #[test]
    fn cli_quoted_sudo_script_forces_pty_when_stdin_is_pipe() {
        assert!(!should_use_pipe_mode(
            "ssh",
            Some(&["sudo -i whoami".into()]),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn askpass_guard_drops_state_and_owner_files() {
        crate::utils::test_home::with_temp_brokre_home(|| {
            std::env::remove_var("BROKRE_DISABLE_HARDENING");
            let mut cmd = Command::new("true");
            let record_id = Uuid::nil();
            let guard = configure_askpass(&mut cmd, record_id).unwrap();
            let state = guard.state_path.clone();
            let owner = guard.owner_path.clone();
            assert_eq!(std::fs::read_to_string(&state).unwrap().trim(), "0");
            assert!(owner.is_file());
            drop(guard);
            assert!(!state.exists());
            assert!(!owner.exists());
        });
    }

    #[cfg(unix)]
    #[test]
    fn prune_stale_askpass_removes_dead_owner_keeps_live() {
        crate::utils::test_home::with_temp_brokre_home(|| {
            let dir = run_dir();
            let state = dir.join("askpass_dead_token");
            let owner = state.with_extension("owner");
            std::fs::write(&state, "0").unwrap();
            std::fs::write(&owner, "999999").unwrap();
            prune_stale_askpass_files();
            assert!(!state.exists());
            assert!(!owner.exists());

            let live = dir.join("askpass_live_token");
            let live_owner = live.with_extension("owner");
            std::fs::write(&live, "0").unwrap();
            std::fs::write(&live_owner, std::process::id().to_string()).unwrap();
            prune_stale_askpass_files();
            assert!(live.exists());
            assert!(live_owner.exists());
        });
    }
}
