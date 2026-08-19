use crate::bastion::gate::prepare_outbound_gate_for_exec;
use crate::bastion::route::{extend_bastion_path, shell_join, visited_bastions, BASTION_PATH_ENV};
use crate::runtime::child_guard::SessionChildGuard;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::remote_brokre_shell_token;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_BASTION_RPC_TIMEOUT_SECS: u64 = 60;

pub(crate) fn bastion_rpc_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("BROKRE_BASTION_RPC_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BASTION_RPC_TIMEOUT_SECS),
    )
}

/// Run a remote brokre command on a bastion via local `brokre ssh <alias> <remote_cmd...>`.
pub fn run_on_bastion(
    bastion_alias: &str,
    remote_args: &[String],
) -> Result<(i32, String, String)> {
    prepare_outbound_gate_for_exec("ssh", &[bastion_alias.to_string()])?;

    let visited = visited_bastions();
    if visited.iter().any(|v| v == bastion_alias) {
        return Err(BrokreError::PolicyDenied);
    }
    let path = extend_bastion_path(&visited, bastion_alias);

    let exe = std::env::current_exe().map_err(BrokreError::Io)?;
    let mut cmd = Command::new(exe);
    cmd.env("BROKRE_MCP_EXEC", "1");
    cmd.env(BASTION_PATH_ENV, &path);
    cmd.env("BROKRE_BASTION_SOURCE", "bastion");
    cmd.arg("ssh");
    cmd.arg(bastion_alias);
    cmd.args(remote_args);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());

    let guard = SessionChildGuard::spawn(cmd)?;
    let output = guard.wait_with_output_timeout(bastion_rpc_timeout())?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok((code, stdout, stderr))
}

pub fn run_remote_list_json_probe(bastion_alias: &str) -> Result<String> {
    let remote = vec![format!(
        "{} list --json --probe --no-bastion-discovery",
        remote_brokre_shell_token()
    )];
    let (code, stdout, stderr) = run_on_bastion(bastion_alias, &remote)?;
    if code != 0 {
        return Err(BrokreError::Runtime(format!(
            "remote list on bastion '{bastion_alias}' failed (exit {code}): {stderr}"
        )));
    }
    Ok(stdout)
}

pub fn run_remote_exec(
    bastion_alias: &str,
    profile: &str,
    inner: &str,
    trailing: &[String],
) -> Result<(i32, String, String, u64)> {
    let started = Instant::now();
    let mut parts = vec![
        remote_brokre_shell_token().to_string(),
        profile.to_string(),
        inner.to_string(),
    ];
    parts.extend(trailing.iter().cloned());
    let remote = vec![shell_join(&parts)];
    let (code, stdout, stderr) = run_on_bastion(bastion_alias, &remote)?;
    Ok((code, stdout, stderr, started.elapsed().as_millis() as u64))
}

/// Spawn `brokre tunnel agent --stdio` on a bastion through the existing SSH credential path.
#[cfg(unix)]
pub fn spawn_tunnel_agent(bastion_alias: &str) -> Result<std::process::Child> {
    prepare_outbound_gate_for_exec("ssh", &[bastion_alias.to_string()])?;

    let exe = std::env::current_exe().map_err(BrokreError::Io)?;
    let remote = "BROKRE_SOFT_MEMLOCK=1 BROKRE_ALLOW_FILE_KEYCHAIN=1 $HOME/.brokre/bin/brokre tunnel agent --stdio";
    let mut cmd = Command::new(exe);
    cmd.env("BROKRE_MCP_EXEC", "1");
    cmd.arg("ssh");
    cmd.arg(bastion_alias);
    cmd.arg(remote);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    cmd.spawn()
        .map_err(|e| BrokreError::Runtime(format!("spawn tunnel agent on {bastion_alias}: {e}")))
}

#[cfg(not(unix))]
pub fn spawn_tunnel_agent(_bastion_alias: &str) -> Result<std::process::Child> {
    Err(BrokreError::Runtime(
        "tunnel agent bootstrap requires Unix".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    #[serial_test::serial]
    fn bastion_rpc_timeout_default_is_60() {
        std::env::remove_var("BROKRE_BASTION_RPC_TIMEOUT");
        assert_eq!(bastion_rpc_timeout(), Duration::from_secs(60));
    }

    #[test]
    #[serial_test::serial]
    fn bastion_rpc_timeout_honors_env() {
        std::env::set_var("BROKRE_BASTION_RPC_TIMEOUT", "15");
        assert_eq!(bastion_rpc_timeout(), Duration::from_secs(15));
        std::env::remove_var("BROKRE_BASTION_RPC_TIMEOUT");
    }
}
