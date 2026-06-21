use crate::bastion::route::{extend_bastion_path, visited_bastions, BASTION_PATH_ENV};
use crate::bastion::session::ensure_gate_for_outbound;
use crate::utils::errors::{BrokreError, Result};
use std::process::{Command, Stdio};
use std::time::Instant;

/// Run a remote brokre command on a bastion via local `brokre ssh <alias> <remote_cmd...>`.
pub fn run_on_bastion(bastion_alias: &str, remote_args: &[String]) -> Result<(i32, String, String)> {
    ensure_gate_for_outbound()?;

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

    let output = cmd.output().map_err(BrokreError::Io)?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok((code, stdout, stderr))
}

pub fn run_remote_list_json_probe(bastion_alias: &str) -> Result<String> {
    let remote = vec![
        "brokre".into(),
        "list".into(),
        "--json".into(),
        "--probe".into(),
        "--no-bastion-discovery".into(),
    ];
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
    let mut remote = vec![
        "brokre".into(),
        profile.into(),
        inner.into(),
    ];
    remote.extend(trailing.iter().cloned());
    let (code, stdout, stderr) = run_on_bastion(bastion_alias, &remote)?;
    Ok((code, stdout, stderr, started.elapsed().as_millis() as u64))
}
