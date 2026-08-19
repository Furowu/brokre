//! Auto-spawned sidecar: one long-lived SSH session + local Unix socket for RPC fan-in.

use crate::audit::logger::{append, exec_audit_source, redact_args, AuditEvent};
use crate::runtime::ssh_rpc::{extract_bash_script_path, is_jsonrpc_ssh_exec, ssh_pool_enabled};
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::model::SecretRecord;
use chrono::Utc;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

const SPAWN_WAIT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq)]
pub enum SshPoolOutcome {
    NotApplicable,
    Completed { exit_code: i32, dur_ms: u64 },
}

pub fn maybe_exec_via_ssh_pool(
    rec: &SecretRecord,
    profile: &str,
    trailing: &[String],
) -> Result<SshPoolOutcome> {
    if !ssh_pool_enabled() || !is_jsonrpc_ssh_exec(profile, rec, trailing) {
        return Ok(SshPoolOutcome::NotApplicable);
    }
    let script = extract_bash_script_path(trailing).ok_or_else(|| {
        BrokreError::Runtime("ssh pool: missing bash script path in remote argv".into())
    })?;
    let method = trailing
        .last()
        .cloned()
        .ok_or_else(|| BrokreError::Runtime("ssh pool: missing RPC method token".into()))?;
    let stdin_body = read_all_stdin()?;
    let params = parse_params_object(&stdin_body)?;

    let socket = pool_socket_path(&rec.name);
    let start = Instant::now();
    let relay = match call_pool(&socket, rec, &script, &method, &params) {
        Ok(body) => {
            std::io::stdout()
                .write_all(&body)
                .map_err(BrokreError::Io)?;
            if !body.ends_with(b"\n") {
                std::io::stdout()
                    .write_all(b"\n")
                    .map_err(BrokreError::Io)?;
            }
            std::io::stdout().flush().map_err(BrokreError::Io)?;
            Ok(())
        }
        Err(e) => Err(e),
    };
    let dur_ms = start.elapsed().as_millis() as u64;
    let exit_code = if relay.is_ok() { 0 } else { 1 };
    if let Err(e) = &relay {
        eprintln!("brokre: ssh pool failed: {e}");
    }

    let mut audit_argv = vec!["<ssh-pool>".into()];
    audit_argv.extend(trailing.iter().cloned());
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: "ssh_pool".into(),
        profile: profile.to_string(),
        name: rec.name.clone(),
        exit: Some(exit_code),
        dur_ms: Some(dur_ms),
        args_redacted: redact_args(&audit_argv),
        hardening: crate::security::hardening::last_hardening_report(),
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: Some(if relay.is_ok() {
            "relay".into()
        } else {
            "error".into()
        }),
        source: Some(exec_audit_source()),
        route: None,
        bastion: None,
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    let _ = append(&mut ev, &get_or_init_audit_hmac_key()?);

    relay?;
    Ok(SshPoolOutcome::Completed { exit_code, dur_ms })
}

fn read_all_stdin() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(BrokreError::Io)?;
    Ok(buf)
}

fn parse_params_object(stdin_body: &[u8]) -> Result<Value> {
    if stdin_body.is_empty() {
        return Ok(json!({}));
    }
    let text = std::str::from_utf8(stdin_body)
        .map_err(|_| BrokreError::Runtime("ssh pool params must be UTF-8 JSON".into()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|e| BrokreError::Runtime(format!("ssh pool params must be JSON: {e}")))?;
    if !value.is_object() {
        return Err(BrokreError::Runtime(
            "ssh pool params must be a JSON object".into(),
        ));
    }
    Ok(value)
}

pub fn pool_socket_path(alias: &str) -> PathBuf {
    let safe = alias
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    run_dir().join(format!("ssh-pool-{safe}.sock"))
}

pub fn pool_pid_path(alias: &str) -> PathBuf {
    pool_socket_path(alias).with_extension("pid")
}

pub fn cleanup_stale_pool(alias: &str) {
    let socket = pool_socket_path(alias);
    let pid_path = pool_pid_path(alias);
    if let Ok(raw) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = raw.trim().parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
    }
    let _ = fs::remove_file(&socket);
    let _ = fs::remove_file(&pid_path);
    let _ = fs::remove_file(socket.with_extension("spawn.lock"));
}

fn call_pool(
    socket: &Path,
    rec: &SecretRecord,
    script: &str,
    method: &str,
    params: &Value,
) -> Result<Vec<u8>> {
    match try_call_pool(socket, method, params) {
        Ok(body) => Ok(body),
        Err(e) if is_connect_error(&e) => {
            ensure_pool_daemon(socket, rec, script)?;
            try_call_pool(socket, method, params)
        }
        Err(_) => {
            cleanup_stale_pool(&rec.name);
            ensure_pool_daemon(socket, rec, script)?;
            try_call_pool(socket, method, params)
        }
    }
}

fn is_connect_error(err: &BrokreError) -> bool {
    match err {
        BrokreError::Io(e) => {
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            )
        }
        _ => false,
    }
}

fn try_call_pool(socket: &Path, method: &str, params: &Value) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket).map_err(BrokreError::Io)?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .map_err(BrokreError::Io)?;
    stream
        .set_write_timeout(Some(REQUEST_TIMEOUT))
        .map_err(BrokreError::Io)?;
    let req = json!({ "method": method, "params": params });
    let line = format!(
        "{}\n",
        serde_json::to_string(&req).map_err(|e| BrokreError::Runtime(e.to_string()))?
    );
    stream.write_all(line.as_bytes()).map_err(BrokreError::Io)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(BrokreError::Io)?;
    if buf.is_empty() {
        return Err(BrokreError::Runtime("ssh pool: empty response".into()));
    }
    Ok(buf)
}

fn ensure_pool_daemon(socket: &Path, rec: &SecretRecord, script: &str) -> Result<()> {
    if UnixStream::connect(socket).is_ok() {
        return Ok(());
    }
    let lock_path = socket.with_extension("spawn.lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(BrokreError::Io)?;
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(BrokreError::Io(std::io::Error::last_os_error()));
    }

    if UnixStream::connect(socket).is_ok() {
        return Ok(());
    }

    if socket.exists() {
        let _ = fs::remove_file(socket);
    }

    let exe = std::env::current_exe().map_err(BrokreError::Io)?;
    let mut cmd = Command::new(exe);
    cmd.arg("--internal-ssh-pool")
        .arg("--record-id")
        .arg(rec.id.to_string())
        .arg("--script")
        .arg(script)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().map_err(BrokreError::Io)?;

    let deadline = Instant::now() + SPAWN_WAIT;
    while Instant::now() < deadline {
        if UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(BrokreError::Runtime(
        "ssh pool sidecar failed to start (timed out waiting for socket)".into(),
    ))
}

/// Entry for `brokre --internal-ssh-pool` (hidden).
pub fn run_internal_daemon(record_id: Uuid, script: &str, socket: &Path) -> Result<()> {
    crate::runtime::ssh_pool::daemon::serve(record_id, script, socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_socket_sanitizes_alias() {
        let p = pool_socket_path("toll06");
        assert!(p.to_string_lossy().contains("ssh-pool-toll06.sock"));
        let p2 = pool_socket_path("b150::db");
        assert!(!p2.to_string_lossy().contains("::"));
    }
}
