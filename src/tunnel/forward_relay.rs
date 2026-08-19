//! Local TCP relay — **opt-in only** via vault `forward-relay=*` label + `BROKRE_FORWARD_RELAY=1`.
//!
//! Default acceleration uses [`crate::runtime::ssh_pool`] (SSH mux + sidecar, no local TCP port).

use crate::audit::logger::{append, exec_audit_source, redact_args, AuditEvent};
use crate::runtime::ssh_rpc::{base_jsonrpc_ssh_gates, looks_like_jsonrpc_trailing};
use crate::tunnel::forward::{
    ensure_forward_for_alias, local_socket_addr_from_spec, resolve_auto_forward_for_record,
};
use crate::utils::errors::{BrokreError, Result};
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::model::SecretRecord;
use crate::vault::store::VaultStore;
use chrono::Utc;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use uuid::Uuid;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ForwardRelayOutcome {
    NotApplicable,
    Relayed { exit_code: i32, dur_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardRelayMode {
    Tcp,
    JsonRpcLine,
}

/// Explicit opt-in: `BROKRE_FORWARD_RELAY=1` (default off — use ssh pool instead).
pub fn forward_relay_enabled() -> bool {
    std::env::var("BROKRE_FORWARD_RELAY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn relay_mode_from_record(rec: &SecretRecord) -> Option<ForwardRelayMode> {
    for label in &rec.labels {
        let mode = label
            .strip_prefix("forward-relay=")
            .or_else(|| label.strip_prefix("forward-relay:"))?;
        return parse_relay_mode(mode);
    }
    None
}

fn parse_relay_mode(value: &str) -> Option<ForwardRelayMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" | "raw" | "passthrough" => Some(ForwardRelayMode::Tcp),
        "jsonrpc" | "jsonrpc-line" | "json-rpc" => Some(ForwardRelayMode::JsonRpcLine),
        _ => None,
    }
}

pub fn should_attempt_forward_relay(
    profile: &str,
    rec: &SecretRecord,
    trailing: &[String],
) -> bool {
    if !forward_relay_enabled() {
        return false;
    }
    let Some(mode) = relay_mode_from_record(rec) else {
        return false;
    };
    if !base_jsonrpc_ssh_gates(profile, rec, trailing) && !matches!(mode, ForwardRelayMode::Tcp) {
        return false;
    }
    match mode {
        ForwardRelayMode::Tcp => crate::security::tty::stdin_is_pipe(),
        ForwardRelayMode::JsonRpcLine => {
            !trailing.is_empty() && looks_like_jsonrpc_trailing(trailing)
        }
    }
}

pub fn maybe_exec_forward_relay(
    store: &VaultStore,
    rec: &SecretRecord,
    profile: &str,
    trailing: &[String],
) -> Result<ForwardRelayOutcome> {
    if !should_attempt_forward_relay(profile, rec, trailing) {
        return Ok(ForwardRelayOutcome::NotApplicable);
    }
    let mode = relay_mode_from_record(rec)
        .ok_or_else(|| BrokreError::Runtime("forward-relay label missing".into()))?;
    let Some(spec) = resolve_auto_forward_for_record(store, rec) else {
        return Err(BrokreError::Runtime(format!(
            "forward-relay requires auto-forward config for alias {}",
            rec.name
        )));
    };

    ensure_forward_for_alias(store, &rec.name, &spec, true)?;

    let stdin_body = read_all_stdin()?;
    let payload = match mode {
        ForwardRelayMode::Tcp => stdin_body,
        ForwardRelayMode::JsonRpcLine => build_jsonrpc_payload(trailing, &stdin_body)?,
    };

    let local = local_socket_addr_from_spec(&spec)?;
    let start = Instant::now();
    let relay_result = tcp_relay(&local, &payload, mode);
    let dur_ms = start.elapsed().as_millis() as u64;
    let exit_code = if relay_result.is_ok() { 0 } else { 1 };
    if let Err(e) = &relay_result {
        eprintln!("brokre: forward-relay failed: {e}");
    }

    audit_relay(profile, rec, trailing, mode, exit_code, dur_ms)?;
    relay_result?;
    Ok(ForwardRelayOutcome::Relayed { exit_code, dur_ms })
}

fn audit_relay(
    profile: &str,
    rec: &SecretRecord,
    trailing: &[String],
    mode: ForwardRelayMode,
    exit_code: i32,
    dur_ms: u64,
) -> Result<()> {
    let mut audit_argv = vec!["<forward-relay>".into()];
    audit_argv.extend(trailing.iter().cloned());
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: "forward_relay".into(),
        profile: profile.to_string(),
        name: rec.name.clone(),
        exit: Some(exit_code),
        dur_ms: Some(dur_ms),
        args_redacted: redact_args(&audit_argv),
        hardening: crate::security::hardening::last_hardening_report(),
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: Some(format!("{:?}", mode).to_ascii_lowercase()),
        source: Some(exec_audit_source()),
        route: None,
        bastion: None,
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    let _ = append(&mut ev, &get_or_init_audit_hmac_key()?);
    Ok(())
}

fn read_all_stdin() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(BrokreError::Io)?;
    Ok(buf)
}

fn build_jsonrpc_payload(trailing: &[String], stdin_body: &[u8]) -> Result<Vec<u8>> {
    let method = trailing.last().ok_or_else(|| {
        BrokreError::Runtime("forward-relay=jsonrpc requires a remote method token".into())
    })?;
    let params = parse_jsonrpc_params(stdin_body)?;
    let line = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut out = serde_json::to_vec(&line).map_err(|e| BrokreError::Runtime(e.to_string()))?;
    out.push(b'\n');
    Ok(out)
}

fn parse_jsonrpc_params(stdin_body: &[u8]) -> Result<Value> {
    if stdin_body.is_empty() {
        return Ok(json!({}));
    }
    let text = std::str::from_utf8(stdin_body)
        .map_err(|_| BrokreError::Runtime("forward-relay params must be UTF-8 JSON".into()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(trimmed)
        .map_err(|e| BrokreError::Runtime(format!("forward-relay invalid params JSON: {e}")))
}

fn tcp_relay(addr: &SocketAddr, payload: &[u8], mode: ForwardRelayMode) -> Result<()> {
    let mut stream = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT).map_err(|e| {
        BrokreError::Runtime(format!("connect {addr} (is auto-forward active?): {e}"))
    })?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(BrokreError::Io)?;
    stream
        .set_write_timeout(Some(READ_TIMEOUT))
        .map_err(BrokreError::Io)?;
    stream.write_all(payload).map_err(BrokreError::Io)?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(BrokreError::Io)?;

    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        if out.len() >= MAX_RESPONSE_BYTES {
            return Err(BrokreError::Runtime(format!(
                "forward-relay response exceeds {} bytes",
                MAX_RESPONSE_BYTES
            )));
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if matches!(mode, ForwardRelayMode::JsonRpcLine) && out.contains(&b'\n') {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(BrokreError::Io(e)),
        }
    }

    if matches!(mode, ForwardRelayMode::JsonRpcLine) {
        if let Some(pos) = out.iter().position(|b| *b == b'\n') {
            out.truncate(pos + 1);
        }
    }

    std::io::stdout().write_all(&out).map_err(BrokreError::Io)?;
    std::io::stdout().flush().map_err(BrokreError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::secret::SecretString;
    use crate::vault::crypto::record::encrypt_record;
    use crate::vault::keychain::get_or_init_master_kek;
    use crate::vault::model::SecretRecord;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn sample_rec(labels: Vec<&str>) -> SecretRecord {
        let master = get_or_init_master_kek().unwrap();
        let reveal_salt = crate::vault::crypto::kdf::new_salt();
        let reveal = crate::vault::crypto::kdf::derive_reveal_key(
            &SecretString::new("reveal-pass".into()),
            &reveal_salt,
        )
        .unwrap();
        let mut fields: BTreeMap<String, SecretString> = BTreeMap::new();
        fields.insert("password".into(), SecretString::new("testpw".into()));
        let crypto = encrypt_record(&fields, &master, &reveal, reveal_salt);
        SecretRecord {
            id: Uuid::new_v4(),
            name: "dev-host".into(),
            profile: "ssh".into(),
            saved_args: vec!["dev-host".into()],
            host_alias: Some("dev-host".into()),
            binary: Some("ssh".into()),
            fields_meta: None,
            labels: labels.into_iter().map(String::from).collect(),
            crypto,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            schema_version: 1,
            reveal_protected: true,
        }
    }

    #[test]
    fn forward_relay_off_by_default() {
        std::env::remove_var("BROKRE_FORWARD_RELAY");
        assert!(!forward_relay_enabled());
    }

    #[test]
    fn requires_explicit_label_even_when_env_on() {
        std::env::set_var("BROKRE_FORWARD_RELAY", "1");
        let rec = sample_rec(vec![]);
        assert!(!should_attempt_forward_relay(
            "ssh",
            &rec,
            &["bash".into(), "rpc.sh".into(), "health".into()]
        ));
        std::env::remove_var("BROKRE_FORWARD_RELAY");
    }

    #[test]
    fn jsonrpc_payload_uses_last_trailing_token_as_method() {
        let trailing = vec![
            "bash".into(),
            "/path/worker.sh".into(),
            "get_snapshot".into(),
        ];
        let body = build_jsonrpc_payload(&trailing, br#"{"dry_run":true}"#).unwrap();
        let line = std::str::from_utf8(&body).unwrap().trim();
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["method"], "get_snapshot");
    }
}
