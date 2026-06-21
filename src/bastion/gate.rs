//! Unified bastion outbound gate — shared by CLI, MCP, and transport.
//!
//! When a bastion key is configured, any outbound SSH to a registered bastion
//! (routed `::` exec, direct bastion alias, remote discovery) requires an
//! unlocked TTL session. Interactive unlock: TTY passphrase prompt, or local
//! browser auth page + polling.

use crate::audit::logger::{append, AuditEvent};
use crate::bastion::key::{key_is_set, verify_bastion_key};
use crate::bastion::registry::{is_registered_bastion, list_bastions};
use crate::bastion::route::ROUTE_SEP;
use crate::bastion::session::{gate_required, is_unlocked, unlock_session};
use crate::manage::instance::find_running_instance;
use crate::manage::open_browser;
use crate::manage::server::{run_manage_server_with, IdleBehavior, ManageServer, ManageServerOptions};
use crate::security::prompt::prompt_passphrase;
use crate::security::tty::{stdin_is_real_tty, stdout_is_real_tty};
use crate::utils::errors::{BrokreError, Result};
use crate::vault::keychain::get_or_init_audit_hmac_key;
use chrono::Utc;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const DEFAULT_POLL_TIMEOUT_SECS: u64 = 90;

pub fn poll_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("BROKRE_BASTION_POLL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_POLL_TIMEOUT_SECS),
    )
}

fn auto_open_enabled() -> bool {
    std::env::var("BROKRE_BASTION_NO_AUTO_OPEN")
        .ok()
        .as_deref()
        != Some("1")
}

fn audit_bastion(action: &str, source: &str) {
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: "bastion".into(),
        name: "-".into(),
        exit: None,
        dur_ms: None,
        args_redacted: vec![],
        hardening: None,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
        source: Some(source.into()),
        route: None,
        bastion: None,
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    if let Ok(key) = get_or_init_audit_hmac_key() {
        let _ = append(&mut ev, &key);
    }
}

/// Whether this exec may initiate outbound SSH through a registered bastion.
pub fn exec_touches_bastion_outbound(profile: &str, args: &[String]) -> bool {
    let idx = match args.iter().position(|a| !a.starts_with('-')) {
        Some(i) => i,
        None => return false,
    };
    let token = &args[idx];
    if token.contains(ROUTE_SEP) {
        return true;
    }
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    matches!(bin, "ssh" | "scp" | "sftp") && is_registered_bastion(token)
}

/// Whether this list operation may SSH to bastions for discovery.
pub fn list_touches_bastion_outbound(probe: bool, include_bastions: bool) -> bool {
    if !(probe || include_bastions) {
        return false;
    }
    list_bastions().map(|b| !b.is_empty()).unwrap_or(false)
}

pub fn needs_unlock_for_exec(profile: &str, args: &[String]) -> bool {
    gate_required() && !is_unlocked() && exec_touches_bastion_outbound(profile, args)
}

pub fn needs_unlock_for_list(probe: bool, include_bastions: bool) -> bool {
    gate_required() && !is_unlocked() && list_touches_bastion_outbound(probe, include_bastions)
}

pub fn bastion_auth_url(server: &ManageServer, elicitation_id: &str) -> String {
    format!(
        "http://127.0.0.1:{}/bastion-auth?t={}&elicitation_id={}",
        server.port, server.token, elicitation_id
    )
}

/// True when running inside the MCP server or a brokre child spawned for MCP exec.
pub fn invocation_from_mcp() -> bool {
    std::env::var_os("BROKRE_MCP").is_some() || std::env::var_os("BROKRE_MCP_EXEC").is_some()
}

/// Ensure bastion outbound access is unlocked; interactively unlock when needed.
///
/// - **CLI** (`brokre ssh …` in a terminal): TTY passphrase prompt only.
/// - **MCP** (server or `BROKRE_MCP_EXEC` child): open local bastion auth page + poll.
pub fn ensure_outbound_unlocked() -> Result<()> {
    if !gate_required() || is_unlocked() {
        return Ok(());
    }
    if invocation_from_mcp() {
        ensure_mcp_unlock()
    } else {
        ensure_cli_unlock()
    }
}

fn ensure_cli_unlock() -> Result<()> {
    if !stdin_is_real_tty() || !stdout_is_real_tty() {
        return Err(BrokreError::Cli(
            "bastion outbound access locked — run from a terminal or `brokre bastion unlock`".into(),
        ));
    }
    unlock_via_tty_prompt()
}

fn ensure_mcp_unlock() -> Result<()> {
    if auto_open_enabled() {
        unlock_via_browser_poll("mcp")
    } else {
        Err(BrokreError::Cli(
            "bastion outbound access locked — complete bastion unlock in the MCP client \
             (or unset BROKRE_BASTION_NO_AUTO_OPEN)"
                .into(),
        ))
    }
}

/// TTY passphrase unlock (also used by `brokre bastion unlock`).
pub fn unlock_via_tty_prompt() -> Result<()> {
    if !key_is_set() {
        return Err(BrokreError::Cli(
            "no bastion key configured — run `brokre bastion set-key`".into(),
        ));
    }
    if is_unlocked() {
        return Ok(());
    }
    if !stdin_is_real_tty() || !stdout_is_real_tty() {
        return Err(BrokreError::NoTty);
    }
    let pass = prompt_passphrase("Bastion key: ")?;
    if !verify_bastion_key(&pass)? {
        audit_bastion("bastion/denied", "cli");
        return Err(BrokreError::PolicyDenied);
    }
    let session = unlock_session()?;
    audit_bastion("bastion/unlock", "cli");
    eprintln!(
        "brokre: bastion session unlocked until {} (idle {})",
        session.expires_at.to_rfc3339(),
        session.idle_expires_at.to_rfc3339()
    );
    Ok(())
}

fn ensure_manage_for_auth() -> Result<ManageServer> {
    if let Some(rec) = find_running_instance() {
        return Ok(ManageServer {
            port: rec.port,
            token: rec.token.clone(),
            url: rec.url(),
        });
    }
    run_manage_server_with(ManageServerOptions {
        onboard: false,
        idle_behavior: IdleBehavior::LogOnly,
    })
}

/// Open local bastion auth page and block until unlocked or timeout.
pub fn unlock_via_browser_poll(source: &str) -> Result<()> {
    if !key_is_set() {
        return Err(BrokreError::Cli(
            "no bastion key configured — run `brokre bastion set-key`".into(),
        ));
    }
    if is_unlocked() {
        return Ok(());
    }
    let server = ensure_manage_for_auth()?;
    let elicitation_id = Uuid::new_v4().to_string();
    let url = bastion_auth_url(&server, &elicitation_id);
    eprintln!("brokre: bastion locked — opening auth page in browser…");
    let url_clone = url.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        let _ = open_browser(&url_clone);
    });
    poll_until_unlocked_sync(&server, poll_timeout(), source)
}

pub fn poll_until_unlocked_sync(
    server: &ManageServer,
    timeout: Duration,
    source: &str,
) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if is_unlocked() {
            audit_bastion("bastion/unlock", source);
            return Ok(());
        }
        if fetch_unlocked_status(server.port, &server.token)? {
            audit_bastion("bastion/unlock", source);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(BrokreError::Cli(
        "bastion unlock timed out — complete authentication in the browser and retry".into(),
    ))
}

pub fn fetch_unlocked_status(port: u16, token: &str) -> Result<bool> {
    let req = format!(
        "GET /api/bastion/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(BrokreError::Io)?;
    stream.write_all(req.as_bytes()).map_err(BrokreError::Io)?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).map_err(BrokreError::Io)?;
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or(&resp);
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| BrokreError::Runtime(e.to_string()))?;
    Ok(v.get("unlocked")
        .and_then(|u| u.as_bool())
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_env_vars<F>(vars: &[(&str, Option<&str>)], f: F)
    where
        F: FnOnce(),
    {
        let saved: Vec<(String, Option<std::ffi::OsString>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var_os(*k)))
            .collect();
        for (k, v) in vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, prev) in saved {
            match prev {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn invocation_from_mcp_detects_server_and_exec_child() {
        with_env_vars(&[("BROKRE_MCP", None), ("BROKRE_MCP_EXEC", None)], || {
            assert!(!invocation_from_mcp());
        });
        with_env_vars(&[("BROKRE_MCP", Some("1")), ("BROKRE_MCP_EXEC", None)], || {
            assert!(invocation_from_mcp());
        });
        with_env_vars(&[("BROKRE_MCP", None), ("BROKRE_MCP_EXEC", Some("1"))], || {
            assert!(invocation_from_mcp());
        });
    }
}
