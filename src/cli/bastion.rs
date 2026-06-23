use crate::audit::logger::{append, AuditEvent};
use crate::bastion::key::{key_is_set, set_bastion_key};
use crate::bastion::registry::{disable_bastion, enable_bastion, list_bastions};
use crate::bastion::session::{clear_session, is_unlocked};
use crate::bastion::transport::run_remote_list_json_probe;
use crate::security::prompt::prompt_passphrase;
use crate::security::tty::{stdin_is_real_tty, stdout_is_real_tty};
use crate::utils::errors::{BrokreError, Result};
use crate::vault::keychain::get_or_init_audit_hmac_key;
use chrono::Utc;
use uuid::Uuid;

fn audit_bastion(action: &str, name: &str) {
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: "bastion".into(),
        name: name.into(),
        exit: None,
        dur_ms: None,
        args_redacted: vec![],
        hardening: None,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
        source: Some("cli".into()),
        route: None,
        bastion: Some(name.into()),
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    if let Ok(key) = get_or_init_audit_hmac_key() {
        let _ = append(&mut ev, &key);
    }
}

pub fn run_enable(alias: String) -> Result<()> {
    let entry = enable_bastion(&alias)?;
    audit_bastion("bastion/enable", &entry.alias);
    println!(
        "bastion enabled: {} (host={})",
        entry.alias,
        entry.host_alias.as_deref().unwrap_or("-")
    );
    if !key_is_set() {
        eprintln!("brokre: set a bastion key with `brokre bastion set-key` before outbound use");
    }
    Ok(())
}

pub fn run_disable(alias: String) -> Result<()> {
    if disable_bastion(&alias)? {
        audit_bastion("bastion/disable", &alias);
        println!("bastion disabled: {alias}");
    } else {
        println!("bastion not registered: {alias}");
    }
    Ok(())
}

pub fn run_list(json: bool) -> Result<()> {
    let entries = list_bastions()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&entries).unwrap());
    } else if entries.is_empty() {
        println!("(no bastions registered)");
    } else {
        println!("== bastions ==");
        for e in entries {
            let host = e.host_alias.as_deref().unwrap_or("-");
            println!(
                "  {:<24}  host={:<24}  enabled={}",
                e.alias,
                host,
                e.enabled_at.format("%Y-%m-%d")
            );
        }
    }
    Ok(())
}

pub fn run_set_key() -> Result<()> {
    if !stdin_is_real_tty() || !stdout_is_real_tty() {
        return Err(BrokreError::NoTty);
    }
    let pass = prompt_passphrase("New bastion key: ")?;
    let confirm = prompt_passphrase("Confirm bastion key: ")?;
    if pass.expose() != confirm.expose() {
        return Err(BrokreError::Cli("bastion keys do not match".into()));
    }
    set_bastion_key(&pass)?;
    println!("bastion key set");
    Ok(())
}

pub fn run_unlock() -> Result<()> {
    if is_unlocked() {
        println!("bastion session already unlocked");
        return Ok(());
    }
    crate::bastion::gate::unlock_cli_interactive()
}

pub fn run_lock() -> Result<()> {
    clear_session()?;
    println!("bastion session locked");
    Ok(())
}

pub fn run_strict(mode: Option<String>) -> Result<()> {
    match mode.as_deref() {
        None | Some("status") => {
            let strict = crate::bastion::policy::strict_mode();
            println!(
                "bastion gate mode: {}",
                if strict { "strict" } else { "default" }
            );
        }
        Some("on") | Some("enable") | Some("true") | Some("1") => {
            crate::bastion::policy::set_strict_mode(true)?;
            audit_bastion("bastion/strict-on", "-");
            println!("bastion gate mode: strict (all operations require unlock)");
        }
        Some("off") | Some("disable") | Some("false") | Some("0") => {
            crate::bastion::policy::set_strict_mode(false)?;
            audit_bastion("bastion/strict-off", "-");
            println!("bastion gate mode: default (bastion outbound only)");
        }
        Some(other) => {
            return Err(BrokreError::Cli(format!(
                "unknown strict mode '{other}' — use on, off, or status"
            )));
        }
    }
    Ok(())
}

pub fn run_sync(alias: String, json: bool) -> Result<()> {
    let stdout = run_remote_list_json_probe(&alias)?;
    if json {
        println!("{stdout}");
    } else {
        let items: Vec<crate::bastion::BastionListItem> = serde_json::from_str(&stdout)
            .map_err(|e| BrokreError::Runtime(format!("parse remote list: {e}")))?;
        println!("== bastion {alias} ==");
        for item in items {
            let host = item.host_alias.as_deref().unwrap_or("-");
            let status = item
                .status
                .as_ref()
                .map(|s| {
                    if s.reachable {
                        format!("up {}ms", s.probe_ms.unwrap_or(0))
                    } else {
                        format!("down: {}", s.error.as_deref().unwrap_or("?"))
                    }
                })
                .unwrap_or_else(|| "-".into());
            println!(
                "  {:<32}  profile={:<8} host={:<20} status={}",
                item.addr, item.profile, host, status
            );
        }
    }
    Ok(())
}
