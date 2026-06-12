use crate::audit::logger::{append, AuditEvent};
use crate::security::prompt::prompt_with_retries;
use crate::security::tty::stdin_is_real_tty;
use crate::utils::errors::{BrokreError, Result};
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::service::verify_reveal_auth;
use crate::vault::store::VaultStore;
use chrono::Utc;
use uuid::Uuid;

fn audit_rm(action: &str, profile: &str, name: &str) {
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: profile.to_string(),
        name: name.to_string(),
        exit: None,
        dur_ms: None,
        args_redacted: vec![],
        hardening: None,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    if let Ok(key) = get_or_init_audit_hmac_key() {
        let _ = append(&mut ev, &key);
    }
}

/// Remove a saved record. Requires:
///   1. interactive TTY
///   2. y/N confirmation
///   3. reveal passphrase (if one was set on the record)
pub fn run(profile: String, name: String) -> Result<()> {
    if !stdin_is_real_tty() {
        audit_rm("rm/denied", &profile, &name);
        return Err(BrokreError::NoTty);
    }

    let store = VaultStore::open()?;
    let rec = store
        .get(&profile, &name)?
        .ok_or_else(|| BrokreError::Cli(format!("record not found: {}/{}", profile, name)))?;

    println!("Remove {}/{}? [y/N]", profile, name);
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    if !buf.trim().eq_ignore_ascii_case("y") {
        audit_rm("rm/denied", &profile, &name);
        return Err(BrokreError::Cli("cancelled".into()));
    }

    // Verify passphrase — if the record has no reveal-capable passphrase
    // (saved with blank), we cannot ask. In that case, fall back to
    // a YES-typed confirmation to avoid accidents.
    let needs_pass = prompt_with_retries(
        "Master passphrase (or YES to confirm)",
        |p| verify_reveal_auth(&rec, p),
        3,
    );
    if needs_pass.is_err() {
        audit_rm("rm/denied", &profile, &name);
        return Err(BrokreError::Cli("authentication failed".into()));
    }

    store.delete(&profile, &name)?;
    audit_rm("rm/success", &profile, &name);
    println!("Removed.");
    Ok(())
}
