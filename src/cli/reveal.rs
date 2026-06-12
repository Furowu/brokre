use crate::audit::logger::{append, AuditEvent};
use crate::security::prompt::prompt_with_retries;
use crate::security::tty::{stdin_is_real_tty, stdout_is_real_tty};
use crate::utils::errors::{BrokrError, Result};
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::store::VaultStore;
use chrono::Utc;
use uuid::Uuid;

pub fn run(profile: String, name: String, field: Option<String>) -> Result<()> {
    if !stdin_is_real_tty() || !stdout_is_real_tty() {
        let mut ev = AuditEvent {
            ts: Utc::now().to_rfc3339(),
            sid: Uuid::new_v4().to_string(),
            action: "reveal/denied".into(),
            profile: profile.clone(),
            name: name.clone(),
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
        let _ = append(&mut ev, &get_or_init_audit_hmac_key()?);
        return Err(BrokrError::NoTty);
    }

    let store = VaultStore::open()?;
    let rec = store
        .get(&profile, &name)?
        .ok_or_else(|| BrokrError::Cli(format!("record not found: {}/{}", profile, name)))?;

    let passphrase = prompt_with_retries(
        "Master passphrase",
        |p| {
            let kek = crate::vault::crypto::kdf::derive_reveal_key(p, &rec.crypto.reveal_salt);
            if let Ok(k) = kek {
                crate::vault::crypto::record::decrypt_for_reveal(&rec.crypto, &k).is_ok()
            } else {
                false
            }
        },
        3,
    )?;

    let kek = crate::vault::crypto::kdf::derive_reveal_key(&passphrase, &rec.crypto.reveal_salt)?;
    let fields = crate::vault::crypto::record::decrypt_for_reveal(&rec.crypto, &kek)?;

    if let Some(f) = field {
        if let Some(val) = fields.get(&f) {
            println!("{}", val.expose());
        } else {
            return Err(BrokrError::Cli(format!("field not found: {}", f)));
        }
    } else {
        for (k, v) in &fields {
            println!("{}: {}", k, v.expose());
        }
    }

    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: "reveal/success".into(),
        profile,
        name,
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
    append(&mut ev, &get_or_init_audit_hmac_key()?)?;
    Ok(())
}
