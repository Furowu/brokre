use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use crate::vault::crypto::record::encrypt_record;
use crate::vault::crypto::wrap::unwrap_dek;
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::model::{FieldMeta, SecretRecord};
use crate::vault::store::VaultStore;
use chrono::Utc;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Common record construction and vault insertion.
pub fn insert_record(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
    alias: &str,
    reveal_kek: &[u8; 32],
    reveal_salt: [u8; 16],
    reveal_protected: bool,
) -> Result<()> {
    let master_kek = get_or_init_master_kek()?;
    let mut fields: BTreeMap<String, SecretString> = BTreeMap::new();
    fields.insert("password".into(), password);
    let crypto = encrypt_record(&fields, &master_kek, reveal_kek, reveal_salt);

    let host_alias = infer_host(profile, args);
    let record = SecretRecord {
        id: Uuid::new_v4(),
        profile: profile.to_string(),
        name: alias.to_string(),
        labels: vec![],
        host_alias,
        binary: Some(profile.to_string()),
        fields_meta: None,
        saved_args: args.to_vec(),
        crypto,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_used_at: None,
        schema_version: 1,
        reveal_protected,
    };
    store.insert(record)?;
    eprintln!("brokr: ✓ saved as {}/{}", profile, alias);
    eprintln!("       next time: brokr {} {}", profile, alias);
    Ok(())
}

/// Create a credential (manage UI / API). Returns the new record id.
pub fn create_credential(
    store: &VaultStore,
    profile: &str,
    name: &str,
    args: &[String],
    password: SecretString,
    reveal_passphrase: Option<&SecretString>,
) -> Result<Uuid> {
    let mut fields = BTreeMap::new();
    fields.insert("password".into(), password);
    create_credential_with_fields(
        store,
        profile,
        name,
        args,
        fields,
        None,
        reveal_passphrase,
    )
}

/// Create a credential with arbitrary encrypted fields (SSH key + dual passphrases).
pub fn create_credential_with_fields(
    store: &VaultStore,
    profile: &str,
    name: &str,
    args: &[String],
    fields: BTreeMap<String, SecretString>,
    fields_meta: Option<Vec<FieldMeta>>,
    reveal_passphrase: Option<&SecretString>,
) -> Result<Uuid> {
    if fields.is_empty() {
        return Err(BrokrError::Vault("at least one secret field is required".into()));
    }
    if !SecretRecord::validate_name(name) {
        return Err(BrokrError::Vault(format!("invalid name: {}", name)));
    }
    if store.get(profile, name)?.is_some() {
        return Err(BrokrError::Vault(format!(
            "record ({}, {}) already exists",
            profile, name
        )));
    }

    let reveal_salt = crate::vault::crypto::kdf::new_salt();
    let reveal_kek = match reveal_passphrase {
        Some(p) if !p.expose().is_empty() => {
            crate::vault::crypto::kdf::derive_reveal_key(p, &reveal_salt)?
        }
        _ => {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
            k
        }
    };

    let reveal_protected = reveal_passphrase
        .map(|p| !p.expose().is_empty())
        .unwrap_or(false);

    let master_kek = get_or_init_master_kek()?;
    let crypto = encrypt_record(&fields, &master_kek, &reveal_kek, reveal_salt);

    let id = Uuid::new_v4();
    let record = SecretRecord {
        id,
        profile: profile.to_string(),
        name: name.to_string(),
        labels: vec![],
        host_alias: infer_host(profile, args),
        binary: Some(profile.to_string()),
        fields_meta,
        saved_args: args.to_vec(),
        crypto,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_used_at: None,
        schema_version: 1,
        reveal_protected,
    };
    store.insert(record)?;
    Ok(id)
}

/// Auto-save after a successful login (no reveal passphrase).
pub fn auto_save(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
    alias: &str,
) -> Result<()> {
    let reveal_salt = crate::vault::crypto::kdf::new_salt();
    let mut reveal_kek = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut reveal_kek);
    insert_record(
        store,
        profile,
        args,
        password,
        alias,
        &reveal_kek,
        reveal_salt,
        false,
    )
}

/// Save with an interactive reveal passphrase prompt.
pub fn save_with_reveal_prompt(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
    alias: &str,
) -> Result<()> {
    eprintln!("       master passphrase for `brokr reveal` (blank = no reveal): ");
    let reveal_input = crate::security::prompt::prompt_field("passphrase", true)
        .unwrap_or_else(|_| SecretString::new(String::new()));

    let reveal_salt = crate::vault::crypto::kdf::new_salt();
    let reveal_protected = !reveal_input.is_empty();
    let reveal_kek = if reveal_input.is_empty() {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        k
    } else {
        crate::vault::crypto::kdf::derive_reveal_key(&reveal_input, &reveal_salt)?
    };

    insert_record(
        store,
        profile,
        args,
        password,
        alias,
        &reveal_kek,
        reveal_salt,
        reveal_protected,
    )
}

/// Verify reveal passphrase. Literal `YES` is accepted only for auto-saved records
/// (`reveal_protected == false`).
pub fn verify_reveal_auth(rec: &SecretRecord, passphrase: &SecretString) -> bool {
    if passphrase.expose() == "YES" {
        return !rec.reveal_protected;
    }
    let Ok(kek) = crate::vault::crypto::kdf::derive_reveal_key(passphrase, &rec.crypto.reveal_salt)
    else {
        return false;
    };
    crate::vault::crypto::record::decrypt_for_reveal(&rec.crypto, &kek).is_ok()
}

/// Replace stored password; never returns plaintext.
pub fn rotate_password(
    store: &VaultStore,
    profile: &str,
    name: &str,
    new_password: SecretString,
    auth: &SecretString,
) -> Result<()> {
    let mut rec = store
        .get(profile, name)?
        .ok_or_else(|| BrokrError::Vault(format!("record ({}, {}) not found", profile, name)))?;

    if !verify_reveal_auth(&rec, auth) {
        return Err(BrokrError::PolicyDenied);
    }

    let master_kek = get_or_init_master_kek()?;
    rec.crypto = if auth.expose() == "YES" {
        reencrypt_update_password(&rec, new_password, &master_kek)?
    } else {
        let reveal_kek =
            crate::vault::crypto::kdf::derive_reveal_key(auth, &rec.crypto.reveal_salt)?;
        let mut fields = crate::vault::crypto::record::decrypt_for_reveal(&rec.crypto, &reveal_kek)?;
        fields.insert("password".into(), new_password);
        encrypt_record(
            &fields,
            &master_kek,
            &reveal_kek,
            rec.crypto.reveal_salt,
        )
    };
    rec.updated_at = Utc::now();
    store.update(rec)
}

fn reencrypt_update_password(
    rec: &SecretRecord,
    new_password: SecretString,
    master_kek: &[u8; 32],
) -> Result<crate::vault::crypto::record::RecordCiphertext> {
    let mut fields = crate::vault::crypto::record::decrypt_for_exec(&rec.crypto, master_kek)?;
    fields.insert("password".into(), new_password);
    let dek = unwrap_dek(&rec.crypto.dek_for_exec, master_kek)?;
    let plain_map: BTreeMap<String, String> = fields
        .iter()
        .map(|(k, v)| (k.clone(), v.expose().to_string()))
        .collect();
    let plaintext = serde_json::to_vec(&plain_map).map_err(|e| BrokrError::Crypto(e.to_string()))?;
    let (nonce, ct) = crate::vault::crypto::aead::aead_encrypt(&dek, &plaintext);
    Ok(crate::vault::crypto::record::RecordCiphertext {
        nonce,
        ct,
        dek_for_exec: rec.crypto.dek_for_exec.clone(),
        dek_for_reveal: rec.crypto.dek_for_reveal.clone(),
        reveal_salt: rec.crypto.reveal_salt,
    })
}

/// Build `saved_args` from manage form fields.
pub fn build_saved_args(
    profile: &str,
    host: &str,
    user: Option<&str>,
    extra: &[String],
) -> Vec<String> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    let mut args = Vec::new();
    match bin {
        "ssh" | "scp" | "sftp" => {
            if let Some(u) = user.filter(|s| !s.is_empty()) {
                args.push(format!("{}@{}", u, host));
            } else {
                args.push(host.to_string());
            }
        }
        "mysql" | "mariadb" => {
            args.push("-h".into());
            args.push(host.to_string());
            if let Some(u) = user.filter(|s| !s.is_empty()) {
                args.push("-u".into());
                args.push(u.to_string());
            }
        }
        "postgres" | "psql" => {
            args.push("-h".into());
            args.push(host.to_string());
            if let Some(u) = user.filter(|s| !s.is_empty()) {
                args.push("-U".into());
                args.push(u.to_string());
            }
        }
        "redis" | "redis-cli" => {
            args.push("-h".into());
            args.push(host.to_string());
        }
        "clickhouse" | "clickhouse-client" => {
            args.push(format!("--host={}", host));
        }
        "ftp" | "lftp" => {
            args.push(host.to_string());
        }
        _ => {
            args.push(host.to_string());
        }
    }
    args.extend(extra.iter().cloned());
    args
}

pub fn suggest_name(profile: &str, args: &[String]) -> String {
    if let Some(host) = infer_host(profile, args) {
        if let Some(user) = infer_user(profile, args) {
            return format!("{}@{}", user, host);
        }
        return host;
    }
    for a in args {
        if !a.starts_with('-') {
            return a.clone();
        }
    }
    "unnamed".into()
}

/// Index of the arg that identifies the connection target for `host`.
pub fn connection_token_index(profile: &str, args: &[String], host: &str) -> Option<usize> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    for (i, a) in args.iter().enumerate() {
        if a.starts_with('-') {
            continue;
        }
        match bin {
            "ssh" | "scp" | "sftp" => {
                if let Some((_u, rest)) = a.split_once('@') {
                    let h = if matches!(bin, "scp" | "sftp") {
                        rest.split(':').next().unwrap_or(rest)
                    } else {
                        rest
                    };
                    if h == host {
                        return Some(i);
                    }
                } else if a == host {
                    return Some(i);
                }
            }
        "mysql" | "mariadb" | "psql" | "postgres" | "redis" | "redis-cli"
        | "clickhouse" | "clickhouse-client" => {
            if a == host {
                return Some(i);
            }
        }
            _ => {}
        }
    }
    None
}

/// Best-effort host extraction from raw args, per CLI.
pub fn infer_host(profile: &str, args: &[String]) -> Option<String> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    match bin {
        "ssh" | "scp" | "sftp" => {
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                if let Some((_u, rest)) = a.split_once('@') {
                    let host = if matches!(bin, "scp" | "sftp") {
                        rest.split(':').next().unwrap_or(rest)
                    } else {
                        rest
                    };
                    return Some(host.to_string());
                }
            }
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                return Some(a.clone());
            }
            None
        }
        "mysql" | "mariadb" | "psql" | "postgres" | "redis" | "redis-cli"
        | "clickhouse" | "clickhouse-client" => {
            let mut iter = args.iter().peekable();
            while let Some(a) = iter.next() {
                if a == "-h" || a == "--host" {
                    return iter.next().cloned();
                }
                if let Some(rest) = a.strip_prefix("--host=") {
                    return Some(rest.to_string());
                }
            }
            None
        }
        "ftp" | "lftp" => {
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                return Some(a.clone());
            }
            None
        }
        _ => {
            for a in args {
                if !a.starts_with('-') {
                    return Some(a.clone());
                }
            }
            None
        }
    }
}

pub fn infer_user(profile: &str, args: &[String]) -> Option<String> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    match bin {
        "ssh" | "scp" | "sftp" => {
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                if let Some((u, _h)) = a.split_once('@') {
                    return Some(u.to_string());
                }
            }
            None
        }
        "mysql" | "mariadb" => {
            let mut iter = args.iter().peekable();
            while let Some(a) = iter.next() {
                if a == "-u" || a == "--user" {
                    return iter.next().cloned();
                }
                if let Some(rest) = a.strip_prefix("--user=") {
                    return Some(rest.to_string());
                }
            }
            None
        }
        "psql" | "postgres" => {
            let mut iter = args.iter().peekable();
            while let Some(a) = iter.next() {
                if a == "-U" || a == "--username" {
                    return iter.next().cloned();
                }
            }
            None
        }
        _ => None,
    }
}

/// Format a brokr command template for display (no secrets).
/// Connection flags live in `saved_args` and are replayed internally when the alias is used.
pub fn command_template(profile: &str, name: &str, _saved_args: &[String]) -> String {
    format!("brokr {} {}", profile, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::secret::SecretString;
    use crate::vault::crypto::record::encrypt_record;
    use crate::vault::model::SecretRecord;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn verify_yes_only_when_not_reveal_protected() {
        let master = [1u8; 32];
        let salt = [2u8; 16];
        let reveal_kek = [3u8; 32];
        let mut f = BTreeMap::new();
        f.insert("password".into(), SecretString::new("p".into()));
        let crypto = encrypt_record(&f, &master, &reveal_kek, salt);
        let auto = SecretRecord {
            id: Uuid::new_v4(),
            profile: "ssh".into(),
            name: "a".into(),
            labels: vec![],
            host_alias: None,
            binary: None,
            fields_meta: None,
            saved_args: vec![],
            crypto,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            schema_version: 1,
            reveal_protected: false,
        };
        assert!(verify_reveal_auth(
            &auto,
            &SecretString::new("YES".into())
        ));
        let mut protected = auto.clone();
        protected.reveal_protected = true;
        assert!(!verify_reveal_auth(
            &protected,
            &SecretString::new("YES".into())
        ));
    }

    #[test]
    fn infer_host_strips_scp_remote_path() {
        let args = vec!["file".into(), "user@198.51.100.3:/tmp/x".into()];
        assert_eq!(
            infer_host("scp", &args).as_deref(),
            Some("198.51.100.3")
        );
    }

    #[test]
    fn build_saved_args_ftp() {
        let args = build_saved_args("ftp", "ftp.example.com", None, &[]);
        assert_eq!(args, vec!["ftp.example.com"]);
    }

    #[test]
    fn build_saved_args_ssh() {
        let args = build_saved_args("ssh", "10.0.0.1", Some("root"), &[]);
        assert_eq!(args, vec!["root@10.0.0.1"]);
    }

    #[test]
    fn build_saved_args_mysql() {
        let args = build_saved_args("mysql", "db.local", Some("admin"), &["-e".into(), "SHOW TABLES".into()]);
        assert_eq!(
            args,
            vec!["-h", "db.local", "-u", "admin", "-e", "SHOW TABLES"]
        );
    }

    #[test]
    fn command_template_is_alias_only() {
        let t = command_template(
            "mysql",
            "prod",
            &["-h".into(), "db".into(), "-e".into(), "SHOW TABLES".into()],
        );
        assert_eq!(t, "brokr mysql prod");
    }
}
