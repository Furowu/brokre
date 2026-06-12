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

    let host_alias = infer_host_alias(profile, args);
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
        host_alias: infer_host_alias(profile, args),
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

/// Split `host:port` / `[::1]:port` from manage UI host field (IPv6-safe).
pub fn parse_host_port(host: &str) -> (String, Option<u16>) {
    let host = host.trim();
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let addr = format!("[{}]", &host[1..end]);
            if let Some(p) = host[end + 1..].strip_prefix(':') {
                if let Ok(port) = p.parse::<u16>() {
                    if port > 0 {
                        return (addr, Some(port));
                    }
                }
            }
            return (addr, None);
        }
    }
    if let Some((h, p)) = host.split_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = p.parse::<u16>() {
                if port > 0 {
                    return (h.to_string(), Some(port));
                }
            }
        }
    }
    (host.to_string(), None)
}

fn openssh_port_flag(bin: &str) -> &'static str {
    match bin {
        "scp" | "sftp" => "-P",
        _ => "-p",
    }
}

/// Well-known default port per CLI (for omitting redundant `-p` / display).
pub fn default_port_for(profile: &str) -> Option<u16> {
    match profile.rsplit('/').next().unwrap_or(profile) {
        "ssh" | "scp" | "sftp" => Some(22),
        "mysql" | "mariadb" => Some(3306),
        "postgres" | "psql" => Some(5432),
        "redis" | "redis-cli" => Some(6379),
        "clickhouse" | "clickhouse-client" => Some(9000),
        "ftp" | "lftp" => Some(21),
        _ => None,
    }
}

fn read_flag_port(args: &[String], flags: &[&str]) -> Option<u16> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        for flag in flags {
            if a == *flag {
                if let Some(p) = iter.next() {
                    return p.parse().ok().filter(|&port: &u16| port > 0);
                }
            } else if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
                if !rest.is_empty() {
                    return rest.parse().ok().filter(|&port: &u16| port > 0);
                }
            }
        }
    }
    None
}

fn infer_ftp_port(args: &[String]) -> Option<u16> {
    let mut seen_host = false;
    for a in args {
        if a.starts_with('-') {
            continue;
        }
        if !seen_host {
            seen_host = true;
            continue;
        }
        if let Ok(p) = a.parse::<u16>() {
            return Some(p).filter(|&port| port > 0);
        }
        break;
    }
    None
}

/// Read port from saved argv for a profile.
pub fn infer_cli_port(profile: &str, args: &[String]) -> Option<u16> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    match bin {
        "ssh" | "scp" | "sftp" => {
            read_flag_port(args, &[openssh_port_flag(bin)])
        }
        "mysql" | "mariadb" => read_flag_port(args, &["-P", "--port"]),
        "postgres" | "psql" | "redis" | "redis-cli" | "lftp" => {
            read_flag_port(args, &["-p", "--port"])
        }
        "clickhouse" | "clickhouse-client" => read_flag_port(args, &["--port"]),
        "ftp" => infer_ftp_port(args),
        _ => read_flag_port(args, &["-p", "-P", "--port"]),
    }
}

/// Host label for list / fuzzy match; includes `:port` when not the CLI default.
pub fn infer_host_alias(profile: &str, args: &[String]) -> Option<String> {
    let host = infer_host(profile, args)?;
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    match infer_cli_port(profile, args) {
        Some(port) if default_port_for(bin).is_none_or(|d| d != port) => {
            Some(format!("{host}:{port}"))
        }
        _ => Some(host),
    }
}

fn push_port_args(args: &mut Vec<String>, bin: &str, port: Option<u16>) {
    let Some(p) = port else {
        return;
    };
    let default = default_port_for(bin);
    if default.is_some_and(|d| d == p) {
        return;
    }
    match bin {
        "ssh" | "scp" | "sftp" => {
            args.push(openssh_port_flag(bin).into());
            args.push(p.to_string());
        }
        "mysql" | "mariadb" => {
            args.push("-P".into());
            args.push(p.to_string());
        }
        "postgres" | "psql" | "redis" | "redis-cli" | "lftp" => {
            args.push("-p".into());
            args.push(p.to_string());
        }
        "clickhouse" | "clickhouse-client" => {
            args.push(format!("--port={p}"));
        }
        "ftp" => {
            args.push(p.to_string());
        }
        _ => {
            args.push("-p".into());
            args.push(p.to_string());
        }
    }
}

/// Build `saved_args` from manage form fields.
pub fn build_saved_args(
    profile: &str,
    host: &str,
    user: Option<&str>,
    extra: &[String],
    port: Option<u16>,
) -> Vec<String> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    let (host, host_port) = parse_host_port(host);
    let port = port.or(host_port);
    let mut args = Vec::new();
    match bin {
        "ssh" | "scp" | "sftp" => {
            push_port_args(&mut args, bin, port);
            if let Some(u) = user.filter(|s| !s.is_empty()) {
                args.push(format!("{}@{}", u, host));
            } else {
                args.push(host);
            }
        }
        "mysql" | "mariadb" => {
            args.push("-h".into());
            args.push(host);
            push_port_args(&mut args, bin, port);
            if let Some(u) = user.filter(|s| !s.is_empty()) {
                args.push("-u".into());
                args.push(u.to_string());
            }
        }
        "postgres" | "psql" => {
            args.push("-h".into());
            args.push(host);
            push_port_args(&mut args, bin, port);
            if let Some(u) = user.filter(|s| !s.is_empty()) {
                args.push("-U".into());
                args.push(u.to_string());
            }
        }
        "redis" | "redis-cli" => {
            args.push("-h".into());
            args.push(host);
            push_port_args(&mut args, bin, port);
        }
        "clickhouse" | "clickhouse-client" => {
            args.push(format!("--host={host}"));
            push_port_args(&mut args, bin, port);
        }
        "ftp" => {
            args.push(host);
            push_port_args(&mut args, bin, port);
        }
        "lftp" => {
            push_port_args(&mut args, bin, port);
            args.push(host);
        }
        _ => {
            push_port_args(&mut args, bin, port);
            args.push(host);
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
                    let (host, _) = parse_host_port(host);
                    return Some(host);
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
                    if let Some(h) = iter.next() {
                        let (host, _) = parse_host_port(h);
                        return Some(host);
                    }
                }
                if let Some(rest) = a.strip_prefix("--host=") {
                    let (host, _) = parse_host_port(rest);
                    return Some(host);
                }
            }
            None
        }
        "ftp" | "lftp" => {
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                let (host, _) = parse_host_port(a);
                return Some(host);
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
        let args = build_saved_args("ftp", "ftp.example.com", None, &[], None);
        assert_eq!(args, vec!["ftp.example.com"]);
    }

    #[test]
    fn build_saved_args_ssh() {
        let args = build_saved_args("ssh", "10.0.0.1", Some("root"), &[], None);
        assert_eq!(args, vec!["root@10.0.0.1"]);
    }

    #[test]
    fn build_saved_args_ssh_with_port() {
        let args = build_saved_args("ssh", "10.0.0.1", Some("root"), &[], Some(9000));
        assert_eq!(args, vec!["-p", "9000", "root@10.0.0.1"]);
    }

    #[test]
    fn build_saved_args_scp_uses_capital_p() {
        let args = build_saved_args("scp", "10.0.0.1", Some("root"), &[], Some(2222));
        assert_eq!(args, vec!["-P", "2222", "root@10.0.0.1"]);
    }

    #[test]
    fn parse_host_port_splits_ipv4_suffix() {
        assert_eq!(
            parse_host_port("198.51.100.88:9000"),
            ("198.51.100.88".into(), Some(9000))
        );
    }

    #[test]
    fn parse_host_port_leaves_ipv6_untouched() {
        assert_eq!(
            parse_host_port("2001:db8::1"),
            ("2001:db8::1".into(), None)
        );
    }

    #[test]
    fn infer_host_alias_includes_non_default_port() {
        let args = vec!["-p".into(), "9000".into(), "root@10.0.0.1".into()];
        assert_eq!(
            infer_host_alias("ssh", &args).as_deref(),
            Some("10.0.0.1:9000")
        );
    }

    #[test]
    fn build_saved_args_mysql_with_port() {
        let args = build_saved_args("mysql", "db.local", Some("u"), &[], Some(3307));
        assert_eq!(
            args,
            vec!["-h", "db.local", "-P", "3307", "-u", "u"]
        );
    }

    #[test]
    fn build_saved_args_psql_with_port() {
        let args = build_saved_args("psql", "db.local", Some("u"), &[], Some(5433));
        assert_eq!(
            args,
            vec!["-h", "db.local", "-p", "5433", "-U", "u"]
        );
    }

    #[test]
    fn build_saved_args_redis_with_port() {
        let args = build_saved_args("redis-cli", "127.0.0.1", None, &[], Some(6380));
        assert_eq!(args, vec!["-h", "127.0.0.1", "-p", "6380"]);
    }

    #[test]
    fn build_saved_args_clickhouse_with_port() {
        let args = build_saved_args("clickhouse-client", "ch.local", None, &[], Some(9440));
        assert_eq!(
            args,
            vec!["--host=ch.local", "--port=9440"]
        );
    }

    #[test]
    fn build_saved_args_ftp_with_port() {
        let args = build_saved_args("ftp", "ftp.example.com", None, &[], Some(2121));
        assert_eq!(args, vec!["ftp.example.com", "2121"]);
    }

    #[test]
    fn build_saved_args_lftp_with_port() {
        let args = build_saved_args("lftp", "ftp.example.com", None, &[], Some(2121));
        assert_eq!(args, vec!["-p", "2121", "ftp.example.com"]);
    }

    #[test]
    fn build_saved_args_splits_host_port_in_field() {
        let args = build_saved_args("mysql", "db.local:3307", Some("u"), &[], None);
        assert_eq!(
            args,
            vec!["-h", "db.local", "-P", "3307", "-u", "u"]
        );
    }

    #[test]
    fn infer_cli_port_mysql_capital_p() {
        let args = vec!["-h".into(), "db".into(), "-P".into(), "3307".into()];
        assert_eq!(infer_cli_port("mysql", &args), Some(3307));
    }

    #[test]
    fn build_saved_args_mysql() {
        let args = build_saved_args(
            "mysql",
            "db.local",
            Some("admin"),
            &["-e".into(), "SHOW TABLES".into()],
            None,
        );
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
