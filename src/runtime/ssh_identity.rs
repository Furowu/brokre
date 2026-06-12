//! Write a vault-stored SSH private key to a short-lived 0600 file for `ssh -i`.

use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use crate::utils::paths::run_dir;
use crate::vault::crypto::record::decrypt_for_exec;
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::model::SecretRecord;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub struct SecureKeyFile {
    pub path: PathBuf,
}

impl Drop for SecureKeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn record_has_private_key(rec: &SecretRecord) -> bool {
    rec.fields_meta
        .as_ref()
        .is_some_and(|m| m.iter().any(|f| f.name == "private_key"))
}

pub fn injectable_field_names(rec: &SecretRecord) -> Vec<String> {
    if let Some(meta) = &rec.fields_meta {
        return meta
            .iter()
            .filter(|f| f.secret && f.name != "private_key")
            .map(|f| f.name.clone())
            .collect();
    }
    vec!["password".into()]
}

pub fn validate_private_key_pem(pem: &str) -> bool {
    let t = pem.trim();
    (t.contains("BEGIN OPENSSH PRIVATE KEY") || t.contains("BEGIN RSA PRIVATE KEY")
        || t.contains("BEGIN EC PRIVATE KEY")
        || t.contains("BEGIN PRIVATE KEY")
        || t.contains("BEGIN DSA PRIVATE KEY"))
        && t.contains("END ")
}

/// Insert `-i <keyfile>` after leading flags, before the connection target.
pub fn insert_identity_arg(argv: &mut Vec<String>, key_path: &std::path::Path) {
    if argv.iter().any(|a| a == "-i" || a.starts_with("-i")) {
        return;
    }
    let pos = argv
        .iter()
        .position(|a| !a.starts_with('-'))
        .unwrap_or(argv.len());
    let p = key_path.display().to_string();
    argv.insert(pos, p);
    argv.insert(pos, "-i".into());
}

/// Decrypt `private_key`, write to `~/.brokr/run/`, return guard that deletes on drop.
///
/// **Security note (T1):** Unlike vault passwords (injector child), private keys are
/// decrypted in the parent process today. See `docs/HARDENING.md`.
pub fn materialize_identity(rec: &SecretRecord) -> Result<Option<SecureKeyFile>> {
    if !record_has_private_key(rec) {
        return Ok(None);
    }
    let master = get_or_init_master_kek()?;
    let fields = decrypt_for_exec(&rec.crypto, &master)?;
    let key = fields
        .get("private_key")
        .ok_or_else(|| BrokrError::Vault("record missing private_key field".into()))?;
    let path = write_key_file(key)?;
    Ok(Some(SecureKeyFile { path }))
}

fn write_key_file(key: &SecretString) -> Result<PathBuf> {
    let dir = run_dir();
    let path = dir.join(format!("id_{}", uuid::Uuid::new_v4()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(BrokrError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        file.write_all(key.expose().as_bytes())
            .map_err(BrokrError::Io)?;
        file.sync_all().map_err(BrokrError::Io)?;
    }
    Ok(path)
}

pub fn build_ssh_field_meta(
    auth_type: &str,
    has_key_passphrase: bool,
) -> Vec<crate::vault::model::FieldMeta> {
    let mut meta = Vec::new();
    match auth_type {
        "key" | "key_and_password" => {
            meta.push(crate::vault::model::FieldMeta {
                name: "private_key".into(),
                secret: true,
                hint: None,
            });
            if has_key_passphrase {
                meta.push(crate::vault::model::FieldMeta {
                    name: "key_passphrase".into(),
                    secret: true,
                    hint: None,
                });
            }
        }
        _ => {}
    }
    if auth_type == "password" || auth_type == "key_and_password" {
        meta.push(crate::vault::model::FieldMeta {
            name: "password".into(),
            secret: true,
            hint: None,
        });
    }
    meta
}

pub fn auth_methods_from_meta(meta: &[crate::vault::model::FieldMeta]) -> Vec<String> {
    let mut out = Vec::new();
    if meta.iter().any(|f| f.name == "private_key") {
        out.push("key".into());
    }
    if meta.iter().any(|f| f.name == "password") {
        out.push("password".into());
    }
    out
}

pub fn build_ssh_secret_fields(
    auth_type: &str,
    password: Option<SecretString>,
    private_key: Option<SecretString>,
    key_passphrase: Option<SecretString>,
) -> Result<BTreeMap<String, SecretString>> {
    let mut fields = BTreeMap::new();
    match auth_type {
        "password" => {
            let pw = password.ok_or_else(|| BrokrError::Vault("password is required".into()))?;
            if pw.is_empty() {
                return Err(BrokrError::Vault("password is required".into()));
            }
            fields.insert("password".into(), pw);
        }
        "key" => {
            let key = private_key.ok_or_else(|| BrokrError::Vault("private_key is required".into()))?;
            if key.is_empty() {
                return Err(BrokrError::Vault("private_key is required".into()));
            }
            if !validate_private_key_pem(key.expose()) {
                return Err(BrokrError::Vault("invalid private key PEM".into()));
            }
            fields.insert("private_key".into(), key);
            if let Some(kp) = key_passphrase.filter(|s| !s.is_empty()) {
                fields.insert("key_passphrase".into(), kp);
            }
        }
        "key_and_password" => {
            let key = private_key.ok_or_else(|| BrokrError::Vault("private_key is required".into()))?;
            let pw = password.ok_or_else(|| BrokrError::Vault("password is required".into()))?;
            if key.is_empty() || pw.is_empty() {
                return Err(BrokrError::Vault("private_key and password are required".into()));
            }
            if !validate_private_key_pem(key.expose()) {
                return Err(BrokrError::Vault("invalid private key PEM".into()));
            }
            fields.insert("private_key".into(), key);
            fields.insert("password".into(), pw);
            if let Some(kp) = key_passphrase.filter(|s| !s.is_empty()) {
                fields.insert("key_passphrase".into(), kp);
            }
        }
        other => {
            return Err(BrokrError::Vault(format!("unknown auth_type: {}", other)));
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_pem_markers() {
        assert!(validate_private_key_pem(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        ));
        assert!(!validate_private_key_pem("not a key"));
    }

    #[test]
    fn insert_identity_after_flags() {
        let mut argv = vec!["-v".into(), "user@host".into()];
        insert_identity_arg(&mut argv, std::path::Path::new("/tmp/k"));
        assert_eq!(
            argv,
            vec!["-v", "-i", "/tmp/k", "user@host"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }
}
