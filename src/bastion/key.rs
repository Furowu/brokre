use crate::security::secret::SecretString;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::bastion_key_path;
use crate::vault::crypto::kdf::{derive_reveal_key, new_salt};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BastionKeyFile {
    pub salt: [u8; 16],
    pub verifier: [u8; 32],
    pub created_at: String,
}

pub fn key_is_set() -> bool {
    bastion_key_path().exists()
}

pub fn load_key_file() -> Result<Option<BastionKeyFile>> {
    let path = bastion_key_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path).map_err(BrokreError::Io)?;
    let file: BastionKeyFile = serde_json::from_str(&data)
        .map_err(|e| BrokreError::Crypto(format!("bastion key: {e}")))?;
    Ok(Some(file))
}

pub fn set_bastion_key(passphrase: &SecretString) -> Result<()> {
    if passphrase.is_empty() {
        return Err(BrokreError::Crypto("empty bastion key".into()));
    }
    let salt = new_salt();
    let derived = derive_reveal_key(passphrase, &salt)?;
    let file = BastionKeyFile {
        salt,
        verifier: derived,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let path = bastion_key_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(BrokreError::Io)?;
    }
    let data = serde_json::to_string_pretty(&file)
        .map_err(|e| BrokreError::Crypto(format!("bastion key serialize: {e}")))?;
    fs::write(&path, data).map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn verify_bastion_key(passphrase: &SecretString) -> Result<bool> {
    let Some(file) = load_key_file()? else {
        return Err(BrokreError::PolicyDenied);
    };
    let derived = derive_reveal_key(passphrase, &file.salt)?;
    Ok(constant_time_eq(&derived, &file.verifier))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
