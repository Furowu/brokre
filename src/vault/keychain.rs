use crate::utils::errors::{BrokreError, Result};
use base64ct::Encoding;
use keyring::Entry;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

const SERVICE: &str = "brokre";
const MASTER_KEK_ACCOUNT: &str = "master_kek";
const AUDIT_HMAC_ACCOUNT: &str = "audit_hmac";

static FILE_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

fn fallback_path(account: &str) -> PathBuf {
    crate::utils::paths::brokre_home().join(format!(".{}", account))
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = base64ct::Base64::decode_vec(b64).map_err(|e| BrokreError::Crypto(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(BrokreError::Crypto("corrupt key length".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn gen_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
    key
}

fn allow_file_fallback() -> bool {
    // Explicit opt-in to file storage.
    if std::env::var("BROKRE_ALLOW_FILE_KEYCHAIN").is_ok() {
        return true;
    }
    // Explicit opt-in to keychain (overrides platform default).
    if std::env::var("BROKRE_USE_KEYCHAIN").is_ok() {
        return false;
    }
    // Default: macOS uses file storage to avoid Keychain authorization
    // dialogs on every run (ad-hoc-signed binaries trigger re-authorisation).
    // Linux uses the OS keychain (secret-service) which is non-interactive.
    cfg!(target_os = "macos")
}

/// When OS keyring is unavailable (headless Linux bastions), fall back to file
/// unless the user explicitly opted into keychain-only mode.
fn allow_auto_file_fallback_on_keyring_failure() -> bool {
    std::env::var("BROKRE_USE_KEYCHAIN").is_err()
}

fn warn_file_fallback_once() {
    if FILE_FALLBACK_WARNED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        eprintln!(
            "brokre: OS keychain unavailable — using file-based master key in ~/.brokre/ (mode 0600). \
             Set BROKRE_USE_KEYCHAIN=1 to require OS keychain."
        );
    }
}

fn persist_key_to_file(path: &PathBuf, b64: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, b64).map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn read_or_create_file_key(path: &PathBuf) -> Result<[u8; 32]> {
    if path.exists() {
        let contents = std::fs::read_to_string(path).map_err(BrokreError::Io)?;
        return decode_key(&contents);
    }
    let key = gen_key();
    let b64 = base64ct::Base64::encode_string(&key);
    persist_key_to_file(path, &b64)?;
    Ok(key)
}

/// Ensure Linux headless hosts can open the vault without manual env exports.
pub fn prepare_platform_storage() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("BROKRE_ALLOW_FILE_KEYCHAIN").is_none()
            && std::env::var_os("BROKRE_USE_KEYCHAIN").is_none()
        {
            // Routed exec and install.sh also set this; defaulting here covers
            // interactive `brokre ssh` / `brokre manage` on bastions.
            std::env::set_var("BROKRE_ALLOW_FILE_KEYCHAIN", "1");
        }
    }
}

fn get_or_init(account: &str) -> Result<[u8; 32]> {
    let path = fallback_path(account);

    // 1. If file fallback is allowed, use it exclusively.
    //    This avoids blocking on macOS keychain in headless / IDE-terminal
    //    environments where the Security Agent dialog cannot be displayed.
    if allow_file_fallback() {
        return read_or_create_file_key(&path);
    }

    let entry = Entry::new(SERVICE, account).map_err(|e| BrokreError::Vault(e.to_string()))?;

    // 2. Try OS keychain read.
    match entry.get_password() {
        Ok(pw) => return decode_key(&pw),
        Err(keyring::Error::NoEntry) => {}
        Err(_) => {}
    }

    // 3. No existing key — generate a fresh one.
    let key = gen_key();
    let b64 = base64ct::Base64::encode_string(&key);

    // 3a. Store in OS keychain.
    if entry.set_password(&b64).is_ok() {
        return Ok(key);
    }

    // 3b. Fallback to file when allowed or when keyring is unavailable on headless Linux.
    if allow_file_fallback() || allow_auto_file_fallback_on_keyring_failure() {
        if allow_auto_file_fallback_on_keyring_failure() && !allow_file_fallback() {
            warn_file_fallback_once();
        }
        persist_key_to_file(&path, &b64)?;
        return Ok(key);
    }

    Err(BrokreError::Vault(
        "Platform secure storage failure: OS keychain unavailable. \
         On macOS file-based storage is used by default; \
         on Linux set BROKRE_ALLOW_FILE_KEYCHAIN=1 to opt-in."
            .into(),
    ))
}

pub fn get_or_init_master_kek() -> Result<[u8; 32]> {
    get_or_init(MASTER_KEK_ACCOUNT)
}

pub fn get_or_init_audit_hmac_key() -> Result<[u8; 32]> {
    get_or_init(AUDIT_HMAC_ACCOUNT)
}

pub fn rotate_master_kek() -> Result<()> {
    Err(BrokreError::Vault("rotate not implemented".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_home::with_temp_brokre_home;
    use std::env;

    #[test]
    fn file_fallback_when_explicitly_allowed() {
        with_temp_brokre_home(|| {
            std::env::set_var("BROKRE_ALLOW_FILE_KEYCHAIN", "1");
            let k1 = get_or_init_master_kek().unwrap();
            let k2 = get_or_init_master_kek().unwrap();
            assert_eq!(k1, k2);
            assert!(fallback_path(MASTER_KEK_ACCOUNT).exists());
        });
    }

    #[test]
    fn linux_prepare_sets_file_keychain_env() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let old = env::var_os("BROKRE_ALLOW_FILE_KEYCHAIN");
        env::remove_var("BROKRE_ALLOW_FILE_KEYCHAIN");
        prepare_platform_storage();
        assert_eq!(
            env::var_os("BROKRE_ALLOW_FILE_KEYCHAIN").as_deref(),
            Some(std::ffi::OsStr::new("1"))
        );
        match old {
            Some(v) => env::set_var("BROKRE_ALLOW_FILE_KEYCHAIN", v),
            None => env::remove_var("BROKRE_ALLOW_FILE_KEYCHAIN"),
        }
    }
}
