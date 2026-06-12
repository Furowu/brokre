use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use argon2::{Argon2, Params};
use rand::RngCore;

pub fn derive_reveal_key(passphrase: &SecretString, salt: &[u8; 16]) -> Result<[u8; 32]> {
    if passphrase.is_empty() {
        return Err(BrokrError::Crypto("empty passphrase".into()));
    }
    let params =
        Params::new(65536, 3, 1, Some(32)).map_err(|e| BrokrError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut hash = [0u8; 32];
    argon2
        .hash_password_into(passphrase.expose().as_bytes(), salt, &mut hash)
        .map_err(|e| BrokrError::Crypto(e.to_string()))?;
    Ok(hash)
}

pub fn new_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let salt = [1u8; 16];
        let pass = SecretString::new("my_pass".to_string());
        let k1 = derive_reveal_key(&pass, &salt).unwrap();
        let k2 = derive_reveal_key(&pass, &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_pass_different_key() {
        let salt = [1u8; 16];
        let k1 = derive_reveal_key(&SecretString::new("a".to_string()), &salt).unwrap();
        let k2 = derive_reveal_key(&SecretString::new("b".to_string()), &salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn empty_pass_err() {
        let salt = [1u8; 16];
        assert!(derive_reveal_key(&SecretString::new("".to_string()), &salt).is_err());
    }
}
