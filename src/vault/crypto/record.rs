use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::wrap::{unwrap_dek, wrap_dek, WrappedKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordCiphertext {
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
    pub dek_for_exec: WrappedKey,
    pub dek_for_reveal: WrappedKey,
    pub reveal_salt: [u8; 16],
}

pub fn encrypt_record(
    fields: &BTreeMap<String, SecretString>,
    master_kek: &[u8; 32],
    reveal_kek: &[u8; 32],
    reveal_salt: [u8; 16],
) -> RecordCiphertext {
    let mut dek = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dek);

    let plain_map: BTreeMap<String, String> = fields
        .iter()
        .map(|(k, v)| (k.clone(), v.expose().to_string()))
        .collect();
    let plaintext = serde_json::to_vec(&plain_map).expect("serialization should not fail");
    let (nonce, ct) = super::aead::aead_encrypt(&dek, &plaintext);

    RecordCiphertext {
        nonce,
        ct,
        dek_for_exec: wrap_dek(&dek, master_kek),
        dek_for_reveal: wrap_dek(&dek, reveal_kek),
        reveal_salt,
    }
}

pub fn decrypt_for_exec(
    rc: &RecordCiphertext,
    master_kek: &[u8; 32],
) -> Result<BTreeMap<String, SecretString>> {
    let dek = unwrap_dek(&rc.dek_for_exec, master_kek)?;
    let pt = super::aead::aead_decrypt(&dek, &rc.nonce, &rc.ct)?;
    let map: BTreeMap<String, String> =
        serde_json::from_slice(pt.expose()).map_err(|e| BrokrError::Crypto(e.to_string()))?;
    Ok(map
        .into_iter()
        .map(|(k, v)| (k, SecretString::new(v)))
        .collect())
}

pub fn decrypt_for_reveal(
    rc: &RecordCiphertext,
    reveal_kek: &[u8; 32],
) -> Result<BTreeMap<String, SecretString>> {
    let dek = unwrap_dek(&rc.dek_for_reveal, reveal_kek)?;
    let pt = super::aead::aead_decrypt(&dek, &rc.nonce, &rc.ct)?;
    let map: BTreeMap<String, String> =
        serde_json::from_slice(pt.expose()).map_err(|e| BrokrError::Crypto(e.to_string()))?;
    Ok(map
        .into_iter()
        .map(|(k, v)| (k, SecretString::new(v)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fields() -> BTreeMap<String, SecretString> {
        let mut m = BTreeMap::new();
        m.insert("user".into(), SecretString::new("alice".into()));
        m.insert("password".into(), SecretString::new("secret123".into()));
        m
    }

    #[test]
    fn round_trip_exec() {
        let fields = sample_fields();
        let master = [1u8; 32];
        let reveal = [2u8; 32];
        let salt = [3u8; 16];
        let rc = encrypt_record(&fields, &master, &reveal, salt);
        let decrypted = decrypt_for_exec(&rc, &master).unwrap();
        assert_eq!(decrypted["user"].expose(), "alice");
        assert_eq!(decrypted["password"].expose(), "secret123");
    }

    #[test]
    fn round_trip_reveal() {
        let fields = sample_fields();
        let master = [1u8; 32];
        let reveal = [2u8; 32];
        let salt = [3u8; 16];
        let rc = encrypt_record(&fields, &master, &reveal, salt);
        let decrypted = decrypt_for_reveal(&rc, &reveal).unwrap();
        assert_eq!(decrypted["password"].expose(), "secret123");
    }

    #[test]
    fn cross_key_fail() {
        let fields = sample_fields();
        let master = [1u8; 32];
        let reveal = [2u8; 32];
        let salt = [3u8; 16];
        let rc = encrypt_record(&fields, &master, &reveal, salt);
        assert!(decrypt_for_exec(&rc, &reveal).is_err());
        assert!(decrypt_for_reveal(&rc, &master).is_err());
    }

    #[test]
    fn exec_reveal_consistency() {
        let fields = sample_fields();
        let master = [1u8; 32];
        let reveal = [2u8; 32];
        let salt = [3u8; 16];
        let rc = encrypt_record(&fields, &master, &reveal, salt);
        let exec = decrypt_for_exec(&rc, &master).unwrap();
        let rev = decrypt_for_reveal(&rc, &reveal).unwrap();
        assert_eq!(exec["user"].expose(), rev["user"].expose());
        assert_eq!(exec["password"].expose(), rev["password"].expose());
    }

    #[test]
    fn round_trip_reveal_passphrase() {
        use crate::vault::crypto::kdf::{derive_reveal_key, new_salt};

        let fields = sample_fields();
        let master = [1u8; 32];
        let salt = new_salt();
        let pass = SecretString::new("my-reveal-pass".into());
        let reveal_kek = derive_reveal_key(&pass, &salt).unwrap();
        let rc = encrypt_record(&fields, &master, &reveal_kek, salt);
        let kek2 = derive_reveal_key(&pass, &rc.reveal_salt).unwrap();
        let decrypted = decrypt_for_reveal(&rc, &kek2).unwrap();
        assert_eq!(decrypted["password"].expose(), "secret123");
    }
}
