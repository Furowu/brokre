use crate::security::secret::SecretBytes;
use crate::utils::errors::{BrokreError, Result};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid 32-byte key");
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption should not fail");
    (nonce_bytes, ciphertext)
}

pub fn aead_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<SecretBytes> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| BrokreError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|_| BrokreError::Crypto("decryption failed: tampered or wrong key".into()))?;
    Ok(SecretBytes::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [42u8; 32];
        let msg = b"hello world";
        let (nonce, ct) = aead_encrypt(&key, msg);
        let pt = aead_decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt.expose(), msg);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [42u8; 32];
        let msg = b"hello world";
        let (nonce, ct) = aead_encrypt(&key, msg);
        let bad_key = [0u8; 32];
        assert!(aead_decrypt(&bad_key, &nonce, &ct).is_err());
    }

    #[test]
    fn one_bit_flip_fails() {
        let key = [42u8; 32];
        let msg = b"hello world";
        let (nonce, mut ct) = aead_encrypt(&key, msg);
        ct[0] ^= 1;
        assert!(aead_decrypt(&key, &nonce, &ct).is_err());
    }
}
