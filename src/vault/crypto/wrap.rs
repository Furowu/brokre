use crate::utils::errors::{BrokrError, Result};
use serde::{Deserialize, Serialize};

/// A DEK wrapped by a KEK using AES-256-GCM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    pub nonce: [u8; 12],
    pub ct: Vec<u8>, // 32-byte key + 16-byte tag = 48 bytes
}

pub fn wrap_dek(dek: &[u8; 32], kek: &[u8; 32]) -> WrappedKey {
    let (nonce, ct) = super::aead::aead_encrypt(kek, dek);
    WrappedKey { nonce, ct }
}

pub fn unwrap_dek(w: &WrappedKey, kek: &[u8; 32]) -> Result<[u8; 32]> {
    let pt = super::aead::aead_decrypt(kek, &w.nonce, &w.ct)?;
    let bytes = pt.expose();
    if bytes.len() != 32 {
        return Err(BrokrError::Crypto("unwrapped dek length mismatch".into()));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(bytes);
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dek = [7u8; 32];
        let kek = [9u8; 32];
        let w = wrap_dek(&dek, &kek);
        let unwrapped = unwrap_dek(&w, &kek).unwrap();
        assert_eq!(dek, unwrapped);
    }

    #[test]
    fn wrong_kek_fails() {
        let dek = [7u8; 32];
        let kek = [9u8; 32];
        let w = wrap_dek(&dek, &kek);
        assert!(unwrap_dek(&w, &[0u8; 32]).is_err());
    }

    #[test]
    fn one_bit_flip_fails() {
        let dek = [7u8; 32];
        let kek = [9u8; 32];
        let mut w = wrap_dek(&dek, &kek);
        w.ct[0] ^= 1;
        assert!(unwrap_dek(&w, &kek).is_err());
    }
}
