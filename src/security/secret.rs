use std::fmt;
use zeroize::Zeroize;

/// Wrapper around Vec<u8> that zeroizes on drop and never exposes via Debug/Display.
#[derive(Clone)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        Self { inner: v }
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<SecretBytes len={}>", self.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Wrapper around String with the same secrecy guarantees.
#[derive(Clone)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    pub fn expose(&self) -> &str {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn into_bytes(mut self) -> SecretBytes {
        let s = std::mem::take(&mut self.inner);
        SecretBytes::new(s.into_bytes())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<SecretString len={}>", self.len())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak() {
        let s = SecretBytes::new(vec![1, 2, 3]);
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains('\x01'));
        assert!(dbg.contains("len=3"));
    }

    #[test]
    fn secret_string_debug_masked() {
        let s = SecretString::new("password".to_string());
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains("password"));
        assert!(dbg.contains("len=8"));
    }
}
