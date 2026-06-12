use rand::RngCore;

/// 32-byte URL-safe session token (hex-encoded for transport).
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn extract_bearer(auth_header: Option<&str>) -> Option<&str> {
    auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

pub fn token_matches(expected: &str, provided: Option<&str>) -> bool {
    match provided {
        Some(p) => constant_time_eq(expected.as_bytes(), p.as_bytes()),
        None => false,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_extraction() {
        assert_eq!(
            extract_bearer(Some("Bearer abc123")),
            Some("abc123")
        );
        assert_eq!(extract_bearer(Some("Basic x")), None);
    }

    #[test]
    fn token_match_constant_time() {
        assert!(token_matches("deadbeef", Some("deadbeef")));
        assert!(!token_matches("deadbeef", Some("deadbeeg")));
    }
}
