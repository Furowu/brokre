//! Bastion gate policy (default vs strict mode).

use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::bastion_policy_path;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BastionPolicy {
    /// When true, any brokre exec/list requires bastion unlock (not only bastion outbound).
    #[serde(default)]
    pub strict_mode: bool,
}

pub fn load_policy() -> BastionPolicy {
    let path = bastion_policy_path();
    if !path.exists() {
        return BastionPolicy::default();
    }
    match fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => BastionPolicy::default(),
    }
}

pub fn save_policy(policy: &BastionPolicy) -> Result<()> {
    let path = bastion_policy_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(BrokreError::Io)?;
    }
    let data = serde_json::to_string_pretty(policy)
        .map_err(|e| BrokreError::Runtime(format!("bastion policy serialize: {e}")))?;
    fs::write(&path, data).map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn strict_mode() -> bool {
    load_policy().strict_mode
}

pub fn set_strict_mode(enabled: bool) -> Result<()> {
    let mut policy = load_policy();
    policy.strict_mode = enabled;
    save_policy(&policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_home::with_temp_brokre_home;

    #[test]
    #[serial_test::serial]
    fn strict_mode_roundtrip() {
        with_temp_brokre_home(|| {
            assert!(!strict_mode());
            set_strict_mode(true).unwrap();
            assert!(strict_mode());
            set_strict_mode(false).unwrap();
            assert!(!strict_mode());
        });
    }
}
