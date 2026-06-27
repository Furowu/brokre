use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::bastion_registry_path;
use crate::vault::model::SecretRecord;
use crate::vault::store::VaultStore;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;

pub const MAX_BASTIONS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BastionEntry {
    pub alias: String,
    pub enabled_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_alias: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    bastions: Vec<BastionEntry>,
}

pub fn load_registry() -> Result<Vec<BastionEntry>> {
    let path = bastion_registry_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = fs::read_to_string(&path).map_err(BrokreError::Io)?;
    let file: RegistryFile = serde_json::from_str(&data)
        .map_err(|e| BrokreError::Vault(format!("bastion registry: {e}")))?;
    Ok(file.bastions)
}

fn save_registry(entries: &[BastionEntry]) -> Result<()> {
    let path = bastion_registry_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(BrokreError::Io)?;
    }
    let file = RegistryFile {
        bastions: entries.to_vec(),
    };
    let data = serde_json::to_string_pretty(&file)
        .map_err(|e| BrokreError::Vault(format!("bastion registry serialize: {e}")))?;
    fs::write(&path, data).map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn is_bastion_alias(alias: &str) -> bool {
    load_registry()
        .ok()
        .map(|entries| entries.iter().any(|e| e.alias == alias))
        .unwrap_or(false)
}

pub fn is_registered_bastion(alias: &str) -> bool {
    is_bastion_alias(alias)
}

pub fn list_bastions() -> Result<Vec<BastionEntry>> {
    load_registry()
}

pub fn enable_bastion(alias: &str) -> Result<BastionEntry> {
    if !SecretRecord::validate_name(alias) {
        return Err(BrokreError::Vault(format!(
            "invalid bastion alias: {alias}"
        )));
    }
    let store = VaultStore::open()?;
    let rec = store.get("ssh", alias)?.ok_or_else(|| {
        BrokreError::Vault(format!(
            "no ssh alias '{alias}' — save it first with `brokre ssh {alias}`"
        ))
    })?;
    let mut entries = load_registry()?;
    if let Some(existing) = entries.iter().find(|e| e.alias == alias) {
        return Ok(existing.clone());
    }
    if entries.len() >= max_bastions() {
        return Err(BrokreError::Cli(format!(
            "bastion limit reached (max {})",
            max_bastions()
        )));
    }
    let entry = BastionEntry {
        alias: alias.to_string(),
        enabled_at: Utc::now(),
        host_alias: rec.host_alias.clone(),
    };
    entries.push(entry.clone());
    save_registry(&entries)?;
    Ok(entry)
}

pub fn disable_bastion(alias: &str) -> Result<bool> {
    let mut entries = load_registry()?;
    let before = entries.len();
    entries.retain(|e| e.alias != alias);
    if entries.len() == before {
        return Ok(false);
    }
    save_registry(&entries)?;
    Ok(true)
}

pub fn max_bastions() -> usize {
    std::env::var("BROKRE_BASTION_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_BASTIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_roundtrip_in_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let entries = vec![BastionEntry {
            alias: "b150".into(),
            enabled_at: Utc::now(),
            host_alias: Some("10.0.0.150".into()),
        }];
        let file = RegistryFile {
            bastions: entries.clone(),
        };
        fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        let data = fs::read_to_string(&path).unwrap();
        let parsed: RegistryFile = serde_json::from_str(&data).unwrap();
        assert_eq!(parsed.bastions, entries);
    }
}
