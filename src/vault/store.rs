use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::vault_path;
use crate::vault::model::SecretRecord;
use fs4::fs_std::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct VaultStore {
    path: PathBuf,
}

/// Holds `{data}.lock`. Dropping the `File` releases the OS lock.
///
/// Windows `LockFileEx` is mandatory: locking the data file and then reading
/// or renaming it through a second handle fails with os error 33. The sidecar
/// lock file is the portable equivalent of Unix `flock` on the data path.
struct SidecarLock {
    _file: File,
}

impl VaultStore {
    pub fn open() -> Result<Self> {
        let path = vault_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        Ok(Self { path })
    }

    fn lock_path(data: &Path) -> PathBuf {
        let mut s = data.as_os_str().to_os_string();
        s.push(".lock");
        PathBuf::from(s)
    }

    fn acquire_lock(&self, exclusive: bool) -> Result<SidecarLock> {
        let lock_path = Self::lock_path(&self.path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
        }
        if exclusive {
            file.lock_exclusive()?;
        } else {
            file.lock_shared()?;
        }
        Ok(SidecarLock { _file: file })
    }

    fn read_all(&self) -> Result<Vec<SecretRecord>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let file = OpenOptions::new().read(true).open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: SecretRecord =
                serde_json::from_str(&line).map_err(|e| BrokreError::Vault(e.to_string()))?;
            records.push(rec);
        }
        Ok(records)
    }

    fn write_all(&self, records: &[SecretRecord]) -> Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
            }
            for rec in records {
                let line =
                    serde_json::to_string(rec).map_err(|e| BrokreError::Vault(e.to_string()))?;
                writeln!(file, "{}", line)?;
            }
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SecretRecord>> {
        let _lock = self.acquire_lock(false)?;
        self.read_all()
    }

    pub fn get(&self, profile: &str, name: &str) -> Result<Option<SecretRecord>> {
        let records = self.list()?;
        Ok(records
            .into_iter()
            .find(|r| r.profile == profile && r.name == name))
    }

    pub fn get_by_id(&self, id: &Uuid) -> Result<Option<SecretRecord>> {
        let records = self.list()?;
        Ok(records.into_iter().find(|r| &r.id == id))
    }

    pub fn insert(&self, r: SecretRecord) -> Result<()> {
        if !SecretRecord::validate_name(&r.name) {
            return Err(BrokreError::Vault(format!("invalid name: {}", r.name)));
        }
        let _lock = self.acquire_lock(true)?;
        let mut records = self.read_all()?;
        if records
            .iter()
            .any(|rec| rec.profile == r.profile && rec.name == r.name)
        {
            return Err(BrokreError::Vault(format!(
                "record ({}, {}) already exists",
                r.profile, r.name
            )));
        }
        records.push(r);
        self.write_all(&records)
    }

    pub fn update(&self, r: SecretRecord) -> Result<()> {
        let _lock = self.acquire_lock(true)?;
        let mut records = self.read_all()?;
        let pos = records
            .iter()
            .position(|rec| rec.profile == r.profile && rec.name == r.name)
            .ok_or_else(|| {
                BrokreError::Vault(format!("record ({}, {}) not found", r.profile, r.name))
            })?;
        records[pos] = r;
        self.write_all(&records)
    }

    pub fn delete(&self, profile: &str, name: &str) -> Result<()> {
        let _lock = self.acquire_lock(true)?;
        let mut records = self.read_all()?;
        let old_len = records.len();
        records.retain(|rec| !(rec.profile == profile && rec.name == name));
        if records.len() == old_len {
            return Err(BrokreError::Vault(format!(
                "record ({}, {}) not found",
                profile, name
            )));
        }
        self.write_all(&records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_home::with_temp_brokre_home;
    use crate::vault::crypto::record::RecordCiphertext;
    use crate::vault::crypto::wrap::WrappedKey;
    use chrono::Utc;

    fn dummy_crypto() -> RecordCiphertext {
        RecordCiphertext {
            nonce: [0u8; 12],
            ct: vec![1, 2, 3, 4],
            dek_for_exec: WrappedKey {
                nonce: [0u8; 12],
                ct: vec![0u8; 48],
            },
            dek_for_reveal: WrappedKey {
                nonce: [0u8; 12],
                ct: vec![0u8; 48],
            },
            reveal_salt: [0u8; 16],
        }
    }

    fn dummy_record(name: &str) -> SecretRecord {
        SecretRecord {
            id: Uuid::new_v4(),
            profile: "ssh".into(),
            name: name.into(),
            labels: vec![],
            host_alias: None,
            binary: Some("ssh".into()),
            fields_meta: None,
            saved_args: vec!["root@198.51.100.10".into()],
            crypto: dummy_crypto(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            schema_version: 1,
            reveal_protected: false,
        }
    }

    #[test]
    #[serial_test::serial]
    fn insert_creates_sidecar_lock_not_locking_data_path() {
        with_temp_brokre_home(|| {
            let store = VaultStore::open().unwrap();
            store.insert(dummy_record("gw")).unwrap();

            let data = vault_path();
            let lock = VaultStore::lock_path(&data);
            assert!(data.is_file(), "vault data file");
            assert!(lock.is_file(), "sidecar lock file {}", lock.display());
            assert_eq!(lock, PathBuf::from(format!("{}.lock", data.display())));
            assert_ne!(lock, data);
        });
    }

    #[test]
    #[serial_test::serial]
    fn list_update_delete_roundtrip_with_sidecar_lock() {
        with_temp_brokre_home(|| {
            let store = VaultStore::open().unwrap();
            store.insert(dummy_record("a")).unwrap();
            store.insert(dummy_record("b")).unwrap();

            let listed = store.list().unwrap();
            assert_eq!(listed.len(), 2);

            let mut rec = store.get("ssh", "a").unwrap().expect("a");
            rec.last_used_at = Some(Utc::now());
            store.update(rec).unwrap();
            assert!(store.get("ssh", "a").unwrap().unwrap().last_used_at.is_some());

            store.delete("ssh", "b").unwrap();
            assert_eq!(store.list().unwrap().len(), 1);
            assert!(store.get("ssh", "b").unwrap().is_none());
        });
    }

    #[test]
    #[serial_test::serial]
    fn list_empty_vault_still_takes_sidecar_lock() {
        with_temp_brokre_home(|| {
            let store = VaultStore::open().unwrap();
            assert!(store.list().unwrap().is_empty());
            let lock = VaultStore::lock_path(&vault_path());
            assert!(lock.is_file());
        });
    }
}
