use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::vault_path;
use crate::vault::model::SecretRecord;
use fs4::fs_std::FileExt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use uuid::Uuid;

pub struct VaultStore {
    path: PathBuf,
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
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let file = OpenOptions::new().read(true).open(&self.path)?;
        file.lock_shared().map_err(BrokreError::Io)?;
        let result = self.read_all();
        let _ = file.unlock();
        result
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;
        file.lock_exclusive().map_err(BrokreError::Io)?;
        let mut records = self.read_all()?;
        if records
            .iter()
            .any(|rec| rec.profile == r.profile && rec.name == r.name)
        {
            let _ = file.unlock();
            return Err(BrokreError::Vault(format!(
                "record ({}, {}) already exists",
                r.profile, r.name
            )));
        }
        records.push(r);
        let result = self.write_all(&records);
        let _ = file.unlock();
        result
    }

    pub fn update(&self, r: SecretRecord) -> Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        file.lock_exclusive().map_err(BrokreError::Io)?;
        let mut records = self.read_all()?;
        let pos = records
            .iter()
            .position(|rec| rec.profile == r.profile && rec.name == r.name)
            .ok_or_else(|| {
                BrokreError::Vault(format!("record ({}, {}) not found", r.profile, r.name))
            })?;
        records[pos] = r;
        let result = self.write_all(&records);
        let _ = file.unlock();
        result
    }

    pub fn delete(&self, profile: &str, name: &str) -> Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        file.lock_exclusive().map_err(BrokreError::Io)?;
        let mut records = self.read_all()?;
        let old_len = records.len();
        records.retain(|rec| !(rec.profile == profile && rec.name == name));
        if records.len() == old_len {
            let _ = file.unlock();
            return Err(BrokreError::Vault(format!(
                "record ({}, {}) not found",
                profile, name
            )));
        }
        let result = self.write_all(&records);
        let _ = file.unlock();
        result
    }
}
