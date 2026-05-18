use crate::utils::errors::{BrokrError, Result};
use crate::utils::mask::redact;
use crate::utils::paths::audit_path;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    pub sid: String,
    pub action: String,
    pub profile: String,
    pub name: String,
    pub exit: Option<i32>,
    pub dur_ms: Option<u64>,
    pub args_redacted: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hmac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

fn compute_hmac(event: &AuditEvent, key: &[u8; 32]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    let data = format!(
        "{}:{}:{}:{}:{:?}:{:?}",
        event.ts, event.sid, event.action, event.profile, event.exit, event.dur_ms
    );
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

pub fn append(event: &mut AuditEvent, hmac_key: &[u8; 32]) -> Result<()> {
    let path = audit_path();
    let mut prev_hmac = None;
    if path.exists() {
        if let Ok(file) = OpenOptions::new().read(true).open(&path) {
            let reader = BufReader::new(file);
            if let Some(Ok(last)) = reader.lines().last() {
                if let Ok(last_ev) = serde_json::from_str::<AuditEvent>(&last) {
                    prev_hmac = last_ev.hmac;
                }
            }
        }
    }
    event.prev_hmac = prev_hmac.clone();
    event.hmac = Some(compute_hmac(event, hmac_key));

    let line = serde_json::to_string(event).map_err(|e| BrokrError::Audit(e.to_string()))?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .map_err(|e| BrokrError::Io(e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    writeln!(file, "{}", line).map_err(|e| BrokrError::Io(e))?;
    file.sync_all().map_err(|e| BrokrError::Io(e))?;
    Ok(())
}

pub fn verify_chain(path: &Path, hmac_key: &[u8; 32]) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| BrokrError::Io(e))?;
    let reader = BufReader::new(file);
    let mut prev_hmac: Option<String> = None;
    for line in reader.lines() {
        let line = line.map_err(|e| BrokrError::Io(e))?;
        let event: AuditEvent =
            serde_json::from_str(&line).map_err(|e| BrokrError::Audit(e.to_string()))?;
        if event.prev_hmac != prev_hmac {
            return Err(BrokrError::Audit("chain broken: prev_hmac mismatch".into()));
        }
        let expected = compute_hmac(&event, hmac_key);
        if event.hmac.as_ref() != Some(&expected) {
            return Err(BrokrError::Audit("chain broken: hmac mismatch".into()));
        }
        prev_hmac = event.hmac;
    }
    Ok(())
}

pub fn redact_args(args: &[String]) -> Vec<String> {
    args.iter().map(|a| redact(a)).collect()
}
