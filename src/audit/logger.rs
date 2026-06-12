use crate::security::hardening::HardeningReport;
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

pub const HMAC_VERSION_LEGACY: u8 = 1;
pub const HMAC_VERSION_CURRENT: u8 = 2;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardening: Option<HardeningReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injector_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injector_dur_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injector_outcome: Option<String>,
    /// HMAC canonicalization version (`1` = legacy, `2` = full payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hmac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

#[derive(Serialize)]
struct HmacPayloadV2<'a> {
    ts: &'a str,
    sid: &'a str,
    action: &'a str,
    profile: &'a str,
    name: &'a str,
    exit: Option<i32>,
    dur_ms: Option<u64>,
    args_redacted: &'a [String],
    hardening: Option<&'a HardeningReport>,
    injector_pid: Option<u32>,
    injector_dur_ms: Option<u64>,
    injector_outcome: Option<&'a str>,
}

fn hmac_with_key(key: &[u8; 32], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn compute_hmac_v1(event: &AuditEvent, key: &[u8; 32]) -> String {
    let data = format!(
        "{}:{}:{}:{}:{:?}:{:?}",
        event.ts, event.sid, event.action, event.profile, event.exit, event.dur_ms
    );
    hmac_with_key(key, data.as_bytes())
}

fn compute_hmac_v2(event: &AuditEvent, key: &[u8; 32]) -> String {
    let payload = HmacPayloadV2 {
        ts: &event.ts,
        sid: &event.sid,
        action: &event.action,
        profile: &event.profile,
        name: &event.name,
        exit: event.exit,
        dur_ms: event.dur_ms,
        args_redacted: &event.args_redacted,
        hardening: event.hardening.as_ref(),
        injector_pid: event.injector_pid,
        injector_dur_ms: event.injector_dur_ms,
        injector_outcome: event.injector_outcome.as_deref(),
    };
    let data = serde_json::to_vec(&payload).expect("HMAC payload serialization");
    hmac_with_key(key, &data)
}

fn compute_hmac(event: &AuditEvent, key: &[u8; 32]) -> String {
    match event.hmac_version {
        Some(HMAC_VERSION_CURRENT) => compute_hmac_v2(event, key),
        _ => compute_hmac_v1(event, key),
    }
}

pub fn append(event: &mut AuditEvent, hmac_key: &[u8; 32]) -> Result<()> {
    event.hmac_version = Some(HMAC_VERSION_CURRENT);
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
        .map_err(BrokrError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    writeln!(file, "{}", line).map_err(BrokrError::Io)?;
    file.sync_all().map_err(BrokrError::Io)?;
    Ok(())
}

pub fn verify_chain(path: &Path, hmac_key: &[u8; 32]) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(BrokrError::Io)?;
    let reader = BufReader::new(file);
    let mut prev_hmac: Option<String> = None;
    for line in reader.lines() {
        let line = line.map_err(BrokrError::Io)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample_event(action: &str, name: &str) -> AuditEvent {
        AuditEvent {
            ts: "2026-01-01T00:00:00Z".into(),
            sid: "test-sid".into(),
            action: action.into(),
            profile: "ssh".into(),
            name: name.into(),
            exit: Some(0),
            dur_ms: Some(42),
            args_redacted: vec!["<REDACTED>".into()],
            hardening: None,
            injector_pid: None,
            injector_dur_ms: None,
            injector_outcome: None,
            hmac_version: None,
            prev_hmac: None,
            hmac: None,
        }
    }

    #[test]
    fn hmac_v2_tamper_on_name_fails_verify() {
        let key = [7u8; 32];
        let mut ev = sample_event("rm/success", "prod");
        ev.hmac_version = Some(HMAC_VERSION_CURRENT);
        ev.hmac = Some(compute_hmac(&ev, &key));
        let line = serde_json::to_string(&ev).unwrap();
        let tampered = line.replace("\"name\":\"prod\"", "\"name\":\"other\"");
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), tampered).unwrap();
        assert!(verify_chain(tmp.path(), &key).is_err());
    }

    #[test]
    fn legacy_hmac_still_verifies() {
        let key = [9u8; 32];
        let mut ev = sample_event("exec", "host1");
        ev.hmac_version = None;
        ev.hmac = Some(compute_hmac_v1(&ev, &key));
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&ev).unwrap()).unwrap();
        assert!(verify_chain(tmp.path(), &key).is_ok());
    }
}
