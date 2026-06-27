use crate::security::hardening::HardeningReport;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::mask::redact;
use crate::utils::paths::audit_path;
use fs4::fs_std::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub const HMAC_VERSION_LEGACY: u8 = 1;
pub const HMAC_VERSION_V2: u8 = 2;
pub const HMAC_VERSION_V3: u8 = 3;
pub const HMAC_VERSION_V4: u8 = 4;

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
    /// Origin of the event: `cli`, `mcp`, or `manage`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Bastion route chain for routed exec/list (e.g. `["b150"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Vec<String>>,
    /// Primary bastion hop for routed operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion: Option<String>,
    /// HMAC canonicalization version (`1` = legacy, `2` = full payload, `3` = + source, `4` = + route/bastion).
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

#[derive(Serialize)]
struct HmacPayloadV4<'a> {
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
    source: Option<&'a str>,
    route: Option<&'a [String]>,
    bastion: Option<&'a str>,
}

#[derive(Serialize)]
struct HmacPayloadV3<'a> {
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
    source: Option<&'a str>,
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

fn compute_hmac_v3(event: &AuditEvent, key: &[u8; 32]) -> String {
    let payload = HmacPayloadV3 {
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
        source: event.source.as_deref(),
    };
    let data = serde_json::to_vec(&payload).expect("HMAC payload serialization");
    hmac_with_key(key, &data)
}

pub fn compute_hmac_for_append(event: &AuditEvent, key: &[u8; 32]) -> String {
    compute_hmac(event, key)
}

fn compute_hmac_v4(event: &AuditEvent, key: &[u8; 32]) -> String {
    let payload = HmacPayloadV4 {
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
        source: event.source.as_deref(),
        route: event.route.as_deref(),
        bastion: event.bastion.as_deref(),
    };
    let data = serde_json::to_vec(&payload).expect("HMAC payload serialization");
    hmac_with_key(key, &data)
}

fn compute_hmac(event: &AuditEvent, key: &[u8; 32]) -> String {
    match event.hmac_version {
        Some(HMAC_VERSION_V4) => compute_hmac_v4(event, key),
        Some(HMAC_VERSION_V3) => compute_hmac_v3(event, key),
        Some(HMAC_VERSION_V2) => compute_hmac_v2(event, key),
        _ => compute_hmac_v1(event, key),
    }
}

/// Parse one or more JSON audit events from a single log line.
/// Tolerates legacy corruption where concurrent appends merged two records.
pub fn events_from_line(line: &str) -> Vec<AuditEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut events = Vec::new();
    let stream = serde_json::Deserializer::from_str(trimmed).into_iter::<AuditEvent>();
    for result in stream {
        match result {
            Ok(ev) => events.push(ev),
            Err(_) => break,
        }
    }
    events
}

/// Audit source for CLI exec paths (`mcp` when spawned from MCP, `bastion` when routed).
pub fn exec_audit_source() -> String {
    if std::env::var_os("BROKRE_BASTION_SOURCE").is_some() {
        "bastion".into()
    } else if std::env::var_os("BROKRE_MCP_EXEC").is_some() {
        "mcp".into()
    } else {
        "cli".into()
    }
}

pub fn append(event: &mut AuditEvent, hmac_key: &[u8; 32]) -> Result<()> {
    event.hmac_version = Some(if event.route.is_some() || event.bastion.is_some() {
        HMAC_VERSION_V4
    } else if event.source.is_some() {
        HMAC_VERSION_V3
    } else {
        HMAC_VERSION_V2
    });
    let path = audit_path();
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)
        .map_err(BrokreError::Io)?;
    file.lock_exclusive().map_err(BrokreError::Io)?;

    let prev_hmac = {
        let reader = BufReader::new(&file);
        reader
            .lines()
            .map_while(|l| l.ok())
            .last()
            .and_then(|last| {
                events_from_line(&last)
                    .last()
                    .and_then(|ev| ev.hmac.clone())
            })
    };
    event.prev_hmac = prev_hmac;
    event.hmac = Some(compute_hmac(event, hmac_key));

    let line = serde_json::to_string(event).map_err(|e| BrokreError::Audit(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    writeln!(file, "{}", line).map_err(BrokreError::Io)?;
    file.sync_all().map_err(BrokreError::Io)?;
    let _ = file.unlock();
    Ok(())
}

pub fn verify_chain(path: &Path, hmac_key: &[u8; 32]) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(BrokreError::Io)?;
    let reader = BufReader::new(file);
    let mut prev_hmac: Option<String> = None;
    for line in reader.lines() {
        let line = line.map_err(BrokreError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let events = events_from_line(&line);
        if events.is_empty() {
            return Err(BrokreError::Audit("invalid audit line".into()));
        }
        for event in events {
            if event.prev_hmac != prev_hmac {
                return Err(BrokreError::Audit(
                    "chain broken: prev_hmac mismatch".into(),
                ));
            }
            let expected = compute_hmac(&event, hmac_key);
            if event.hmac.as_ref() != Some(&expected) {
                return Err(BrokreError::Audit("chain broken: hmac mismatch".into()));
            }
            prev_hmac = event.hmac;
        }
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
            source: None,
            route: None,
            bastion: None,
            hmac_version: None,
            prev_hmac: None,
            hmac: None,
        }
    }

    #[test]
    fn hmac_v2_tamper_on_name_fails_verify() {
        let key = [7u8; 32];
        let mut ev = sample_event("rm/success", "prod");
        ev.hmac_version = Some(HMAC_VERSION_V2);
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

    #[test]
    fn hmac_v3_with_source_verifies() {
        let key = [3u8; 32];
        let mut ev = sample_event("exec", "prod");
        ev.source = Some("mcp".into());
        ev.hmac_version = Some(HMAC_VERSION_V3);
        ev.hmac = Some(compute_hmac(&ev, &key));
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&ev).unwrap()).unwrap();
        assert!(verify_chain(tmp.path(), &key).is_ok());
    }

    #[test]
    fn hmac_v3_tamper_on_source_fails_verify() {
        let key = [3u8; 32];
        let mut ev = sample_event("exec", "prod");
        ev.source = Some("mcp".into());
        ev.hmac_version = Some(HMAC_VERSION_V3);
        ev.hmac = Some(compute_hmac(&ev, &key));
        let line = serde_json::to_string(&ev).unwrap();
        let tampered = line.replace("\"source\":\"mcp\"", "\"source\":\"cli\"");
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), tampered).unwrap();
        assert!(verify_chain(tmp.path(), &key).is_err());
    }

    #[test]
    fn events_from_line_parses_concatenated_records() {
        let key = [1u8; 32];
        let mut a = sample_event("exec", "a");
        a.hmac_version = Some(HMAC_VERSION_V2);
        a.hmac = Some(compute_hmac(&a, &key));
        let mut b = sample_event("exec", "b");
        b.hmac_version = Some(HMAC_VERSION_V2);
        b.hmac = Some(compute_hmac(&b, &key));
        let line = format!(
            "{}{}",
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        let parsed = events_from_line(&line);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "a");
        assert_eq!(parsed[1].name, "b");
    }

    #[test]
    fn hmac_v4_with_route_bastion_verifies() {
        let key = [4u8; 32];
        let mut ev = sample_event("exec", "b150::db");
        ev.source = Some("bastion".into());
        ev.route = Some(vec!["b150".into()]);
        ev.bastion = Some("b150".into());
        ev.hmac_version = Some(HMAC_VERSION_V4);
        ev.hmac = Some(compute_hmac(&ev, &key));
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), serde_json::to_string(&ev).unwrap()).unwrap();
        assert!(verify_chain(tmp.path(), &key).is_ok());
    }
}
