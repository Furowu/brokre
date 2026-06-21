use crate::audit::logger::{events_from_line, verify_chain, AuditEvent};
use crate::security::hardening::HardeningReport;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::audit_path;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    pub profile: Option<String>,
    pub name: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub bastion: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_newest_first")]
    pub newest_first: bool,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

fn default_newest_first() -> bool {
    true
}

impl AuditQuery {
    pub fn normalized(mut self) -> Self {
        if self.limit == 0 {
            self.limit = DEFAULT_LIMIT;
        }
        if self.limit > MAX_LIMIT {
            self.limit = MAX_LIMIT;
        }
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEventView {
    pub ts: String,
    pub sid: String,
    pub action: String,
    pub profile: String,
    pub name: String,
    pub exit: Option<i32>,
    pub dur_ms: Option<u64>,
    pub args_redacted: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardening: Option<HardeningReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injector_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injector_dur_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injector_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bastion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_version: Option<u8>,
}

impl From<AuditEvent> for AuditEventView {
    fn from(ev: AuditEvent) -> Self {
        Self {
            ts: ev.ts,
            sid: ev.sid,
            action: ev.action,
            profile: ev.profile,
            name: ev.name,
            exit: ev.exit,
            dur_ms: ev.dur_ms,
            args_redacted: ev.args_redacted,
            hardening: ev.hardening,
            injector_pid: ev.injector_pid,
            injector_dur_ms: ev.injector_dur_ms,
            injector_outcome: ev.injector_outcome,
            source: ev.source,
            route: ev.route,
            bastion: ev.bastion,
            hmac_version: ev.hmac_version,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditListResult {
    pub total_matched: usize,
    pub events: Vec<AuditEventView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyStats {
    pub ok: bool,
    pub count: usize,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
}

fn read_all_events(path: &Path) -> Result<Vec<AuditEvent>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(BrokreError::Io)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(BrokreError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let events = events_from_line(&line);
        if events.is_empty() {
            return Err(BrokreError::Audit("invalid audit line".into()));
        }
        out.extend(events);
    }
    Ok(out)
}

fn matches_action(event_action: &str, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    event_action == filter || event_action.starts_with(&format!("{filter}/"))
}

fn matches_filter(event: &AuditEvent, query: &AuditQuery) -> bool {
    if let Some(ref p) = query.profile {
        if event.profile != *p {
            return false;
        }
    }
    if let Some(ref n) = query.name {
        if event.name != *n {
            return false;
        }
    }
    if let Some(ref a) = query.action {
        if !matches_action(&event.action, a) {
            return false;
        }
    }
    if let Some(ref s) = query.source {
        if event.source.as_deref() != Some(s.as_str()) {
            return false;
        }
    }
    if let Some(ref b) = query.bastion {
        if event.bastion.as_deref() != Some(b.as_str()) {
            return false;
        }
    }
    if let Some(ref since) = query.since {
        if event.ts < *since {
            return false;
        }
    }
    if let Some(ref until) = query.until {
        if event.ts > *until {
            return false;
        }
    }
    true
}

pub fn list(query: AuditQuery) -> Result<AuditListResult> {
    list_from_path(&audit_path(), query)
}

pub fn list_from_path(path: &Path, query: AuditQuery) -> Result<AuditListResult> {
    let query = query.normalized();
    let mut matched: Vec<AuditEvent> = read_all_events(path)?
        .into_iter()
        .filter(|ev| matches_filter(ev, &query))
        .collect();

    if query.newest_first {
        matched.reverse();
    }

    let total_matched = matched.len();
    let page: Vec<AuditEventView> = matched
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(AuditEventView::from)
        .collect();

    Ok(AuditListResult {
        total_matched,
        events: page,
    })
}

pub fn verify_with_stats(path: &Path, hmac_key: &[u8; 32]) -> Result<VerifyStats> {
    if !path.exists() {
        return Ok(VerifyStats {
            ok: true,
            count: 0,
            first_ts: None,
            last_ts: None,
        });
    }
    verify_chain(path, hmac_key)?;
    let events = read_all_events(path)?;
    let count = events.len();
    let first_ts = events.first().map(|e| e.ts.clone());
    let last_ts = events.last().map(|e| e.ts.clone());
    Ok(VerifyStats {
        ok: true,
        count,
        first_ts,
        last_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::logger::HMAC_VERSION_V3;
    use tempfile::NamedTempFile;

    fn sample(path: &Path, action: &str, profile: &str, name: &str, source: Option<&str>) {
        let key = [1u8; 32];
        let mut ev = AuditEvent {
            ts: format!("2026-01-0{}T00:00:00Z", name.len()),
            sid: uuid::Uuid::new_v4().to_string(),
            action: action.into(),
            profile: profile.into(),
            name: name.into(),
            exit: Some(0),
            dur_ms: Some(10),
            args_redacted: vec!["<REDACTED>".into()],
            hardening: None,
            injector_pid: None,
            injector_dur_ms: None,
            injector_outcome: None,
            source: source.map(str::to_string),
            route: None,
            bastion: None,
            hmac_version: None,
            prev_hmac: None,
            hmac: None,
        };
        append_to_path(path, &mut ev, &key).unwrap();
    }

    fn append_to_path(path: &Path, event: &mut AuditEvent, hmac_key: &[u8; 32]) -> Result<()> {
        use crate::audit::logger::compute_hmac_for_append;
        if event.source.is_some() {
            event.hmac_version = Some(HMAC_VERSION_V3);
        } else {
            event.hmac_version = Some(crate::audit::logger::HMAC_VERSION_V2);
        }
        let mut prev_hmac = None;
        if path.exists() {
            if let Ok(file) = OpenOptions::new().read(true).open(path) {
                let reader = BufReader::new(file);
                if let Some(Ok(last)) = reader.lines().last() {
                    if let Ok(last_ev) = serde_json::from_str::<AuditEvent>(&last) {
                        prev_hmac = last_ev.hmac;
                    }
                }
            }
        }
        event.prev_hmac = prev_hmac;
        event.hmac = Some(compute_hmac_for_append(event, hmac_key));
        let line =
            serde_json::to_string(event).map_err(|e| BrokreError::Audit(e.to_string()))?;
        use std::io::Write;
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(BrokreError::Io)?;
        writeln!(file, "{}", line).map_err(BrokreError::Io)?;
        Ok(())
    }

    #[test]
    fn list_filters_profile_and_action_prefix() {
        let tmp = NamedTempFile::new().unwrap();
        sample(tmp.path(), "exec", "ssh", "a", Some("cli"));
        sample(tmp.path(), "exec/fresh", "ssh", "b", Some("cli"));
        sample(tmp.path(), "manage/create", "ssh", "c", Some("manage"));

        let q = AuditQuery {
            profile: Some("ssh".into()),
            action: Some("exec".into()),
            ..Default::default()
        };
        let res = list_from_path(tmp.path(), q).unwrap();
        assert_eq!(res.total_matched, 2);
    }

    #[test]
    fn list_pagination_and_newest_first() {
        let tmp = NamedTempFile::new().unwrap();
        sample(tmp.path(), "exec", "ssh", "1", None);
        sample(tmp.path(), "exec", "ssh", "2", None);
        sample(tmp.path(), "exec", "ssh", "3", None);

        let q = AuditQuery {
            limit: 1,
            offset: 1,
            newest_first: true,
            ..Default::default()
        };
        let res = list_from_path(tmp.path(), q).unwrap();
        assert_eq!(res.total_matched, 3);
        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].name, "2");
    }

    #[test]
    fn list_filters_source() {
        let tmp = NamedTempFile::new().unwrap();
        sample(tmp.path(), "exec", "ssh", "a", Some("mcp"));
        sample(tmp.path(), "exec", "ssh", "b", Some("cli"));

        let q = AuditQuery {
            source: Some("mcp".into()),
            ..Default::default()
        };
        let res = list_from_path(tmp.path(), q).unwrap();
        assert_eq!(res.total_matched, 1);
        assert_eq!(res.events[0].name, "a");
    }

    fn sample_with_bastion(
        path: &Path,
        action: &str,
        profile: &str,
        name: &str,
        source: Option<&str>,
        route: Option<Vec<String>>,
        bastion: Option<&str>,
    ) {
        let key = [1u8; 32];
        let mut ev = AuditEvent {
            ts: "2026-01-01T00:00:00Z".into(),
            sid: uuid::Uuid::new_v4().to_string(),
            action: action.into(),
            profile: profile.into(),
            name: name.into(),
            exit: Some(0),
            dur_ms: Some(10),
            args_redacted: vec!["<REDACTED>".into()],
            hardening: None,
            injector_pid: None,
            injector_dur_ms: None,
            injector_outcome: None,
            source: source.map(str::to_string),
            route,
            bastion: bastion.map(str::to_string),
            hmac_version: None,
            prev_hmac: None,
            hmac: None,
        };
        append_to_path(path, &mut ev, &key).unwrap();
    }

    #[test]
    fn list_filters_bastion_and_exposes_route_fields() {
        let tmp = NamedTempFile::new().unwrap();
        sample_with_bastion(
            tmp.path(),
            "exec",
            "ssh",
            "db",
            Some("bastion"),
            Some(vec!["b150".into()]),
            Some("b150"),
        );
        sample_with_bastion(
            tmp.path(),
            "exec",
            "ssh",
            "other",
            Some("cli"),
            None,
            None,
        );

        let q = AuditQuery {
            bastion: Some("b150".into()),
            ..Default::default()
        };
        let res = list_from_path(tmp.path(), q).unwrap();
        assert_eq!(res.total_matched, 1);
        assert_eq!(res.events[0].bastion.as_deref(), Some("b150"));
        assert_eq!(
            res.events[0].route.as_deref(),
            Some(&["b150".to_string()][..])
        );
    }
}
