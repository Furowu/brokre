use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::bastion_session_path;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_IDLE_SECS: u64 = 1800;
const DEFAULT_MAX_SECS: u64 = 28800;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BastionSession {
    pub unlocked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
}

static LAST_ACTIVITY: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();

fn last_activity() -> &'static Mutex<Option<Instant>> {
    LAST_ACTIVITY.get_or_init(|| Mutex::new(None))
}

pub fn idle_limit() -> Duration {
    Duration::from_secs(env_u64("BROKRE_BASTION_IDLE_SECS", DEFAULT_IDLE_SECS))
}

pub fn max_lifetime() -> Duration {
    Duration::from_secs(env_u64("BROKRE_BASTION_MAX_SECS", DEFAULT_MAX_SECS))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn load_session() -> Result<Option<BastionSession>> {
    let path = bastion_session_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path).map_err(BrokreError::Io)?;
    let session: BastionSession =
        serde_json::from_str(&data).map_err(|e| BrokreError::Runtime(format!("bastion session: {e}")))?;
    Ok(Some(session))
}

pub fn save_session(session: &BastionSession) -> Result<()> {
    let path = bastion_session_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(BrokreError::Io)?;
    }
    let data = serde_json::to_string_pretty(session)
        .map_err(|e| BrokreError::Runtime(format!("bastion session serialize: {e}")))?;
    fs::write(&path, data).map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    if let Ok(mut g) = last_activity().lock() {
        *g = Some(Instant::now());
    }
    Ok(())
}

pub fn unlock_session() -> Result<BastionSession> {
    let now = Utc::now();
    let session = BastionSession {
        unlocked_at: now,
        expires_at: now + ChronoDuration::seconds(max_lifetime().as_secs() as i64),
        idle_expires_at: now + ChronoDuration::seconds(idle_limit().as_secs() as i64),
    };
    save_session(&session)?;
    Ok(session)
}

pub fn touch_session() -> Result<()> {
    if let Some(mut session) = load_session()? {
        let now = Utc::now();
        session.idle_expires_at = now + ChronoDuration::seconds(idle_limit().as_secs() as i64);
        save_session(&session)?;
    }
    Ok(())
}

pub fn clear_session() -> Result<()> {
    let path = bastion_session_path();
    if path.exists() {
        fs::remove_file(&path).map_err(BrokreError::Io)?;
    }
    Ok(())
}

pub fn is_unlocked() -> bool {
    session_valid(load_session().ok().flatten()).is_ok()
}

pub fn require_unlocked() -> Result<()> {
    session_valid(load_session().ok().flatten())?;
    touch_session().ok();
    Ok(())
}

fn session_valid(session: Option<BastionSession>) -> Result<()> {
    let Some(session) = session else {
        return Err(BrokreError::PolicyDenied);
    };
    let now = Utc::now();
    if now > session.expires_at {
        let _ = clear_session();
        return Err(BrokreError::PolicyDenied);
    }
    if now > session.idle_expires_at {
        let _ = clear_session();
        return Err(BrokreError::PolicyDenied);
    }
    Ok(())
}

pub fn gate_required() -> bool {
    crate::bastion::key::key_is_set()
}

pub fn ensure_gate_for_outbound() -> Result<()> {
    crate::bastion::gate::ensure_outbound_unlocked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_home::with_temp_brokre_home;
    use serial_test::serial;

    #[test]
    #[serial]
    fn touch_session_extends_idle_window() {
        with_temp_brokre_home(|| {
            let session = unlock_session().unwrap();
            let first_idle = session.idle_expires_at;
            std::thread::sleep(std::time::Duration::from_millis(20));
            touch_session().unwrap();
            let updated = load_session().unwrap().expect("session");
            assert!(updated.idle_expires_at > first_idle);
            assert_eq!(updated.expires_at, session.expires_at);
        });
    }
}
