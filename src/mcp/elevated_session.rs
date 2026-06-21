//! In-process persistent elevated PTY sessions for MCP (Unix).

#[cfg(not(unix))]
use crate::runtime::elevated::{SessionKey, SessionPolicy};
#[cfg(not(unix))]
use crate::utils::errors::{BrokreError, Result};

pub struct RunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub session_reused: bool,
    pub idle_expires_at: String,
}

pub fn mcp_session_enabled() -> bool {
    #[cfg(not(unix))]
    {
        return false;
    }
    #[cfg(unix)]
    std::env::var("BROKRE_MCP_SESSION")
        .ok()
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

#[cfg(unix)]
mod imp {
    use super::RunResult;
    use crate::audit::logger::{append, redact_args, AuditEvent};
    use crate::runtime::elevated::{
        compose_ssh_bootstrap_argv, ElevatedMode, SessionKey, SessionPolicy,
    };
    use crate::runtime::pty_session::PtySession;
    use crate::runtime::session_markers::READY;
    use crate::runtime::ssh_identity::{
        insert_force_tty_for_privileged_remote, insert_identity_arg, materialize_identity,
    };
    use crate::utils::errors::{BrokreError, Result};
    use crate::vault::keychain::get_or_init_audit_hmac_key;
    use crate::vault::model::SecretRecord;
    use crate::vault::store::VaultStore;
    use chrono::{Duration as ChronoDuration, Utc};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    struct SessionEntry {
        pty: PtySession,
        created_at: Instant,
        last_active: Instant,
    }

    pub struct ElevatedSessionPool {
        sessions: HashMap<SessionKey, SessionEntry>,
        idle_limit: Duration,
        max_lifetime: Duration,
        cmd_timeout: Duration,
        bootstrap_timeout: Duration,
    }

    impl ElevatedSessionPool {
    pub fn from_env() -> Self {
        Self {
            sessions: HashMap::new(),
            idle_limit: Duration::from_secs(env_u64("BROKRE_MCP_SESSION_IDLE_SECS", 600)),
            max_lifetime: Duration::from_secs(env_u64("BROKRE_MCP_SESSION_MAX_SECS", 1800)),
            cmd_timeout: Duration::from_secs(env_u64("BROKRE_MCP_SESSION_CMD_TIMEOUT", 120)),
            bootstrap_timeout: Duration::from_secs(60),
        }
    }

    pub fn sweep_idle(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|key, entry| {
            let idle = now.duration_since(entry.last_active) > self.idle_limit;
            let expired = now.duration_since(entry.created_at) > self.max_lifetime;
            let dead = !entry.pty.is_alive();
            if idle || expired || dead {
                audit_action(
                    "mcp/elevated-session/expire",
                    key,
                    None,
                    None,
                    0,
                );
                entry.pty.kill();
                false
            } else {
                true
            }
        });
    }

    pub fn shutdown_all(&mut self) {
        for (key, mut entry) in self.sessions.drain() {
            audit_action("mcp/elevated-session/close", &key, None, Some(0), 0);
            entry.pty.kill();
        }
    }

    pub fn run(
        &mut self,
        key: SessionKey,
        command: Option<&str>,
        policy: SessionPolicy,
    ) -> Result<RunResult> {
        self.sweep_idle();

        if policy == SessionPolicy::Close {
            let existed = self.sessions.remove(&key).is_some();
            if existed {
                audit_action("mcp/elevated-session/close", &key, None, Some(0), 0);
            }
            return Ok(RunResult {
                exit_code: 0,
                stdout: if existed {
                    "session closed".into()
                } else {
                    "no active session".into()
                },
                stderr: String::new(),
                session_reused: false,
                idle_expires_at: idle_expires_iso(self.idle_limit),
            });
        }

        if policy == SessionPolicy::New {
            if let Some(mut entry) = self.sessions.remove(&key) {
                entry.pty.kill();
                audit_action("mcp/elevated-session/close", &key, None, Some(0), 0);
            }
        }

        let cmd = command.unwrap_or("").trim();
        if cmd.is_empty() {
            return Err(BrokreError::Runtime(
                "elevated session: command is required (use session=close to end session)".into(),
            ));
        }

        let start = Instant::now();
        let mut session_reused = false;

        if let Some(entry) = self.sessions.get_mut(&key) {
            if entry.pty.is_alive() {
                session_reused = true;
                entry.last_active = Instant::now();
            } else {
                self.sessions.remove(&key);
            }
        }

        if !session_reused {
            let rec = resolve_ssh_alias(&key.alias)?;
            let pty = open_session(&key, &rec, self.bootstrap_timeout)?;
            self.sessions.insert(
                key.clone(),
                SessionEntry {
                    pty,
                    created_at: Instant::now(),
                    last_active: Instant::now(),
                },
            );
            audit_action(
                "mcp/elevated-session/open",
                &key,
                None,
                Some(0),
                start.elapsed().as_millis() as u64,
            );
        }

        let entry = self
            .sessions
            .get_mut(&key)
            .ok_or_else(|| BrokreError::Runtime("session missing after open".into()))?;

        let run_result = entry.pty.run_command(cmd, self.cmd_timeout);
        entry.last_active = Instant::now();

        let (stdout, exit_code) = match run_result {
            Ok(v) => v,
            Err(e) => {
                self.sessions.remove(&key);
                return Err(e);
            }
        };

        let dur = start.elapsed().as_millis() as u64;
        audit_action(
            "mcp/elevated-session/run",
            &key,
            Some(cmd),
            Some(exit_code),
            dur,
        );

        Ok(RunResult {
            exit_code,
            stdout,
            stderr: String::new(),
            session_reused,
            idle_expires_at: idle_expires_iso(self.idle_limit),
        })
    }
    }

    impl Drop for ElevatedSessionPool {
        fn drop(&mut self) {
            self.shutdown_all();
        }
    }

    fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn idle_expires_iso(idle: Duration) -> String {
    (Utc::now() + ChronoDuration::from_std(idle).unwrap_or_else(|_| ChronoDuration::minutes(10)))
        .to_rfc3339()
}

fn resolve_ssh_alias(alias: &str) -> Result<SecretRecord> {
    let store = VaultStore::open()?;
    for profile in ["ssh", "scp", "sftp"] {
        if let Some(rec) = store.get(profile, alias)? {
            return Ok(rec);
        }
    }
    Err(BrokreError::Runtime(format!(
        "no saved SSH alias {:?}",
        alias
    )))
}

fn open_session(
    key: &SessionKey,
    rec: &SecretRecord,
    bootstrap_timeout: Duration,
) -> Result<PtySession> {
    let mut argv = compose_ssh_bootstrap_argv(rec, key.mode, Some(&key.su_user));
    // Do not mux here: this SSH child stays open for the life of the elevated PTY session.
    insert_force_tty_for_privileged_remote(&mut argv, &["sudo".into()]);
    let _key_guard = match materialize_identity(rec)? {
        Some(guard) => {
            insert_identity_arg(&mut argv, &guard.path);
            Some(guard)
        }
        None => None,
    };

    let ssh =
        which::which("ssh").map_err(|_| BrokreError::Runtime("ssh: command not found".into()))?;
    let ssh_str = ssh.to_string_lossy().into_owned();
    let expect_su = key.mode == ElevatedMode::Su;

    let session = PtySession::spawn_ssh(rec.id, &ssh_str, &argv, expect_su)?;
    session.wait_for_substring(READY, bootstrap_timeout)?;
    session.clear_output();
    Ok(session)
}

fn audit_action(
    action: &str,
    session_key: &SessionKey,
    command: Option<&str>,
    exit: Option<i32>,
    dur_ms: u64,
) {
    let args = match command {
        Some(c) => redact_args(&[c.to_string()]),
        None => redact_args(&[
            session_key.alias.clone(),
            format!("{:?}", session_key.mode),
            session_key.su_user.clone(),
        ]),
    };
    let Ok(audit_key) = get_or_init_audit_hmac_key() else {
        return;
    };
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: "ssh".into(),
        name: session_key.alias.clone(),
        exit,
        dur_ms: Some(dur_ms),
        args_redacted: args,
        hardening: None,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
        source: Some("mcp".into()),
        route: None,
        bastion: None,
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    let _ = append(&mut ev, &audit_key);
    }
}

#[cfg(unix)]
pub use imp::ElevatedSessionPool;

#[cfg(not(unix))]
pub struct ElevatedSessionPool;

#[cfg(not(unix))]
impl ElevatedSessionPool {
    pub fn from_env() -> Self {
        Self
    }

    pub fn sweep_idle(&mut self) {}

    pub fn shutdown_all(&mut self) {}

    pub fn run(
        &mut self,
        _key: SessionKey,
        _command: Option<&str>,
        _policy: SessionPolicy,
    ) -> Result<RunResult> {
        Err(BrokreError::Runtime(
            "persistent elevated PTY sessions require Unix".into(),
        ))
    }
}
