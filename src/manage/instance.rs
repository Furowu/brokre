//! Cross-process singleton registry for the manage HTTP server (`~/.brokre/run/manage.json`).

use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

const MANAGE_INSTANCE_FILE: &str = "manage.json";
const MANAGE_LOCK_FILE: &str = "manage.lock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManageInstanceRecord {
    pub pid: u32,
    pub port: u16,
    pub token: String,
}

impl ManageInstanceRecord {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/?t={}", self.port, self.token)
    }
}

pub fn instance_path() -> PathBuf {
    run_dir().join(MANAGE_INSTANCE_FILE)
}

fn lock_path() -> PathBuf {
    run_dir().join(MANAGE_LOCK_FILE)
}

#[cfg(unix)]
pub fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    match kill(Pid::from_raw(pid as i32), None) {
        Ok(()) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub fn process_alive(_pid: u32) -> bool {
    false
}

fn probe_manage(port: u16, token: &str) -> bool {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
        return false;
    };
    let req = format!(
        "GET /api/config HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    let resp = String::from_utf8_lossy(&buf[..n]);
    resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200")
}

fn read_record() -> Option<ManageInstanceRecord> {
    let path = instance_path();
    let mut f = File::open(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    serde_json::from_str(&s).ok()
}

fn remove_stale_record() {
    let _ = std::fs::remove_file(instance_path());
}

/// Return a live manage server registered on this machine, if any.
pub fn find_running_instance() -> Option<ManageInstanceRecord> {
    let rec = read_record()?;
    if !process_alive(rec.pid) {
        remove_stale_record();
        return None;
    }
    if !probe_manage(rec.port, &rec.token) {
        remove_stale_record();
        return None;
    }
    Some(rec)
}

/// Exclusive lock while binding a new manage port (prevents concurrent double-starts).
pub struct ManageStartLock {
    _lock: File,
}

pub fn acquire_start_lock() -> Result<ManageStartLock> {
    let path = lock_path();
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    file.try_lock_exclusive()
        .map_err(|_| BrokreError::Runtime("another brokre manage is starting".into()))?;
    Ok(ManageStartLock { _lock: file })
}

pub fn register_instance(port: u16, token: &str) -> Result<()> {
    let rec = ManageInstanceRecord {
        pid: std::process::id(),
        port,
        token: token.to_string(),
    };
    let json = serde_json::to_string_pretty(&rec).map_err(|e| BrokreError::Cli(e.to_string()))?;
    let path = instance_path();
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(json.as_bytes()).map_err(BrokreError::Io)?;
    f.sync_all().ok();
    Ok(())
}

pub fn unregister_instance() {
    let Some(rec) = read_record() else {
        return;
    };
    if rec.pid == std::process::id() {
        remove_stale_record();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_url_format() {
        let rec = ManageInstanceRecord {
            pid: 1,
            port: 56777,
            token: "abc".into(),
        };
        assert_eq!(rec.url(), "http://127.0.0.1:56777/?t=abc");
    }

    #[test]
    #[serial_test::serial]
    fn register_writes_json_for_current_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let old = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let _guard = ManageStartLock {
            _lock: acquire_start_lock().unwrap()._lock,
        };
        register_instance(56777, "tok").unwrap();
        let rec = read_record().expect("manage.json");
        assert_eq!(rec.port, 56777);
        assert_eq!(rec.token, "tok");
        assert_eq!(rec.pid, std::process::id());
        unregister_instance();
        assert!(read_record().is_none());
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
