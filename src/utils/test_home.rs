//! Mutex-serialized `BROKRE_HOME` / `HOME` swap for unit tests.
//!
//! Parallel tests that only set `HOME` race on the process-global env and share
//! vault, audit, and bastion state. Always route isolated tests through here.

use std::ffi::OsString;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct SavedBrokreEnv {
    brokre_home: Option<OsString>,
    home: Option<OsString>,
    allow_file_keychain: Option<OsString>,
    use_keychain: Option<OsString>,
}

impl SavedBrokreEnv {
    fn capture() -> Self {
        Self {
            brokre_home: std::env::var_os("BROKRE_HOME"),
            home: std::env::var_os("HOME"),
            allow_file_keychain: std::env::var_os("BROKRE_ALLOW_FILE_KEYCHAIN"),
            use_keychain: std::env::var_os("BROKRE_USE_KEYCHAIN"),
        }
    }

    fn apply_isolated(&self, root: &Path) {
        std::env::set_var("BROKRE_HOME", root);
        std::env::set_var("HOME", root);
        std::env::set_var("BROKRE_ALLOW_FILE_KEYCHAIN", "1");
    }

    fn restore(&self) {
        restore_var("BROKRE_HOME", self.brokre_home.as_ref());
        restore_var("HOME", self.home.as_ref());
        restore_var(
            "BROKRE_ALLOW_FILE_KEYCHAIN",
            self.allow_file_keychain.as_ref(),
        );
        restore_var("BROKRE_USE_KEYCHAIN", self.use_keychain.as_ref());
    }
}

fn restore_var(name: &str, value: Option<&OsString>) {
    match value {
        Some(v) => std::env::set_var(name, v),
        None => std::env::remove_var(name),
    }
}

/// Point `BROKRE_HOME` and `HOME` at a fresh temp directory for `f`.
///
/// Holds a process-wide lock for the duration so parallel tests cannot clobber
/// each other's environment.
pub fn with_temp_brokre_home<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let _lock: MutexGuard<'_, ()> = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().expect("tempdir");
    let saved = SavedBrokreEnv::capture();
    saved.apply_isolated(tmp.path());
    let result = f();
    saved.restore();
    result
}
