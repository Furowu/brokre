//! Cross-process coordination so only one local brokre process opens the bastion auth page.

use crate::manage::open_browser;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;
use fs4::fs_std::FileExt;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const LOCK_FILE: &str = "bastion_unlock.lock";

fn lock_path() -> PathBuf {
    run_dir().join(LOCK_FILE)
}

/// Holds an exclusive flock while this process leads an interactive unlock round.
/// Waiters have `_lock: None` and only poll shared session state.
pub struct BastionUnlockCoordinator {
    _lock: Option<File>,
}

impl BastionUnlockCoordinator {
    /// Acquire opener role when possible; otherwise become a waiter.
    pub fn try_acquire() -> Result<Self> {
        let path = lock_path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(BrokreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        match file.try_lock_exclusive() {
            Ok(()) => {
                if crate::bastion::session::is_unlocked() {
                    drop(file);
                    return Ok(Self { _lock: None });
                }
                Ok(Self { _lock: Some(file) })
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(Self { _lock: None }),
            Err(e) => Err(BrokreError::Io(e)),
        }
    }

    pub fn is_opener(&self) -> bool {
        self._lock.is_some()
    }

    /// Open the auth page when this process is the opener; waiters log and skip.
    pub fn maybe_open_browser(&self, url: &str) {
        if !self.is_opener() {
            eprintln!("brokre: bastion unlock already in progress — waiting for authorization…");
            return;
        }
        eprintln!("brokre: bastion locked — opening auth page in browser…");
        let url = url.to_string();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let _ = open_browser(&url);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_home::with_temp_brokre_home;
    use serial_test::serial;

    #[test]
    #[serial]
    fn already_unlocked_does_not_take_opener_slot() {
        with_temp_brokre_home(|| {
            crate::bastion::session::unlock_session().unwrap();
            let coord = BastionUnlockCoordinator::try_acquire().unwrap();
            assert!(!coord.is_opener());
        });
    }

    #[test]
    #[serial]
    fn second_acquire_is_waiter_while_opener_holds_lock() {
        with_temp_brokre_home(|| {
            let opener = BastionUnlockCoordinator::try_acquire().unwrap();
            assert!(opener.is_opener());

            let waiter = BastionUnlockCoordinator::try_acquire().unwrap();
            assert!(!waiter.is_opener());

            drop(opener);
            let next = BastionUnlockCoordinator::try_acquire().unwrap();
            assert!(next.is_opener());
        });
    }
}
