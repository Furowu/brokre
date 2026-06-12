use crate::utils::paths::brokre_home;
use std::path::PathBuf;

pub fn onboard_done_path() -> PathBuf {
    brokre_home().join("onboard.done")
}

pub fn onboard_spawned_path() -> PathBuf {
    brokre_home().join(".onboard_spawned")
}

pub fn is_onboard_complete() -> bool {
    onboard_done_path().exists()
}

pub fn mark_onboard_complete() -> std::io::Result<()> {
    std::fs::write(onboard_done_path(), "1\n")
}

pub fn mark_onboard_spawned() -> std::io::Result<()> {
    std::fs::write(onboard_spawned_path(), "1\n")
}

pub fn was_onboard_spawned() -> bool {
    onboard_spawned_path().exists()
}
