use crate::manage::instance::{acquire_start_lock, find_running_instance, unregister_instance};
use crate::manage::run_manage_server;
use crate::utils::errors::Result;
use std::thread;
use std::time::Duration;

pub fn run(onboard: bool, open: bool) -> Result<()> {
    if onboard {
        let _ = crate::manage::onboard::mark_onboard_spawned();
    }

    if let Some(existing) = find_running_instance() {
        return reuse_existing(existing, open);
    }

    let _start_lock = acquire_start_lock()?;
    if let Some(existing) = find_running_instance() {
        return reuse_existing(existing, open);
    }

    let server = run_manage_server(onboard)?;

    if open {
        let url = server.url.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let _ = crate::manage::open_browser(&url);
        });
    }

    wait_for_shutdown();
    Ok(())
}

fn reuse_existing(
    existing: crate::manage::instance::ManageInstanceRecord,
    open: bool,
) -> Result<()> {
    let url = existing.url();
    eprintln!(
        "brokr manage: reusing existing instance (pid {})",
        existing.pid
    );
    eprintln!("brokr manage: {}", url);
    if open {
        let open_url = url.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let _ = crate::manage::open_browser(&open_url);
        });
    } else {
        eprintln!(
            "brokr manage: already running — use --open for browser, or stop pid {} first",
            existing.pid
        );
    }
    Ok(())
}

fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;
        if let Ok(mut signals) = Signals::new([SIGINT, SIGTERM]) {
            if signals.forever().next().is_some() {
                eprintln!("brokr manage: stopped");
                unregister_instance();
                std::process::exit(0);
            }
            return;
        }
    }
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// Spawn manage in background for first-run onboarding (non-blocking).
pub fn spawn_onboard_background() {
    eprintln!("brokr: starting setup wizard in background…");
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ = std::process::Command::new(exe)
        .args(["manage", "--onboard", "--open"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn();
}
