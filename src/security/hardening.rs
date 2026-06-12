//! OS-level hardening to shrink T1 attack surface (core dumps, ptrace, swap of
//! locked pages). Root-level memory attacks remain out of scope.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;

const ENV_DISABLE: &str = "BROKR_DISABLE_HARDENING";
#[cfg(target_os = "linux")]
const ENV_SOFT_MEMLOCK: &str = "BROKR_SOFT_MEMLOCK";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardeningMode {
    /// Fail closed on critical hardening failures (release default).
    Enforce,
    /// Log warnings but continue (debug builds / tests).
    WarnOnly,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HardeningReport {
    pub dumpable_cleared: bool,
    pub core_disabled: bool,
    pub traced: bool,
    pub mlock_ok: bool,
    pub ptrace_denied: bool,
    pub disabled_by_env: bool,
    pub warnings: Vec<String>,
}

/// Returns true if injector must refuse to decrypt (user disabled hardening).
pub fn hardening_disabled_by_env() -> bool {
    std::env::var(ENV_DISABLE)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

thread_local! {
    static LAST_REPORT: RefCell<Option<HardeningReport>> = const { RefCell::new(None) };
}

/// Apply hardening and cache the report for audit (`exec` / `exec/fresh`).
pub fn apply_hardening_cached(mode: HardeningMode) -> HardeningReport {
    let r = apply_hardening(mode);
    LAST_REPORT.with(|c| *c.borrow_mut() = Some(r.clone()));
    r
}

pub fn last_hardening_report() -> Option<HardeningReport> {
    LAST_REPORT.with(|c| c.borrow().clone())
}

pub fn apply_hardening(mode: HardeningMode) -> HardeningReport {
    if hardening_disabled_by_env() {
        return HardeningReport {
            disabled_by_env: true,
            warnings: vec![format!(
                "{}=1 — OS hardening skipped; injector will refuse to run",
                ENV_DISABLE
            )],
            ..Default::default()
        };
    }

    #[cfg(unix)]
    {
        apply_unix(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        HardeningReport::default()
    }
}

#[cfg(unix)]
fn apply_unix(mode: HardeningMode) -> HardeningReport {
    let mut r = HardeningReport::default();
    let enforce = matches!(mode, HardeningMode::Enforce);

    #[cfg(target_os = "linux")]
    {
        r.traced = linux_tracer_pid_nonzero();
        if r.traced {
            r.warnings
                .push("process appears ptraced (TracerPid != 0)".into());
            if enforce {
                eprintln!("brokr: fatal: refusing to run under ptrace (TracerPid)");
                std::process::exit(2);
            }
        }

        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
                r.dumpable_cleared = true;
            } else {
                r.warnings.push(format!(
                    "PR_SET_DUMPABLE: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0 {
                r.core_disabled = true;
            } else {
                r.warnings.push(format!(
                    "setrlimit(RLIMIT_CORE): {}",
                    std::io::Error::last_os_error()
                ));
            }

            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 {
                r.mlock_ok = true;
            } else {
                r.warnings
                    .push(format!("mlockall: {}", std::io::Error::last_os_error()));
                let soft = std::env::var(ENV_SOFT_MEMLOCK)
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if enforce && !soft {
                    eprintln!(
                        "brokr: fatal: mlockall failed — set {}=1 to allow soft start, or raise memlock ulimit",
                        ENV_SOFT_MEMLOCK
                    );
                    std::process::exit(2);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        r.traced = macos_is_traced();
        if r.traced {
            r.warnings.push("kern.proc shows P_TRACED".into());
            if enforce {
                eprintln!("brokr: fatal: refusing to run while being traced");
                std::process::exit(2);
            }
        }

        unsafe {
            let lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0 {
                r.core_disabled = true;
            } else {
                r.warnings.push(format!(
                    "setrlimit(RLIMIT_CORE): {}",
                    std::io::Error::last_os_error()
                ));
            }

            if libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 {
                r.ptrace_denied = true;
            } else {
                r.warnings.push(format!(
                    "ptrace(PT_DENY_ATTACH): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        // mlockall is not used on macOS; optional page locks live in SecretArena.
        r.mlock_ok = true;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = enforce;
        r.warnings
            .push("hardening: unsupported unix — no-op".into());
    }

    r
}

#[cfg(target_os = "linux")]
fn linux_tracer_pid_nonzero() -> bool {
    use std::fs;
    if let Ok(s) = fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                if let Ok(n) = rest.trim().parse::<u32>() {
                    return n != 0;
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn macos_is_traced() -> bool {
    // `libc` does not always expose `kinfo_proc` / `P_TRACED` for Rust targets.
    // Rely on `PT_DENY_ATTACH` + core limits for macOS; tracing detection is Linux-only.
    false
}
