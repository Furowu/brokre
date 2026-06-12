//! Short-lived subprocess entrypoints:
//! - `--internal-injector`: write vault secret once to PTY fd 3
//! - `BROKRE_INTERNAL_ASKPASS=1`: print vault secret for `SSH_ASKPASS`

use crate::runtime::ssh_identity;
use crate::security::hardening::{self, HardeningMode};
use crate::utils::errors::{BrokreError, Result};
use crate::vault::crypto::record::decrypt_for_exec;
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::store::VaultStore;
use std::io::Write;
use uuid::Uuid;

const INJECTOR_TOKEN_MAX: usize = 256;

/// Run the injector entrypoint (`brokre --internal-injector …`). Exits the process.
pub fn run_internal_injector_main() -> ! {
    let code = match run_internal_injector() {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::io::stderr().write_all(format!("{}\n", e).as_bytes());
            1
        }
    };
    std::process::exit(code);
}

fn run_internal_injector() -> Result<()> {
    if hardening::hardening_disabled_by_env() {
        return Err(BrokreError::Runtime(
            "injector: BROKRE_DISABLE_HARDENING=1 — refusing to decrypt".into(),
        ));
    }

    let _hr = hardening::apply_hardening(HardeningMode::WarnOnly);

    let mut args = std::env::args();
    let _exe = args.next();
    let _flag = args.next(); // --internal-injector
    let id_str = args
        .next()
        .ok_or_else(|| BrokreError::Runtime("injector: missing record id".into()))?;
    let ppid_str = args
        .next()
        .ok_or_else(|| BrokreError::Runtime("injector: missing parent pid".into()))?;
    let field = args.next().unwrap_or_else(|| "password".into());

    let id: Uuid = id_str
        .parse()
        .map_err(|_| BrokreError::Runtime("injector: bad record id".into()))?;
    let expected_ppid: u32 = ppid_str
        .parse()
        .map_err(|_| BrokreError::Runtime("injector: bad parent pid".into()))?;

    let actual_ppid = unsafe { libc::getppid() } as u32;
    if actual_ppid != expected_ppid {
        return Err(BrokreError::Runtime("injector: parent pid mismatch".into()));
    }

    let fd_pty = 3i32;
    let fd_tok = 4i32;
    if unsafe { libc::isatty(fd_pty) } != 1 {
        return Err(BrokreError::Runtime("injector: fd 3 is not a tty".into()));
    }

    let mut tok = vec![0u8; INJECTOR_TOKEN_MAX];
    let n = unsafe { libc::read(fd_tok, tok.as_mut_ptr().cast(), tok.len().saturating_sub(1)) };
    if n <= 0 {
        return Err(BrokreError::Runtime("injector: empty token".into()));
    }
    tok.truncate(n as usize);

    let store = VaultStore::open()?;
    let rec = store
        .get_by_id(&id)?
        .ok_or_else(|| BrokreError::Vault("injector: record not found".into()))?;

    let master = get_or_init_master_kek()?;
    let fields = decrypt_for_exec(&rec.crypto, &master)?;
    let pw = fields
        .get(&field)
        .ok_or_else(|| BrokreError::Vault(format!("injector: no {} field", field)))?;

    let secret = pw.expose().as_bytes();
    let w1 = unsafe { libc::write(fd_pty, secret.as_ptr().cast(), secret.len()) };
    let w2 = unsafe { libc::write(fd_pty, b"\r".as_ptr().cast(), 1) };
    if w1 < 0 || w2 != 1 {
        return Err(BrokreError::Io(std::io::Error::last_os_error()));
    }

    Ok(())
}

/// Run the SSH_ASKPASS entrypoint. Exits the process.
pub fn run_internal_askpass_main() -> ! {
    let code = match run_internal_askpass() {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::io::stderr().write_all(format!("{}\n", e).as_bytes());
            1
        }
    };
    std::process::exit(code);
}

fn run_internal_askpass() -> Result<()> {
    if hardening::hardening_disabled_by_env() {
        return Err(BrokreError::Runtime(
            "askpass: BROKRE_DISABLE_HARDENING=1 — refusing to decrypt".into(),
        ));
    }

    let _hr = hardening::apply_hardening(HardeningMode::WarnOnly);

    let id_str = std::env::var("BROKRE_ASKPASS_RECORD_ID")
        .map_err(|_| BrokreError::Runtime("askpass: missing record id".into()))?;
    let token = std::env::var("BROKRE_ASKPASS_TOKEN")
        .map_err(|_| BrokreError::Runtime("askpass: missing token".into()))?;
    let state_path = std::env::var_os("BROKRE_ASKPASS_STATE")
        .ok_or_else(|| BrokreError::Runtime("askpass: missing state path".into()))?;
    let owner_str = std::env::var("BROKRE_ASKPASS_OWNER")
        .map_err(|_| BrokreError::Runtime("askpass: missing owner pid".into()))?;
    let owner_pid: u32 = owner_str
        .parse()
        .map_err(|_| BrokreError::Runtime("askpass: bad owner pid".into()))?;

    let ssh_pid = unsafe { libc::getppid() } as u32;
    if parent_pid_of(ssh_pid) != Some(owner_pid) {
        return Err(BrokreError::Runtime("askpass: owner pid mismatch".into()));
    }

    let id: Uuid = id_str
        .parse()
        .map_err(|_| BrokreError::Runtime("askpass: bad record id".into()))?;

    if !state_path
        .to_string_lossy()
        .contains(&format!("askpass_{}_{}", id, token))
    {
        return Err(BrokreError::Runtime("askpass: state path mismatch".into()));
    }

    let store = VaultStore::open()?;
    let rec = store
        .get_by_id(&id)?
        .ok_or_else(|| BrokreError::Vault("askpass: record not found".into()))?;

    let fields = ssh_identity::injectable_field_names(&rec);
    if fields.is_empty() {
        return Err(BrokreError::Vault("askpass: no injectable fields".into()));
    }

    let mut invocation: usize = std::fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let field = fields
        .get(invocation)
        .or_else(|| fields.last())
        .ok_or_else(|| BrokreError::Vault("askpass: no field".into()))?
        .clone();
    invocation += 1;
    std::fs::write(&state_path, format!("{}\n", invocation)).map_err(BrokreError::Io)?;

    let master = get_or_init_master_kek()?;
    let decrypted = decrypt_for_exec(&rec.crypto, &master)?;
    let secret = decrypted
        .get(&field)
        .ok_or_else(|| BrokreError::Vault(format!("askpass: no {} field", field)))?;

    let mut out = std::io::stdout().lock();
    out.write_all(secret.expose().as_bytes())
        .map_err(BrokreError::Io)?;
    out.write_all(b"\n").map_err(BrokreError::Io)?;
    Ok(())
}

#[cfg(all(unix, target_os = "macos"))]
fn parent_pid_of(pid: u32) -> Option<u32> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let rc = unsafe {
        libc::proc_pidinfo(
            pid as libc::pid_t,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut _,
            size,
        )
    };
    if rc <= 0 {
        return None;
    }
    Some(info.pbi_ppid as u32)
}

#[cfg(all(unix, target_os = "linux"))]
fn parent_pid_of(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|p| p.parse().ok())
        })
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn parent_pid_of(_pid: u32) -> Option<u32> {
    None
}

#[cfg(not(unix))]
fn parent_pid_of(_pid: u32) -> Option<u32> {
    None
}
