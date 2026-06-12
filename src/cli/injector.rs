//! Short-lived subprocess entry: decrypt vault record and write password once to PTY fd 3.

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
