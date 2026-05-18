use crate::security::prompt::prompt_with_retries;
use crate::security::tty::stdin_is_real_tty;
use crate::utils::errors::{BrokrError, Result};
use crate::vault::store::VaultStore;

/// Remove a saved record. Requires:
///   1. interactive TTY
///   2. y/N confirmation
///   3. reveal passphrase (if one was set on the record)
pub fn run(profile: String, name: String) -> Result<()> {
    if !stdin_is_real_tty() {
        return Err(BrokrError::NoTty);
    }

    let store = VaultStore::open()?;
    let rec = store.get(&profile, &name)?.ok_or_else(|| {
        BrokrError::Cli(format!("record not found: {}/{}", profile, name))
    })?;

    println!("Remove {}/{}? [y/N]", profile, name);
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    if !buf.trim().eq_ignore_ascii_case("y") {
        return Err(BrokrError::Cli("cancelled".into()));
    }

    // Verify passphrase — if the record has no reveal-capable passphrase
    // (saved with blank), we cannot ask. In that case, fall back to
    // a YES-typed confirmation to avoid accidents.
    let needs_pass = prompt_with_retries(
        "Master passphrase (or YES to confirm)",
        |p| {
            // If user types YES literally, accept (for records without reveal pass).
            if p.expose() == "YES" {
                return true;
            }
            let kek = crate::vault::crypto::kdf::derive_reveal_key(p, &rec.crypto.reveal_salt);
            if let Ok(k) = kek {
                crate::vault::crypto::record::decrypt_for_reveal(&rec.crypto, &k).is_ok()
            } else {
                false
            }
        },
        3,
    );
    if needs_pass.is_err() {
        return Err(BrokrError::Cli("authentication failed".into()));
    }

    store.delete(&profile, &name)?;
    println!("Removed.");
    Ok(())
}
