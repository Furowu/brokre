use crate::audit::logger::verify_chain;
use crate::utils::errors::Result;

pub fn run_verify() -> Result<()> {
    let path = crate::utils::paths::audit_path();
    let key = crate::vault::keychain::get_or_init_audit_hmac_key()?;
    verify_chain(&path, &key)?;
    println!("Audit chain verified successfully.");
    Ok(())
}
