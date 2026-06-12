use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use std::thread;
use std::time::Duration;

pub fn prompt_passphrase(label: &str) -> Result<SecretString> {
    if !crate::security::tty::stdin_is_real_tty() {
        return Err(BrokrError::NoTty);
    }
    let input = rpassword::prompt_password(format!("{}: ", label))
        .map_err(|e| BrokrError::Cli(e.to_string()))?;
    let input = input
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    Ok(SecretString::new(input))
}

pub fn prompt_with_retries<F>(label: &str, verify: F, max: u8) -> Result<SecretString>
where
    F: Fn(&SecretString) -> bool,
{
    for attempt in 1..=max {
        let secret = prompt_passphrase(label)?;
        if verify(&secret) {
            return Ok(secret);
        }
        if attempt < max {
            let delay = Duration::from_secs(4_u64.pow(attempt as u32 - 1));
            eprintln!("Incorrect. Retrying in {:?}...", delay);
            thread::sleep(delay);
        }
    }
    Err(BrokrError::Cli(format!("Failed after {} attempts", max)))
}

pub fn prompt_field(label: &str, secret: bool) -> Result<SecretString> {
    if !crate::security::tty::stdin_is_real_tty() {
        return Err(BrokrError::NoTty);
    }
    let input = if secret {
        rpassword::prompt_password(format!("{}: ", label))
    } else {
        println!("{}: ", label);
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(BrokrError::Io)?;
        Ok(buf)
    }
    .map_err(|e| BrokrError::Cli(e.to_string()))?;
    let input = input
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    Ok(SecretString::new(input))
}
