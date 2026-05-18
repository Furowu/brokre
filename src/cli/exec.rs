//! `brokr <cli> [args...]` — transparent PTY wrapper that:
//!   1. Looks up an existing alias matching args; replays its saved_args
//!      (with extra args appended) and auto-injects the stored password.
//!   2. Otherwise runs the CLI verbatim, captures any password the user
//!      types at a prompt, and offers to save it as an alias on success.
//!
//! Exit code of the child is propagated verbatim. brokr never invents
//! its own error code to mask a real connection / auth failure.

use crate::audit::logger::{append, redact_args, AuditEvent};
use crate::runtime::prompts::patterns_for;
use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
use crate::vault::crypto::record::{decrypt_for_exec, encrypt_record};
use crate::vault::keychain::{get_or_init_audit_hmac_key, get_or_init_master_kek};
use crate::vault::model::SecretRecord;
use crate::vault::store::VaultStore;
use chrono::Utc;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::time::Instant;
use uuid::Uuid;

/// Entry point used by `main.rs` for any external subcommand.
pub fn run(binary: String, args: Vec<String>) -> Result<()> {
    // Confirm binary is actually on PATH; otherwise produce the same error a
    // user would see by typing the command directly.
    if which::which(&binary).is_err() {
        return Err(BrokrError::Runtime(format!(
            "{}: command not found",
            binary
        )));
    }

    let profile = binary.clone();
    let store = VaultStore::open()?;

    // ---- Try to resolve a saved alias ----
    let lookup = resolve_record(&store, &profile, &args)?;
    if let Some((rec, extras)) = lookup {
        return exec_saved(&store, rec, extras, &profile);
    }

    // ---- First-time / unknown — run raw with prompt capture ----
    exec_fresh(&store, profile, binary, args)
}


/// Resolve a saved record from CLI args. Returns the record plus the *extra*
/// args (everything after the alias / lookup token).
fn resolve_record(
    store: &VaultStore,
    profile: &str,
    args: &[String],
) -> Result<Option<(SecretRecord, Vec<String>)>> {
    if args.is_empty() {
        return Ok(None);
    }

    // 1. First positional non-flag arg == alias name.
    let first_positional = args.iter().position(|a| !a.starts_with('-'));
    if let Some(idx) = first_positional {
        let token = &args[idx];
        if let Some(rec) = store.get(profile, token)? {
            let mut extras = args.to_vec();
            extras.remove(idx);
            return Ok(Some((rec, extras)));
        }
    }

    // 2. Fall back to host-alias fuzzy match.
    let host = infer_host(profile, args);
    if let Some(h) = host {
        let records = store.list()?;
        let matches: Vec<_> = records
            .into_iter()
            .filter(|r| r.profile == profile && r.host_alias.as_deref() == Some(&h))
            .collect();
        match matches.len() {
            0 => {}
            1 => return Ok(Some((matches.into_iter().next().unwrap(), args.to_vec()))),
            _ => {
                eprintln!("brokr: multiple records match host '{}':", h);
                for r in &matches {
                    eprintln!("  - {}/{}", r.profile, r.name);
                }
                eprintln!("Use the alias name to disambiguate, e.g. `brokr {} <alias>`", profile);
                std::process::exit(2);
            }
        }
    }

    Ok(None)
}

/// Execute against an existing saved record.
fn exec_saved(
    store: &VaultStore,
    rec: SecretRecord,
    extra_args: Vec<String>,
    profile: &str,
) -> Result<()> {
    let master_kek = get_or_init_master_kek()?;
    let fields = decrypt_for_exec(&rec.crypto, &master_kek)?;
    let password = fields.get("password").cloned();

    // Compose final argv: saved_args first, then extras appended.
    let mut argv: Vec<String> = rec.saved_args.clone();
    argv.extend(extra_args.iter().cloned());

    let patterns = patterns_for(&rec.profile);
    let start = Instant::now();
    let result = crate::runtime::pty::run(&rec.profile, &argv, password.as_ref(), &patterns)?;
    let dur = start.elapsed().as_millis() as u64;

    // Audit
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: "exec".into(),
        profile: profile.to_string(),
        name: rec.name.clone(),
        exit: Some(result.exit_code),
        dur_ms: Some(dur),
        args_redacted: redact_args(&extra_args),
        prev_hmac: None,
        hmac: None,
    };
    let _ = append(&mut ev, &get_or_init_audit_hmac_key()?);

    // Touch last_used_at if exit 0.
    if result.exit_code == 0 {
        let mut updated = rec.clone();
        updated.last_used_at = Some(Utc::now());
        let _ = store.update(updated);
    }

    std::process::exit(result.exit_code);
}

/// Run the CLI verbatim, capture password if a prompt is seen, optionally save.
fn exec_fresh(
    store: &VaultStore,
    profile: String,
    binary: String,
    args: Vec<String>,
) -> Result<()> {
    if args.is_empty() {
        // Allow zero-arg invocation (e.g. `brokr mysql` to launch interactive shell)
        // — still run it but skip the save prompt.
    }

    // Pre-collect alias so the user doesn't forget to save after the session ends.
    let pre_alias = if !args.is_empty() && crate::security::tty::stdin_is_real_tty() {
        prompt_alias_beforehand(store, &profile, &args)?
    } else {
        None
    };

    let patterns = patterns_for(&profile);
    let start = Instant::now();
    let result = crate::runtime::pty::run(&binary, &args, None, &patterns)?;
    let dur = start.elapsed().as_millis() as u64;
    // Audit
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: "exec/fresh".into(),
        profile: profile.clone(),
        name: "<unsaved>".into(),
        exit: Some(result.exit_code),
        dur_ms: Some(dur),
        args_redacted: redact_args(&args),
        prev_hmac: None,
        hmac: None,
    };
    let _ = append(&mut ev, &get_or_init_audit_hmac_key()?);

    // Only save if everything succeeded AND we actually saw a prompt
    // AND we captured a non-empty password AND stdin is still a TTY.
    let should_save = result.exit_code == 0
        && result.had_prompt
        && result.captured_password.is_some()
        && crate::security::tty::stdin_is_real_tty();

    if should_save {
        if let Some(pw) = result.captured_password {
            if let Some(ref alias) = pre_alias {
                let _ = auto_save(store, &profile, &args, pw, alias);
            } else {
                let _ = offer_save(store, &profile, &args, pw);
            }
        }
    } else if pre_alias.is_some() {
        eprintln!(
            "brokr: connection did not complete successfully — password not saved for alias '{}'",
            pre_alias.unwrap()
        );
    }

    std::process::exit(result.exit_code);
}

/// Prompt for alias before the command runs so the user doesn't forget.
fn prompt_alias_beforehand(
    store: &VaultStore,
    profile: &str,
    args: &[String],
) -> Result<Option<String>> {
    let suggested = suggest_name(profile, args);
    eprintln!();
    eprintln!("brokr: first-time connection. Save as alias for next time?");
    eprintln!("       alias (blank = skip) [{}]: ", suggested);

    let alias = read_line_from_tty()?;
    let alias = alias.trim().to_string();
    if alias.is_empty() {
        return Ok(None);
    }
    let alias = if alias.eq_ignore_ascii_case("y") || alias.eq_ignore_ascii_case("yes") {
        suggested
    } else {
        alias
    };
    if !SecretRecord::validate_name(&alias) {
        eprintln!("brokr: invalid alias '{}' — will skip save", alias);
        return Ok(None);
    }
    if store.get(profile, &alias)?.is_some() {
        eprintln!("brokr: alias '{}/{}' already exists — will skip save", profile, alias);
        return Ok(None);
    }
    Ok(Some(alias))
}

/// Common record construction and vault insertion.
fn insert_record(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
    alias: &str,
    reveal_kek: &[u8; 32],
) -> Result<()> {
    let master_kek = get_or_init_master_kek()?;
    let mut fields: BTreeMap<String, SecretString> = BTreeMap::new();
    fields.insert("password".into(), password);
    let crypto = encrypt_record(&fields, &master_kek, reveal_kek);

    let host_alias = infer_host(profile, args);
    let record = SecretRecord {
        id: Uuid::new_v4(),
        profile: profile.to_string(),
        name: alias.to_string(),
        labels: vec![],
        host_alias,
        binary: Some(profile.to_string()),
        fields_meta: None,
        saved_args: args.to_vec(),
        crypto,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_used_at: None,
        schema_version: 1,
    };
    store.insert(record)?;
    eprintln!("brokr: ✓ saved as {}/{}", profile, alias);
    eprintln!("       next time: brokr {} {}", profile, alias);
    Ok(())
}

/// Save with an interactive reveal passphrase prompt.
fn save_with_reveal_prompt(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
    alias: &str,
) -> Result<()> {
    eprintln!("       master passphrase for `brokr reveal` (blank = no reveal): ");
    let reveal_input =
        crate::security::prompt::prompt_field("passphrase", true).unwrap_or_else(|_| SecretString::new(String::new()));

    let reveal_salt = crate::vault::crypto::kdf::new_salt();
    let reveal_kek = if reveal_input.is_empty() {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        k
    } else {
        crate::vault::crypto::kdf::derive_reveal_key(&reveal_input, &reveal_salt)?
    };

    insert_record(store, profile, args, password, alias, &reveal_kek)
}

/// Auto-save after a successful login (no reveal passphrase).
fn auto_save(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
    alias: &str,
) -> Result<()> {
    let mut reveal_kek = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut reveal_kek);
    insert_record(store, profile, args, password, alias, &reveal_kek)
}

fn offer_save(
    store: &VaultStore,
    profile: &str,
    args: &[String],
    password: SecretString,
) -> Result<()> {
    eprintln!();
    eprintln!("brokr: ✓ login successful — save this connection for next time?");
    let suggested = suggest_name(profile, args);
    eprintln!("       alias (blank = skip) [{}]: ", suggested);

    let alias = read_line_from_tty()?;
    let alias = alias.trim().to_string();
    if alias.is_empty() {
        return Ok(());
    }
    let alias = if alias.eq_ignore_ascii_case("y") || alias.eq_ignore_ascii_case("yes") {
        suggested.clone()
    } else {
        alias
    };
    if !SecretRecord::validate_name(&alias) {
        eprintln!("brokr: invalid alias '{}' — skipping save", alias);
        return Ok(());
    }
    if store.get(profile, &alias)?.is_some() {
        eprintln!("brokr: alias '{}/{}' already exists — skipping save", profile, alias);
        return Ok(());
    }

    save_with_reveal_prompt(store, profile, args, password, &alias)
}

fn read_line_from_tty() -> Result<String> {
    let mut buf = String::new();
    #[cfg(unix)]
    {
        if let Ok(f) = std::fs::OpenOptions::new().read(true).open("/dev/tty") {
            std::io::BufReader::new(f).read_line(&mut buf)?;
            return Ok(buf);
        }
    }
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf)
}

fn suggest_name(profile: &str, args: &[String]) -> String {
    if let Some(host) = infer_host(profile, args) {
        if let Some(user) = infer_user(profile, args) {
            return format!("{}@{}", user, host);
        }
        return host;
    }
    for a in args {
        if !a.starts_with('-') {
            return a.clone();
        }
    }
    "unnamed".into()
}

/// Best-effort host extraction from raw args, per CLI.
fn infer_host(profile: &str, args: &[String]) -> Option<String> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    match bin {
        "ssh" | "scp" | "sftp" => {
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                if let Some((_u, h)) = a.split_once('@') {
                    return Some(h.to_string());
                }
                return Some(a.clone());
            }
            None
        }
        "mysql" | "mariadb" | "psql" | "redis-cli" | "clickhouse-client" => {
            // -h <host> or --host <host>
            let mut iter = args.iter().peekable();
            while let Some(a) = iter.next() {
                if a == "-h" || a == "--host" {
                    return iter.next().cloned();
                }
                if let Some(rest) = a.strip_prefix("--host=") {
                    return Some(rest.to_string());
                }
            }
            None
        }
        _ => None,
    }
}

fn infer_user(profile: &str, args: &[String]) -> Option<String> {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    match bin {
        "ssh" | "scp" | "sftp" => {
            for a in args {
                if a.starts_with('-') {
                    continue;
                }
                if let Some((u, _h)) = a.split_once('@') {
                    return Some(u.to_string());
                }
            }
            None
        }
        "mysql" | "mariadb" => {
            let mut iter = args.iter().peekable();
            while let Some(a) = iter.next() {
                if a == "-u" || a == "--user" {
                    return iter.next().cloned();
                }
                if let Some(rest) = a.strip_prefix("--user=") {
                    return Some(rest.to_string());
                }
            }
            None
        }
        "psql" | "postgres" => {
            let mut iter = args.iter().peekable();
            while let Some(a) = iter.next() {
                if a == "-U" || a == "--username" {
                    return iter.next().cloned();
                }
            }
            None
        }
        _ => None,
    }
}
