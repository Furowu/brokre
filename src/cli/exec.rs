//! `brokr <cli> [args...]` — transparent PTY wrapper that:
//!   1. Looks up an existing alias matching args; replays its saved_args
//!      (leading flags before the alias, trailing command args after it)
//!      and auto-injects the stored password.
//!   2. Otherwise runs the CLI verbatim, captures any password the user
//!      types at a prompt, and offers to save it as an alias on success.
//!
//! Saved-alias one-shot commands:
//!   `brokr ssh prod-bastion uname -a`
//!   `brokr mysql prod-db -e "SHOW TABLES"`
//!
//! Exit code of the child is propagated verbatim. brokr never invents
//! its own error code to mask a real connection / auth failure.

use crate::audit::logger::{append, redact_args, AuditEvent};
use crate::runtime::prompts::patterns_for;
use crate::runtime::pty::PtyCredential;
use crate::security::secret::SecretString;
use crate::utils::errors::{BrokrError, Result};
#[cfg(not(unix))]
use crate::vault::crypto::record::decrypt_for_exec;
use crate::vault::keychain::get_or_init_audit_hmac_key;
#[cfg(not(unix))]
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::model::SecretRecord;
use crate::vault::service::{
    auto_save, connection_token_index, infer_host, save_with_reveal_prompt, suggest_name,
};
use crate::vault::store::VaultStore;
use chrono::Utc;
use std::io::BufRead;
use std::time::Instant;
use uuid::Uuid;

const OPENSSH_PROFILES: &[&str] = &["ssh", "scp", "sftp"];

/// CLI args around a resolved alias or connection token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResolvedArgv {
    /// Flags before the alias / host token (e.g. `ssh -v`).
    leading: Vec<String>,
    /// Alias name or connection target removed from argv when same-profile replay uses `saved_args`.
    removed: Option<String>,
    /// Args after the alias / host token (remote command, `-e "SQL"`, etc.).
    trailing: Vec<String>,
}

impl ResolvedArgv {
    fn split_at(args: &[String], idx: usize) -> Self {
        Self {
            leading: args[..idx].to_vec(),
            removed: args.get(idx).cloned(),
            trailing: args.get(idx + 1..).unwrap_or(&[]).to_vec(),
        }
    }

    /// User-supplied args excluding the resolved alias / connection token.
    fn audit_args(&self) -> Vec<String> {
        let mut v = self.leading.clone();
        v.extend(self.trailing.iter().cloned());
        v
    }

    fn compose_argv(&self, rec: &SecretRecord, profile: &str) -> Vec<String> {
        if rec.profile == profile {
            let mut v = self.leading.clone();
            v.extend(rec.saved_args.iter().cloned());
            v.extend(self.trailing.iter().cloned());
            v
        } else {
            // Cross-profile (e.g. scp borrowing ssh): replay full user argv.
            self.audit_args()
        }
    }
}

/// Profiles to search when resolving a saved record (OpenSSH family shares credentials).
fn lookup_profiles(current: &str) -> Vec<&str> {
    let base = current.rsplit('/').next().unwrap_or(current);
    if OPENSSH_PROFILES.contains(&base) {
        let mut out = vec![base];
        for p in OPENSSH_PROFILES {
            if *p != base {
                out.push(p);
            }
        }
        out
    } else {
        vec![base]
    }
}

fn is_openssh_profile(profile: &str) -> bool {
    let base = profile.rsplit('/').next().unwrap_or(profile);
    OPENSSH_PROFILES.contains(&base)
}

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
    if let Some((rec, resolved)) = lookup {
        return exec_saved(&store, rec, resolved, &profile);
    }

    // ---- First-time / unknown — run raw with prompt capture ----
    exec_fresh(&store, profile, binary, args)
}

/// Resolve a saved record from CLI args. Returns the record plus argv fragments
/// around the matched alias / connection token.
fn resolve_record(
    store: &VaultStore,
    profile: &str,
    args: &[String],
) -> Result<Option<(SecretRecord, ResolvedArgv)>> {
    if args.is_empty() {
        return Ok(None);
    }

    // 1. First positional non-flag arg == alias name.
    let first_positional = args.iter().position(|a| !a.starts_with('-'));
    if let Some(idx) = first_positional {
        let token = &args[idx];
        for lp in lookup_profiles(profile) {
            if let Some(rec) = store.get(lp, token)? {
                return Ok(Some((rec, ResolvedArgv::split_at(args, idx))));
            }
        }
    }

    // 2. Fall back to host-alias fuzzy match.
    let host = infer_host(profile, args);
    if let Some(h) = host {
        let records = store.list()?;
        let profiles = lookup_profiles(profile);
        let matches: Vec<_> = records
            .into_iter()
            .filter(|r| {
                profiles.contains(&r.profile.as_str()) && r.host_alias.as_deref() == Some(&h)
            })
            .collect();
        match matches.len() {
            0 => {}
            1 => {
                let idx = connection_token_index(profile, args, &h).unwrap_or_else(|| {
                    first_positional.expect("infer_host implied a positional arg")
                });
                return Ok(Some((
                    matches.into_iter().next().unwrap(),
                    ResolvedArgv::split_at(args, idx),
                )));
            }
            _ => {
                eprintln!("brokr: multiple records match host '{}':", h);
                for r in &matches {
                    eprintln!("  - {}/{}", r.profile, r.name);
                }
                eprintln!(
                    "Use the alias name to disambiguate, e.g. `brokr {} <alias>`",
                    profile
                );
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
    resolved: ResolvedArgv,
    profile: &str,
) -> Result<()> {
    // Compose final argv: saved_args for same-profile replay; cross-profile borrows password only.
    let args_for_audit = redact_args(&resolved.audit_args());
    let mut argv = resolved.compose_argv(&rec, profile);
    #[cfg(unix)]
    let _key_guard = if is_openssh_profile(profile) {
        match crate::runtime::ssh_identity::materialize_identity(&rec)? {
            Some(guard) => {
                crate::runtime::ssh_identity::insert_identity_arg(&mut argv, &guard.path);
                Some(guard)
            }
            None => None,
        }
    } else {
        None
    };

    let patterns = patterns_for(profile);
    let start = Instant::now();
    #[cfg(unix)]
    let result = crate::runtime::pty::run(
        profile,
        &argv,
        PtyCredential::VaultRecord(rec.id),
        &patterns,
    )?;
    #[cfg(not(unix))]
    let result = {
        let master_kek = get_or_init_master_kek()?;
        let fields = decrypt_for_exec(&rec.crypto, &master_kek)?;
        let password = fields
            .get("password")
            .ok_or_else(|| BrokrError::Vault("no password field in record".into()))?;
        crate::runtime::pty::run(
            profile,
            &argv,
            PtyCredential::Secret(password),
            &patterns,
        )?
    };
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
        args_redacted: args_for_audit,
        hardening: crate::security::hardening::last_hardening_report(),
        injector_pid: result.injector_pid,
        injector_dur_ms: result.injector_dur_ms,
        injector_outcome: result.injector_outcome.clone(),
        hmac_version: None,
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

    if crate::security::tty::stdin_is_pipe() && is_openssh_profile(&profile) {
        eprintln!(
            "brokr: stdin is a pipe; save credentials first with an interactive `brokr {} <host>` (TTY required).",
            profile.rsplit('/').next().unwrap_or(&profile)
        );
    }

    // Pre-collect alias so the user doesn't forget to save after the session ends.
    let pre_alias = if !args.is_empty() && crate::security::tty::stdin_is_real_tty() {
        prompt_alias_beforehand(store, &profile, &args)?
    } else {
        None
    };

    let patterns = patterns_for(&profile);
    let start = Instant::now();
    let result = crate::runtime::pty::run(&binary, &args, PtyCredential::None, &patterns)?;
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
        hardening: crate::security::hardening::last_hardening_report(),
        injector_pid: result.injector_pid,
        injector_dur_ms: result.injector_dur_ms,
        injector_outcome: result.injector_outcome.clone(),
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    let _ = append(&mut ev, &get_or_init_audit_hmac_key()?);

    if result.had_prompt
        && result.captured_password.is_none()
        && crate::security::tty::stdin_is_pipe()
        && is_openssh_profile(&profile)
    {
        eprintln!(
            "brokr: password prompt seen but stdin is a pipe — cannot type or save. Run interactively first."
        );
    }

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
        eprintln!(
            "brokr: alias '{}/{}' already exists — will skip save",
            profile, alias
        );
        return Ok(None);
    }
    Ok(Some(alias))
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
        eprintln!(
            "brokr: alias '{}/{}' already exists — skipping save",
            profile, alias
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::record::encrypt_record;
    use crate::vault::keychain::get_or_init_master_kek;
    use std::collections::BTreeMap;
    use std::env;

    fn with_temp_home<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let tmp = tempfile::tempdir().unwrap();
        let old_home = env::var_os("HOME");
        let old_fallback = env::var_os("BROKR_ALLOW_FILE_KEYCHAIN");
        env::set_var("HOME", tmp.path());
        env::set_var("BROKR_ALLOW_FILE_KEYCHAIN", "1");
        let result = f();
        match old_home {
            Some(v) => env::set_var("HOME", v),
            None => env::remove_var("HOME"),
        }
        match old_fallback {
            Some(v) => env::set_var("BROKR_ALLOW_FILE_KEYCHAIN", v),
            None => env::remove_var("BROKR_ALLOW_FILE_KEYCHAIN"),
        }
        result
    }

    fn sample_ssh_record(name: &str, host: &str) -> SecretRecord {
        let master = get_or_init_master_kek().unwrap();
        let reveal_salt = crate::vault::crypto::kdf::new_salt();
        let reveal = crate::vault::crypto::kdf::derive_reveal_key(
            &SecretString::new("reveal-pass".into()),
            &reveal_salt,
        )
        .unwrap();
        let mut fields: BTreeMap<String, SecretString> = BTreeMap::new();
        fields.insert("password".into(), SecretString::new("testpw".into()));
        let crypto = encrypt_record(&fields, &master, &reveal, reveal_salt);

        SecretRecord {
            id: Uuid::new_v4(),
            profile: "ssh".into(),
            name: name.into(),
            labels: vec![],
            host_alias: Some(host.into()),
            binary: Some("ssh".into()),
            fields_meta: None,
            saved_args: vec![format!("user@{}", host)],
            crypto,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            schema_version: 1,
            reveal_protected: true,
        }
    }

    #[test]
    #[serial_test::serial]
    fn scp_resolves_ssh_record_by_host() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            let rec = sample_ssh_record("lan", "10.0.0.1");
            store.insert(rec).unwrap();

            let args = vec!["/etc/hosts".into(), "user@10.0.0.1:/tmp/x".into()];
            let resolved = resolve_record(&store, "scp", &args)
                .unwrap()
                .expect("scp should borrow ssh record by host");
            assert_eq!(resolved.0.profile, "ssh");
            assert_eq!(resolved.0.host_alias.as_deref(), Some("10.0.0.1"));
        });
    }

    #[test]
    fn lookup_profiles_includes_openssh_siblings() {
        let p = lookup_profiles("scp");
        assert!(p.contains(&"scp"));
        assert!(p.contains(&"ssh"));
        assert!(p.contains(&"sftp"));
    }

    #[test]
    #[serial_test::serial]
    fn alias_appends_trailing_remote_command() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            let mut rec = sample_ssh_record("b150", "198.51.100.2");
            rec.name = "b150".into();
            rec.saved_args = vec!["root@198.51.100.2".into()];
            store.insert(rec).unwrap();

            let args = vec!["b150".into(), "uname".into(), "-a".into()];
            let (rec, resolved) = resolve_record(&store, "ssh", &args)
                .unwrap()
                .expect("alias should resolve");
            assert_eq!(
                resolved.compose_argv(&rec, "ssh"),
                vec![
                    "root@198.51.100.2".to_string(),
                    "uname".to_string(),
                    "-a".to_string()
                ]
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn alias_preserves_leading_flags_before_remote_command() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            let mut rec = sample_ssh_record("prod", "10.0.0.1");
            rec.saved_args = vec!["deploy@10.0.0.1".into()];
            store.insert(rec).unwrap();

            let args = vec![
                "-v".into(),
                "prod".into(),
                "hostname".into(),
            ];
            let (rec, resolved) = resolve_record(&store, "ssh", &args)
                .unwrap()
                .expect("alias should resolve");
            assert_eq!(
                resolved.compose_argv(&rec, "ssh"),
                vec![
                    "-v".to_string(),
                    "deploy@10.0.0.1".to_string(),
                    "hostname".to_string()
                ]
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn host_match_appends_trailing_remote_command() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            let mut rec = sample_ssh_record("root@198.51.100.2", "198.51.100.2");
            rec.saved_args = vec!["root@198.51.100.2".into()];
            store.insert(rec).unwrap();

            let args = vec!["198.51.100.2".into(), "uptime".into()];
            let (rec, resolved) = resolve_record(&store, "ssh", &args)
                .unwrap()
                .expect("host alias should resolve");
            assert_eq!(
                resolved.compose_argv(&rec, "ssh"),
                vec!["root@198.51.100.2".to_string(), "uptime".to_string()]
            );
        });
    }
}
