//! `brokre <cli> [args...]` — transparent PTY wrapper that:
//!   1. Looks up an existing alias matching args; replays its saved_args
//!      (leading flags before the alias, trailing command args after it)
//!      and auto-injects the stored password.
//!   2. Otherwise runs the CLI verbatim, captures any password the user
//!      types at a prompt, and offers to save it as an alias on success.
//!
//! Saved-alias one-shot commands:
//!   `brokre ssh prod-bastion uname -a`
//!   `brokre mysql prod-db -e "SHOW TABLES"`
//!
//! Exit code of the child is propagated verbatim. brokre never invents
//! its own error code to mask a real connection / auth failure.

use crate::audit::logger::{append, exec_audit_source, redact_args, AuditEvent};
use crate::bastion::gate::prepare_outbound_gate_for_exec;
use crate::bastion::route::{
    build_routed_direct_inner_argv, build_routed_local_argv, parse_route, BastionRoute,
    DIRECT_INNER_ENV, ROUTED_INNER_ALIAS_ENV,
};
use crate::runtime::prompts::patterns_for;
use crate::runtime::pty::PtyCredential;
use crate::security::secret::SecretString;
use crate::utils::errors::{BrokreError, Result};
#[cfg(not(unix))]
use crate::vault::crypto::record::decrypt_for_exec;
use crate::vault::keychain::get_or_init_audit_hmac_key;
#[cfg(not(unix))]
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::model::SecretRecord;
use crate::vault::service::{
    auto_save, connection_token_index, infer_host, rewrite_scp_remote_spec,
    save_with_reveal_prompt, scp_remote_host_token, suggest_name,
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
        let bin = profile.rsplit('/').next().unwrap_or(profile);
        if matches!(bin, "scp" | "sftp") {
            let mut v = self.leading.clone();
            if let Some(ref removed) = self.removed {
                v.push(rewrite_scp_remote_spec(&rec.saved_args, removed));
            }
            v.extend(self.trailing.iter().cloned());
            return v;
        }
        if rec.profile == profile {
            let mut v = self.leading.clone();
            v.extend(rec.saved_args.iter().cloned());
            v.extend(self.trailing.iter().cloned());
            v
        } else {
            // Cross-profile (e.g. scp borrowing ssh): replay user argv without the token.
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

fn is_openssh_file_transfer(profile: &str) -> bool {
    matches!(
        profile.rsplit('/').next().unwrap_or(profile),
        "scp" | "sftp"
    )
}

/// SSH-only TTY forwarding flags (`-tt`). Must not run for `scp`/`sftp`: their argv
/// is `[local…, remote:path]` with an empty remote-command tail, which would otherwise
/// look like an interactive login and inject `-tt` before the local path — OpenSSH 10.x
/// then fails locally with `scp: ambiguous target`.
fn apply_openssh_tty_argv_adjustments(
    profile: &str,
    argv: &mut Vec<String>,
    trailing: &[String],
) {
    if !is_openssh_profile(profile) || is_openssh_file_transfer(profile) {
        return;
    }
    if trailing.is_empty() {
        crate::runtime::ssh_identity::insert_force_tty_for_interactive_login(argv, trailing);
    } else {
        crate::runtime::ssh_identity::insert_force_tty_for_privileged_remote(argv, trailing);
        crate::runtime::ssh_identity::insert_force_tty_for_routed_interactive(argv, trailing);
    }
}

/// Vault alias tokens to try for a single scp/sftp positional arg.
fn scp_alias_lookup_tokens(arg: &str) -> Vec<String> {
    let mut out = vec![arg.to_string()];
    if let Some(host) = scp_remote_host_token(arg) {
        if host != arg {
            out.push(host);
        }
    }
    out
}

/// Routed exec through one or more bastion hops (`bastion::inner`).
struct RoutedExec {
    profile: String,
    route: BastionRoute,
    leading: Vec<String>,
    trailing: Vec<String>,
}

/// Entry point used by `main.rs` for any external subcommand.
pub fn run(binary: String, args: Vec<String>) -> Result<()> {
    // Confirm binary is actually on PATH; otherwise produce the same error a
    // user would see by typing the command directly.
    if which::which(&binary).is_err() {
        return Err(BrokreError::Runtime(format!(
            "{}: command not found",
            binary
        )));
    }

    let profile = binary.clone();

    if let Some(routed) = detect_bastion_route(&profile, &args)? {
        return exec_routed(routed);
    }

    let store = VaultStore::open()?;

    // ---- Try to resolve a saved alias ----
    let lookup = resolve_record(&store, &profile, &args)?;
    if let Some((rec, resolved)) = lookup {
        return exec_saved(&store, rec, resolved, &profile);
    }

    // ---- First-time / unknown — run raw with prompt capture ----
    exec_fresh(&store, profile, binary, args)
}

fn detect_bastion_route(profile: &str, args: &[String]) -> Result<Option<RoutedExec>> {
    let idx = match args.iter().position(|a| !a.starts_with('-')) {
        Some(i) => i,
        None => return Ok(None),
    };
    let token = &args[idx];
    if let Some(route) = parse_route(token)? {
        return Ok(Some(RoutedExec {
            profile: profile.to_string(),
            route,
            leading: args[..idx].to_vec(),
            trailing: args[idx + 1..].to_vec(),
        }));
    }
    Ok(None)
}

fn exec_routed(r: RoutedExec) -> Result<()> {
    let mut gate_args = r.leading.clone();
    gate_args.push(r.route.addr.clone());
    gate_args.extend(r.trailing.clone());
    prepare_outbound_gate_for_exec(&r.profile, &gate_args)?;
    let store = VaultStore::open()?;
    let inner_record = resolve_routed_inner_record(&store, &r.profile, &r.route)?;
    let direct_inner = std::env::var_os(DIRECT_INNER_ENV).is_some();
    let mut argv = if direct_inner {
        if let Some((_, ref target, ref inner_name)) = inner_record {
            std::env::set_var(ROUTED_INNER_ALIAS_ENV, inner_name);
            build_routed_direct_inner_argv(&r.route, target, &r.trailing)
        } else {
            std::env::remove_var(ROUTED_INNER_ALIAS_ENV);
            build_routed_local_argv(&r.profile, &r.route, &r.trailing)
        }
    } else {
        std::env::remove_var(ROUTED_INNER_ALIAS_ENV);
        build_routed_local_argv(&r.profile, &r.route, &r.trailing)
    };
    let mut full = r.leading;
    full.append(&mut argv);
    run("ssh".to_string(), full)
}

/// Mac-vault inner target for a routed exec (`openssh` connection token + alias name).
fn resolve_routed_inner_record(
    store: &VaultStore,
    profile: &str,
    route: &BastionRoute,
) -> Result<Option<(Uuid, String, String)>> {
    let routed_name = format!("{}::{}", route.first_hop(), route.inner);
    for lp in lookup_profiles(profile) {
        let rec = store
            .get(lp, &routed_name)?
            .or_else(|| store.get(lp, &route.inner).ok().flatten());
        if let Some(rec) = rec {
            let target = crate::runtime::ssh_identity::openssh_connection_target(&rec.saved_args)
                .unwrap_or_else(|| route.inner.clone());
            return Ok(Some((rec.id, target, route.inner.clone())));
        }
    }
    Ok(None)
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

    // 1b. scp/sftp: alias may appear in any remote spec (`alias:path`), not only argv[0].
    if is_openssh_file_transfer(profile) {
        for (idx, a) in args.iter().enumerate() {
            if a.starts_with('-') {
                continue;
            }
            for token in scp_alias_lookup_tokens(a) {
                for lp in lookup_profiles(profile) {
                    if let Some(rec) = store.get(lp, &token)? {
                        return Ok(Some((rec, ResolvedArgv::split_at(args, idx))));
                    }
                }
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
                eprintln!("brokre: multiple records match host '{}':", h);
                for r in &matches {
                    eprintln!("  - {}/{}", r.profile, r.name);
                }
                eprintln!(
                    "Use the alias name to disambiguate, e.g. `brokre {} <alias>`",
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
    let mut gate_args = resolved.leading.clone();
    if let Some(t) = &resolved.removed {
        gate_args.push(t.clone());
    }
    gate_args.extend(resolved.trailing.clone());
    prepare_outbound_gate_for_exec(profile, &gate_args)?;

    // Compose final argv: saved_args for same-profile replay; cross-profile borrows password only.
    let mut argv = resolved.compose_argv(&rec, profile);
    let args_for_audit = redact_args(&argv);
    #[cfg(unix)]
    apply_openssh_tty_argv_adjustments(profile, &mut argv, &resolved.trailing);
    #[cfg(unix)]
    let _key_guard = if is_openssh_profile(profile) {
        crate::runtime::ssh_identity::insert_mux_options(&mut argv);
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
    let remote_trailing = if is_openssh_profile(profile) && !resolved.trailing.is_empty() {
        Some(resolved.trailing.as_slice())
    } else {
        None
    };
    #[cfg(unix)]
    let user_trailing =
        crate::runtime::ssh_identity::routed_bastion_user_trailing(&resolved.trailing)
            .unwrap_or(resolved.trailing.as_slice());
    #[cfg(unix)]
    let interactive_elevated =
        crate::runtime::ssh_identity::remote_command_needs_tty(user_trailing)
            && user_trailing
                .windows(2)
                .any(|w| w[0] == "sudo" && w[1] == "-i");
    #[cfg(unix)]
    let is_bastion_outer_hop =
        crate::runtime::ssh_identity::is_routed_bastion_outer_trailing(&resolved.trailing);
    #[cfg(unix)]
    let routed_inner_passive = std::env::var_os("BROKRE_ROUTED_INNER").is_some();
    #[cfg(unix)]
    let inner_route = if is_bastion_outer_hop {
        let inner_name = std::env::var(ROUTED_INNER_ALIAS_ENV)
            .ok()
            .or_else(|| {
                crate::runtime::ssh_identity::routed_bastion_inner_alias(&resolved.trailing)
                    .map(|s| s.to_string())
            });
        inner_name.and_then(|inner_name| {
                let routed_name = format!("{}::{}", rec.name, inner_name);
                lookup_profiles(profile).into_iter().find_map(|lp| {
                    store
                        .get(lp, &routed_name)
                        .ok()
                        .flatten()
                        .or_else(|| store.get(lp, &inner_name).ok().flatten())
                        .map(|r| {
                            let hint = crate::runtime::ssh_identity::openssh_connection_target(
                                &r.saved_args,
                            )
                            .or(r.host_alias.clone())
                            .unwrap_or_else(|| inner_name.to_string());
                            (r.id, hint)
                        })
                })
            })
    } else {
        None
    };
    #[cfg(unix)]
    let inner_vault_record = inner_route.as_ref().map(|(id, _)| *id);
    #[cfg(unix)]
    let inner_host_hint = inner_route.map(|(_, host)| host);
    #[cfg(unix)]
    let pty_options = crate::runtime::pty::PtyRunOptions {
        bastion_outer_hop: is_bastion_outer_hop,
        defer_stdin_forward: interactive_elevated && !is_bastion_outer_hop && !routed_inner_passive,
        inner_vault_record,
        inner_host_hint,
        inject_disabled: false,
        passive_inner_ssh: routed_inner_passive,
    };
    #[cfg(unix)]
    let exec_cred = PtyCredential::VaultRecord(rec.id);
    #[cfg(unix)]
    let result = if crate::runtime::pipe_exec::should_use_inherited_tty_mode(
        profile,
        routed_inner_passive,
        resolved.trailing.is_empty(),
    ) {
        crate::runtime::pipe_exec::run_inherited_tty(profile, &argv)?
    } else if crate::runtime::pipe_exec::should_use_askpass_inherited_tty_mode(
        profile,
        remote_trailing,
    ) {
        crate::runtime::pipe_exec::run_askpass_inherited_tty(profile, &argv, rec.id)?
    } else if crate::runtime::pipe_exec::should_use_pipe_mode(
        profile,
        crate::security::tty::stdin_is_pipe(),
        remote_trailing,
    ) {
        crate::runtime::pipe_exec::run(profile, &argv, rec.id)?
    } else {
        crate::runtime::pty::run(profile, &argv, exec_cred, &patterns, pty_options)?
    };
    #[cfg(not(unix))]
    let result = {
        let master_kek = get_or_init_master_kek()?;
        let fields = decrypt_for_exec(&rec.crypto, &master_kek)?;
        let password = fields
            .get("password")
            .ok_or_else(|| BrokreError::Vault("no password field in record".into()))?;
        crate::runtime::pty::run(
            profile,
            &argv,
            PtyCredential::Secret(password),
            &patterns,
            crate::runtime::pty::PtyRunOptions::default(),
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
        source: Some(exec_audit_source()),
        route: None,
        bastion: None,
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
        // Allow zero-arg invocation (e.g. `brokre mysql` to launch interactive shell)
        // — still run it but skip the save prompt.
    }

    if crate::security::tty::stdin_is_pipe() && is_openssh_profile(&profile) {
        eprintln!(
            "brokre: stdin is a pipe; save credentials first with an interactive `brokre {} <host>` (TTY required).",
            profile.rsplit('/').next().unwrap_or(&profile)
        );
    }

    prepare_outbound_gate_for_exec(&profile, &args)?;

    // Pre-collect alias so the user doesn't forget to save after the session ends.
    let pre_alias = if !args.is_empty() && crate::security::tty::stdin_is_real_tty() {
        prompt_alias_beforehand(store, &profile, &args)?
    } else {
        None
    };

    let patterns = patterns_for(&profile);
    let start = Instant::now();
    let result = crate::runtime::pty::run(
        &binary,
        &args,
        PtyCredential::None,
        &patterns,
        crate::runtime::pty::PtyRunOptions::default(),
    )?;
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
        source: Some(exec_audit_source()),
        route: None,
        bastion: None,
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
            "brokre: password prompt seen but stdin is a pipe — cannot type or save. Run interactively first."
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
            "brokre: connection did not complete successfully — password not saved for alias '{}'",
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
    eprintln!("brokre: first-time connection. Save as alias for next time?");
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
        eprintln!("brokre: invalid alias '{}' — will skip save", alias);
        return Ok(None);
    }
    if store.get(profile, &alias)?.is_some() {
        eprintln!(
            "brokre: alias '{}/{}' already exists — will skip save",
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
    eprintln!("brokre: ✓ login successful — save this connection for next time?");
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
        eprintln!("brokre: invalid alias '{}' — skipping save", alias);
        return Ok(());
    }
    if store.get(profile, &alias)?.is_some() {
        eprintln!(
            "brokre: alias '{}/{}' already exists — skipping save",
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
    use crate::utils::test_home::with_temp_brokre_home;
    use crate::vault::crypto::record::encrypt_record;
    use crate::vault::keychain::get_or_init_master_kek;
    use std::collections::BTreeMap;

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
        with_temp_brokre_home(|| {
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
    #[serial_test::serial]
    fn scp_resolves_ssh_alias_in_remote_spec() {
        with_temp_brokre_home(|| {
            let store = VaultStore::open().unwrap();
            let mut rec = sample_ssh_record("dev-host", "10.0.0.1");
            rec.saved_args = vec!["root@10.0.0.1".into()];
            store.insert(rec).unwrap();

            let args = vec!["./local.bin".into(), "dev-host:/remote/path".into()];
            let (rec, resolved) = resolve_record(&store, "scp", &args)
                .unwrap()
                .expect("scp should borrow ssh alias from remote spec");
            assert_eq!(rec.name, "dev-host");
            assert_eq!(
                resolved.compose_argv(&rec, "scp"),
                vec![
                    "./local.bin".to_string(),
                    "root@10.0.0.1:/remote/path".to_string()
                ]
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn scp_host_match_rewrites_remote_endpoint() {
        with_temp_brokre_home(|| {
            let store = VaultStore::open().unwrap();
            let mut rec = sample_ssh_record("lan", "10.0.0.1");
            rec.saved_args = vec!["root@10.0.0.1".into()];
            store.insert(rec).unwrap();

            let args = vec!["/etc/hosts".into(), "user@10.0.0.1:/tmp/x".into()];
            let (rec, resolved) = resolve_record(&store, "scp", &args)
                .unwrap()
                .expect("scp should borrow ssh record by host");
            assert_eq!(
                resolved.compose_argv(&rec, "scp"),
                vec!["/etc/hosts".to_string(), "root@10.0.0.1:/tmp/x".to_string()]
            );
        });
    }

    #[test]
    fn scp_argv_skips_interactive_tty_insert() {
        let mut argv = vec![
            "./local.bin".into(),
            "root@10.0.0.1:/remote/path".into(),
        ];
        apply_openssh_tty_argv_adjustments("scp", &mut argv, &[]);
        assert_eq!(
            argv,
            vec![
                "./local.bin".to_string(),
                "root@10.0.0.1:/remote/path".to_string()
            ]
        );
    }

    #[test]
    fn ssh_interactive_login_still_gets_force_tty() {
        let mut argv = vec!["root@10.0.0.1".into()];
        apply_openssh_tty_argv_adjustments("ssh", &mut argv, &[]);
        assert_eq!(argv, vec!["-tt".to_string(), "root@10.0.0.1".to_string()]);
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
        with_temp_brokre_home(|| {
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
        with_temp_brokre_home(|| {
            let store = VaultStore::open().unwrap();
            let mut rec = sample_ssh_record("prod", "10.0.0.1");
            rec.saved_args = vec!["deploy@10.0.0.1".into()];
            store.insert(rec).unwrap();

            let args = vec!["-v".into(), "prod".into(), "hostname".into()];
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
        with_temp_brokre_home(|| {
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
