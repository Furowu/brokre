//! Write a vault-stored SSH private key to a short-lived 0600 file for `ssh -i`.

use crate::security::secret::SecretString;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;

/// Seconds to keep a multiplexed SSH control socket warm between commands.
const SSH_MUX_PERSIST_SECS: &str = "300";
/// Default OpenSSH ConnectTimeout (seconds). Override with BROKRE_SSH_CONNECT_TIMEOUT.
const DEFAULT_SSH_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_SSH_SERVER_ALIVE_INTERVAL: u64 = 15;
const DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX: u64 = 2;
use crate::vault::crypto::record::decrypt_for_exec;
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::model::SecretRecord;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct SecureKeyFile {
    pub path: PathBuf,
}

impl Drop for SecureKeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn record_has_private_key(rec: &SecretRecord) -> bool {
    rec.fields_meta
        .as_ref()
        .is_some_and(|m| m.iter().any(|f| f.name == "private_key"))
}

pub fn injectable_field_names(rec: &SecretRecord) -> Vec<String> {
    if let Some(meta) = &rec.fields_meta {
        return meta
            .iter()
            .filter(|f| f.secret && f.name != "private_key")
            .map(|f| f.name.clone())
            .collect();
    }
    vec!["password".into()]
}

/// Unescape JSON/notebook-style `\\n` when PEM was pasted as a single line.
/// Ensures a trailing newline — OpenSSH rejects PEM without one.
pub fn normalize_private_key_pem(raw: &str) -> String {
    let mut t = if raw.contains('\n') {
        raw.to_string()
    } else if raw.contains("\\n") {
        raw.replace("\\n", "\n")
    } else {
        raw.to_string()
    };
    t = t.trim_start().trim_end_matches('\r').to_string();
    if !t.ends_with('\n') {
        t.push('\n');
    }
    t
}

pub fn validate_private_key_pem(pem: &str) -> bool {
    let t = normalize_private_key_pem(pem);
    (t.contains("BEGIN OPENSSH PRIVATE KEY")
        || t.contains("BEGIN RSA PRIVATE KEY")
        || t.contains("BEGIN EC PRIVATE KEY")
        || t.contains("BEGIN PRIVATE KEY")
        || t.contains("BEGIN DSA PRIVATE KEY"))
        && t.contains("END ")
}

/// OpenSSH short options that consume the next argv token (ssh/scp/sftp union).
fn openssh_short_takes_value(ch: char) -> bool {
    matches!(
        ch,
        'b' | 'c'
            | 'D'
            | 'E'
            | 'e'
            | 'F'
            | 'I'
            | 'i'
            | 'J'
            | 'L'
            | 'l'
            | 'm'
            | 'O'
            | 'o'
            | 'p'
            | 'P'
            | 'R'
            | 'S'
            | 'W'
            | 'w'
            | 'B'
            | 's'
    )
}

fn openssh_attached_short_value(arg: &str) -> bool {
    if arg.len() < 3 || !arg.starts_with('-') || arg.starts_with("--") {
        return false;
    }
    let ch = arg.as_bytes()[1] as char;
    openssh_short_takes_value(ch)
}

fn openssh_option_consumes_next_for_profile(profile: &str, arg: &str) -> bool {
    if arg == "--" {
        return false;
    }
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    if bin == "scp" && arg == "-O" {
        return false;
    }
    if arg.starts_with("--") {
        return !arg.contains('=');
    }
    if arg.starts_with("-o") && arg.len() > 2 {
        return false;
    }
    if openssh_attached_short_value(arg) {
        return false;
    }
    if arg.len() > 2 && !arg.starts_with("--") {
        // Combined short flags such as `-vvv`.
        return false;
    }
    if arg.len() == 2 && arg.starts_with('-') {
        let ch = arg.as_bytes()[1] as char;
        return openssh_short_takes_value(ch);
    }
    false
}

/// Connection target token (`user@host` / `host`) from saved OpenSSH argv.
pub fn openssh_connection_target(argv: &[String]) -> Option<String> {
    let idx = connection_target_index(argv);
    argv.get(idx).cloned()
}

/// Index of the connection target (`user@host` / `host`) in a saved OpenSSH argv.
fn connection_target_index(argv: &[String]) -> usize {
    connection_target_index_for_profile("ssh", argv)
}

fn connection_target_index_for_profile(profile: &str, argv: &[String]) -> usize {
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            return (i + 1).min(argv.len());
        }
        if !a.starts_with('-') {
            return i;
        }
        if openssh_option_consumes_next_for_profile(profile, a) {
            i += 2;
        } else {
            i += 1;
        }
    }
    argv.len()
}

/// Index of the first connection target / alias token in OpenSSH-style argv
/// (skips `-o Value`, `-F path`, etc.).
pub fn openssh_first_positional_index(profile: &str, argv: &[String]) -> Option<usize> {
    let idx = connection_target_index_for_profile(profile, argv);
    if idx < argv.len() {
        Some(idx)
    } else {
        None
    }
}

/// Compatibility alias used by tunnel/ssh_pool call sites.
pub fn openssh_connection_target_index_for_profile(profile: &str, argv: &[String]) -> usize {
    connection_target_index_for_profile(profile, argv)
}

fn has_mux_options(argv: &[String]) -> bool {
    has_openssh_option_prefix(argv, "ControlPath=")
        || has_openssh_option_prefix(argv, "ControlMaster=")
        || has_openssh_option_exact(argv, "ControlMaster")
}

/// True when argv already contains `-o Name=…` or `-o Name` matching `prefix` (e.g. `ConnectTimeout=`).
pub fn has_openssh_option_prefix(argv: &[String], prefix: &str) -> bool {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "-o" && i + 1 < argv.len() {
            if argv[i + 1].starts_with(prefix) {
                return true;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

fn has_openssh_option_exact(argv: &[String], name: &str) -> bool {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "-o" && i + 1 < argv.len() {
            if argv[i + 1] == name {
                return true;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

fn is_openssh_family_profile(profile: &str) -> bool {
    matches!(
        profile.rsplit('/').next().unwrap_or(profile),
        "ssh" | "scp" | "sftp"
    )
}

pub fn ssh_connect_timeout_secs() -> u64 {
    std::env::var("BROKRE_SSH_CONNECT_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SSH_CONNECT_TIMEOUT_SECS)
}

/// Inject default OpenSSH timeouts when the user did not pass them.
/// `ConnectTimeout` default is 5s (`BROKRE_SSH_CONNECT_TIMEOUT`).
pub fn insert_default_ssh_timeouts(profile: &str, argv: &mut Vec<String>) {
    if !is_openssh_family_profile(profile) {
        return;
    }
    let pos = connection_target_index_for_profile(profile, argv);
    let mut pairs: Vec<(String, String)> = Vec::new();
    if !has_openssh_option_prefix(argv, "ConnectTimeout=") {
        pairs.push((
            "-o".into(),
            format!("ConnectTimeout={}", ssh_connect_timeout_secs()),
        ));
    }
    if !has_openssh_option_prefix(argv, "ServerAliveInterval=") {
        pairs.push((
            "-o".into(),
            format!("ServerAliveInterval={DEFAULT_SSH_SERVER_ALIVE_INTERVAL}"),
        ));
    }
    if !has_openssh_option_prefix(argv, "ServerAliveCountMax=") {
        pairs.push((
            "-o".into(),
            format!("ServerAliveCountMax={DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX}"),
        ));
    }
    for (flag, val) in pairs.into_iter().rev() {
        argv.insert(pos, val);
        argv.insert(pos, flag);
    }
}

/// True when OpenSSH argv has tokens after the connection target (a remote command).
pub fn argv_has_remote_command(profile: &str, argv: &[String]) -> bool {
    let idx = connection_target_index_for_profile(profile, argv);
    argv.get(idx).is_some() && argv.len() > idx + 1
}

/// Reuse one authenticated SSH session across rapid `brokre ssh` invocations (e.g. deploy scripts).
pub fn insert_mux_options(argv: &mut Vec<String>) {
    insert_mux_options_for_profile("ssh", argv)
}

pub fn insert_mux_options_for_profile(profile: &str, argv: &mut Vec<String>) {
    let detach_mux = remote_command_detaches_mux(profile, argv);
    if has_mux_options(argv) {
        // Remote commands must not attach to a mux master (exit hang after
        // "Shared connection … closed."). Rewrite auto → no when needed.
        if detach_mux {
            force_control_master_no(argv);
            force_control_path_none(argv);
        } else if argv_has_remote_command(profile, argv) {
            force_control_master_no(argv);
        }
        return;
    }
    let pos = connection_target_index_for_profile(profile, argv);
    if detach_mux {
        let pairs = [
            ("-o", "ControlPath=none".to_string()),
            ("-o", "ControlMaster=no".to_string()),
        ];
        for (flag, val) in pairs.iter().rev() {
            argv.insert(pos, val.clone());
            argv.insert(pos, (*flag).into());
        }
        return;
    }
    let sock = run_dir().join("ssh-%C.sock");
    let path = sock.to_string_lossy().to_string();
    let master = if argv_has_remote_command(profile, argv) {
        "ControlMaster=no"
    } else {
        "ControlMaster=auto"
    };
    let pairs = [
        ("-o", format!("ControlPersist={}", SSH_MUX_PERSIST_SECS)),
        ("-o", format!("ControlPath={}", path)),
        ("-o", master.into()),
    ];
    for (flag, val) in pairs.iter().rev() {
        argv.insert(pos, val.clone());
        argv.insert(pos, (*flag).into());
    }
}

fn remote_command_detaches_mux(profile: &str, argv: &[String]) -> bool {
    if !argv_has_remote_command(profile, argv) {
        return false;
    }
    let idx = connection_target_index_for_profile(profile, argv);
    let trailing = &argv[idx + 1..];
    !(is_routed_interactive_trailing(trailing) || is_routed_bastion_outer_trailing(trailing))
}

fn force_control_master_no(argv: &mut [String]) {
    let mut i = 0;
    while i + 1 < argv.len() {
        if argv[i] == "-o" && argv[i + 1].starts_with("ControlMaster=") {
            argv[i + 1] = "ControlMaster=no".into();
            return;
        }
        i += 1;
    }
}

fn force_control_path_none(argv: &mut [String]) {
    let mut i = 0;
    while i + 1 < argv.len() {
        if argv[i] == "-o" && argv[i + 1].starts_with("ControlPath=") {
            argv[i + 1] = "ControlPath=none".into();
            return;
        }
        i += 1;
    }
}

/// Connection target from an OpenSSH argv slice (flags + `user@host` + optional remote command).
pub fn openssh_argv_connection_target(argv: &[String]) -> Option<String> {
    let idx = connection_target_index(argv);
    argv.get(idx).cloned()
}

/// `ControlPath` from `-o ControlPath=…` in an OpenSSH argv slice.
pub fn mux_control_path_from_argv(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i + 1 < argv.len() {
        if argv[i] == "-o" && argv[i + 1].starts_with("ControlPath=") {
            return Some(argv[i + 1]["ControlPath=".len()..].to_string());
        }
        i += 1;
    }
    None
}

/// Argv for `ssh -N -f` mux master (hop auth only; no remote command).
pub fn build_mux_master_argv(argv: &[String]) -> Vec<String> {
    let target_idx = connection_target_index(argv);
    let mut out = Vec::new();
    let mut i = 0;
    while i < target_idx {
        match argv[i].as_str() {
            "-t" | "-tt" => {
                i += 1;
            }
            "-o" if i + 1 < target_idx => {
                let val = &argv[i + 1];
                if val.starts_with("ControlMaster=") {
                    out.push("-o".into());
                    out.push("ControlMaster=yes".into());
                } else {
                    out.push("-o".into());
                    out.push(val.clone());
                }
                i += 2;
            }
            other => {
                out.push(other.into());
                i += 1;
            }
        }
    }
    if let Some(target) = argv.get(target_idx) {
        out.push(target.clone());
    }
    out.push("-N".into());
    out.push("-f".into());
    out
}

/// Argv for an interactive session that attaches to an existing mux master (never creates one).
pub fn build_mux_session_argv(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|arg| {
            if arg == "ControlMaster=auto" || arg.starts_with("ControlMaster=auto") {
                "ControlMaster=no".into()
            } else {
                arg.clone()
            }
        })
        .collect()
}

#[cfg(unix)]
fn run_mux_op(binary: &str, op: &str, control_path: &str, target: &str) -> Result<()> {
    let bin = which::which(binary)
        .map_err(|_| BrokreError::Runtime(format!("{}: command not found", binary)))?;
    let _ = Command::new(bin)
        .arg("-O")
        .arg(op)
        .arg("-o")
        .arg(format!("ControlPath={control_path}"))
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(BrokreError::Io)?;
    Ok(())
}

/// Candidate mux socket files for a `ControlPath` template (expands `%C` via directory scan).
pub fn mux_socket_candidates(control_path_template: &str) -> Vec<PathBuf> {
    if control_path_template.contains("%C") {
        let parent = PathBuf::from(control_path_template)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(run_dir);
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("ssh-") && name.ends_with(".sock") {
                    out.push(entry.path());
                }
            }
        }
        out
    } else {
        vec![PathBuf::from(control_path_template)]
    }
}

/// Resolved `ControlPath` after OpenSSH expands `%C` / applies config for this argv.
#[cfg(unix)]
pub fn expanded_mux_control_path(binary: &str, argv: &[String]) -> Option<PathBuf> {
    let target_idx = connection_target_index(argv);
    let target = argv.get(target_idx)?;
    let bin = which::which(binary).ok()?;
    let mut cmd = Command::new(bin);
    cmd.arg("-G");
    for arg in &argv[..target_idx] {
        cmd.arg(arg);
    }
    cmd.arg(target);
    cmd.stdin(Stdio::null());
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        if parts
            .next()
            .is_some_and(|k| k.eq_ignore_ascii_case("controlpath"))
        {
            return parts.next().map(PathBuf::from);
        }
    }
    None
}

#[cfg(not(unix))]
pub fn expanded_mux_control_path(_binary: &str, _argv: &[String]) -> Option<PathBuf> {
    None
}

/// Remove dead mux sockets so `ssh -N -f` can establish a fresh authenticated master.
#[cfg(unix)]
pub fn prune_stale_mux_sockets(binary: &str, argv: &[String]) -> Result<()> {
    if mux_master_alive(binary, argv)? {
        return Ok(());
    }
    let Some(template) = mux_control_path_from_argv(argv) else {
        return Ok(());
    };
    let Some(target) = openssh_argv_connection_target(argv) else {
        return Ok(());
    };

    let _ = run_mux_op(binary, "exit", &template, &target);
    if let Some(expanded) = expanded_mux_control_path(binary, argv) {
        let path = expanded.to_string_lossy().into_owned();
        let _ = run_mux_op(binary, "exit", &path, &target);
    }
    if mux_master_alive(binary, argv)? {
        return Ok(());
    }

    let mut paths = mux_socket_candidates(&template);
    if let Some(expanded) = expanded_mux_control_path(binary, argv) {
        if !paths.iter().any(|p| p == &expanded) {
            paths.push(expanded);
        }
    }

    for path in paths {
        if !path.exists() {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        let _ = run_mux_op(binary, "exit", &path_str, &target);
        if mux_master_alive(binary, argv)? {
            return Ok(());
        }
        let _ = fs::remove_file(&path);
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn prune_stale_mux_sockets(_binary: &str, _argv: &[String]) -> Result<()> {
    Ok(())
}

/// True when an OpenSSH mux control socket is already authenticated for this argv.
#[cfg(unix)]
pub fn mux_master_alive(binary: &str, argv: &[String]) -> Result<bool> {
    let Some(target) = openssh_argv_connection_target(argv) else {
        return Ok(false);
    };
    let path = match expanded_mux_control_path(binary, argv)
        .or_else(|| mux_control_path_from_argv(argv).map(PathBuf::from))
    {
        Some(p) => p,
        None => return Ok(false),
    };
    let path_str = path.to_string_lossy().into_owned();
    let bin = which::which(binary)
        .map_err(|_| BrokreError::Runtime(format!("{}: command not found", binary)))?;
    let status = Command::new(bin)
        .arg("-O")
        .arg("check")
        .arg("-o")
        .arg(format!("ControlPath={path_str}"))
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(BrokreError::Io)?;
    Ok(status.success())
}

/// Poll until mux master answers `ssh -O check` or timeout.
#[cfg(unix)]
pub fn wait_mux_master_alive(binary: &str, argv: &[String], timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if mux_master_alive(binary, argv)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(not(unix))]
pub fn wait_mux_master_alive(_binary: &str, _argv: &[String], _timeout: Duration) -> Result<bool> {
    Ok(false)
}

#[cfg(not(unix))]
pub fn mux_master_alive(_binary: &str, _argv: &[String]) -> Result<bool> {
    Ok(false)
}

/// True when argv after the connection target is a bastion-routed remote brokre exec.
pub fn is_routed_bastion_trailing(trailing: &[String]) -> bool {
    trailing
        .first()
        .is_some_and(|s| crate::utils::paths::remote_shell_token_passthrough(s))
}

/// Direct-inner routing is active (`exec_routed` set [`ROUTED_INNER_ALIAS_ENV`]).
pub fn is_routed_direct_inner_active() -> bool {
    std::env::var_os(crate::bastion::route::ROUTED_INNER_ALIAS_ENV).is_some()
}

/// Index of the connection target in `[ssh, (-tt)?, (-o opt)*, target, …]`.
fn direct_inner_ssh_target_index(trailing: &[String]) -> Option<usize> {
    if trailing.first().map(String::as_str) != Some("ssh") {
        return None;
    }
    let mut i = 1usize;
    while i < trailing.len() {
        match trailing.get(i).map(String::as_str) {
            Some("-t") | Some("-tt") => i += 1,
            Some("-o") if i + 1 < trailing.len() => i += 2,
            Some(t) if !t.starts_with('-') => return Some(i),
            _ => return None,
        }
    }
    None
}

/// True when the bastion hop runs plain `ssh <inner_target> …` on the remote host (no remote brokre).
pub fn is_direct_inner_openssh_trailing(trailing: &[String]) -> bool {
    let i = match direct_inner_ssh_target_index(trailing) {
        Some(i) => i,
        None => return false,
    };
    let Some(target) = trailing.get(i).map(String::as_str) else {
        return false;
    };
    target.contains('@')
        || target.contains('.')
        || target
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | ':'))
}

/// `ssh <inner_target> …` produced by [`exec_routed`] direct-inner mode (not manual remote `ssh`).
pub fn is_routed_direct_inner_trailing(trailing: &[String]) -> bool {
    is_routed_direct_inner_active() && is_direct_inner_openssh_trailing(trailing)
}

/// Outer bastion hop: remote brokre chain or routed direct inner OpenSSH.
pub fn is_routed_bastion_outer_trailing(trailing: &[String]) -> bool {
    is_routed_bastion_trailing(trailing) || is_routed_direct_inner_trailing(trailing)
}

/// Connection target alias in `bastion::inner` routed argv (`[token, ssh, (-tt)?, inner, …]`).
pub fn routed_bastion_inner_alias(trailing: &[String]) -> Option<&str> {
    if !is_routed_bastion_trailing(trailing) {
        return None;
    }
    let mut i = 1usize;
    if trailing.get(i).map(String::as_str) != Some("ssh") {
        return None;
    }
    i += 1;
    if matches!(
        trailing.get(i).map(String::as_str),
        Some("-t") | Some("-tt")
    ) {
        i += 1;
    }
    let inner = trailing.get(i)?;
    if inner.starts_with('-') {
        return None;
    }
    Some(inner.as_str())
}

/// Skip `[token, ssh, (-tt)?, inner]` and return the user command suffix.
pub fn routed_bastion_user_trailing(trailing: &[String]) -> Option<&[String]> {
    if is_routed_bastion_trailing(trailing) {
        let mut i = 1usize;
        if trailing.get(i).map(String::as_str) != Some("ssh") {
            return None;
        }
        i += 1;
        if matches!(
            trailing.get(i).map(String::as_str),
            Some("-t") | Some("-tt")
        ) {
            i += 1;
        }
        let inner = trailing.get(i)?;
        if inner.starts_with('-') {
            return None;
        }
        i += 1;
        return Some(&trailing[i..]);
    }
    if is_routed_direct_inner_trailing(trailing) {
        let i = direct_inner_ssh_target_index(trailing)?;
        return Some(&trailing[i + 1..]);
    }
    None
}

/// Interactive `brokre ssh bastion::inner` (no user command after the inner alias).
pub fn is_routed_interactive_trailing(trailing: &[String]) -> bool {
    routed_bastion_user_trailing(trailing).is_some_and(|user| user.is_empty())
}

/// Interactive `brokre ssh alias` with no remote subcommand.
pub fn is_interactive_login_trailing(trailing: &[String]) -> bool {
    trailing.is_empty()
}

/// Prepend `-tt` for saved-alias interactive logins so the remote shell gets a real TTY.
pub fn insert_force_tty_for_interactive_login(argv: &mut Vec<String>, trailing: &[String]) {
    if !is_interactive_login_trailing(trailing) {
        return;
    }
    if has_tty_request_flag(argv) || has_disable_tty_flag(argv) {
        return;
    }
    let pos = connection_target_index(argv);
    argv.insert(pos, "-tt".into());
}

/// Prepend `-tt` before the connection target for interactive bastion routes.
pub fn insert_force_tty_for_routed_interactive(argv: &mut Vec<String>, trailing: &[String]) {
    if !is_routed_interactive_trailing(trailing) {
        return;
    }
    if has_tty_request_flag(argv) || has_disable_tty_flag(argv) {
        return;
    }
    let pos = connection_target_index(argv);
    argv.insert(pos, "-tt".into());
}

fn user_remote_command_needs_tty(trailing: &[String]) -> bool {
    if trailing.is_empty() {
        return false;
    }
    match trailing[0].as_str() {
        "sudo" | "su" => return true,
        _ => {}
    }
    if trailing.len() == 1 {
        return script_invokes_privilege_escalation(&trailing[0]);
    }
    if let Some(script) = shell_script_from_argv(trailing) {
        return script_invokes_privilege_escalation(script);
    }
    false
}

/// True when a remote command (argv after the connection target) needs a TTY (`sudo` / `su`).
pub fn remote_command_needs_tty(trailing: &[String]) -> bool {
    if let Some(user) = routed_bastion_user_trailing(trailing) {
        return user_remote_command_needs_tty(user);
    }
    user_remote_command_needs_tty(trailing)
}

/// Prepend `-tt` before the connection target when the remote command uses `sudo` / `su`.
pub fn insert_force_tty_for_privileged_remote(argv: &mut Vec<String>, trailing: &[String]) {
    if !remote_command_needs_tty(trailing) {
        return;
    }
    if has_tty_request_flag(argv) || has_disable_tty_flag(argv) {
        return;
    }
    let pos = connection_target_index(argv);
    argv.insert(pos, "-tt".into());
}

fn shell_script_from_argv(trailing: &[String]) -> Option<&str> {
    if trailing.len() < 3 {
        return None;
    }
    if !matches!(
        trailing[0].as_str(),
        "bash" | "sh" | "zsh" | "fish" | "dash" | "ksh" | "csh" | "tcsh"
    ) {
        return None;
    }
    if trailing[1] != "-c" {
        return None;
    }
    trailing.get(2).map(String::as_str)
}

fn script_invokes_privilege_escalation(script: &str) -> bool {
    let s = script.trim().to_ascii_lowercase();
    if s.starts_with("sudo ") || s == "sudo" || s.starts_with("su ") || s == "su" {
        return true;
    }
    [
        " sudo ", " su ", ";sudo", "&&sudo", "||sudo", "|sudo", ";su", "&&su", "||su", "|su",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

fn remote_command_user_trailing(trailing: &[String]) -> &[String] {
    routed_bastion_user_trailing(trailing).unwrap_or(trailing)
}

fn program_basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

fn argv_has_inline_script_flag(trailing: &[String]) -> bool {
    trailing.iter().any(|a| a == "-c" || a == "-e")
}

fn is_stdin_consumer_program(name: &str) -> bool {
    matches!(
        name,
        "cat"
            | "tee"
            | "dd"
            | "tar"
            | "patch"
            | "mysql"
            | "psql"
            | "sqlite3"
            | "gzip"
            | "gunzip"
            | "bzip2"
            | "xz"
            | "zstd"
            | "base64"
    )
}

fn is_stdin_consumer_interpreter(name: &str) -> bool {
    matches!(
        name,
        "sh"
            | "bash"
            | "zsh"
            | "dash"
            | "ash"
            | "ksh"
            | "fish"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
    )
}

fn first_remote_program_token(token: &str) -> &str {
    token.split_whitespace().next().unwrap_or(token)
}

/// True when the remote command is expected to read payload bytes from stdin.
pub fn remote_command_consumes_stdin(trailing: &[String]) -> bool {
    let user = remote_command_user_trailing(trailing);
    if user.is_empty() {
        return false;
    }
    let name = program_basename(first_remote_program_token(&user[0])).to_ascii_lowercase();
    if is_stdin_consumer_program(&name) {
        return true;
    }
    if is_stdin_consumer_interpreter(&name) && !argv_has_inline_script_flag(user) {
        return true;
    }
    false
}

/// Brokre-specific SSH flags stripped before invoking OpenSSH.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrokreSshStdinFlags {
    pub force_disconnect_stdin: bool,
    pub force_forward_stdin: bool,
}

/// Remove brokre-only flags (`--no-stdin`, `--with-stdin`) from argv before OpenSSH sees them.
pub fn strip_brokre_ssh_flags(argv: &mut Vec<String>) -> BrokreSshStdinFlags {
    let mut flags = BrokreSshStdinFlags::default();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--no-stdin" => {
                flags.force_disconnect_stdin = true;
                argv.remove(i);
            }
            "--with-stdin" => {
                flags.force_forward_stdin = true;
                argv.remove(i);
            }
            _ => {
                i += 1;
            }
        }
    }
    flags
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn openssh_short_flag_set(arg: &str, ch: char) -> bool {
    arg.len() >= 2
        && arg.starts_with('-')
        && !arg.starts_with("--")
        && arg[1..].contains(ch)
}

/// True when OpenSSH argv already requests disconnected stdin (`-n`, `-f`, `StdinNull=yes`).
pub fn has_null_stdin_flag(argv: &[String]) -> bool {
    let end = connection_target_index(argv);
    let mut i = 0;
    while i < end {
        let a = &argv[i];
        if a == "-n"
            || a == "-f"
            || openssh_short_flag_set(a, 'n')
            || openssh_short_flag_set(a, 'f')
        {
            return true;
        }
        if a == "-o" && i + 1 < end {
            let v = argv[i + 1].to_ascii_lowercase();
            if v.starts_with("stdinnull=yes") {
                return true;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Whether brokre should not forward caller stdin to OpenSSH for this invocation.
pub fn should_disconnect_stdin(
    profile: &str,
    argv: &[String],
    remote_trailing: Option<&[String]>,
    brokre_flags: &BrokreSshStdinFlags,
) -> bool {
    if brokre_flags.force_forward_stdin {
        return false;
    }
    if brokre_flags.force_disconnect_stdin || has_null_stdin_flag(argv) {
        return true;
    }
    if std::env::var_os("BROKRE_MCP_EXEC").is_some() {
        return true;
    }
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    if bin != "ssh" {
        return false;
    }
    if env_truthy("BROKRE_SSH_LEGACY_STDIN") {
        return legacy_should_disconnect_stdin(remote_trailing);
    }
    if let Some(trailing) = remote_trailing {
        if trailing.is_empty() || remote_command_needs_tty(trailing) {
            return false;
        }
        return !remote_command_consumes_stdin(trailing);
    }
    false
}

fn legacy_should_disconnect_stdin(remote_trailing: Option<&[String]>) -> bool {
    if env_truthy("BROKRE_SSH_AUTO_NULL_STDIN") {
        if let Some(trailing) = remote_trailing {
            if !trailing.is_empty() && !remote_command_needs_tty(trailing) {
                return true;
            }
        }
    }
    false
}

fn has_disable_tty_flag(argv: &[String]) -> bool {
    let end = connection_target_index(argv);
    let mut i = 0;
    while i < end {
        let a = &argv[i];
        if a == "-T" {
            return true;
        }
        if a == "-o" && i + 1 < end {
            let v = argv[i + 1].to_ascii_lowercase();
            if v == "requesttty=no" || v == "requesttty=never" {
                return true;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

fn has_tty_request_flag(argv: &[String]) -> bool {
    let end = connection_target_index(argv);
    let mut i = 0;
    while i < end {
        let a = &argv[i];
        if a == "-t" || a == "-tt" {
            return true;
        }
        if a.len() >= 2
            && a.starts_with('-')
            && !a.starts_with("--")
            && a[1..].chars().any(|c| c == 't')
        {
            return true;
        }
        if a == "-o" && i + 1 < end {
            let v = argv[i + 1].to_ascii_lowercase();
            if v.starts_with("requesttty=") && v != "requesttty=no" && v != "requesttty=never" {
                return true;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Insert `-i <keyfile>` after leading flags, before the connection target.
pub fn insert_identity_arg(argv: &mut Vec<String>, key_path: &std::path::Path) {
    insert_identity_arg_for_profile("ssh", argv, key_path)
}

pub fn insert_identity_arg_for_profile(
    profile: &str,
    argv: &mut Vec<String>,
    key_path: &std::path::Path,
) {
    if argv.iter().any(|a| a == "-i" || a.starts_with("-i")) {
        return;
    }
    let pos = connection_target_index_for_profile(profile, argv);
    let p = key_path.display().to_string();
    argv.insert(pos, p);
    argv.insert(pos, "-i".into());
}

/// Decrypt `private_key`, write to `~/.brokre/run/`, return guard that deletes on drop.
///
/// **Security note (T1):** Unlike vault passwords (injector child), private keys are
/// decrypted in the parent process today. See `docs/HARDENING.md`.
pub fn materialize_identity(rec: &SecretRecord) -> Result<Option<SecureKeyFile>> {
    if !record_has_private_key(rec) {
        return Ok(None);
    }
    let master = get_or_init_master_kek()?;
    let fields = decrypt_for_exec(&rec.crypto, &master)?;
    let key = fields
        .get("private_key")
        .ok_or_else(|| BrokreError::Vault("record missing private_key field".into()))?;
    let path = write_key_file(key)?;
    Ok(Some(SecureKeyFile { path }))
}

fn write_key_file(key: &SecretString) -> Result<PathBuf> {
    let dir = run_dir();
    let path = dir.join(format!("id_{}", uuid::Uuid::new_v4()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(BrokreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        file.write_all(normalize_private_key_pem(key.expose()).as_bytes())
            .map_err(BrokreError::Io)?;
        file.sync_all().map_err(BrokreError::Io)?;
    }
    Ok(path)
}

pub fn build_ssh_field_meta(
    auth_type: &str,
    has_key_passphrase: bool,
) -> Vec<crate::vault::model::FieldMeta> {
    let mut meta = Vec::new();
    match auth_type {
        "key" | "key_and_password" => {
            meta.push(crate::vault::model::FieldMeta {
                name: "private_key".into(),
                secret: true,
                hint: None,
            });
            if has_key_passphrase {
                meta.push(crate::vault::model::FieldMeta {
                    name: "key_passphrase".into(),
                    secret: true,
                    hint: None,
                });
            }
        }
        _ => {}
    }
    if auth_type == "password" || auth_type == "key_and_password" {
        meta.push(crate::vault::model::FieldMeta {
            name: "password".into(),
            secret: true,
            hint: None,
        });
    }
    meta
}

pub fn auth_methods_from_meta(meta: &[crate::vault::model::FieldMeta]) -> Vec<String> {
    let mut out = Vec::new();
    if meta.iter().any(|f| f.name == "private_key") {
        out.push("key".into());
    }
    if meta.iter().any(|f| f.name == "password") {
        out.push("password".into());
    }
    out
}

pub fn build_ssh_secret_fields(
    auth_type: &str,
    password: Option<SecretString>,
    private_key: Option<SecretString>,
    key_passphrase: Option<SecretString>,
) -> Result<BTreeMap<String, SecretString>> {
    let mut fields = BTreeMap::new();
    match auth_type {
        "password" => {
            let pw = password.ok_or_else(|| BrokreError::Vault("password is required".into()))?;
            if pw.is_empty() {
                return Err(BrokreError::Vault("password is required".into()));
            }
            fields.insert("password".into(), pw);
        }
        "key" => {
            let key =
                private_key.ok_or_else(|| BrokreError::Vault("private_key is required".into()))?;
            if key.is_empty() {
                return Err(BrokreError::Vault("private_key is required".into()));
            }
            let normalized = normalize_private_key_pem(key.expose());
            if !validate_private_key_pem(&normalized) {
                return Err(BrokreError::Vault("invalid private key PEM".into()));
            }
            fields.insert("private_key".into(), SecretString::new(normalized));
            if let Some(kp) = key_passphrase.filter(|s| !s.is_empty()) {
                fields.insert("key_passphrase".into(), kp);
            }
        }
        "key_and_password" => {
            let key =
                private_key.ok_or_else(|| BrokreError::Vault("private_key is required".into()))?;
            let pw = password.ok_or_else(|| BrokreError::Vault("password is required".into()))?;
            if key.is_empty() || pw.is_empty() {
                return Err(BrokreError::Vault(
                    "private_key and password are required".into(),
                ));
            }
            let normalized = normalize_private_key_pem(key.expose());
            if !validate_private_key_pem(&normalized) {
                return Err(BrokreError::Vault("invalid private key PEM".into()));
            }
            fields.insert("private_key".into(), SecretString::new(normalized));
            fields.insert("password".into(), pw);
            if let Some(kp) = key_passphrase.filter(|s| !s.is_empty()) {
                fields.insert("key_passphrase".into(), kp);
            }
        }
        other => {
            return Err(BrokreError::Vault(format!("unknown auth_type: {}", other)));
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_mux_master_argv_strips_remote_command_and_tty_flags() {
        let token = crate::utils::paths::remote_brokre_shell_token().to_string();
        let argv = vec![
            "-o".into(),
            "ControlPersist=300".into(),
            "-o".into(),
            "ControlPath=/tmp/ssh-%C.sock".into(),
            "-o".into(),
            "ControlMaster=auto".into(),
            "-tt".into(),
            "b150".into(),
            token,
            "ssh".into(),
            "-tt".into(),
            "db".into(),
        ];
        assert_eq!(
            build_mux_master_argv(&argv),
            vec![
                "-o",
                "ControlPersist=300",
                "-o",
                "ControlPath=/tmp/ssh-%C.sock",
                "-o",
                "ControlMaster=yes",
                "b150",
                "-N",
                "-f",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
        assert_eq!(
            mux_control_path_from_argv(&argv).as_deref(),
            Some("/tmp/ssh-%C.sock")
        );
        assert_eq!(
            openssh_argv_connection_target(&argv).as_deref(),
            Some("b150")
        );
    }

    #[test]
    fn build_mux_session_argv_attaches_without_creating_master() {
        let argv = vec![
            "-o".into(),
            "ControlPersist=300".into(),
            "-o".into(),
            "ControlPath=/tmp/ssh-%C.sock".into(),
            "-o".into(),
            "ControlMaster=auto".into(),
            "-tt".into(),
            "b150".into(),
            "uptime".into(),
        ];
        let session = build_mux_session_argv(&argv);
        assert!(session.iter().any(|a| a == "ControlMaster=no"));
        assert!(!session.iter().any(|a| a == "ControlMaster=auto"));
    }

    #[test]
    fn insert_default_ssh_timeouts_injects_connect_timeout_5() {
        let mut argv = vec!["-v".into(), "user@10.0.0.1".into()];
        insert_default_ssh_timeouts("ssh", &mut argv);
        assert!(argv.iter().any(|a| a == "ConnectTimeout=5"));
        assert!(argv.iter().any(|a| a == "ServerAliveInterval=15"));
        assert!(argv.iter().any(|a| a == "ServerAliveCountMax=2"));
    }

    #[test]
    fn insert_default_ssh_timeouts_skips_existing_connect_timeout() {
        let mut argv = vec![
            "-o".into(),
            "ConnectTimeout=30".into(),
            "user@10.0.0.1".into(),
        ];
        insert_default_ssh_timeouts("ssh", &mut argv);
        let ct: Vec<_> = argv
            .iter()
            .filter(|a| a.starts_with("ConnectTimeout="))
            .collect();
        assert_eq!(ct, vec!["ConnectTimeout=30"]);
    }

    #[test]
    fn insert_mux_uses_control_master_no_for_remote_command() {
        let mut argv = vec!["user@10.0.0.1".into(), "true".into()];
        insert_mux_options_for_profile("ssh", &mut argv);
        assert!(argv.iter().any(|a| a == "ControlMaster=no"));
        assert!(argv.iter().any(|a| a == "ControlPath=none"));
        assert!(!argv.iter().any(|a| a.contains("ssh-%C.sock")));
        assert!(!argv.iter().any(|a| a == "ControlMaster=auto"));
    }

    #[test]
    fn insert_mux_uses_control_master_auto_for_interactive_login() {
        let mut argv = vec!["user@10.0.0.1".into()];
        insert_mux_options_for_profile("ssh", &mut argv);
        assert!(argv.iter().any(|a| a == "ControlMaster=auto"));
        assert!(argv.iter().any(|a| a.contains("ssh-%C.sock")));
    }

    #[test]
    fn insert_mux_rewrites_existing_control_path_for_remote_command() {
        let mut argv = vec![
            "-o".into(),
            "ControlPath=/tmp/ssh-%C.sock".into(),
            "-o".into(),
            "ControlMaster=auto".into(),
            "user@10.0.0.1".into(),
            "true".into(),
        ];
        insert_mux_options_for_profile("ssh", &mut argv);
        assert!(argv.iter().any(|a| a == "ControlMaster=no"));
        assert!(argv.iter().any(|a| a == "ControlPath=none"));
        assert!(!argv.iter().any(|a| a.contains("ssh-%C.sock")));
    }

    #[test]
    fn openssh_first_positional_skips_dash_o_value() {
        let argv = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-v".into(),
            "lan07".into(),
            "true".into(),
        ];
        assert_eq!(openssh_first_positional_index("ssh", &argv), Some(3));
        assert_eq!(argv[3], "lan07");
    }

    #[test]
    fn validates_pem_markers() {
        assert!(validate_private_key_pem(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        ));
        assert!(!validate_private_key_pem("not a key"));
    }

    #[test]
    fn normalizes_literal_backslash_n_pem() {
        let one_line =
            "-----BEGIN OPENSSH PRIVATE KEY-----\\nabc\\n-----END OPENSSH PRIVATE KEY-----\\n";
        let norm = normalize_private_key_pem(one_line);
        assert_eq!(norm.lines().count(), 3);
        assert!(norm.ends_with('\n'));
        assert!(validate_private_key_pem(one_line));
    }

    #[test]
    fn insert_identity_after_flags() {
        let mut argv = vec!["-v".into(), "user@host".into()];
        insert_identity_arg(&mut argv, std::path::Path::new("/tmp/k"));
        assert_eq!(
            argv,
            vec!["-v", "-i", "/tmp/k", "user@host"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn insert_identity_after_port_flag() {
        let mut argv = vec!["-p".into(), "9000".into(), "root@10.0.0.1".into()];
        insert_identity_arg(&mut argv, std::path::Path::new("/tmp/k"));
        assert_eq!(
            argv,
            vec!["-p", "9000", "-i", "/tmp/k", "root@10.0.0.1"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn insert_identity_before_remote_command() {
        let mut argv = vec![
            "-p".into(),
            "9000".into(),
            "root@10.0.0.1".into(),
            "uptime".into(),
        ];
        insert_identity_arg(&mut argv, std::path::Path::new("/tmp/k"));
        assert_eq!(
            argv,
            vec!["-p", "9000", "-i", "/tmp/k", "root@10.0.0.1", "uptime"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn scp_legacy_o_does_not_consume_local_path() {
        let mut argv = vec![
            "-O".into(),
            "/tmp/local".into(),
            "dev-host:/tmp/remote".into(),
        ];
        insert_identity_arg_for_profile("scp", &mut argv, std::path::Path::new("/tmp/k"));
        assert_eq!(
            argv,
            vec!["-O", "-i", "/tmp/k", "/tmp/local", "dev-host:/tmp/remote"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );

        insert_mux_options_for_profile("scp", &mut argv);
        let local_idx = argv.iter().position(|arg| arg == "/tmp/local").unwrap();
        let first_mux_idx = argv
            .iter()
            .position(|arg| arg.starts_with("ControlPath=") || arg.starts_with("ControlMaster="))
            .unwrap();
        assert!(first_mux_idx < local_idx);
        assert!(argv.iter().any(|a| a == "ControlPath=none"));
    }

    #[test]
    fn remote_command_needs_tty_for_routed_sudo() {
        let token = crate::utils::paths::remote_brokre_shell_token().to_string();
        assert!(remote_command_needs_tty(&[
            token,
            "ssh".into(),
            "db".into(),
            "sudo".into(),
            "-i".into(),
        ]));
    }

    #[test]
    fn remote_command_needs_tty_for_sudo_and_su() {
        assert!(remote_command_needs_tty(&["sudo".into(), "whoami".into()]));
        assert!(remote_command_needs_tty(&[
            "su".into(),
            "-".into(),
            "root".into()
        ]));
        assert!(!remote_command_needs_tty(&["uptime".into()]));
        assert!(!remote_command_needs_tty(&[]));
        assert!(remote_command_needs_tty(&[
            "bash".into(),
            "-c".into(),
            "sudo systemctl status nginx".into(),
        ]));
        assert!(!remote_command_needs_tty(&[
            "echo".into(),
            "hello sudo world".into(),
        ]));
        assert!(!remote_command_needs_tty(&[
            "grep".into(),
            "pattern".into(),
            "file".into(),
        ]));
        assert!(remote_command_needs_tty(&["sudo -i whoami".into()]));
    }

    #[test]
    fn insert_force_tty_for_routed_interactive_before_target() {
        let token = crate::utils::paths::remote_brokre_shell_token().to_string();
        let mut argv = vec![
            "-v".into(),
            "bastion@10.0.0.1".into(),
            token.clone(),
            "ssh".into(),
            "-tt".into(),
            "db".into(),
        ];
        insert_force_tty_for_routed_interactive(
            &mut argv,
            &[token, "ssh".into(), "-tt".into(), "db".into()],
        );
        assert_eq!(
            argv,
            vec![
                "-v".to_string(),
                "-tt".to_string(),
                "bastion@10.0.0.1".to_string(),
                crate::utils::paths::remote_brokre_shell_token().to_string(),
                "ssh".to_string(),
                "-tt".to_string(),
                "db".to_string(),
            ]
        );
    }

    #[test]
    fn insert_force_tty_before_target() {
        let mut argv = vec![
            "-v".into(),
            "deploy@10.0.0.1".into(),
            "sudo".into(),
            "whoami".into(),
        ];
        insert_force_tty_for_privileged_remote(&mut argv, &["sudo".into(), "whoami".into()]);
        assert_eq!(
            argv,
            vec!["-v", "-tt", "deploy@10.0.0.1", "sudo", "whoami"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn insert_force_tty_skips_when_already_requested() {
        let mut argv = vec![
            "-tt".into(),
            "deploy@10.0.0.1".into(),
            "sudo".into(),
            "whoami".into(),
        ];
        insert_force_tty_for_privileged_remote(&mut argv, &["sudo".into(), "whoami".into()]);
        assert_eq!(
            argv,
            vec!["-tt", "deploy@10.0.0.1", "sudo", "whoami"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn direct_inner_openssh_trailing_detects_user_at_host() {
        let t = vec![
            "ssh".into(),
            "-tt".into(),
            "root@10.0.0.195".into(),
            "uname".into(),
            "-a".into(),
        ];
        assert!(is_direct_inner_openssh_trailing(&t));
        std::env::set_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV, "db");
        assert!(is_routed_bastion_outer_trailing(&t));
        assert_eq!(routed_bastion_user_trailing(&t), Some(&t[3..]));
        std::env::remove_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV);
    }

    #[test]
    fn routed_outer_trailing_requires_direct_inner_env() {
        let t = vec![
            "ssh".into(),
            "-tt".into(),
            "root@10.0.0.195".into(),
            "uname".into(),
            "-a".into(),
        ];
        std::env::remove_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV);
        assert!(is_direct_inner_openssh_trailing(&t));
        assert!(!is_routed_bastion_outer_trailing(&t));
        std::env::set_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV, "db");
        assert!(is_routed_bastion_outer_trailing(&t));
        assert_eq!(routed_bastion_user_trailing(&t), Some(&t[3..]));
        std::env::remove_var(crate::bastion::route::ROUTED_INNER_ALIAS_ENV);
    }

    #[test]
    fn direct_inner_openssh_trailing_rejects_ssh_flags() {
        let t = vec!["ssh".into(), "-l".into(), "root".into()];
        assert!(!is_direct_inner_openssh_trailing(&t));
    }

    #[test]
    fn has_null_stdin_flag_detects_n_and_stdinnull() {
        assert!(has_null_stdin_flag(&["-n".into(), "host".into()]));
        assert!(has_null_stdin_flag(&["-nf".into(), "host".into()]));
        assert!(has_null_stdin_flag(&[
            "-o".into(),
            "StdinNull=yes".into(),
            "host".into(),
        ]));
        assert!(!has_null_stdin_flag(&["-v".into(), "host".into(), "true".into()]));
    }

    #[test]
    fn strip_brokre_ssh_flags_removes_no_stdin() {
        let mut argv = vec!["--no-stdin".into(), "host".into(), "true".into()];
        let flags = strip_brokre_ssh_flags(&mut argv);
        assert!(flags.force_disconnect_stdin);
        assert_eq!(argv, vec!["host".to_string(), "true".to_string()]);
    }

    #[test]
    fn should_disconnect_stdin_for_mcp() {
        let argv = vec!["host".into(), "true".into()];
        let flags = BrokreSshStdinFlags::default();
        std::env::set_var("BROKRE_MCP_EXEC", "1");
        assert!(should_disconnect_stdin("ssh", &argv, Some(&["true".into()]), &flags));
        std::env::remove_var("BROKRE_MCP_EXEC");
    }

    #[test]
    fn remote_command_consumes_stdin_intent_matrix() {
        assert!(!remote_command_consumes_stdin(&["test".into(), "-f".into(), "/tmp/x".into()]));
        assert!(!remote_command_consumes_stdin(&["uname".into(), "-a".into()]));
        assert!(!remote_command_consumes_stdin(&[
            "bash".into(),
            "-c".into(),
            "echo hi".into(),
        ]));
        assert!(remote_command_consumes_stdin(&["cat".into()]));
        assert!(remote_command_consumes_stdin(&["cat".into(), ">".into(), "/tmp/x".into()]));
        assert!(remote_command_consumes_stdin(&["cat > /tmp/x".into()]));
        assert!(remote_command_consumes_stdin(&["tar xzf -".into()]));
        assert!(remote_command_consumes_stdin(&["bash".into()]));
        assert!(!remote_command_consumes_stdin(&["bash".into(), "-c".into(), "id".into()]));
    }

    #[test]
    fn should_disconnect_stdin_intent_routing() {
        let argv = vec!["host".into(), "true".into()];
        let flags = BrokreSshStdinFlags::default();
        std::env::remove_var("BROKRE_SSH_LEGACY_STDIN");
        std::env::remove_var("BROKRE_MCP_EXEC");

        assert!(should_disconnect_stdin(
            "ssh",
            &argv,
            Some(&["test".into(), "-f".into(), "/tmp/x".into()]),
            &flags,
        ));
        assert!(!should_disconnect_stdin(
            "ssh",
            &argv,
            Some(&["cat".into(), ">".into(), "/tmp/x".into()]),
            &flags,
        ));

        let mut forward_flags = BrokreSshStdinFlags::default();
        forward_flags.force_forward_stdin = true;
        assert!(!should_disconnect_stdin(
            "ssh",
            &argv,
            Some(&["test".into(), "-f".into(), "/tmp/x".into()]),
            &forward_flags,
        ));
    }

    #[test]
    fn should_disconnect_stdin_legacy_auto_null() {
        let argv = vec!["host".into(), "true".into()];
        let flags = BrokreSshStdinFlags::default();
        std::env::set_var("BROKRE_SSH_LEGACY_STDIN", "1");
        std::env::set_var("BROKRE_SSH_AUTO_NULL_STDIN", "1");
        assert!(should_disconnect_stdin("ssh", &argv, Some(&["true".into()]), &flags));
        assert!(!should_disconnect_stdin("ssh", &argv, None, &flags));
        std::env::remove_var("BROKRE_SSH_LEGACY_STDIN");
        std::env::remove_var("BROKRE_SSH_AUTO_NULL_STDIN");
    }
}
