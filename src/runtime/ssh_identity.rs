//! Write a vault-stored SSH private key to a short-lived 0600 file for `ssh -i`.

use crate::security::secret::SecretString;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::run_dir;

/// Seconds to keep a multiplexed SSH control socket warm between commands.
const SSH_MUX_PERSIST_SECS: &str = "300";
use crate::vault::crypto::record::decrypt_for_exec;
use crate::vault::keychain::get_or_init_master_kek;
use crate::vault::model::SecretRecord;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

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

fn openssh_option_consumes_next(arg: &str) -> bool {
    if arg == "--" {
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
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            return (i + 1).min(argv.len());
        }
        if !a.starts_with('-') {
            return i;
        }
        if openssh_option_consumes_next(a) {
            i += 2;
        } else {
            i += 1;
        }
    }
    argv.len()
}

fn has_mux_options(argv: &[String]) -> bool {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "-o" && i + 1 < argv.len() {
            let v = argv[i + 1].as_str();
            if v.starts_with("ControlPath=")
                || v.starts_with("ControlMaster=")
                || v == "ControlMaster"
            {
                return true;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

/// Reuse one authenticated SSH session across rapid `brokre ssh` invocations (e.g. deploy scripts).
pub fn insert_mux_options(argv: &mut Vec<String>) {
    if has_mux_options(argv) {
        return;
    }
    let sock = run_dir().join("ssh-%C.sock");
    let path = sock.to_string_lossy().to_string();
    let pos = connection_target_index(argv);
    let pairs = [
        ("-o", format!("ControlPersist={}", SSH_MUX_PERSIST_SECS)),
        ("-o", format!("ControlPath={}", path)),
        ("-o", "ControlMaster=auto".into()),
    ];
    for (flag, val) in pairs.iter().rev() {
        argv.insert(pos, val.clone());
        argv.insert(pos, (*flag).into());
    }
}

/// True when argv after the connection target is a bastion-routed remote brokre exec.
pub fn is_routed_bastion_trailing(trailing: &[String]) -> bool {
    trailing
        .first()
        .is_some_and(|s| crate::utils::paths::remote_shell_token_passthrough(s))
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
    let Some(inner) = trailing.get(i) else {
        return None;
    };
    if inner.starts_with('-') {
        return None;
    }
    i += 1;
    Some(&trailing[i..])
}

/// Interactive `brokre ssh bastion::inner` (no user command after the inner alias).
pub fn is_routed_interactive_trailing(trailing: &[String]) -> bool {
    routed_bastion_user_trailing(trailing).is_some_and(|user| user.is_empty())
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
    if argv.iter().any(|a| a == "-i" || a.starts_with("-i")) {
        return;
    }
    let pos = connection_target_index(argv);
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
    fn remote_command_needs_tty_for_routed_sudo() {
        let token = crate::utils::paths::remote_brokre_shell_token().to_string();
        assert!(remote_command_needs_tty(&[
            token,
            "ssh".into(),
            "lan07".into(),
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
}
