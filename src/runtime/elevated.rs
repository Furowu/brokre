//! Compose OpenSSH argv for MCP one-shot elevated remote commands (`sudo` / `sudo -i` / `su`).
//!
//! MCP is request/response — true interactive `sudo -i` / `su` shells use a persistent
//! PTY session pool (`brokre_exec_elevated` with default `session=reuse`).

use crate::runtime::session_markers::READY;
use crate::utils::errors::{BrokreError, Result};
use crate::vault::model::SecretRecord;

/// How to elevate privileges on the remote host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElevatedMode {
    /// `sudo bash -lc '<command>'`
    Sudo,
    /// `sudo -i bash -lc '<command>'` — root login environment (profiles, PATH, etc.)
    SudoLogin,
    /// `su - <user> -c '<command>'` — login shell as target user (default root)
    Su,
}

impl ElevatedMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sudo" => Ok(Self::Sudo),
            "sudo_login" | "sudo-login" | "sudo_i" | "sudo-i" => Ok(Self::SudoLogin),
            "su" => Ok(Self::Su),
            other => Err(BrokreError::Runtime(format!(
                "unknown elevated mode {:?} (use sudo, sudo_login, or su)",
                other
            ))),
        }
    }

    /// Value for `BROKRE_MCP_ELEVATED` (PTY prompt hints).
    pub fn mcp_env_value(self) -> &'static str {
        match self {
            Self::Sudo | Self::SudoLogin => "sudo",
            Self::Su => "su",
        }
    }
}

/// MCP elevated session reuse policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPolicy {
    #[default]
    Reuse,
    New,
    Close,
}

impl SessionPolicy {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "reuse" => Ok(Self::Reuse),
            "new" => Ok(Self::New),
            "close" => Ok(Self::Close),
            other => Err(BrokreError::Runtime(format!(
                "unknown session policy {:?} (use reuse, new, or close)",
                other
            ))),
        }
    }
}

/// Session pool lookup key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub alias: String,
    pub mode: ElevatedMode,
    pub su_user: String,
}

impl SessionKey {
    pub fn new(alias: &str, mode: ElevatedMode, su_user: Option<&str>) -> Self {
        Self {
            alias: alias.to_string(),
            mode,
            su_user: su_user
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .unwrap_or("root")
                .to_string(),
        }
    }
}

/// Remote argv to bootstrap a persistent elevated shell (after connection target).
pub fn build_persistent_shell_remote_argv(
    mode: ElevatedMode,
    su_user: Option<&str>,
) -> Vec<String> {
    // Echo READY explicitly: remote .bashrc / TERM=dumb can override PS1 so the marker
    // never appears in PTY output if we only export PS1 before exec bash -i.
    let inner = format!(
        "echo {ready}; export PS1={ready}; exec bash --norc --noprofile -i",
        ready = READY,
    );
    let quoted = shell_single_quote_escape(&inner);
    match mode {
        ElevatedMode::Sudo => vec![
            "sudo".into(),
            "bash".into(),
            "-c".into(),
            quoted,
        ],
        ElevatedMode::SudoLogin => vec![
            "sudo".into(),
            "-i".into(),
            "bash".into(),
            "-c".into(),
            quoted,
        ],
        ElevatedMode::Su => {
            let user = su_user
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .unwrap_or("root");
            vec![
                "su".into(),
                "-".into(),
                user.to_string(),
                "-c".into(),
                quoted,
            ]
        }
    }
}

/// Compose OpenSSH argv for bootstrap: `saved_args` + persistent shell remote command.
pub fn compose_ssh_bootstrap_argv(
    rec: &SecretRecord,
    mode: ElevatedMode,
    su_user: Option<&str>,
) -> Vec<String> {
    let mut argv = rec.saved_args.clone();
    argv.extend(build_persistent_shell_remote_argv(mode, su_user));
    argv
}

/// Parse trailing ssh args after alias when they start with `sudo` / `su`.
pub fn parse_elevated_trailing(
    trailing: &[String],
) -> Option<(ElevatedMode, String, Option<String>)> {
    if trailing.is_empty() {
        return None;
    }
    match trailing[0].as_str() {
        "sudo" => {
            let (mode, rest) = if trailing.get(1).map(String::as_str) == Some("-i") {
                (ElevatedMode::SudoLogin, trailing.get(2..)?)
            } else {
                (ElevatedMode::Sudo, trailing.get(1..)?)
            };
            if rest.is_empty() {
                return None;
            }
            Some((mode, rest.join(" "), None))
        }
        "su" => {
            let mut i = 1;
            let mut user = None;
            while i < trailing.len() {
                match trailing[i].as_str() {
                    "-" | "-l" => {
                        i += 1;
                    }
                    "-c" => break,
                    u => {
                        user = Some(u.to_string());
                        i += 1;
                        break;
                    }
                }
            }
            let mut rest = &trailing[i..];
            if rest.first().map(String::as_str) == Some("-c") {
                rest = &rest[1..];
            }
            if rest.is_empty() {
                return None;
            }
            Some((ElevatedMode::Su, rest.join(" "), user))
        }
        _ => None,
    }
}

/// Infer elevated exec from `brokre ssh <alias> sudo|su …` MCP args.
pub fn ssh_exec_args_to_elevated(
    args: &[String],
) -> Option<(String, ElevatedMode, String, Option<String>)> {
    let idx = args.iter().position(|a| !a.starts_with('-'))?;
    let alias = args[idx].clone();
    let trailing: Vec<String> = args.get(idx + 1..)?.to_vec();
    if !crate::runtime::ssh_identity::remote_command_needs_tty(&trailing) {
        return None;
    }
    let (mode, command, user) = parse_elevated_trailing(&trailing)?;
    Some((alias, mode, command, user))
}

/// Escape a string for embedding in a remote `sh -c` / `bash -lc` single-quoted argument.
pub fn shell_single_quote_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Build `brokre ssh <alias> …` argv for a one-shot elevated remote command.
pub fn build_ssh_argv(alias: &str, mode: ElevatedMode, command: &str, su_user: Option<&str>) -> Result<Vec<String>> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Err(BrokreError::Runtime("elevated exec: alias is required".into()));
    }
    let command = command.trim();
    if command.is_empty() {
        return Err(BrokreError::Runtime(
            "elevated exec: command is required — MCP cannot hold an interactive sudo -i / su shell; \
             pass the command to run (use mode sudo_login for root login environment)."
                .into(),
        ));
    }

    let quoted = shell_single_quote_escape(command);
    let mut argv = vec![alias.to_string()];
    match mode {
        ElevatedMode::Sudo => {
            argv.extend([
                "sudo".into(),
                "bash".into(),
                "-lc".into(),
                quoted,
            ]);
        }
        ElevatedMode::SudoLogin => {
            argv.extend([
                "sudo".into(),
                "-i".into(),
                "bash".into(),
                "-lc".into(),
                quoted,
            ]);
        }
        ElevatedMode::Su => {
            let user = su_user
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .unwrap_or("root");
            argv.extend([
                "su".into(),
                "-".into(),
                user.to_string(),
                "-c".into(),
                quoted,
            ]);
        }
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(ElevatedMode::parse("sudo").unwrap(), ElevatedMode::Sudo);
        assert_eq!(
            ElevatedMode::parse("sudo_login").unwrap(),
            ElevatedMode::SudoLogin
        );
        assert_eq!(ElevatedMode::parse("su").unwrap(), ElevatedMode::Su);
        assert!(ElevatedMode::parse("nope").is_err());
    }

    #[test]
    fn build_sudo_argv() {
        let argv = build_ssh_argv("prod", ElevatedMode::Sudo, "whoami", None).unwrap();
        assert_eq!(
            argv,
            vec![
                "prod".to_string(),
                "sudo".to_string(),
                "bash".to_string(),
                "-lc".to_string(),
                "'whoami'".to_string(),
            ]
        );
    }

    #[test]
    fn build_sudo_login_argv() {
        let argv =
            build_ssh_argv("prod", ElevatedMode::SudoLogin, "echo $HOME", None).unwrap();
        assert_eq!(argv[1..5], ["sudo", "-i", "bash", "-lc"]);
    }

    #[test]
    fn build_su_argv_defaults_root() {
        let argv = build_ssh_argv("prod", ElevatedMode::Su, "id", None).unwrap();
        assert_eq!(
            argv,
            vec![
                "prod".to_string(),
                "su".to_string(),
                "-".to_string(),
                "root".to_string(),
                "-c".to_string(),
                "'id'".to_string(),
            ]
        );
    }

    #[test]
    fn shell_escape_embedded_quote() {
        assert_eq!(
            shell_single_quote_escape("it's fine"),
            "'it'\"'\"'s fine'"
        );
    }

    #[test]
    fn rejects_empty_command() {
        assert!(build_ssh_argv("prod", ElevatedMode::Sudo, "  ", None).is_err());
    }

    #[test]
    fn parse_sudo_trailing() {
        let t = vec![
            "sudo".into(),
            "systemctl".into(),
            "status".into(),
            "nginx".into(),
        ];
        let (mode, cmd, user) = parse_elevated_trailing(&t).unwrap();
        assert_eq!(mode, ElevatedMode::Sudo);
        assert_eq!(cmd, "systemctl status nginx");
        assert!(user.is_none());
    }

    #[test]
    fn parse_sudo_login_trailing() {
        let t = vec!["sudo".into(), "-i".into(), "whoami".into()];
        let (mode, cmd, _) = parse_elevated_trailing(&t).unwrap();
        assert_eq!(mode, ElevatedMode::SudoLogin);
        assert_eq!(cmd, "whoami");
    }

    #[test]
    fn session_policy_parse() {
        assert_eq!(SessionPolicy::parse("reuse").unwrap(), SessionPolicy::Reuse);
        assert_eq!(SessionPolicy::parse("close").unwrap(), SessionPolicy::Close);
    }

    #[test]
    fn ssh_exec_args_to_elevated_parses_sudo() {
        let args = vec![
            "prod".into(),
            "sudo".into(),
            "systemctl".into(),
            "status".into(),
            "nginx".into(),
        ];
        let (alias, mode, cmd, _) = ssh_exec_args_to_elevated(&args).unwrap();
        assert_eq!(alias, "prod");
        assert_eq!(mode, ElevatedMode::Sudo);
        assert_eq!(cmd, "systemctl status nginx");
    }

    #[test]
    fn ssh_exec_args_skips_non_elevated() {
        let args = vec!["prod".into(), "uptime".into()];
        assert!(ssh_exec_args_to_elevated(&args).is_none());
    }

    #[test]
    fn persistent_bootstrap_echoes_ready_marker() {
        let argv = build_persistent_shell_remote_argv(ElevatedMode::SudoLogin, None);
        let joined = argv.join(" ");
        assert!(joined.contains("echo __BROKRE_READY__"));
        assert!(joined.contains("--norc --noprofile"));
    }
}
