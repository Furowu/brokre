//! Password / passphrase prompt regex dictionary, keyed by CLI binary name.
//!
//! The regexes match on the *trailing* output bytes (case-insensitive) so they
//! fire as the prompt becomes visible to the user. They are deliberately strict
//! enough to avoid matching unrelated text like "password rotation policy".
//!
//! Users may override / extend this dictionary via `~/.brokre/prompts.toml`.

use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

/// Classic OpenSSH `sudo` and Rust `sudo-rs` remote password prompts (post-SSH-auth).
const REMOTE_SUDO_PASSWORD_PROMPT: &str =
    r"(?:\[sudo\]\s+password\s+for\s+[^:]+:|\[sudo:[^\]]*\]\s+[Pp]assword:)\s*$";
const REMOTE_SU_PASSWORD_PROMPT: &str = r"(?:^|\r?\n)Password:\s*$";

/// Return the compiled prompt patterns for the given CLI binary name.
/// Falls back to a generic set if nothing more specific is configured.
pub fn patterns_for(binary: &str) -> Vec<Regex> {
    let base = binary
        .rsplit('/')
        .next()
        .unwrap_or(binary)
        .to_ascii_lowercase();

    let mut out = Vec::new();
    if let Some(user) = user_overrides().get(&base) {
        for s in user {
            if let Ok(re) = compile(s) {
                out.push(re);
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    for s in builtin_patterns(&base) {
        if let Ok(re) = compile(s) {
            out.push(re);
        }
    }
    out
}

/// True when PTY output ends with a remote `sudo` password prompt (post-SSH-auth).
pub fn is_remote_sudo_password_prompt(buf: &[u8]) -> bool {
    remote_sudo_password_prompt_regex().is_match(buf)
}

/// True when PTY output ends with `su`'s `Password:` prompt (elevated MCP path only).
pub fn is_remote_su_password_prompt(buf: &[u8]) -> bool {
    remote_su_password_prompt_regex().is_match(buf)
}

fn remote_sudo_password_prompt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| compile(REMOTE_SUDO_PASSWORD_PROMPT).expect("sudo prompt regex"))
}

fn remote_su_password_prompt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| compile(REMOTE_SU_PASSWORD_PROMPT).expect("su prompt regex"))
}

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern).case_insensitive(true).build()
}

fn builtin_patterns(binary: &str) -> &'static [&'static str] {
    match binary {
        "ssh" | "scp" | "sftp" => &[
            r"[Pp]assword:\s*$",
            r"[Pp]assphrase[^:]*:\s*$",
            r"\(yes/no(?:/\[fingerprint\])?\)\?\s*$",
            REMOTE_SUDO_PASSWORD_PROMPT,
        ],
        "mysql" | "mariadb" => &[r"Enter password:\s*$"],
        "psql" | "postgres" => &[r"Password for user [^:]+:\s*$", r"Password:\s*$"],
        "redis-cli" => &[r"[Pp]lease input password:\s*$", r"Password:\s*$"],
        "ftp" | "lftp" | "curlftpfs" => &[r"[Pp]assword:\s*$"],
        "git" => &[r"Password for [^:]+:\s*$", r"Username for [^:]+:\s*$"],
        "docker" | "podman" => &[r"Password:\s*$"],
        "clickhouse-client" => &[r"Password for user[^:]*:\s*$", r"Password:\s*$"],
        "kubectl" => &[r"Please enter password:\s*$"],
        "sudo" => &[REMOTE_SUDO_PASSWORD_PROMPT],
        "su" => &[r"Password:\s*$"],
        // Generic catch-all
        _ => &[r"[Pp]assword[^:]*:\s*$", r"[Pp]assphrase[^:]*:\s*$"],
    }
}

#[derive(Debug, Deserialize)]
struct PromptsConfig {
    #[serde(flatten)]
    binaries: HashMap<String, Vec<String>>,
}

fn user_overrides() -> &'static HashMap<String, Vec<String>> {
    static CACHE: OnceLock<HashMap<String, Vec<String>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = crate::utils::paths::brokre_home().join("prompts.toml");
        if !path.exists() {
            return HashMap::new();
        }
        let Ok(content) = fs::read_to_string(&path) else {
            return HashMap::new();
        };
        let Ok(cfg): Result<PromptsConfig, _> = toml::from_str(&content) else {
            return HashMap::new();
        };
        cfg.binaries
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_password_prompt_matches() {
        let pats = patterns_for("ssh");
        assert!(!pats.is_empty());
        assert!(pats.iter().any(|p| p.is_match(b"root@host's password: ")));
    }

    #[test]
    fn mysql_prompt_matches() {
        let pats = patterns_for("mysql");
        assert!(pats.iter().any(|p| p.is_match(b"Enter password: ")));
    }

    #[test]
    fn unrelated_text_does_not_match_ssh() {
        let pats = patterns_for("ssh");
        // Rotation policy banner should not look like a prompt (no trailing colon).
        let banner = b"Your password expires in 7 days.\n";
        assert!(!pats.iter().any(|p| p.is_match(banner)));
    }

    #[test]
    fn ssh_passphrase_prompt_matches() {
        let pats = patterns_for("ssh");
        assert!(pats
            .iter()
            .any(|p| { p.is_match(b"Enter passphrase for key '/home/user/.ssh/id_rsa': ") }));
        assert!(pats
            .iter()
            .any(|p| { p.is_match(b"Passphrase for /Users/alice/.ssh/id_ed25519: ") }));
    }

    #[test]
    fn ssh_remote_sudo_prompt_matches() {
        let pats = patterns_for("ssh");
        assert!(pats
            .iter()
            .any(|p| p.is_match(b"[sudo] password for deploy: ")));
        assert!(is_remote_sudo_password_prompt(
            b"Last login: Mon May 18 08:41:12 2026\n[sudo] password for deploy: "
        ));
        assert!(pats.iter().any(|p| {
            p.is_match(b"[sudo: authenticate] Password: ")
        }));
        assert!(is_remote_sudo_password_prompt(
            b"rowu3@host:~$ sudo -i\n[sudo: authenticate] Password: "
        ));
    }

    #[test]
    fn su_password_prompt_matches_elevated_path() {
        assert!(is_remote_su_password_prompt(b"Password: "));
        assert!(!is_remote_su_password_prompt(
            b"Configure your account password: "
        ));
    }

    #[test]
    fn generic_fallback() {
        let pats = patterns_for("nonsense");
        assert!(!pats.is_empty());
        assert!(pats.iter().any(|p| p.is_match(b"Password: ")));
    }
}
