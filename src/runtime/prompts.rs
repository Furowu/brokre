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
    let stripped = strip_ansi_for_prompt_match(buf);
    remote_sudo_password_prompt_regex().is_match(&stripped)
}

/// True when PTY output ends with `su`'s `Password:` prompt (elevated MCP path only).
pub fn is_remote_su_password_prompt(buf: &[u8]) -> bool {
    let stripped = strip_ansi_for_prompt_match(buf);
    remote_su_password_prompt_regex().is_match(&stripped)
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

/// Strip CSI / OSC / simple ESC sequences so prompt regexes can match ConPTY output.
///
/// Windows ConPTY often appends SGR/cursor OSC after `password: ` (e.g. `password: \x1b[0m`).
/// Display paths must keep the raw bytes; only the matcher should see this view.
pub fn strip_ansi_for_prompt_match(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] != 0x1b {
            out.push(buf[i]);
            i += 1;
            continue;
        }
        // ESC
        if i + 1 >= buf.len() {
            // Lone ESC at end — drop it for matching.
            break;
        }
        match buf[i + 1] {
            b'[' => {
                // CSI: ESC [ ... final (0x40..=0x7E)
                i += 2;
                while i < buf.len() {
                    let b = buf[i];
                    i += 1;
                    if (0x40..=0x7e).contains(&b) {
                        break;
                    }
                }
            }
            b']' => {
                // OSC: ESC ] ... BEL or ST (ESC \)
                i += 2;
                while i < buf.len() {
                    if buf[i] == 0x07 {
                        i += 1;
                        break;
                    }
                    if buf[i] == 0x1b && i + 1 < buf.len() && buf[i + 1] == b'\\' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            // Simple single-char ESC sequences (charset, keypad, DECKPAM, etc.)
            b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' => {
                // ESC ( B  — consume ESC, intermediate, final if present
                i += 2;
                if i < buf.len() {
                    i += 1;
                }
            }
            _ => {
                // ESC X — skip ESC + one following byte
                i += 2;
            }
        }
    }
    out
}

/// Host-key confirmation `(yes/no)?` / `(yes/no/[fingerprint])?` after ANSI strip.
pub fn is_host_key_yes_no_prompt(buf: &[u8]) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        compile(r"\(yes/no(?:/\[fingerprint\])?\)\?\s*$").expect("yes/no prompt regex")
    });
    let stripped = strip_ansi_for_prompt_match(buf);
    re.is_match(&stripped)
}

/// Password / passphrase prompt suitable for `PtyCredential::Secret` inject.
///
/// Returns false for host-key yes/no so an empty `inject_fields` preset cannot
/// send the password to the wrong prompt.
pub fn is_secret_injectable_password_prompt(buf: &[u8]) -> bool {
    if is_host_key_yes_no_prompt(buf) {
        return false;
    }
    let stripped = strip_ansi_for_prompt_match(buf);
    let lower: Vec<u8> = stripped.iter().map(|b| b.to_ascii_lowercase()).collect();
    let text = String::from_utf8_lossy(&lower);
    let trimmed = text.trim_end();
    let has_password = text.contains("password") && trimmed.ends_with(':');
    let has_passphrase = text.contains("passphrase") && trimmed.ends_with(':');
    has_password || has_passphrase
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
        assert!(pats
            .iter()
            .any(|p| { p.is_match(b"[sudo: authenticate] Password: ") }));
        assert!(is_remote_sudo_password_prompt(
            b"dev-user@host:~$ sudo -i\n[sudo: authenticate] Password: "
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

    #[test]
    fn strip_ansi_password_with_trailing_csi_matches() {
        let pats = patterns_for("ssh");
        let raw = b"root@host's password: \x1b[0m";
        let stripped = strip_ansi_for_prompt_match(raw);
        assert_eq!(&stripped[..], b"root@host's password: ");
        assert!(pats.iter().any(|p| p.is_match(&stripped)));
        // Raw with CSI must NOT match \s*$ patterns (ConPTY bug).
        assert!(!pats.iter().any(|p| p.is_match(raw)));
        assert!(is_secret_injectable_password_prompt(raw));
    }

    #[test]
    fn strip_ansi_password_with_trailing_hide_cursor_csi() {
        let pats = patterns_for("ssh");
        let raw = b"Password: \x1b[?25l";
        let stripped = strip_ansi_for_prompt_match(raw);
        assert_eq!(&stripped[..], b"Password: ");
        assert!(pats.iter().any(|p| p.is_match(&stripped)));
        assert!(is_secret_injectable_password_prompt(raw));
    }

    #[test]
    fn strip_ansi_osc_bel_and_st() {
        let bel = b"hi\x1b]0;title\x07password: ";
        assert_eq!(
            strip_ansi_for_prompt_match(bel),
            b"hipassword: ".to_vec()
        );
        let st = b"x\x1b]0;title\x1b\\Password: ";
        assert_eq!(strip_ansi_for_prompt_match(st), b"xPassword: ".to_vec());
    }

    #[test]
    fn yes_no_host_key_does_not_arm_secret_password_inject() {
        let raw = b"Are you sure you want to continue connecting (yes/no/[fingerprint])? ";
        assert!(is_host_key_yes_no_prompt(raw));
        assert!(!is_secret_injectable_password_prompt(raw));
        let with_csi = b"Are you sure you want to continue connecting (yes/no)? \x1b[0m";
        assert!(is_host_key_yes_no_prompt(with_csi));
        assert!(!is_secret_injectable_password_prompt(with_csi));
    }

    #[test]
    fn bare_password_prompt_is_secret_injectable() {
        assert!(is_secret_injectable_password_prompt(b"password: "));
        assert!(is_secret_injectable_password_prompt(
            b"Enter passphrase for key '/home/u/.ssh/id_rsa': "
        ));
    }
}
