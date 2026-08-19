//! JSON-RPC-shaped `brokre ssh alias bash script method` acceleration without local TCP ports.
//!
//! Cross-process pool via a auto-spawned sidecar (`--internal-ssh-pool`) that keeps one SSH
//! session over OpenSSH ControlMaster and reuses the remote wrapper script.

use crate::vault::model::SecretRecord;

/// Explicit opt-in: true only when `BROKRE_SSH_POOL=1|true`.
pub fn ssh_pool_enabled() -> bool {
    std::env::var("BROKRE_SSH_POOL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Shared security gates for JSON-RPC-shaped piped ssh exec.
pub fn base_jsonrpc_ssh_gates(profile: &str, rec: &SecretRecord, trailing: &[String]) -> bool {
    let base = profile.rsplit('/').next().unwrap_or(profile);
    if base != "ssh" {
        return false;
    }
    if rec.name.contains("::") {
        return false;
    }
    if std::env::var_os("BROKRE_ROUTED_INNER").is_some()
        || std::env::var_os("BROKRE_TUNNEL_AGENT_INNER").is_some()
    {
        return false;
    }
    if !crate::security::tty::stdin_is_pipe() {
        return false;
    }
    if trailing.is_empty() {
        return false;
    }
    if crate::runtime::ssh_identity::remote_command_needs_tty(trailing) {
        return false;
    }
    if crate::runtime::ssh_identity::is_routed_bastion_outer_trailing(trailing) {
        return false;
    }
    true
}

/// `bash /path/to/script method` — last token is RPC method name.
pub fn looks_like_jsonrpc_trailing(trailing: &[String]) -> bool {
    if trailing.len() < 3 {
        return false;
    }
    if trailing.first().map(|s| s.as_str()) != Some("bash") {
        return false;
    }
    trailing
        .last()
        .is_some_and(|method| is_method_token(method))
}

pub fn is_method_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 128
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && token
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Script path from `bash <script> … <method>`.
pub fn extract_bash_script_path(trailing: &[String]) -> Option<String> {
    if trailing.first().map(|s| s.as_str()) != Some("bash") {
        return None;
    }
    trailing.get(1).cloned()
}

pub fn is_jsonrpc_ssh_exec(profile: &str, rec: &SecretRecord, trailing: &[String]) -> bool {
    base_jsonrpc_ssh_gates(profile, rec, trailing) && looks_like_jsonrpc_trailing(trailing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jsonrpc_trailing() {
        assert!(looks_like_jsonrpc_trailing(&[
            "bash".into(),
            "/path/rpc.sh".into(),
            "health".into(),
        ]));
        assert!(!looks_like_jsonrpc_trailing(&["uptime".into()]));
    }

    #[test]
    fn extracts_script_path() {
        assert_eq!(
            extract_bash_script_path(&["bash".into(), "/path/rpc.sh".into(), "health".into(),]),
            Some("/path/rpc.sh".into())
        );
    }
}
