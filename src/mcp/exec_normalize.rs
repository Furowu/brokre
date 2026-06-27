//! Normalize MCP `brokre_exec` requests — especially `shell_command` → `sh -c` argv.

use crate::utils::errors::{BrokreError, Result};

/// Index of the first positional (non-flag) token in argv — the saved alias / route.
fn first_positional_index(args: &[String]) -> Option<usize> {
    args.iter().position(|a| !a.starts_with('-'))
}

/// Normalize MCP exec args.
///
/// When `shell_command` is set:
/// - `binary` must be `ssh`
/// - no trailing argv after the alias
/// - output: `[leading_flags..., alias, "sh", "-c", shell_command]`
pub fn normalize_exec_argv(
    binary: &str,
    args: &[String],
    shell_command: Option<&str>,
) -> Result<Vec<String>> {
    let Some(cmd) = shell_command else {
        return Ok(args.to_vec());
    };

    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err(BrokreError::Runtime(
            "shell_command must not be empty".into(),
        ));
    }

    let bin = binary
        .rsplit('/')
        .next()
        .unwrap_or(binary)
        .to_ascii_lowercase();
    if bin != "ssh" {
        return Err(BrokreError::Runtime(
            "shell_command is only supported with binary=ssh".into(),
        ));
    }

    let alias_idx = first_positional_index(args).ok_or_else(|| {
        BrokreError::Runtime(
            "shell_command requires a saved alias in args (e.g. args=[\"prod\"])".into(),
        )
    })?;

    if alias_idx + 1 < args.len() {
        return Err(BrokreError::Runtime(
            "cannot use shell_command when args already contain trailing remote argv after the alias; \
             use args=[\"alias\"] with shell_command only, or omit shell_command and pass split argv. \
             For privileged writes use brokre_exec_elevated.command. \
             Do not pass sh -c '...' as a single argv token."
                .into(),
        ));
    }

    let mut out = args.to_vec();
    out.push("sh".into());
    out.push("-c".into());
    out.push(cmd.to_string());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_string()).collect()
    }

    #[test]
    fn passthrough_without_shell_command() {
        let args = s(&["prod", "uptime"]);
        let out = normalize_exec_argv("ssh", &args, None).unwrap();
        assert_eq!(out, args);
    }

    #[test]
    fn shell_command_appends_sh_c() {
        let args = s(&["prod"]);
        let out = normalize_exec_argv("ssh", &args, Some("echo a > /tmp/f")).unwrap();
        assert_eq!(out, s(&["prod", "sh", "-c", "echo a > /tmp/f"]));
    }

    #[test]
    fn shell_command_with_leading_flag() {
        let args = s(&["-v", "prod"]);
        let out = normalize_exec_argv("ssh", &args, Some("hostname")).unwrap();
        assert_eq!(out, s(&["-v", "prod", "sh", "-c", "hostname"]));
    }

    #[test]
    fn shell_command_bastion_route() {
        let args = s(&["b150::db"]);
        let script = "echo line1 > /etc/app.conf";
        let out = normalize_exec_argv("ssh", &args, Some(script)).unwrap();
        assert_eq!(out, s(&["b150::db", "sh", "-c", script]));
    }

    #[test]
    fn rejects_trailing_argv_conflict() {
        let args = s(&["prod", "uptime"]);
        let err = normalize_exec_argv("ssh", &args, Some("echo hi"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("shell_command"));
        assert!(err.contains("trailing"));
    }

    #[test]
    fn rejects_non_ssh_binary() {
        let args = s(&["prod"]);
        let err = normalize_exec_argv("mysql", &args, Some("SELECT 1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("binary=ssh"));
    }

    #[test]
    fn rejects_empty_shell_command() {
        let args = s(&["prod"]);
        assert!(normalize_exec_argv("ssh", &args, Some("   ")).is_err());
    }

    #[test]
    fn rejects_missing_alias() {
        let args = s(&["-v"]);
        assert!(normalize_exec_argv("ssh", &args, Some("echo hi")).is_err());
    }

    #[test]
    fn complex_quotes_stay_single_argv_element() {
        let script = "printf '%s\\n' \"it's fine\" > /tmp/f";
        let args = s(&["prod"]);
        let out = normalize_exec_argv("ssh", &args, Some(script)).unwrap();
        assert_eq!(out.len(), 4);
        assert_eq!(out[0], "prod");
        assert_eq!(out[1], "sh");
        assert_eq!(out[2], "-c");
        assert_eq!(out[3], script);
    }

    #[test]
    fn heredoc_script_stays_single_element() {
        let script = "cat > /tmp/deploy.sh <<'EOF'\n#!/bin/sh\necho ok\nEOF";
        let out = normalize_exec_argv("ssh", &s(&["prod"]), Some(script)).unwrap();
        assert_eq!(out[3], script);
        assert!(out[3].contains("<<'EOF'"));
        assert!(out[3].contains("#!/bin/sh"));
    }
}
