use crate::bastion::registry::is_registered_bastion;
use crate::runtime::ssh_identity::remote_command_needs_tty;
use crate::utils::errors::{BrokreError, Result};
use serde::{Deserialize, Serialize};

pub const ROUTE_SEP: &str = "::";
pub const BASTION_PATH_ENV: &str = "BROKRE_BASTION_PATH";
/// Set during `exec_routed` direct-inner mode so outer `exec_saved` can resolve the inner vault.
pub const ROUTED_INNER_ALIAS_ENV: &str = "BROKRE_ROUTED_INNER_ALIAS";
/// Opt in to `ssh hop ssh -tt user@inner …` from the Mac vault (experimental).
pub const DIRECT_INNER_ENV: &str = "BROKRE_DIRECT_INNER";
pub const DEFAULT_MAX_DEPTH: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BastionRoute {
    pub hops: Vec<String>,
    pub inner: String,
    pub addr: String,
}

impl BastionRoute {
    pub fn depth(&self) -> usize {
        self.hops.len()
    }

    pub fn first_hop(&self) -> &str {
        &self.hops[0]
    }
}

/// Parse `bastion::inner` or `b1::b2::inner`. Returns `None` when no `::` separator.
pub fn parse_route(addr: &str) -> Result<Option<BastionRoute>> {
    if !addr.contains(ROUTE_SEP) {
        return Ok(None);
    }
    let parts: Vec<&str> = addr.split(ROUTE_SEP).collect();
    if parts.len() < 2 {
        return Err(BrokreError::Cli(format!("invalid route address: {addr}")));
    }
    for part in &parts {
        if part.is_empty() {
            return Err(BrokreError::Cli(format!("empty route segment in: {addr}")));
        }
        if part.contains(':') {
            return Err(BrokreError::Cli(format!(
                "route segment '{part}' contains ':' — use '::' as separator"
            )));
        }
        if !crate::vault::model::SecretRecord::validate_name(part) {
            return Err(BrokreError::Cli(format!("invalid route segment: {part}")));
        }
    }
    let inner = parts.last().unwrap().to_string();
    let hops: Vec<String> = parts[..parts.len() - 1]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let depth = hops.len();
    if depth > max_depth() {
        return Err(BrokreError::PolicyDenied);
    }
    for hop in &hops {
        if !is_registered_bastion(hop) {
            return Err(BrokreError::Cli(format!(
                "'{hop}' is not a registered bastion — run `brokre bastion enable {hop}`"
            )));
        }
    }
    check_loop(&hops)?;
    Ok(Some(BastionRoute {
        hops,
        inner,
        addr: addr.to_string(),
    }))
}

pub fn max_depth() -> usize {
    std::env::var("BROKRE_BASTION_MAX_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_DEPTH)
}

pub fn visited_bastions() -> Vec<String> {
    std::env::var(BASTION_PATH_ENV)
        .ok()
        .map(|v| {
            v.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub fn check_loop(hops: &[String]) -> Result<()> {
    let visited = visited_bastions();
    for hop in hops {
        if visited.iter().any(|v| v == hop) {
            return Err(BrokreError::PolicyDenied);
        }
    }
    for (idx, hop) in hops.iter().enumerate() {
        if hops.iter().skip(idx + 1).any(|next| next == hop) {
            return Err(BrokreError::PolicyDenied);
        }
    }
    Ok(())
}

pub fn extend_bastion_path(current: &[String], next: &str) -> String {
    let mut path = current.to_vec();
    path.push(next.to_string());
    path.join(",")
}

/// Shell-escape args into a single remote command string.
pub fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| shell_escape_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_escape_arg(s: &str) -> String {
    if crate::utils::paths::remote_shell_token_passthrough(s) {
        return s.to_string();
    }
    shell_escape(s)
}

pub fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-' | '@'))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build local `brokre ssh <first_hop> ...` argv for a routed exec.
pub fn build_routed_local_argv(
    binary: &str,
    route: &BastionRoute,
    trailing: &[String],
) -> Vec<String> {
    let remote_brokre = crate::utils::paths::remote_brokre_shell_token().to_string();
    let after_binary: Vec<String> = if trailing.is_empty() || remote_command_needs_tty(trailing) {
        let mut v = vec!["-tt".into(), route.inner.clone()];
        v.extend(trailing.iter().cloned());
        v
    } else {
        std::iter::once(route.inner.clone())
            .chain(trailing.iter().cloned())
            .collect()
    };
    let inner_exec: Vec<String> = std::iter::once(remote_brokre.clone())
        .chain(std::iter::once(binary.to_string()))
        .chain(after_binary)
        .collect();

    match route.hops.len() {
        1 => {
            let mut args = vec![route.hops[0].clone()];
            args.push(shell_join(&inner_exec));
            args
        }
        _ => {
            let mut wrapped = inner_exec;
            for hop in route.hops.iter().skip(1).rev() {
                let inner = shell_join(&wrapped);
                wrapped = vec![remote_brokre.clone(), "ssh".into(), hop.clone(), inner];
            }
            let mut args = vec![route.hops[0].clone()];
            args.push(shell_join(&wrapped));
            args
        }
    }
}

/// Build local `brokre ssh <first_hop> ssh <inner_target> …` when the Mac vault owns the inner hop.
///
/// Avoids relying on a (possibly stale) `~/.brokre/bin/brokre` on the bastion. Password injection
/// for both hops is handled on the Mac via PTY (`bastion_outer_hop` + `inner_vault_record`).
pub fn build_routed_direct_inner_argv(
    route: &BastionRoute,
    inner_target: &str,
    trailing: &[String],
) -> Vec<String> {
    let remote_cmd: Vec<String> = std::iter::once("ssh".into())
        .chain(std::iter::once("-tt".into()))
        .chain(std::iter::once(inner_target.to_string()))
        .chain(trailing.iter().cloned())
        .collect();

    match route.hops.len() {
        1 => {
            let mut args = vec![route.hops[0].clone()];
            args.extend(remote_cmd);
            args
        }
        _ => {
            let mut args = vec![route.hops[0].clone()];
            args.push(shell_join(&remote_cmd));
            args
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape_basic() {
        assert_eq!(shell_escape("uname"), "uname");
        assert_eq!(shell_escape("a b"), "'a b'");
    }

    #[test]
    fn shell_join_preserves_remote_brokre_home_expansion() {
        let args = vec![
            crate::utils::paths::remote_brokre_shell_token().to_string(),
            "ssh".into(),
            "db".into(),
        ];
        let joined = shell_join(&args);
        assert!(joined.starts_with(
            "BROKRE_SOFT_MEMLOCK=1 BROKRE_ALLOW_FILE_KEYCHAIN=1 BROKRE_ROUTED_INNER=1 $HOME/.brokre/bin/brokre ssh db"
        ));
        assert!(!joined.contains("'$HOME"));
        assert!(!joined.contains("'BROKRE_SOFT_MEMLOCK"));
        assert!(!joined.contains("'BROKRE_ALLOW_FILE_KEYCHAIN"));
    }

    #[test]
    fn build_single_hop_interactive_argv() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        let args = build_routed_local_argv("ssh", &route, &[]);
        let token = crate::utils::paths::remote_brokre_shell_token();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "b150");
        assert_eq!(
            args[1],
            format!("{} ssh -tt db", token)
        );
    }

    #[test]
    fn build_single_hop_sudo_argv() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        let args = build_routed_local_argv("ssh", &route, &["sudo".into(), "-i".into()]);
        let token = crate::utils::paths::remote_brokre_shell_token();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "b150");
        assert_eq!(args[1], format!("{} ssh -tt db sudo -i", token));
    }

    #[test]
    fn build_single_hop_argv() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        let args = build_routed_local_argv("ssh", &route, &["uname".into(), "-a".into()]);
        let token = crate::utils::paths::remote_brokre_shell_token();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "b150");
        assert_eq!(args[1], format!("{} ssh db uname -a", token));
    }

    #[test]
    fn build_multi_hop_argv() {
        let route = BastionRoute {
            hops: vec!["b1".into(), "b2".into()],
            inner: "db".into(),
            addr: "b1::b2::db".into(),
        };
        let argv = build_routed_local_argv("ssh", &route, &["uname".into()]);
        assert_eq!(argv[0], "b1");
        assert!(argv[1].contains("b2"), "argv[1]={}", argv[1]);
        assert!(argv[1].contains("db"));
    }

    #[test]
    fn check_loop_rejects_duplicate_hops_in_same_route() {
        let hops = vec!["b1".to_string(), "b2".to_string(), "b1".to_string()];
        assert!(matches!(check_loop(&hops), Err(BrokreError::PolicyDenied)));
    }

    #[test]
    fn build_single_hop_sh_c_complex_script() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        let script = "printf '%s\\n' \"it's fine\" > /tmp/f";
        let trailing = vec!["sh".into(), "-c".into(), script.to_string()];
        let args = build_routed_local_argv("ssh", &route, &trailing);
        assert_eq!(args[0], "b150");
        let joined = &args[1];
        assert!(joined.contains("sh -c"), "joined={joined}");
        assert!(joined.contains("printf"), "joined={joined}");
        assert!(joined.contains("/tmp/f"), "joined={joined}");
    }

    #[test]
    fn build_multi_hop_sh_c_shell_join_escapes_script() {
        let route = BastionRoute {
            hops: vec!["b1".into(), "b2".into()],
            inner: "db".into(),
            addr: "b1::b2::db".into(),
        };
        let script = "echo a > /tmp/f && printf '%s' ok";
        let trailing = vec!["sh".into(), "-c".into(), script.to_string()];
        let argv = build_routed_local_argv("ssh", &route, &trailing);
        assert_eq!(argv[0], "b1");
        let joined = &argv[1];
        assert!(joined.contains("sh -c"), "joined={joined}");
        assert!(
            joined.contains("echo a > /tmp/f"),
            "script should survive shell_join: {joined}"
        );
    }

    #[test]
    fn build_direct_inner_single_hop_argv() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        let args = build_routed_direct_inner_argv(
            &route,
            "root@10.0.0.195",
            &["uname".into(), "-a".into()],
        );
        assert_eq!(
            args,
            vec!["b150", "ssh", "-tt", "root@10.0.0.195", "uname", "-a"]
        );
    }

    #[test]
    fn shell_join_quotes_script_with_spaces() {
        let script = "cat > /tmp/x <<'EOF'\nline\nEOF";
        let joined = shell_join(&["sh".into(), "-c".into(), script.to_string()]);
        assert!(joined.starts_with("sh -c "));
        assert!(joined.contains("cat > /tmp/x"));
    }
}
