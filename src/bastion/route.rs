use crate::bastion::registry::is_registered_bastion;
use crate::utils::errors::{BrokreError, Result};
use serde::{Deserialize, Serialize};

pub const ROUTE_SEP: &str = "::";
pub const BASTION_PATH_ENV: &str = "BROKRE_BASTION_PATH";
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
        .map(|a| shell_escape(a))
        .collect::<Vec<_>>()
        .join(" ")
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
    let inner_exec: Vec<String> = std::iter::once("brokre".to_string())
        .chain(std::iter::once(binary.to_string()))
        .chain(std::iter::once(route.inner.clone()))
        .chain(trailing.iter().cloned())
        .collect();

    match route.hops.len() {
        1 => {
            let mut args = vec![route.hops[0].clone()];
            args.extend(inner_exec);
            args
        }
        _ => {
            let mut wrapped = inner_exec;
            for hop in route.hops.iter().skip(1).rev() {
                let inner = shell_join(&wrapped);
                wrapped = vec!["brokre".into(), "ssh".into(), hop.clone(), inner];
            }
            let mut args = vec![route.hops[0].clone()];
            args.push(shell_join(&wrapped));
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
    fn build_single_hop_argv() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        let args = build_routed_local_argv("ssh", &route, &["uname".into(), "-a".into()]);
        assert_eq!(
            args,
            vec!["b150", "brokre", "ssh", "db", "uname", "-a"]
        );
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
}
