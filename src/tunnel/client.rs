use crate::bastion::route::BastionRoute;
use crate::runtime::pty::PtyRunResult;
use crate::tunnel::protocol::{read_frame, write_frame, Frame};
use crate::utils::errors::{BrokreError, Result};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub bastion: String,
    pub protocol_version: u16,
    pub agent_ok: bool,
    pub arch: Option<String>,
    pub elapsed_ms: u64,
}

pub fn doctor(bastion: &str) -> Result<DoctorReport> {
    let started = Instant::now();
    let mut child = crate::bastion::transport::spawn_tunnel_agent(bastion)?;
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| BrokreError::Runtime("tunnel agent stdin missing".into()))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| BrokreError::Runtime("tunnel agent stdout missing".into()))?;

    write_frame(&mut child_stdin, &Frame::hello())?;
    match read_frame(&mut child_stdout)? {
        Some(Frame::HelloAck { version }) => {
            crate::tunnel::protocol::require_version(version)?;
        }
        Some(Frame::Error { message }) => return Err(BrokreError::Runtime(message)),
        Some(other) => {
            return Err(BrokreError::Runtime(format!(
                "unexpected tunnel doctor frame: {other:?}"
            )))
        }
        None => {
            return Err(BrokreError::Runtime(
                "tunnel agent closed during doctor".into(),
            ))
        }
    }
    drop(child_stdin);
    let _ = child.wait();
    Ok(DoctorReport {
        bastion: bastion.to_string(),
        protocol_version: crate::tunnel::PROTOCOL_VERSION,
        agent_ok: true,
        arch: remote_arch(bastion).ok(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

fn remote_arch(bastion: &str) -> Result<String> {
    let remote = vec!["uname -m".to_string()];
    let (code, stdout, stderr) = crate::bastion::transport::run_on_bastion(bastion, &remote)?;
    if code == 0 {
        Ok(stdout.trim().to_string())
    } else {
        Err(BrokreError::Runtime(format!(
            "remote arch check failed (exit {code}): {stderr}"
        )))
    }
}

pub fn exec_route(route: &BastionRoute, trailing: Vec<String>) -> Result<PtyRunResult> {
    let forward_stdin = should_forward_stdin(&trailing);
    let mut child = crate::bastion::transport::spawn_tunnel_agent(route.first_hop())?;
    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| BrokreError::Runtime("tunnel agent stdin missing".into()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| BrokreError::Runtime("tunnel agent stdout missing".into()))?;

    let code = crate::tunnel::session_relay::run_local_session(
        child_stdout,
        child_stdin,
        agent_inner_addr(route),
        trailing,
        forward_stdin,
    )?;
    let _ = child.wait();
    Ok(PtyRunResult {
        exit_code: code,
        captured_password: None,
        had_prompt: false,
        ssh_authenticated: false,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: Some("tunnel-sessionrelay".into()),
    })
}

fn should_forward_stdin(trailing: &[String]) -> bool {
    should_forward_stdin_with_pipe(crate::security::tty::stdin_is_pipe(), trailing)
}

fn should_forward_stdin_with_pipe(stdin_is_pipe: bool, trailing: &[String]) -> bool {
    stdin_is_pipe
        || trailing.is_empty()
        || (crate::runtime::ssh_identity::remote_command_needs_tty(trailing)
            && crate::runtime::elevated::parse_elevated_trailing(trailing).is_none())
}

fn agent_inner_addr(route: &BastionRoute) -> String {
    if route.hops.len() == 1 {
        return route.inner.clone();
    }
    route
        .hops
        .iter()
        .skip(1)
        .chain(std::iter::once(&route.inner))
        .cloned()
        .collect::<Vec<_>>()
        .join(crate::bastion::route::ROUTE_SEP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_inner_addr_single_hop_is_inner_alias() {
        let route = BastionRoute {
            hops: vec!["b150".into()],
            inner: "db".into(),
            addr: "b150::db".into(),
        };
        assert_eq!(agent_inner_addr(&route), "db");
    }

    #[test]
    fn agent_inner_addr_multi_hop_passes_remaining_route() {
        let route = BastionRoute {
            hops: vec!["b1".into(), "b2".into()],
            inner: "db".into(),
            addr: "b1::b2::db".into(),
        };
        assert_eq!(agent_inner_addr(&route), "b2::db");
    }

    #[test]
    fn agent_inner_addr_preserves_deeper_remaining_route() {
        let route = BastionRoute {
            hops: vec!["b1".into(), "b2".into(), "b3".into()],
            inner: "db".into(),
            addr: "b1::b2::b3::db".into(),
        };
        assert_eq!(agent_inner_addr(&route), "b2::b3::db");
    }

    #[test]
    fn sudo_one_shot_does_not_forward_stdin() {
        let trailing = vec!["sudo".into(), "id".into()];
        assert!(!should_forward_stdin_with_pipe(false, &trailing));
    }

    #[test]
    fn sudo_login_one_shot_does_not_forward_stdin() {
        let trailing = vec!["sudo".into(), "-i".into(), "whoami".into()];
        assert!(!should_forward_stdin_with_pipe(false, &trailing));
    }

    #[test]
    fn interactive_login_forwards_stdin() {
        assert!(should_forward_stdin_with_pipe(false, &[]));
        let trailing = vec!["sudo".into(), "-i".into()];
        assert!(should_forward_stdin_with_pipe(false, &trailing));
    }
}
