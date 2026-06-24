//! MCP-specific bastion gate: URL-mode elicitation, then shared browser poll.

use crate::bastion::gate::{
    bastion_auth_url, fetch_unlocked_status, manage_unreachable, poll_timeout,
    refresh_manage_for_gate, BastionAuthContext,
};
use crate::bastion::session::{gate_required, is_unlocked, load_session, touch_session};
use crate::bastion::unlock_coord::BastionUnlockCoordinator;
use crate::manage::server::ManageServer;
use rmcp::model::ElicitationAction;
use rmcp::service::ElicitationMode;
use rmcp::{ErrorData as McpError, Peer, RoleServer};
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

/// Bastion outbound gate metadata included in MCP tool responses.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BastionGateInfo {
    /// This call is subject to bastion outbound gate (key configured + operation touches bastions).
    pub required: bool,
    /// Human unlocked the bastion session during this tool call (browser / elicitation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocked_during_call: Option<bool>,
    /// Rolling idle expiry of the active bastion session (RFC3339), when unlocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_expires_at: Option<String>,
}

impl BastionGateInfo {
    pub fn for_list(probe: bool, include_bastions: bool, unlocked_during_call: bool) -> Self {
        Self::build(
            gate_applies_for_list(probe, include_bastions),
            unlocked_during_call,
        )
    }

    pub fn for_exec(profile: &str, args: &[String], unlocked_during_call: bool) -> Self {
        Self::build(gate_applies_for_exec(profile, args), unlocked_during_call)
    }

    fn build(applies: bool, unlocked_during_call: bool) -> Self {
        if !gate_required() || !applies {
            return Self {
                required: false,
                unlocked_during_call: None,
                idle_expires_at: None,
            };
        }
        let idle_expires_at = if is_unlocked() {
            load_session()
                .ok()
                .flatten()
                .map(|s| s.idle_expires_at.to_rfc3339())
        } else {
            None
        };
        Self {
            required: true,
            unlocked_during_call: Some(unlocked_during_call),
            idle_expires_at,
        }
    }
}

pub fn gate_applies_for_list(probe: bool, include_bastions: bool) -> bool {
    crate::bastion::gate::gate_applies_to_list(probe, include_bastions)
}

pub fn gate_applies_for_exec(profile: &str, args: &[String]) -> bool {
    crate::bastion::gate::gate_applies_to_exec(profile, args)
}

pub fn needs_unlock_for_exec(profile: &str, args: &[String]) -> bool {
    crate::bastion::gate::needs_unlock_for_exec(profile, args)
}

pub fn needs_unlock_for_list(probe: bool, include_bastions: bool) -> bool {
    crate::bastion::gate::needs_unlock_for_list(probe, include_bastions)
}

/// Build auth-page context from the MCP peer initialize info and tool name.
pub fn auth_context_from_peer(
    peer: &Peer<RoleServer>,
    tool: &str,
    elicitation_id: String,
) -> BastionAuthContext {
    let (client, client_version) = peer
        .peer_info()
        .map(|info| {
            let impl_ = &info.client_info;
            let label = impl_
                .title
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(impl_.name.as_str())
                .to_string();
            (Some(label), Some(impl_.version.clone()))
        })
        .unwrap_or((None, None));
    BastionAuthContext {
        elicitation_id,
        channel: Some("mcp".into()),
        tool: Some(tool.into()),
        client,
        client_version,
    }
}

fn elicitation_message(ctx: &BastionAuthContext) -> String {
    let client = ctx.client.as_deref().unwrap_or("your MCP client");
    format!("Unlock bastion access in your browser to continue in {client}.")
}

/// Ensure bastion outbound access is unlocked. Returns `true` when the human unlocked during this call.
pub async fn ensure_bastion_unlocked(
    server: &ManageServer,
    peer: &Peer<RoleServer>,
    tool: &str,
) -> std::result::Result<bool, McpError> {
    if !gate_required() {
        return Ok(false);
    }
    if is_unlocked() {
        let _ = touch_session();
        return Ok(false);
    }

    let mut server = refresh_manage_for_gate(None)
        .or_else(|_| refresh_manage_for_gate(Some(server)))
        .map_err(|e| McpError::internal_error(format!("manage server unavailable: {e}"), None))?;

    let elicitation_id = Uuid::new_v4().to_string();
    let ctx = auth_context_from_peer(peer, tool, elicitation_id);
    let url = bastion_auth_url(&server, &ctx);
    let coordinator = BastionUnlockCoordinator::try_acquire().map_err(|e| {
        McpError::internal_error(format!("bastion unlock coordination failed: {e}"), None)
    })?;
    if is_unlocked() {
        return Ok(false);
    }

    eprintln!(
        "brokre mcp: bastion auth on http://127.0.0.1:{}/bastion-auth (manage.json registry)",
        server.port
    );

    if coordinator.is_opener() {
        let modes = peer.supported_elicitation_modes();
        if modes.contains(&ElicitationMode::Url) {
            let parsed = url::Url::parse(&url)
                .map_err(|e| McpError::internal_error(format!("bastion auth url: {e}"), None))?;
            match peer
                .elicit_url_with_timeout(
                    elicitation_message(&ctx),
                    parsed,
                    &ctx.elicitation_id,
                    Some(poll_timeout()),
                )
                .await
            {
                Ok(ElicitationAction::Accept) if is_unlocked() => return Ok(true),
                Ok(ElicitationAction::Accept) => {}
                Ok(ElicitationAction::Decline) => {
                    return Err(McpError::invalid_request(
                        "bastion unlock declined by user",
                        None,
                    ));
                }
                Ok(ElicitationAction::Cancel) => {
                    return Err(McpError::invalid_request(
                        "bastion unlock cancelled by user",
                        None,
                    ));
                }
                Err(_) => {}
            }
        }

        coordinator.maybe_open_browser(&url);
    }

    poll_until_unlocked_async(&mut server, poll_timeout()).await?;
    Ok(true)
}

async fn poll_until_unlocked_async(
    server: &mut ManageServer,
    timeout: Duration,
) -> std::result::Result<(), McpError> {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if is_unlocked() {
            let _ = touch_session();
            return Ok(());
        }
        match fetch_unlocked_status(server.port, &server.token) {
            Ok(true) => {
                let _ = touch_session();
                return Ok(());
            }
            Ok(false) => {}
            Err(e) if manage_unreachable(&e) => {
                *server = refresh_manage_for_gate(Some(server)).map_err(|e| {
                    McpError::internal_error(format!("manage server unavailable: {e}"), None)
                })?;
            }
            Err(e) => {
                return Err(McpError::internal_error(e.to_string(), None));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(McpError::invalid_request(
        "bastion unlock timed out — open the auth page and retry",
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_home::with_temp_brokre_home;

    #[test]
    fn bastion_gate_info_not_required_serializes_minimal() {
        let info = BastionGateInfo::build(false, false);
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v, serde_json::json!({ "required": false }));
    }

    #[test]
    fn bastion_gate_info_required_includes_unlocked_during_call() {
        let info = BastionGateInfo::build(true, true);
        let v = serde_json::to_value(&info).unwrap();
        // Without a configured bastion key, gate is not active.
        assert_eq!(v["required"], false);
    }

    #[test]
    fn bastion_gate_info_applies_when_key_configured() {
        with_temp_brokre_home(|| {
            crate::bastion::key::set_bastion_key(&crate::security::secret::SecretString::new(
                "test-key".into(),
            ))
            .unwrap();
            let info = BastionGateInfo::build(true, true);
            let v = serde_json::to_value(&info).unwrap();
            assert_eq!(v["required"], true);
            assert_eq!(v["unlocked_during_call"], true);
        });
    }
}
