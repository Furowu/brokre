//! MCP-specific bastion gate: URL-mode elicitation, then shared browser poll.

use crate::bastion::gate::{bastion_auth_url, fetch_unlocked_status, poll_timeout};
use crate::bastion::session::{gate_required, is_unlocked};
use crate::manage::open_browser;
use crate::manage::server::ManageServer;
use rmcp::model::ElicitationAction;
use rmcp::service::ElicitationMode;
use rmcp::{ErrorData as McpError, Peer, RoleServer};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

pub fn needs_unlock_for_exec(profile: &str, args: &[String]) -> bool {
    crate::bastion::gate::needs_unlock_for_exec(profile, args)
}

pub fn needs_unlock_for_list(probe: bool, include_bastions: bool) -> bool {
    crate::bastion::gate::needs_unlock_for_list(probe, include_bastions)
}

pub async fn ensure_bastion_unlocked(
    server: &ManageServer,
    peer: &Peer<RoleServer>,
) -> std::result::Result<(), McpError> {
    if !gate_required() || is_unlocked() {
        return Ok(());
    }

    let elicitation_id = Uuid::new_v4().to_string();
    let url = bastion_auth_url(server, &elicitation_id);

    let modes = peer.supported_elicitation_modes();
    if modes.contains(&ElicitationMode::Url) {
        let parsed = url::Url::parse(&url)
            .map_err(|e| McpError::internal_error(format!("bastion auth url: {e}"), None))?;
        match peer
            .elicit_url_with_timeout(
                "Unlock bastion access in your browser to continue this MCP tool call.",
                parsed,
                &elicitation_id,
                Some(poll_timeout()),
            )
            .await
        {
            Ok(ElicitationAction::Accept) if is_unlocked() => return Ok(()),
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

    let url_clone = url.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        let _ = open_browser(&url_clone);
    });

    poll_until_unlocked_async(server, poll_timeout()).await
}

async fn poll_until_unlocked_async(
    server: &ManageServer,
    timeout: Duration,
) -> std::result::Result<(), McpError> {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if is_unlocked() {
            return Ok(());
        }
        if fetch_unlocked_status(server.port, &server.token)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(McpError::invalid_request(
        "bastion unlock timed out — open the auth page and retry",
        None,
    ))
}
