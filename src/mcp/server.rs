//! brokre MCP server — security-first AI integration.
//!
//! Exposes metadata listing and saved-credential exec only.
//! Never exposes reveal, rm, or session tokens via MCP tool results.

use crate::manage::{
    open_browser, run_manage_server_with, IdleBehavior, ManageServer, ManageServerOptions,
};
use crate::utils::errors::BrokreError;
use crate::vault::store::VaultStore;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt,
};
use rmcp::transport::stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const SERVER_INSTRUCTIONS: &str = "\
brokre is an AI-safe credential broker. Rules for agents:\n\
1. NEVER ask the user for passwords or call brokre reveal — it is TTY-gated and unavailable here.\n\
2. Use brokre_list to discover saved aliases (metadata only: profile, name, host).\n\
3. Use brokre_exec with a saved alias for ssh/mysql/psql/etc. Example: binary=ssh, args=[\"prod-bastion\", \"uname\", \"-a\"].\n\
4. If brokre_list is empty or exec fails with no saved credential, call brokre_setup to open the local manage UI for the human to add accounts.\n\
5. Passwords are injected locally and never returned through MCP.";

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListRequest {
    /// Filter by connector profile (ssh, mysql, postgres, …).
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecRequest {
    /// CLI binary / connector (ssh, mysql, psql, …).
    pub binary: String,
    /// Arguments after the binary. First positional should be a saved alias when using stored credentials.
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone)]
pub struct BrokreMcp {
    manage: Arc<Mutex<Option<ManageServer>>>,
}

impl BrokreMcp {
    pub fn new() -> Self {
        Self {
            manage: Arc::new(Mutex::new(None)),
        }
    }

    fn ensure_manage(&self, onboard: bool) -> std::result::Result<ManageServer, BrokreError> {
        let mut guard = self
            .manage
            .lock()
            .map_err(|_| BrokreError::Runtime("manage server lock poisoned".into()))?;
        if let Some(ref s) = *guard {
            return Ok(ManageServer {
                port: s.port,
                token: s.token.clone(),
                url: s.url.clone(),
            });
        }
        let server = run_manage_server_with(ManageServerOptions {
            onboard,
            idle_behavior: IdleBehavior::LogOnly,
        })?;
        *guard = Some(ManageServer {
            port: server.port,
            token: server.token.clone(),
            url: server.url.clone(),
        });
        Ok(server)
    }

    fn open_manage_ui(&self, onboard: bool) -> std::result::Result<(), BrokreError> {
        let server = self.ensure_manage(onboard)?;
        let url = server.url.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let _ = open_browser(&url);
        });
        Ok(())
    }

    fn vault_is_empty() -> bool {
        VaultStore::open()
            .and_then(|s| s.list())
            .map(|r| r.is_empty())
            .unwrap_or(true)
    }

    fn auto_open_setup_if_needed(&self) -> std::result::Result<(), BrokreError> {
        if std::env::var("BROKRE_MCP_NO_AUTO_OPEN").ok().as_deref() == Some("1") {
            return Ok(());
        }
        if !Self::vault_is_empty() {
            return Ok(());
        }
        self.open_manage_ui(true)?;
        eprintln!("brokre mcp: vault empty — opened manage UI in browser for credential setup");
        Ok(())
    }
}

#[tool_router]
impl BrokreMcp {
    #[tool(
        description = "List saved credential aliases (metadata only — never passwords). Use before brokre_exec."
    )]
    fn brokre_list(
        &self,
        Parameters(req): Parameters<ListRequest>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let store = VaultStore::open().map_err(mcp_err)?;
        let mut records = store.list().map_err(mcp_err)?;
        if let Some(p) = req.profile {
            records.retain(|r| r.profile == p);
        }
        let out: Vec<_> = records
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "profile": r.profile,
                    "name": r.name,
                    "labels": r.labels,
                    "host_alias": r.host_alias,
                    "created_at": r.created_at,
                    "last_used_at": r.last_used_at,
                })
            })
            .collect();
        let text = serde_json::to_string_pretty(&out).map_err(mcp_err)?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(
        description = "Run a CLI through brokre with saved credentials (ssh/mysql/psql/…). Requires a saved alias. Output may contain command results but never vault passwords."
    )]
    async fn brokre_exec(
        &self,
        Parameters(req): Parameters<ExecRequest>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let exe = std::env::current_exe().map_err(mcp_err)?;
        let mut cmd = tokio::process::Command::new(exe);
        cmd.arg(&req.binary);
        cmd.args(&req.args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().await.map_err(|e| {
            McpError::internal_error(format!("failed to spawn brokre exec: {e}"), None)
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);

        let body = serde_json::json!({
            "exit_code": code,
            "stdout": stdout,
            "stderr": stderr,
        });
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()),
        )]))
    }

    #[tool(
        description = "Open the local brokre manage web UI in the user's browser so they can add or rotate credentials. Session token is never returned to the agent — only the human sees it in the browser/terminal."
    )]
    fn brokre_setup(&self) -> std::result::Result<CallToolResult, McpError> {
        self.open_manage_ui(false).map_err(mcp_err)?;
        Ok(CallToolResult::success(vec![Content::text(
            "Opened brokre manage UI in your default browser (http://127.0.0.1). \
             Add credentials there — passwords are write-only and never exposed via MCP. \
             After saving, use brokre_list and brokre_exec."
                .to_string(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for BrokreMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("brokre", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(SERVER_INSTRUCTIONS.to_string())
    }
}

fn mcp_err(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

pub async fn run_mcp_server() -> std::result::Result<(), BrokreError> {
    let service = BrokreMcp::new();
    service.auto_open_setup_if_needed()?;

    let running = service
        .serve(stdio())
        .await
        .map_err(|e| BrokreError::Runtime(format!("mcp serve: {e}")))?;

    running
        .waiting()
        .await
        .map_err(|e| BrokreError::Runtime(format!("mcp waiting: {e}")))?;

    Ok(())
}
