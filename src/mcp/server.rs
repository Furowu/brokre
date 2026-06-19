//! brokre MCP server — security-first AI integration.
//!
//! Exposes metadata listing and saved-credential exec only.
//! Never exposes reveal, rm, or session tokens via MCP tool results.

use crate::audit::query::{list, verify_with_stats, AuditQuery};
use crate::manage::{
    open_browser, run_manage_server_with, IdleBehavior, ManageServer, ManageServerOptions,
};
use crate::mcp::elevated_session::{mcp_session_enabled, ElevatedSessionPool, RunResult};
use crate::runtime::elevated::{SessionKey, SessionPolicy};
use crate::utils::errors::BrokreError;
use crate::utils::paths::audit_path;
use crate::vault::keychain::get_or_init_audit_hmac_key;
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
4. For remote root/sudo: use brokre_exec_elevated (alias + command + mode sudo|sudo_login|su). \
Sessions reuse by default (session=reuse) — sudo password once per idle window (~10 min). \
session=new forces fresh session; session=close ends it. Set BROKRE_MCP_SESSION=0 to disable reuse.\n\
5. brokre_exec with ssh+sudo/su args also uses the session pool when enabled.\n\
6. If brokre_list is empty or exec fails with no saved credential, call brokre_setup to open the local manage UI for the human to add accounts.\n\
7. Passwords are injected locally and never returned through MCP.\n\
8. Use brokre_audit_list to review past operations (metadata only). Use brokre_audit_verify to check log integrity.";

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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecElevatedRequest {
    /// Saved SSH alias from brokre_list (profile ssh).
    pub alias: String,
    /// Shell command to run with elevated privileges on the remote host.
    pub command: String,
    /// `sudo` — run via sudo; `sudo_login` — sudo -i login environment; `su` — su - <user> -c.
    #[serde(default = "default_elevated_mode")]
    pub mode: String,
    /// Target user for `su` mode (default root). Ignored for sudo modes.
    #[serde(default)]
    pub user: Option<String>,
    /// `reuse` (default) — reuse elevated PTY session; `new` — fresh session; `close` — end session.
    #[serde(default = "default_session_policy")]
    pub session: String,
}

fn default_elevated_mode() -> String {
    "sudo".into()
}

fn default_session_policy() -> String {
    "reuse".into()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditListRequest {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Clone)]
pub struct BrokreMcp {
    manage: Arc<Mutex<Option<ManageServer>>>,
    sessions: Arc<Mutex<ElevatedSessionPool>>,
}

impl BrokreMcp {
    pub fn new(sessions: Arc<Mutex<ElevatedSessionPool>>) -> Self {
        Self {
            manage: Arc::new(Mutex::new(None)),
            sessions,
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
        if mcp_session_enabled() && req.binary == "ssh" {
            if let Some((alias, mode, command, user)) =
                crate::runtime::elevated::ssh_exec_args_to_elevated(&req.args)
            {
                let key = SessionKey::new(&alias, mode, user.as_deref());
                return run_elevated_pool(
                    self.sessions.clone(),
                    key,
                    Some(command),
                    SessionPolicy::Reuse,
                )
                .await;
            }
        }
        run_brokre_cli(&req.binary, &req.args, &[]).await
    }

    #[tool(
        description = "Run a command on a saved SSH host with elevated privileges (sudo, sudo -i environment, or su). \
Reuses a persistent elevated session by default (session=reuse) so sudo password is not re-prompted every call. \
session=new starts fresh; session=close ends the session. BROKRE_MCP_SESSION=0 disables session reuse."
    )]
    async fn brokre_exec_elevated(
        &self,
        Parameters(req): Parameters<ExecElevatedRequest>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let mode = crate::runtime::elevated::ElevatedMode::parse(&req.mode).map_err(mcp_err)?;
        let policy = SessionPolicy::parse(&req.session).map_err(mcp_err)?;
        let key = SessionKey::new(&req.alias, mode, req.user.as_deref());

        if mcp_session_enabled() {
            let cmd = if policy == SessionPolicy::Close {
                None
            } else {
                Some(req.command.clone())
            };
            return run_elevated_pool(self.sessions.clone(), key, cmd, policy).await;
        }

        let args = crate::runtime::elevated::build_ssh_argv(
            &req.alias,
            mode,
            &req.command,
            req.user.as_deref(),
        )
        .map_err(mcp_err)?;
        run_brokre_cli(
            "ssh",
            &args,
            &[
                ("BROKRE_MCP_EXEC", "1"),
                ("BROKRE_MCP_ELEVATED", mode.mcp_env_value()),
            ],
        )
        .await
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

    #[tool(
        description = "List audit log events (metadata only — command args are redacted). Filter by profile, alias, action, or source (cli/mcp/manage)."
    )]
    fn brokre_audit_list(
        &self,
        Parameters(req): Parameters<AuditListRequest>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let query = AuditQuery {
            profile: req.profile,
            name: req.name,
            action: req.action,
            source: req.source,
            since: req.since,
            until: req.until,
            limit: req.limit.unwrap_or(crate::audit::query::DEFAULT_LIMIT),
            offset: req.offset.unwrap_or(0),
            newest_first: true,
        };
        let result = list(query).map_err(mcp_err)?;
        let text = serde_json::to_string_pretty(&result).map_err(mcp_err)?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(
        description = "Verify the tamper-evident audit log HMAC chain. Returns event count and time range on success."
    )]
    fn brokre_audit_verify(&self) -> std::result::Result<CallToolResult, McpError> {
        let path = audit_path();
        let key = get_or_init_audit_hmac_key().map_err(mcp_err)?;
        let stats = verify_with_stats(&path, &key).map_err(mcp_err)?;
        let text = serde_json::to_string_pretty(&stats).map_err(mcp_err)?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
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

async fn run_brokre_cli(
    binary: &str,
    args: &[String],
    extra_env: &[(&str, &str)],
) -> std::result::Result<CallToolResult, McpError> {
    let exe = std::env::current_exe().map_err(mcp_err)?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env("BROKRE_MCP_EXEC", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.arg(binary);
    cmd.args(args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());

    let output = cmd
        .output()
        .await
        .map_err(|e| McpError::internal_error(format!("failed to spawn brokre exec: {e}"), None))?;

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

async fn run_elevated_pool(
    sessions: Arc<Mutex<ElevatedSessionPool>>,
    key: SessionKey,
    command: Option<String>,
    policy: SessionPolicy,
) -> std::result::Result<CallToolResult, McpError> {
    let result = tokio::task::spawn_blocking(move || {
        let mut pool = sessions
            .lock()
            .map_err(|_| BrokreError::Runtime("session pool lock poisoned".into()))?;
        pool.run(key, command.as_deref(), policy)
    })
    .await
    .map_err(|e| McpError::internal_error(format!("session task: {e}"), None))?
    .map_err(mcp_err)?;
    Ok(session_result_to_call_tool(result))
}

fn session_result_to_call_tool(r: RunResult) -> CallToolResult {
    let body = serde_json::json!({
        "exit_code": r.exit_code,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "session_reused": r.session_reused,
        "session_idle_expires_at": r.idle_expires_at,
    });
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()),
    )])
}

pub async fn run_mcp_server() -> std::result::Result<(), BrokreError> {
    let sessions = Arc::new(Mutex::new(ElevatedSessionPool::from_env()));
    let sweeper = sessions.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(60));
        if let Ok(mut pool) = sweeper.lock() {
            pool.sweep_idle();
        }
    });

    let service = BrokreMcp::new(sessions);
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
