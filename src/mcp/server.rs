//! brokre MCP server — security-first AI integration.
//!
//! Exposes metadata listing and saved-credential exec only.
//! Never exposes reveal, rm, or session tokens via MCP tool results.

use crate::audit::query::{list, verify_with_stats, AuditQuery};
use crate::bastion::list_policy::{collect_list_items, resolve_list_options, RawListOptions};
use crate::bastion::mcp_gate::{
    ensure_bastion_unlocked, needs_unlock_for_exec, needs_unlock_for_list, BastionGateInfo,
};
use crate::manage::{
    open_browser, refresh_live_manage, run_manage_server_with, IdleBehavior, ManageServer,
    ManageServerOptions,
};
use crate::mcp::elevated_session::{mcp_session_enabled, ElevatedSessionPool, RunResult};
use crate::runtime::elevated::{SessionKey, SessionPolicy};
use crate::utils::errors::BrokreError;
use crate::utils::paths::audit_path;
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::store::VaultStore;
use rmcp::transport::stdio;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, Peer, ServerHandler,
    ServiceExt,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const SERVER_INSTRUCTIONS: &str = "\
brokre is an AI-safe credential broker. Rules for agents:\n\
1. NEVER ask the user for passwords or call brokre reveal — it is TTY-gated and unavailable here.\n\
2. Use brokre_list to discover saved aliases (metadata: profile, name, addr, host_alias, route, access, availability, status).\n\
3. Cross-network: when local LAN aliases are unreachable, brokre_list hides them and shows routed entries \
(e.g. b150::db with access=via_b150, route=[\"b150\"]). Prefer addr containing `::` with availability=available.\n\
4. Exec routed aliases: brokre_exec binary=ssh, args=[\"b150::db\", \"uname\", \"-a\"] — credentials inject on the bastion.\n\
5. Non-privileged remote commands — brokre_exec: binary=ssh, args=[\"alias\", \"uname\", \"-a\"]. \
Args are argv tokens after the alias (NOT one shell string). Example: args=[\"prod\", \"docker\", \"ps\"].\n\
5b. Writing remote scripts/files — brokre_exec: binary=ssh, args=[\"alias\"], shell_command=\"cat > /path <<'EOF'\\n...\\nEOF\". \
Do NOT put sh -c '...' in args or split printf/redirects across argv tokens. For privileged paths use brokre_exec_elevated.command.\n\
6. Privileged remote commands (sudo/su) — prefer brokre_exec_elevated:\n\
   {\"alias\":\"prod\",\"command\":\"whoami\",\"mode\":\"sudo_login\"} for root login env (like sudo -i).\n\
   mode: sudo (default) | sudo_login (sudo -i env) | su. user: target for su (default root).\n\
   session: reuse (default, ~10 min idle) | new (fresh sudo) | close (end session; command=\"\").\n\
7. brokre_exec shortcut for sudo: binary=ssh, args=[\"prod\",\"sudo\",\"systemctl\",\"status\",\"nginx\"] \
(split argv, not quoted). args=[\"prod\",\"sudo\",\"-i\",\"whoami\"] maps to sudo_login. Uses same session pool.\n\
8. Do NOT ask the user for sudo passwords — vault password is injected locally. If sudo fails, tell the user \
to verify the vault password matches the remote sudo password via brokre manage UI (brokre_setup).\n\
9. If brokre_list is empty or exec fails with no saved credential, call brokre_setup for the human to add accounts.\n\
10. Passwords are injected locally and never returned through MCP.\n\
11. Bastion outbound access may require human unlock via browser (URL elicitation or local auth page). \
When gate applies, tell the user to complete bastion unlock in the browser if `bastion_gate.unlocked_during_call` is true or the call blocks waiting.\n\
12. brokre_list / brokre_exec / brokre_exec_elevated responses include `bastion_gate` \
(`required`, `unlocked_during_call`, `idle_expires_at`) so agents know unlock state.\n\
13. brokre_audit_list / brokre_audit_verify: read-only audit metadata (args redacted).\n\
14. CLI equivalents (when the user asks to run in a terminal, or you need to debug MCP):\n\
   - Always prefix brokre — NEVER bare `ssh prod` / `mysql prod` (no vault injection).\n\
   - brokre_list ≈ `brokre list --json`\n\
   - brokre_exec binary=ssh, args=[\"prod\",\"uname\",\"-a\"] ≈ `brokre ssh prod uname -a`\n\
   - brokre_exec binary=mysql, args=[\"prod-db\",\"-e\",\"SHOW TABLES\"] ≈ `brokre mysql prod-db -e SHOW TABLES`\n\
   - shell_command=\"…\" ≈ `brokre ssh <alias> sh -c '…'` (script as single -c argument)\n\
   - brokre_setup ≈ `brokre manage --open` (human adds credentials; no password in MCP response)\n\
   - First-time save requires human TTY: `brokre ssh user@host` — not available via MCP.";

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListRequest {
    /// Filter by connector profile (ssh, mysql, postgres, …).
    #[serde(default)]
    pub profile: Option<String>,
    /// TCP reachability probe (ms-level timeout).
    #[serde(default)]
    pub probe: bool,
    /// Include aliases discovered on registered bastions (auto-enabled when bastions are registered).
    #[serde(default)]
    pub include_bastions: bool,
    /// Include unreachable aliases (default: hidden when probing).
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecRequest {
    /// CLI binary / connector (ssh, mysql, psql, …).
    pub binary: String,
    /// Arguments after the binary. First positional must be a saved alias. Remaining tokens are the remote argv \
    /// (split form): [\"prod\", \"df\", \"-h\"] not a single shell string. For sudo use brokre_exec_elevated or \
    /// [\"alias\", \"sudo\", \"systemctl\", \"status\", \"nginx\"]. When using shell_command, args should contain \
    /// only flags and the alias (e.g. [\"prod\"]).
    #[serde(default)]
    pub args: Vec<String>,
    /// SSH only: run `sh -c <this>` on the remote host after the alias. Mutually exclusive with trailing argv \
    /// after the alias. Preferred for writing remote scripts/files with complex quoting.
    #[serde(default)]
    pub shell_command: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecElevatedRequest {
    /// Saved SSH alias from brokre_list (profile ssh).
    pub alias: String,
    /// Shell command to run with elevated privileges on the remote host (e.g. \"docker ps\", \"systemctl restart nginx\").
    pub command: String,
    /// `sudo` — run via sudo bash -lc; `sudo_login` — sudo -i login environment; `su` — su - <user> -c.
    #[serde(default = "default_elevated_mode")]
    pub mode: String,
    /// Target user for `su` mode (default root). Ignored for sudo modes.
    #[serde(default)]
    pub user: Option<String>,
    /// `reuse` (default) — reuse elevated PTY session; `new` — fresh session; `close` — end session (use empty command).
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
            if let Some(live) = refresh_live_manage(None).or_else(|| refresh_live_manage(Some(s))) {
                if live.port != s.port || live.token != s.token {
                    eprintln!(
                        "brokre mcp: manage server moved to port {} (was {})",
                        live.port, s.port
                    );
                }
                *guard = Some(live.clone());
                return Ok(live);
            }
            *guard = None;
        } else if let Some(live) = refresh_live_manage(None) {
            *guard = Some(live.clone());
            return Ok(live);
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

    fn ensure_manage_server(&self) -> std::result::Result<ManageServer, BrokreError> {
        self.ensure_manage(false)
    }
}

#[tool_router]
impl BrokreMcp {
    #[tool(
        description = "List saved credential aliases (metadata only — never passwords). When bastions are registered, auto-probes reachability, merges routed aliases (e.g. b150::db), and hides unreachable entries. Use all=true to show everything. Response includes items (addr, route, access, availability, host_alias, status) and bastion_gate. Always call before brokre_exec."
    )]
    async fn brokre_list(
        &self,
        Parameters(req): Parameters<ListRequest>,
        peer: Peer<rmcp::RoleServer>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let effective = resolve_list_options(RawListOptions {
            probe: req.probe,
            include_bastions: req.include_bastions,
            no_bastion_discovery: false,
            show_all: req.all,
            for_mcp: true,
        });
        let mut unlocked_during_call = false;
        if needs_unlock_for_list(effective.probe, effective.include_bastions) {
            let server = self.ensure_manage_server().map_err(mcp_err)?;
            unlocked_during_call = ensure_bastion_unlocked(&server, &peer, "brokre_list").await?;
        }
        let store = VaultStore::open().map_err(mcp_err)?;
        let mut records = store.list().map_err(mcp_err)?;
        if let Some(p) = req.profile {
            records.retain(|r| r.profile == p);
        }
        let items = collect_list_items(records, &effective).map_err(mcp_err)?;
        let gate = BastionGateInfo::for_list(
            effective.probe,
            effective.include_bastions,
            unlocked_during_call,
        );
        let body = serde_json::json!({
            "items": items,
            "bastion_gate": gate,
        });
        Ok(text_json_result(&body))
    }

    #[tool(
        description = "Run a CLI through brokre with saved credentials (ssh/mysql/psql/…). \
Requires a saved alias as the first positional arg in args. Args are argv tokens, not a shell string: \
use [\"prod\",\"uptime\"] not [\"prod\",\"uptime\"]. For remote scripts/files with complex quoting use \
shell_command (ssh only): args=[\"prod\"], shell_command=\"cat > /path <<'EOF'\\n...\\nEOF\". \
For remote sudo/su prefer brokre_exec_elevated; \
shortcut: binary=ssh, args=[\"alias\",\"sudo\",\"cmd\",...] or args=[\"alias\",\"sudo\",\"-i\",\"whoami\"]. \
Supports bastion routes like b150::db. Response includes `bastion_gate` unlock metadata. Never returns vault passwords."
    )]
    async fn brokre_exec(
        &self,
        Parameters(req): Parameters<ExecRequest>,
        peer: Peer<rmcp::RoleServer>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let source_env = mcp_source_env(&peer, "brokre_exec");
        let args = crate::mcp::normalize_exec_argv(
            &req.binary,
            &req.args,
            req.shell_command.as_deref(),
        )
        .map_err(mcp_err)?;
        let mut unlocked_during_call = false;
        if needs_unlock_for_exec(&req.binary, &args) {
            let server = self.ensure_manage_server().map_err(mcp_err)?;
            unlocked_during_call = ensure_bastion_unlocked(&server, &peer, "brokre_exec").await?;
        }
        let gate = BastionGateInfo::for_exec(&req.binary, &args, unlocked_during_call);
        if mcp_session_enabled() && req.binary == "ssh" {
            if let Some((alias, mode, command, user)) =
                crate::runtime::elevated::ssh_exec_args_to_elevated(&args)
            {
                if !alias.contains(crate::bastion::route::ROUTE_SEP) {
                    let key = SessionKey::new(&alias, mode, user.as_deref());
                    return run_elevated_pool(
                        self.sessions.clone(),
                        key,
                        Some(command),
                        SessionPolicy::Reuse,
                        gate,
                    )
                    .await;
                }
            }
        }
        run_brokre_cli(&req.binary, &args, &source_env, gate).await
    }

    #[tool(
        description = "Run a command on a saved SSH host with elevated privileges (sudo, sudo -i environment, or su). \
Preferred for any remote root/sudo work. Example: {\"alias\":\"prod\",\"command\":\"docker ps\",\"mode\":\"sudo_login\"}. \
mode: sudo (default) | sudo_login (root login env, like sudo -i) | su. user: su target (default root). \
session: reuse (default, sudo once per ~10 min idle) | new | close (empty command). \
Reuses a persistent elevated shell by default. BROKRE_MCP_SESSION=0 disables reuse. Response includes `bastion_gate` unlock metadata."
    )]
    async fn brokre_exec_elevated(
        &self,
        Parameters(req): Parameters<ExecElevatedRequest>,
        peer: Peer<rmcp::RoleServer>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let source_env = mcp_source_env(&peer, "brokre_exec_elevated");
        let mut unlocked_during_call = false;
        if needs_unlock_for_exec("ssh", std::slice::from_ref(&req.alias)) {
            let server = self.ensure_manage_server().map_err(mcp_err)?;
            unlocked_during_call =
                ensure_bastion_unlocked(&server, &peer, "brokre_exec_elevated").await?;
        }
        let gate = BastionGateInfo::for_exec("ssh", &[req.alias.clone()], unlocked_during_call);
        let mode = crate::runtime::elevated::ElevatedMode::parse(&req.mode).map_err(mcp_err)?;
        let policy = SessionPolicy::parse(&req.session).map_err(mcp_err)?;

        if req.alias.contains(crate::bastion::route::ROUTE_SEP) {
            let route = crate::bastion::route::parse_route(&req.alias)
                .map_err(mcp_err)?
                .ok_or_else(|| McpError::internal_error("invalid bastion route", None))?;
            let trailing = crate::runtime::elevated::build_ssh_argv(
                &route.inner,
                mode,
                &req.command,
                req.user.as_deref(),
            )
            .map_err(mcp_err)?;
            let args =
                crate::bastion::route::build_routed_local_argv("ssh", &route, &trailing[1..]);
            return run_brokre_cli(
                "ssh",
                &args,
                &with_extra_env(
                    &source_env,
                    &[("BROKRE_MCP_ELEVATED", mode.mcp_env_value())],
                ),
                gate,
            )
            .await;
        }

        let key = SessionKey::new(&req.alias, mode, req.user.as_deref());

        if mcp_session_enabled() {
            let cmd = if policy == SessionPolicy::Close {
                None
            } else {
                Some(req.command.clone())
            };
            return run_elevated_pool(self.sessions.clone(), key, cmd, policy, gate).await;
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
            &with_extra_env(
                &source_env,
                &[("BROKRE_MCP_ELEVATED", mode.mcp_env_value())],
            ),
            gate,
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
            bastion: None,
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
            .with_protocol_version(ProtocolVersion::V_2025_06_18)
            .with_instructions(SERVER_INSTRUCTIONS.to_string())
    }
}

fn mcp_err(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

fn text_json_result(body: &serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(body).unwrap_or_else(|_| body.to_string()),
    )])
}

fn mcp_source_env(peer: &Peer<rmcp::RoleServer>, tool: &str) -> Vec<(String, String)> {
    let mut env = vec![
        ("BROKRE_MCP_TOOL".to_string(), tool.to_string()),
        ("BROKRE_MCP_CLIENT".to_string(), "MCP client".to_string()),
    ];
    if let Some(info) = peer.peer_info() {
        let impl_ = &info.client_info;
        let client = impl_
            .title
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(impl_.name.as_str());
        env[1].1 = client.to_string();
        if !impl_.version.is_empty() {
            env.push((
                "BROKRE_MCP_CLIENT_VERSION".to_string(),
                impl_.version.clone(),
            ));
        }
    }
    env
}

fn with_extra_env(base: &[(String, String)], extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = base.to_vec();
    env.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );
    env
}

async fn run_brokre_cli(
    binary: &str,
    args: &[String],
    extra_env: &[(String, String)],
    gate: BastionGateInfo,
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
        "bastion_gate": gate,
    });
    Ok(text_json_result(&body))
}

async fn run_elevated_pool(
    sessions: Arc<Mutex<ElevatedSessionPool>>,
    key: SessionKey,
    command: Option<String>,
    policy: SessionPolicy,
    gate: BastionGateInfo,
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
    Ok(session_result_to_call_tool(result, gate))
}

fn session_result_to_call_tool(r: RunResult, gate: BastionGateInfo) -> CallToolResult {
    let body = serde_json::json!({
        "exit_code": r.exit_code,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "session_reused": r.session_reused,
        "session_idle_expires_at": r.idle_expires_at,
        "bastion_gate": gate,
    });
    text_json_result(&body)
}

pub async fn run_mcp_server() -> std::result::Result<(), BrokreError> {
    // Gate fallback paths (discover/transport) use browser auth, not TTY.
    std::env::set_var("BROKRE_MCP", "1");
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
