use crate::audit::logger::{append, exec_audit_source, redact_args, AuditEvent};
use crate::bastion::gate::prepare_outbound_gate_for_exec;
use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::{auto_forwards_path, run_dir};
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::model::SecretRecord;
use crate::vault::store::VaultStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DEFAULT_IDLE_SECS: u64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoForwardSpec {
    pub local: String,
    pub remote: String,
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
}

fn default_idle_secs() -> u64 {
    DEFAULT_IDLE_SECS
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct AutoForwardFile {
    #[serde(flatten)]
    aliases: BTreeMap<String, AutoForwardSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForwardState {
    name: String,
    alias: String,
    local: Endpoint,
    remote: Endpoint,
    target: String,
    control_path: String,
    started_at: String,
    idle_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    fn socket_addr(&self) -> Result<SocketAddr> {
        let ip = match self.host.as_str() {
            "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "::1" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            other => {
                return Err(BrokreError::Runtime(format!(
                    "cannot probe non-loopback endpoint: {other}"
                )))
            }
        };
        Ok(SocketAddr::new(ip, self.port))
    }

    fn local_forward_bind(&self) -> String {
        if self.host == "::1" {
            "[::1]".into()
        } else {
            self.host.clone()
        }
    }

    fn remote_forward_host(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    fn display(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug)]
struct StartOptions {
    alias: String,
    local: Endpoint,
    remote: Endpoint,
    idle_secs: u64,
}

#[derive(Debug, Serialize)]
struct StatusRow {
    name: String,
    alias: String,
    local: String,
    remote: String,
    active: bool,
    port_open: bool,
    mux_alive: bool,
    started_at: String,
}

/// Explicit opt-in: true only when `BROKRE_AUTO_FORWARD=1|true`.
pub fn auto_forward_enabled() -> bool {
    std::env::var("BROKRE_AUTO_FORWARD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Whether `exec_saved` should auto-ensure a configured local forward for this invocation.
pub fn should_auto_ensure_on_exec(profile: &str) -> bool {
    if !auto_forward_enabled() {
        return false;
    }
    let base = profile.rsplit('/').next().unwrap_or(profile);
    if base != "ssh" {
        return false;
    }
    if std::env::var_os("BROKRE_ROUTED_INNER").is_some()
        || std::env::var_os("BROKRE_TUNNEL_AGENT_INNER").is_some()
    {
        return false;
    }
    true
}

/// Idempotently ensure configured local forwards before `brokre ssh <alias> …`.
pub fn ensure_auto_for_ssh_record(rec: &SecretRecord) -> Result<()> {
    if !auto_forward_enabled() {
        return Ok(());
    }
    if rec.name.contains("::") {
        return Ok(());
    }
    let store = VaultStore::open()?;
    let Some(spec) = resolve_auto_forward_spec(&store, &rec.name, Some(rec)) else {
        return Ok(());
    };
    ensure_forward_spec(&store, &rec.name, &spec, true)
}

/// Resolved auto-forward spec for a saved alias (JSON file, then vault labels).
pub fn resolve_auto_forward_for_record(
    store: &VaultStore,
    rec: &SecretRecord,
) -> Option<AutoForwardSpec> {
    resolve_auto_forward_spec(store, &rec.name, Some(rec))
}

/// Loopback socket address for a forward spec (local bind must be loopback).
pub fn local_socket_addr_from_spec(spec: &AutoForwardSpec) -> Result<SocketAddr> {
    parse_endpoint(&spec.local, true)?.socket_addr()
}

/// Ensure a forward tunnel for an explicit spec (used by forward-relay).
pub fn ensure_forward_for_alias(
    store: &VaultStore,
    alias: &str,
    spec: &AutoForwardSpec,
    quiet: bool,
) -> Result<()> {
    ensure_forward_spec(store, alias, spec, quiet)
}

/// Persist auto-forward spec for an alias (`~/.brokre/auto_forwards.json`).
pub fn persist_auto_forward_alias(alias: &str, spec: &AutoForwardSpec) -> Result<()> {
    register_auto_forward(alias, spec)
}

/// Default loopback forward when auto-detecting JSON-RPC relay (override via `BROKRE_AUTO_FORWARD_PORT`).
pub fn default_implicit_forward_spec() -> AutoForwardSpec {
    let port = std::env::var("BROKRE_AUTO_FORWARD_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(19034);
    let ep = format!("127.0.0.1:{port}");
    AutoForwardSpec {
        local: ep.clone(),
        remote: ep,
        idle_secs: DEFAULT_IDLE_SECS,
    }
}

/// True when argv establishes a background forward (`-N` + `-L`, no remote command).
pub fn is_forward_only_ssh_argv(argv: &[String], trailing: &[String]) -> bool {
    trailing.is_empty()
        && argv.iter().any(|a| a == "-N")
        && local_forward_bind_from_argv(argv).is_some()
}

/// Handle `brokre ssh -N [-f] -L bind:host:port alias` using vault injection + state tracking.
pub fn exec_forward_only_ssh(rec: &SecretRecord, argv: &[String]) -> Result<()> {
    let bind = local_forward_bind_from_argv(argv)
        .ok_or_else(|| BrokreError::Cli("forward-only ssh requires -L bind:host:port".into()))?;
    let (local, remote) = parse_local_forward_bind(&bind)?;
    let spec = AutoForwardSpec {
        local: local.display(),
        remote: remote.display(),
        idle_secs: DEFAULT_IDLE_SECS,
    };
    register_auto_forward(&rec.name, &spec)?;
    let store = VaultStore::open()?;
    ensure_forward_spec(&store, &rec.name, &spec, false)?;
    Ok(())
}

pub fn run_cli(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        return Err(usage());
    }
    match args[0].as_str() {
        "list" => run_list(parse_json_flag(&args[1..])?),
        "status" => {
            let (name, json) = parse_name_json(&args[1..])?;
            run_status(name, json)
        }
        "stop" => {
            let (name, all, json) = parse_stop(&args[1..])?;
            run_stop(name, all, json)
        }
        "start" => run_start(parse_start(&args[1..])?),
        _ => run_start(parse_start(&args)?),
    }
}

fn usage() -> BrokreError {
    BrokreError::Cli(
        "usage: brokre tunnel forward <alias> --local 127.0.0.1:19034 --remote 127.0.0.1:19034\n       brokre tunnel forward list [--json]\n       brokre tunnel forward status [--name NAME] [--json]\n       brokre tunnel forward stop (--name NAME | --all) [--json]"
            .into(),
    )
}

fn parse_start(args: &[String]) -> Result<StartOptions> {
    if args.is_empty() {
        return Err(usage());
    }
    let alias = args[0].clone();
    if alias == "list" || alias == "status" || alias == "stop" || alias == "start" {
        return Err(usage());
    }

    let mut local = None;
    let mut remote = None;
    let mut idle_secs = DEFAULT_IDLE_SECS;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--local" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                local = Some(parse_endpoint(value, true)?);
            }
            "--remote" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                remote = Some(parse_endpoint(value, false)?);
            }
            "--foreground" => {
                return Err(BrokreError::Cli(
                    "--foreground is not supported yet; use the default background mode".into(),
                ))
            }
            "--idle-secs" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                idle_secs = value.parse::<u64>().map_err(|_| {
                    BrokreError::Cli("--idle-secs must be a positive integer".into())
                })?;
                if idle_secs == 0 {
                    return Err(BrokreError::Cli(
                        "--idle-secs must be greater than 0".into(),
                    ));
                }
            }
            other => return Err(BrokreError::Cli(format!("unknown forward option: {other}"))),
        }
        i += 1;
    }

    Ok(StartOptions {
        alias,
        local: local.ok_or_else(usage)?,
        remote: remote.ok_or_else(usage)?,
        idle_secs,
    })
}

fn parse_endpoint(input: &str, loopback_only: bool) -> Result<Endpoint> {
    let (host, port_s) = if loopback_only && input.chars().all(|c| c.is_ascii_digit()) {
        ("127.0.0.1".to_string(), input.to_string())
    } else if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest
            .split_once("]:")
            .ok_or_else(|| BrokreError::Cli(format!("invalid endpoint: {input}")))?;
        (host.to_string(), tail.to_string())
    } else {
        let (host, port) = input
            .rsplit_once(':')
            .ok_or_else(|| BrokreError::Cli(format!("invalid endpoint: {input}")))?;
        (host.to_string(), port.to_string())
    };
    let port = port_s
        .parse::<u16>()
        .map_err(|_| BrokreError::Cli(format!("invalid port in endpoint: {input}")))?;
    if port == 0 {
        return Err(BrokreError::Cli(format!(
            "invalid port in endpoint: {input}"
        )));
    }
    if loopback_only && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return Err(BrokreError::PolicyDenied);
    }
    Ok(Endpoint { host, port })
}

fn parse_json_flag(args: &[String]) -> Result<bool> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => return Err(BrokreError::Cli(format!("unknown option: {other}"))),
        }
    }
    Ok(json)
}

fn parse_name_json(args: &[String]) -> Result<(Option<String>, bool)> {
    let mut name = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--name" => {
                i += 1;
                name = Some(args.get(i).ok_or_else(usage)?.clone());
            }
            other => return Err(BrokreError::Cli(format!("unknown option: {other}"))),
        }
        i += 1;
    }
    Ok((name, json))
}

fn parse_stop(args: &[String]) -> Result<(Option<String>, bool, bool)> {
    let mut name = None;
    let mut all = false;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--all" => all = true,
            "--json" => json = true,
            "--name" => {
                i += 1;
                name = Some(args.get(i).ok_or_else(usage)?.clone());
            }
            other => return Err(BrokreError::Cli(format!("unknown option: {other}"))),
        }
        i += 1;
    }
    if !all && name.is_none() {
        return Err(BrokreError::Cli(
            "forward stop requires --name NAME or --all".into(),
        ));
    }
    Ok((name, all, json))
}

fn load_auto_forwards() -> Result<AutoForwardFile> {
    let path = auto_forwards_path();
    if !path.exists() {
        return Ok(AutoForwardFile::default());
    }
    let bytes = fs::read(&path).map_err(BrokreError::Io)?;
    if bytes.is_empty() {
        return Ok(AutoForwardFile::default());
    }
    serde_json::from_slice(&bytes).map_err(|e| BrokreError::Runtime(e.to_string()))
}

fn save_auto_forwards(file: &AutoForwardFile) -> Result<()> {
    let path = auto_forwards_path();
    let tmp = path.with_extension("json.tmp");
    {
        let mut out = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(BrokreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        let body =
            serde_json::to_vec_pretty(file).map_err(|e| BrokreError::Runtime(e.to_string()))?;
        out.write_all(&body).map_err(BrokreError::Io)?;
        out.sync_all().map_err(BrokreError::Io)?;
    }
    fs::rename(tmp, path).map_err(BrokreError::Io)
}

fn register_auto_forward(alias: &str, spec: &AutoForwardSpec) -> Result<()> {
    let mut file = load_auto_forwards()?;
    file.aliases.insert(alias.to_string(), spec.clone());
    save_auto_forwards(&file)
}

fn resolve_auto_forward_spec(
    store: &VaultStore,
    alias: &str,
    rec_hint: Option<&SecretRecord>,
) -> Option<AutoForwardSpec> {
    if let Ok(file) = load_auto_forwards() {
        if let Some(spec) = file.aliases.get(alias) {
            return Some(spec.clone());
        }
    }
    rec_hint
        .and_then(auto_forward_spec_from_labels)
        .or_else(|| {
            resolve_ssh_record(store, alias)
                .ok()
                .and_then(|rec| auto_forward_spec_from_labels(&rec))
        })
}

fn auto_forward_spec_from_labels(rec: &SecretRecord) -> Option<AutoForwardSpec> {
    let mut local = None;
    let mut remote = None;
    for label in &rec.labels {
        if let Some(v) = label.strip_prefix("auto-forward=") {
            return parse_auto_forward_label_value(v).ok();
        }
        if let Some(v) = label.strip_prefix("forward-local=") {
            local = Some(v.to_string());
        }
        if let Some(v) = label.strip_prefix("forward-remote=") {
            remote = Some(v.to_string());
        }
    }
    match (local, remote) {
        (Some(l), Some(r)) => Some(AutoForwardSpec {
            local: l,
            remote: r,
            idle_secs: DEFAULT_IDLE_SECS,
        }),
        _ => None,
    }
}

fn parse_auto_forward_label_value(value: &str) -> Result<AutoForwardSpec> {
    if value.chars().all(|c| c.is_ascii_digit()) {
        let port = value
            .parse::<u16>()
            .map_err(|_| BrokreError::Runtime("invalid auto-forward port".into()))?;
        let ep = format!("127.0.0.1:{port}");
        return validated_auto_forward_spec(&ep, &ep, DEFAULT_IDLE_SECS);
    }
    if let Some((l, r)) = value.split_once("->") {
        return validated_auto_forward_spec(l.trim(), r.trim(), DEFAULT_IDLE_SECS);
    }
    validated_auto_forward_spec(value, value, DEFAULT_IDLE_SECS)
}

fn validated_auto_forward_spec(
    local: &str,
    remote: &str,
    idle_secs: u64,
) -> Result<AutoForwardSpec> {
    parse_endpoint(local, true)?;
    parse_endpoint(remote, false)?;
    Ok(AutoForwardSpec {
        local: local.into(),
        remote: remote.into(),
        idle_secs,
    })
}

fn ensure_forward_spec(
    store: &VaultStore,
    alias: &str,
    spec: &AutoForwardSpec,
    quiet: bool,
) -> Result<()> {
    let local = parse_endpoint(&spec.local, true)?;
    let remote = parse_endpoint(&spec.remote, false)?;
    let rec = resolve_ssh_record(store, alias)?;
    let target = crate::runtime::ssh_identity::openssh_connection_target(&rec.saved_args)
        .ok_or_else(|| BrokreError::Runtime("saved SSH record has no connection target".into()))?;
    let name = forward_name(alias, &local);
    let control_path = forward_control_path(alias, &local).to_string_lossy().into();
    let mut state = ForwardState {
        name,
        alias: alias.to_string(),
        local,
        remote,
        target,
        control_path,
        started_at: Utc::now().to_rfc3339(),
        idle_secs: spec.idle_secs,
    };

    prune_stale_forward_state(&state);
    if status_for(&state).active {
        return Ok(());
    }

    let started = Instant::now();
    let result = run_ssh_forward(&rec, &state, false)?;
    let dur = started.elapsed().as_millis() as u64;
    audit_forward(
        "tunnel_forward_start",
        &state,
        Some(result.exit_code),
        Some(dur),
    );
    if result.exit_code != 0 {
        return Err(BrokreError::Runtime(format!(
            "ssh forward failed with exit {}",
            result.exit_code
        )));
    }

    state.started_at = Utc::now().to_rfc3339();
    let mut states = load_states()?;
    states.retain(|s| s.name != state.name);
    states.push(state.clone());
    save_states(&states)?;
    if !quiet {
        println!(
            "Forward active: {} -> {} ({})",
            state.local.display(),
            state.remote.display(),
            state.name
        );
    }
    Ok(())
}

pub fn local_forward_bind_from_argv(argv: &[String]) -> Option<String> {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "-L" {
            return argv.get(i + 1).cloned();
        }
        if argv[i].starts_with("-L") && argv[i].len() > 2 {
            return Some(argv[i]["-L".len()..].to_string());
        }
        i += 1;
    }
    None
}

fn parse_local_forward_bind(spec: &str) -> Result<(Endpoint, Endpoint)> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => {
            let local = parse_endpoint(parts[0], true)?;
            let remote = Endpoint {
                host: parts[1].into(),
                port: parts[2]
                    .parse()
                    .map_err(|_| BrokreError::Cli(format!("invalid forward port: {spec}")))?,
            };
            Ok((local, remote))
        }
        4 => {
            let local = parse_endpoint(&format!("{}:{}", parts[0], parts[1]), true)?;
            let remote = Endpoint {
                host: parts[2].into(),
                port: parts[3]
                    .parse()
                    .map_err(|_| BrokreError::Cli(format!("invalid forward port: {spec}")))?,
            };
            Ok((local, remote))
        }
        _ => Err(BrokreError::Cli(format!("invalid -L forward spec: {spec}"))),
    }
}

fn run_start(opts: StartOptions) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = opts;
        Err(BrokreError::Runtime(
            "brokre tunnel forward requires Unix OpenSSH support".into(),
        ))
    }
    #[cfg(unix)]
    {
        prepare_outbound_gate_for_exec("ssh", std::slice::from_ref(&opts.alias))?;
        let spec = AutoForwardSpec {
            local: opts.local.display(),
            remote: opts.remote.display(),
            idle_secs: opts.idle_secs,
        };
        register_auto_forward(&opts.alias, &spec)?;
        let store = VaultStore::open()?;
        ensure_forward_spec(&store, &opts.alias, &spec, false)
    }
}

#[cfg(unix)]
fn run_ssh_forward(
    rec: &SecretRecord,
    state: &ForwardState,
    foreground: bool,
) -> Result<crate::runtime::pty::PtyRunResult> {
    let mut argv = forward_argv(rec, state, foreground)?;
    let _key_guard = match crate::runtime::ssh_identity::materialize_forward_identity(rec)? {
        Some(guard) => {
            crate::runtime::ssh_identity::insert_identity_arg_for_profile(
                "ssh",
                &mut argv,
                &guard.path,
            );
            Some(guard)
        }
        None => None,
    };
    crate::runtime::pipe_exec::run("ssh", &argv, rec.id)
}

#[cfg(unix)]
fn forward_argv(rec: &SecretRecord, state: &ForwardState, foreground: bool) -> Result<Vec<String>> {
    let target_idx = crate::runtime::ssh_identity::openssh_connection_target_index_for_profile(
        "ssh",
        &rec.saved_args,
    );
    if target_idx >= rec.saved_args.len() {
        return Err(BrokreError::Runtime(
            "saved SSH record has no connection target".into(),
        ));
    }

    let mut argv = rec.saved_args[..=target_idx].to_vec();
    let pos =
        crate::runtime::ssh_identity::openssh_connection_target_index_for_profile("ssh", &argv);
    let mut forward_flags = vec![
        "-N".to_string(),
        "-L".to_string(),
        format!(
            "{}:{}:{}:{}",
            state.local.local_forward_bind(),
            state.local.port,
            state.remote.remote_forward_host(),
            state.remote.port
        ),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ControlMaster=yes".to_string(),
        "-o".to_string(),
        format!("ControlPath={}", state.control_path),
        "-o".to_string(),
        format!("ControlPersist={}", state.idle_secs),
    ];
    if !foreground {
        forward_flags.insert(1, "-f".to_string());
    }
    for (offset, flag) in forward_flags.into_iter().enumerate() {
        argv.insert(pos + offset, flag);
    }
    Ok(argv)
}

fn resolve_ssh_record(store: &VaultStore, alias: &str) -> Result<SecretRecord> {
    if alias.contains("::") {
        return Err(BrokreError::Cli(
            "tunnel forward expects a saved SSH hop alias; for routed targets, use the bastion alias and set --remote to the inner host:port"
                .into(),
        ));
    }
    if let Some(rec) = store.get("ssh", alias)? {
        return Ok(rec);
    }
    let matches: Vec<_> = store
        .list()?
        .into_iter()
        .filter(|r| r.profile == "ssh" && r.host_alias.as_deref() == Some(alias))
        .collect();
    match matches.len() {
        1 => Ok(matches.into_iter().next().unwrap()),
        0 => Err(BrokreError::Vault(format!("no saved SSH alias: {alias}"))),
        _ => Err(BrokreError::Vault(format!(
            "multiple SSH records match host alias: {alias}"
        ))),
    }
}

fn run_list(json: bool) -> Result<()> {
    let mut states = load_states()?;
    let rows = status_rows(&states);
    states.retain(|s| rows.iter().any(|r| r.name == s.name && r.active));
    save_states(&states)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(|e| BrokreError::Runtime(e.to_string()))?
        );
    } else if rows.is_empty() {
        println!("No forwards.");
    } else {
        for row in rows {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                row.name,
                row.alias,
                row.local,
                row.remote,
                if row.active { "active" } else { "stale" }
            );
        }
    }
    Ok(())
}

fn run_status(name: Option<String>, json: bool) -> Result<()> {
    let rows: Vec<_> = status_rows(&load_states()?)
        .into_iter()
        .filter(|r| name.as_ref().is_none_or(|n| &r.name == n))
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(|e| BrokreError::Runtime(e.to_string()))?
        );
    } else if rows.is_empty() {
        println!("No matching forwards.");
    } else {
        for row in rows {
            println!("Name: {}", row.name);
            println!("Alias: {}", row.alias);
            println!("Local: {}", row.local);
            println!("Remote: {}", row.remote);
            println!("Active: {}", row.active);
            println!("Port open: {}", row.port_open);
            println!("Mux alive: {}", row.mux_alive);
        }
    }
    Ok(())
}

fn run_stop(name: Option<String>, all: bool, json: bool) -> Result<()> {
    let states = load_states()?;
    let selected: Vec<_> = states
        .iter()
        .filter(|s| all || name.as_ref().is_some_and(|n| &s.name == n))
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err(BrokreError::Runtime("no matching forwards".into()));
    }

    let mut stopped = Vec::new();
    for state in &selected {
        stop_state(state);
        audit_forward("tunnel_forward_stop", state, Some(0), None);
        stopped.push(state.name.clone());
    }
    let remaining: Vec<_> = states
        .into_iter()
        .filter(|s| !stopped.iter().any(|name| name == &s.name))
        .collect();
    save_states(&remaining)?;
    if json {
        println!("{}", serde_json::json!({ "stopped": stopped }));
    } else {
        for name in stopped {
            println!("Stopped: {name}");
        }
    }
    Ok(())
}

fn status_rows(states: &[ForwardState]) -> Vec<StatusRow> {
    states
        .iter()
        .map(|state| {
            let (port_open, mux_alive) = status_bits(state);
            StatusRow {
                name: state.name.clone(),
                alias: state.alias.clone(),
                local: state.local.display(),
                remote: state.remote.display(),
                active: port_open || mux_alive,
                port_open,
                mux_alive,
                started_at: state.started_at.clone(),
            }
        })
        .collect()
}

fn status_for(state: &ForwardState) -> StatusRow {
    let (port_open, mux_alive) = status_bits(state);
    StatusRow {
        name: state.name.clone(),
        alias: state.alias.clone(),
        local: state.local.display(),
        remote: state.remote.display(),
        active: port_open || mux_alive,
        port_open,
        mux_alive,
        started_at: state.started_at.clone(),
    }
}

fn status_bits(state: &ForwardState) -> (bool, bool) {
    let port_open = state
        .local
        .socket_addr()
        .ok()
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(150)).ok())
        .is_some();
    let mux_alive = mux_alive(state).unwrap_or(false);
    (port_open, mux_alive)
}

fn stop_state(state: &ForwardState) {
    let _ = mux_op(state, "exit");
    let _ = fs::remove_file(&state.control_path);
}

fn prune_stale_forward_state(state: &ForwardState) {
    if status_for(state).active {
        return;
    }
    stop_state(state);
    if let Ok(mut states) = load_states() {
        let before = states.len();
        states.retain(|s| s.name != state.name);
        if states.len() != before {
            let _ = save_states(&states);
        }
    }
}

fn mux_alive(state: &ForwardState) -> Result<bool> {
    Ok(mux_op(state, "check")
        .map(|status| status.success())
        .unwrap_or(false))
}

fn mux_op(state: &ForwardState, op: &str) -> Result<std::process::ExitStatus> {
    let bin =
        which::which("ssh").map_err(|_| BrokreError::Runtime("ssh: command not found".into()))?;
    Command::new(bin)
        .arg("-O")
        .arg(op)
        .arg("-o")
        .arg(format!("ControlPath={}", state.control_path))
        .arg(&state.target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(BrokreError::Io)
}

fn audit_forward(action: &str, state: &ForwardState, exit: Option<i32>, dur_ms: Option<u64>) {
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: "ssh".into(),
        name: state.alias.clone(),
        exit,
        dur_ms,
        args_redacted: redact_args(&[
            state.alias.clone(),
            "--local".into(),
            state.local.display(),
            "--remote".into(),
            state.remote.display(),
        ]),
        hardening: crate::security::hardening::last_hardening_report(),
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: Some("ssh-forward".into()),
        source: Some(exec_audit_source()),
        route: None,
        bastion: None,
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    if let Ok(key) = get_or_init_audit_hmac_key() {
        let _ = append(&mut ev, &key);
    }
}

fn state_path() -> PathBuf {
    run_dir().join("forwards.json")
}

fn load_states() -> Result<Vec<ForwardState>> {
    let path = state_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(BrokreError::Io)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&bytes).map_err(|e| BrokreError::Runtime(e.to_string()))
}

fn save_states(states: &[ForwardState]) -> Result<()> {
    let path = state_path();
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(BrokreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        let body =
            serde_json::to_vec_pretty(states).map_err(|e| BrokreError::Runtime(e.to_string()))?;
        file.write_all(&body).map_err(BrokreError::Io)?;
        file.sync_all().map_err(BrokreError::Io)?;
    }
    fs::rename(tmp, path).map_err(BrokreError::Io)
}

fn forward_name(alias: &str, local: &Endpoint) -> String {
    format!("{}@{}", sanitize(alias), sanitize(&local.display()))
}

fn forward_control_path(alias: &str, local: &Endpoint) -> PathBuf {
    run_dir().join(format!("forward-{}.sock", forward_name(alias, local)))
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_port_shortcut() {
        let ep = parse_endpoint("19034", true).unwrap();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 19034);
    }

    #[test]
    fn rejects_non_loopback_local_bind() {
        assert!(parse_endpoint("0.0.0.0:19034", true).is_err());
        assert!(parse_endpoint("198.51.100.10:19034", true).is_err());
    }

    #[test]
    fn parses_start_alias_form() {
        let args = vec![
            "dev-host".into(),
            "--local".into(),
            "127.0.0.1:19034".into(),
            "--remote".into(),
            "127.0.0.1:19034".into(),
        ];
        let opts = parse_start(&args).unwrap();
        assert_eq!(opts.alias, "dev-host");
        assert_eq!(opts.local.port, 19034);
        assert_eq!(opts.remote.port, 19034);
    }

    #[test]
    fn detects_forward_only_ssh_argv() {
        let argv = vec![
            "-N".into(),
            "-f".into(),
            "-L".into(),
            "127.0.0.1:19034:127.0.0.1:19034".into(),
            "dev-host".into(),
        ];
        assert!(is_forward_only_ssh_argv(&argv, &[]));
        assert!(!is_forward_only_ssh_argv(&argv, &["uptime".into()]));
    }

    #[test]
    fn parses_auto_forward_port_label() {
        let spec = parse_auto_forward_label_value("19034").unwrap();
        assert_eq!(spec.local, "127.0.0.1:19034");
        assert_eq!(spec.remote, "127.0.0.1:19034");
    }

    #[test]
    fn rejects_non_loopback_auto_forward_label() {
        assert!(parse_auto_forward_label_value("0.0.0.0:19034").is_err());
        assert!(parse_auto_forward_label_value("0.0.0.0:19034->127.0.0.1:19034").is_err());
    }

    #[test]
    fn should_auto_ensure_only_for_top_level_ssh() {
        assert!(!should_auto_ensure_on_exec("scp"));
        assert!(!should_auto_ensure_on_exec("sftp"));
        assert!(!should_auto_ensure_on_exec("ssh/scp"));
        std::env::set_var("BROKRE_AUTO_FORWARD", "0");
        assert!(!should_auto_ensure_on_exec("ssh"));
        std::env::remove_var("BROKRE_AUTO_FORWARD");
        assert!(!should_auto_ensure_on_exec("ssh"));
        std::env::set_var("BROKRE_AUTO_FORWARD", "1");
        std::env::set_var("BROKRE_ROUTED_INNER", "1");
        assert!(!should_auto_ensure_on_exec("ssh"));
        std::env::remove_var("BROKRE_ROUTED_INNER");
        assert!(should_auto_ensure_on_exec("ssh"));
        std::env::remove_var("BROKRE_AUTO_FORWARD");
    }
}
