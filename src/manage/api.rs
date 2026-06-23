use crate::audit::logger::{append, AuditEvent};
use crate::audit::query::{list, verify_with_stats, AuditQuery};
use crate::manage::auth::{extract_bearer, token_matches};
use crate::manage::onboard::mark_onboard_complete;
use crate::manage::profiles::{detect_profile_groups, profile_available_for_create};
use crate::runtime::ssh_identity::{
    auth_methods_from_meta, build_ssh_field_meta, build_ssh_secret_fields,
};
use crate::security::secret::SecretString;
use crate::utils::errors::BrokreError;
use crate::utils::paths::audit_path;
use crate::vault::keychain::get_or_init_audit_hmac_key;
use crate::vault::service::{
    build_saved_args, command_template, create_credential, create_credential_with_fields,
    rotate_password, verify_reveal_auth,
};
use crate::vault::store::VaultStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tiny_http::{Header, Request, Response, StatusCode};
use uuid::Uuid;

const INDEX_HTML: &str = include_str!("static/index.html");
const BASTION_AUTH_HTML: &str = include_str!("static/bastion_auth.html");

pub struct ManageState {
    pub token: String,
    pub onboard: bool,
    pub last_activity: Mutex<Instant>,
    pub session_expired: AtomicBool,
}

impl ManageState {
    pub fn touch(&self) {
        if let Ok(mut g) = self.last_activity.lock() {
            *g = Instant::now();
        }
    }

    pub fn idle_secs(&self) -> u64 {
        self.last_activity
            .lock()
            .map(|g| g.elapsed().as_secs())
            .unwrap_or(0)
    }
}

fn audit_manage(action: &str, profile: &str, name: &str) {
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: profile.to_string(),
        name: name.to_string(),
        exit: None,
        dur_ms: None,
        args_redacted: vec![],
        hardening: None,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
        source: Some("manage".into()),
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

fn audit_bastion_manage(action: &str, name: &str) {
    let mut ev = AuditEvent {
        ts: Utc::now().to_rfc3339(),
        sid: Uuid::new_v4().to_string(),
        action: action.into(),
        profile: "bastion".into(),
        name: name.into(),
        exit: None,
        dur_ms: None,
        args_redacted: vec![],
        hardening: None,
        injector_pid: None,
        injector_dur_ms: None,
        injector_outcome: None,
        source: Some("manage".into()),
        route: None,
        bastion: Some(name.into()),
        hmac_version: None,
        prev_hmac: None,
        hmac: None,
    };
    if let Ok(key) = get_or_init_audit_hmac_key() {
        let _ = append(&mut ev, &key);
    }
}

type HttpResponse = Response<std::io::Cursor<Vec<u8>>>;

fn json_response(status: StatusCode, body: &str) -> HttpResponse {
    Response::from_string(body)
        .with_status_code(status)
        .with_header(
            Header::from_bytes(
                &b"Content-Type"[..],
                &b"application/json; charset=utf-8"[..],
            )
            .unwrap(),
        )
}

fn error_response(status: StatusCode, msg: &str) -> HttpResponse {
    let body = serde_json::json!({ "error": msg }).to_string();
    json_response(status, &body)
}

fn empty_response(status: StatusCode) -> HttpResponse {
    Response::from_data(Vec::new()).with_status_code(status)
}

fn unauthorized() -> HttpResponse {
    error_response(StatusCode(401), "unauthorized")
}

fn check_auth(state: &ManageState, req: &Request) -> bool {
    if state.session_expired.load(Ordering::Acquire) {
        return false;
    }
    token_matches(&state.token, session_token_from_request(req).as_deref())
}

/// Bastion unlock/status: valid session token only — survives manage idle expiry.
fn check_bastion_gate_auth(state: &ManageState, req: &Request) -> bool {
    token_matches(&state.token, session_token_from_request(req).as_deref())
}

fn session_token_from_request(req: &Request) -> Option<String> {
    let bearer = extract_bearer(req.headers().iter().find_map(|h| {
        if h.field.equiv("Authorization") {
            Some(h.value.as_str())
        } else {
            None
        }
    }));
    if bearer.is_some() {
        return bearer.map(str::to_string);
    }
    req.url().split('?').nth(1).and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == "t" {
                Some(v.to_string())
            } else {
                None
            }
        })
    })
}

fn check_write_auth(state: &ManageState, req: &Request) -> bool {
    if state.session_expired.load(Ordering::Acquire) {
        return false;
    }
    let bearer = extract_bearer(req.headers().iter().find_map(|h| {
        if h.field.equiv("Authorization") {
            Some(h.value.as_str())
        } else {
            None
        }
    }));
    token_matches(&state.token, bearer)
}

fn read_body(req: &mut Request) -> Result<String, BrokreError> {
    let mut body = String::new();
    req.as_reader()
        .read_to_string(&mut body)
        .map_err(BrokreError::Io)?;
    Ok(body)
}

#[derive(Serialize)]
struct CredentialMeta {
    id: Uuid,
    profile: String,
    name: String,
    labels: Vec<String>,
    host_alias: Option<String>,
    saved_args: Vec<String>,
    command: String,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
    last_used_at: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    auth_methods: Vec<String>,
}

fn list_credentials() -> Result<String, BrokreError> {
    let store = VaultStore::open()?;
    let records = store.list()?;
    let out: Vec<CredentialMeta> = records
        .into_iter()
        .map(|r| CredentialMeta {
            id: r.id,
            profile: r.profile.clone(),
            name: r.name.clone(),
            labels: r.labels.clone(),
            host_alias: r.host_alias.clone(),
            saved_args: r.saved_args.clone(),
            command: command_template(&r.profile, &r.name, &r.saved_args),
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_used_at: r.last_used_at,
            auth_methods: r
                .fields_meta
                .as_ref()
                .map(|m| auth_methods_from_meta(m))
                .unwrap_or_else(|| vec!["password".into()]),
        })
        .collect();
    serde_json::to_string(&out).map_err(|e| BrokreError::Cli(e.to_string()))
}

#[derive(Deserialize)]
struct CreateBody {
    profile: String,
    name: String,
    host: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    extra_args: Vec<String>,
    /// SSH / SCP / SFTP port (omit or 22 for default).
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    auth_type: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    key_passphrase: Option<String>,
    #[serde(default)]
    reveal_passphrase: Option<String>,
}

fn is_ssh_profile(profile: &str) -> bool {
    matches!(profile, "ssh" | "scp" | "sftp")
}

#[derive(Deserialize)]
struct AuthBody {
    reveal_passphrase: String,
}

#[derive(Deserialize)]
struct RotateBody {
    new_password: String,
    reveal_passphrase: String,
}

#[derive(Deserialize)]
struct MetaBody {
    #[serde(default)]
    labels: Option<Vec<String>>,
    #[serde(default)]
    host_alias: Option<String>,
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn parse_query_params(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn audit_query_from_params(params: &std::collections::HashMap<String, String>) -> AuditQuery {
    let parse_usize = |key: &str, default: usize| -> usize {
        params
            .get(key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    };
    AuditQuery {
        profile: params.get("profile").cloned(),
        name: params.get("name").cloned(),
        action: params.get("action").cloned(),
        source: params.get("source").cloned(),
        bastion: params.get("bastion").cloned(),
        since: params.get("since").cloned(),
        until: params.get("until").cloned(),
        limit: parse_usize("limit", crate::audit::query::DEFAULT_LIMIT),
        offset: parse_usize("offset", 0),
        newest_first: true,
    }
}

/// Parse `/api/credentials/{profile}/{name}` or `.../{name}/password|meta`.
/// Only the first `/` separates profile from name so aliases may contain `/`.
fn parse_credential_path(path: &str) -> Option<(String, String, Option<&'static str>)> {
    let rest = path
        .strip_prefix("/api/credentials/")?
        .trim_end_matches('/');
    if rest.is_empty() {
        return None;
    }
    let (rest, suffix) = if let Some(r) = rest.strip_suffix("/password") {
        (r, Some("password"))
    } else if let Some(r) = rest.strip_suffix("/meta") {
        (r, Some("meta"))
    } else {
        (rest, None)
    };
    let slash = rest.find('/')?;
    let profile = percent_decode(&rest[..slash]);
    let name = percent_decode(&rest[slash + 1..]);
    if profile.is_empty() || name.is_empty() {
        return None;
    }
    Some((profile, name, suffix))
}

fn bastion_status_json() -> serde_json::Value {
    let key_set = crate::bastion::key::key_is_set();
    let unlocked = crate::bastion::session::is_unlocked();
    let strict_mode = crate::bastion::policy::strict_mode();
    let mut body = serde_json::json!({
        "key_set": key_set,
        "unlocked": unlocked,
        "strict_mode": strict_mode,
        "gate_mode": if strict_mode { "strict" } else { "default" },
    });
    if unlocked {
        if let Ok(Some(session)) = crate::bastion::session::load_session() {
            body["expires_at"] = serde_json::json!(session.expires_at);
            body["idle_expires_at"] = serde_json::json!(session.idle_expires_at);
        }
    }
    body
}

fn parse_bastion_sync_path(path: &str) -> Option<String> {
    let alias = path.strip_prefix("/api/bastion/sync/")?;
    if alias.is_empty() || alias.contains('/') {
        return None;
    }
    Some(percent_decode(alias))
}

fn handle_bastion_routes(
    state: &Arc<ManageState>,
    req: &mut Request,
    method: &tiny_http::Method,
    path: &str,
) -> Option<HttpResponse> {
    if *method == tiny_http::Method::Get && path == "/api/bastion" {
        return Some(match crate::bastion::registry::list_bastions() {
            Ok(bastions) => {
                let mut body = bastion_status_json();
                body["bastions"] = serde_json::to_value(bastions).unwrap_or(serde_json::json!([]));
                body["max_bastions"] = serde_json::json!(crate::bastion::registry::max_bastions());
                json_response(StatusCode(200), &body.to_string())
            }
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        });
    }

    if let Some(alias) = parse_bastion_sync_path(path) {
        if *method != tiny_http::Method::Get {
            return Some(error_response(StatusCode(405), "method not allowed"));
        }
        if crate::bastion::session::gate_required() && !crate::bastion::session::is_unlocked() {
            return Some(error_response(
                StatusCode(423),
                "bastion outbound access locked — unlock first",
            ));
        }
        return Some(
            match crate::bastion::transport::run_remote_list_json_probe(&alias) {
                Ok(stdout) => json_response(StatusCode(200), &stdout),
                Err(e) => error_response(StatusCode(400), &e.to_string()),
            },
        );
    }

    if *method == tiny_http::Method::Post && path == "/api/bastion/lock" {
        if !check_write_auth(state, req) {
            audit_bastion_manage("bastion/denied", "-");
            return Some(unauthorized());
        }
        return Some(match crate::bastion::session::clear_session() {
            Ok(()) => {
                audit_bastion_manage("bastion/lock", "-");
                empty_response(StatusCode(204))
            }
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        });
    }

    if *method == tiny_http::Method::Post && path == "/api/bastion/enable" {
        if !check_write_auth(state, req) {
            audit_bastion_manage("bastion/denied", "-");
            return Some(unauthorized());
        }
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        #[derive(Deserialize)]
        struct AliasBody {
            alias: String,
        }
        let parsed: AliasBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        if parsed.alias.trim().is_empty() {
            return Some(error_response(StatusCode(400), "alias is required"));
        }
        return Some(
            match crate::bastion::registry::enable_bastion(parsed.alias.trim()) {
                Ok(entry) => {
                    audit_bastion_manage("bastion/enable", &entry.alias);
                    match serde_json::to_string(&entry) {
                        Ok(resp) => json_response(StatusCode(201), &resp),
                        Err(e) => error_response(StatusCode(500), &e.to_string()),
                    }
                }
                Err(e) => error_response(StatusCode(400), &e.to_string()),
            },
        );
    }

    if *method == tiny_http::Method::Post && path == "/api/bastion/disable" {
        if !check_write_auth(state, req) {
            audit_bastion_manage("bastion/denied", "-");
            return Some(unauthorized());
        }
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        #[derive(Deserialize)]
        struct AliasBody {
            alias: String,
        }
        let parsed: AliasBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        if parsed.alias.trim().is_empty() {
            return Some(error_response(StatusCode(400), "alias is required"));
        }
        let alias = parsed.alias.trim();
        return Some(match crate::bastion::registry::disable_bastion(alias) {
            Ok(true) => {
                audit_bastion_manage("bastion/disable", alias);
                empty_response(StatusCode(204))
            }
            Ok(false) => error_response(StatusCode(404), "bastion not registered"),
            Err(e) => error_response(StatusCode(400), &e.to_string()),
        });
    }

    if *method == tiny_http::Method::Post && path == "/api/bastion/set-key" {
        if !check_write_auth(state, req) {
            audit_bastion_manage("bastion/denied", "-");
            return Some(unauthorized());
        }
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        #[derive(Deserialize)]
        struct SetKeyBody {
            passphrase: String,
            confirm: String,
        }
        let parsed: SetKeyBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        if parsed.passphrase.is_empty() {
            return Some(error_response(StatusCode(400), "passphrase is required"));
        }
        if parsed.passphrase != parsed.confirm {
            return Some(error_response(StatusCode(400), "passphrases do not match"));
        }
        let pass = SecretString::new(parsed.passphrase);
        return Some(match crate::bastion::key::set_bastion_key(&pass) {
            Ok(()) => {
                let _ = crate::bastion::session::clear_session();
                audit_bastion_manage("bastion/set-key", "-");
                json_response(StatusCode(200), r#"{"ok":true}"#)
            }
            Err(e) => error_response(StatusCode(400), &e.to_string()),
        });
    }

    if *method == tiny_http::Method::Post && path == "/api/bastion/strict-mode" {
        if !check_write_auth(state, req) {
            audit_bastion_manage("bastion/denied", "-");
            return Some(unauthorized());
        }
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        #[derive(Deserialize)]
        struct StrictBody {
            strict_mode: bool,
        }
        let parsed: StrictBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return Some(error_response(StatusCode(400), &e.to_string())),
        };
        return Some(
            match crate::bastion::policy::set_strict_mode(parsed.strict_mode) {
                Ok(()) => {
                    let action = if parsed.strict_mode {
                        "bastion/strict-on"
                    } else {
                        "bastion/strict-off"
                    };
                    audit_bastion_manage(action, "-");
                    json_response(
                        StatusCode(200),
                        &serde_json::json!({
                            "ok": true,
                            "strict_mode": parsed.strict_mode,
                            "gate_mode": if parsed.strict_mode { "strict" } else { "default" },
                        })
                        .to_string(),
                    )
                }
                Err(e) => error_response(StatusCode(500), &e.to_string()),
            },
        );
    }

    None
}

fn handle_bastion_unlock(req: &mut Request) -> HttpResponse {
    let body = match read_body(req) {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode(400), &e.to_string()),
    };
    #[derive(Deserialize)]
    struct UnlockBody {
        passphrase: String,
        #[serde(default)]
        elicitation_id: Option<String>,
    }
    let parsed: UnlockBody = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return error_response(StatusCode(400), &e.to_string()),
    };
    if !crate::bastion::key::key_is_set() {
        return error_response(StatusCode(400), "bastion key not configured");
    }
    let pass = SecretString::new(parsed.passphrase);
    match crate::bastion::key::verify_bastion_key(&pass) {
        Ok(true) => match crate::bastion::session::unlock_session() {
            Ok(session) => {
                audit_bastion_manage("bastion/unlock", "-");
                let resp = serde_json::json!({
                    "ok": true,
                    "expires_at": session.expires_at,
                    "idle_expires_at": session.idle_expires_at,
                    "elicitation_id": parsed.elicitation_id,
                });
                json_response(StatusCode(200), &resp.to_string())
            }
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        },
        Ok(false) => {
            audit_bastion_manage("bastion/denied", "-");
            error_response(StatusCode(401), "invalid bastion key")
        }
        Err(e) => error_response(StatusCode(500), &e.to_string()),
    }
}

pub fn handle_request(state: Arc<ManageState>, mut req: Request) {
    state.touch();
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (url, None),
    };

    let response = dispatch(state, &mut req, &method, &path, query.as_deref());
    let _ = req.respond(response);
}

fn dispatch(
    state: Arc<ManageState>,
    req: &mut Request,
    method: &tiny_http::Method,
    path: &str,
    query: Option<&str>,
) -> HttpResponse {
    // GET / allows token in query for initial HTML load.
    if *method == tiny_http::Method::Get && path == "/" {
        if !check_auth(&state, req) {
            return unauthorized();
        }
        return Response::from_string(INDEX_HTML)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
            )
            .with_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap())
            .with_header(
                Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap(),
            );
    }

    if *method == tiny_http::Method::Get && path == "/bastion-auth" {
        return Response::from_string(BASTION_AUTH_HTML)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
            )
            .with_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap())
            .with_header(
                Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap(),
            );
    }

    if *method == tiny_http::Method::Get && path == "/api/bastion/status" {
        if !check_bastion_gate_auth(&state, req) {
            return unauthorized();
        }
        let body = bastion_status_json().to_string();
        return json_response(StatusCode(200), &body);
    }

    if *method == tiny_http::Method::Post && path == "/api/bastion/unlock" {
        if !check_bastion_gate_auth(&state, req) {
            audit_bastion_manage("bastion/denied", "-");
            return unauthorized();
        }
        return handle_bastion_unlock(req);
    }

    if path.starts_with("/api/") && !check_auth(&state, req) {
        return unauthorized();
    }

    if *method == tiny_http::Method::Get && path == "/api/credentials" {
        match list_credentials() {
            Ok(body) => json_response(StatusCode(200), &body),
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        }
    } else if *method == tiny_http::Method::Get && path == "/api/config" {
        let body = serde_json::json!({
            "onboard": state.onboard,
            "idle_secs": state.idle_secs(),
            "idle_limit_secs": 900,
        })
        .to_string();
        json_response(StatusCode(200), &body)
    } else if *method == tiny_http::Method::Get && path == "/api/profiles" {
        let groups = detect_profile_groups();
        match serde_json::to_string(&groups) {
            Ok(body) => json_response(StatusCode(200), &body),
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        }
    } else if *method == tiny_http::Method::Post && path == "/api/credentials" {
        if !check_write_auth(&state, req) {
            audit_manage("manage/denied", "-", "-");
            return unauthorized();
        }
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        let parsed: CreateBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        if parsed.name.trim().is_empty() || parsed.host.trim().is_empty() {
            return error_response(StatusCode(400), "name and host are required");
        }
        if parsed.port == Some(0) {
            return error_response(StatusCode(400), "port must be 1-65535");
        }
        if let Err(msg) = crate::manage::profiles::validate_user_for_profile(
            &parsed.profile,
            parsed.user.as_deref(),
        ) {
            return error_response(StatusCode(400), msg);
        }
        if !profile_available_for_create(&parsed.profile) {
            audit_manage("manage/denied", &parsed.profile, &parsed.name);
            return error_response(
                StatusCode(400),
                "CLI not installed on this system (not on PATH)",
            );
        }
        let (host, host_port) = crate::vault::service::parse_host_port(parsed.host.trim());
        let port = parsed.port.or(host_port);
        let args = build_saved_args(
            &parsed.profile,
            &host,
            parsed.user.as_deref(),
            &parsed.extra_args,
            port,
        );
        let reveal = parsed
            .reveal_passphrase
            .filter(|s| !s.is_empty())
            .map(SecretString::new);
        let reveal_ref = reveal.as_ref();
        let store = match VaultStore::open() {
            Ok(s) => s,
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        let create_result = if is_ssh_profile(&parsed.profile) {
            let auth_type = parsed.auth_type.as_deref().unwrap_or("password");
            let password = parsed
                .password
                .filter(|s| !s.is_empty())
                .map(SecretString::new);
            let private_key = parsed
                .private_key
                .filter(|s| !s.is_empty())
                .map(SecretString::new);
            let has_key_passphrase = parsed
                .key_passphrase
                .as_ref()
                .is_some_and(|s| !s.is_empty());
            let key_passphrase = parsed
                .key_passphrase
                .filter(|s| !s.is_empty())
                .map(SecretString::new);
            let fields =
                match build_ssh_secret_fields(auth_type, password, private_key, key_passphrase) {
                    Ok(f) => f,
                    Err(e) => {
                        audit_manage("manage/denied", &parsed.profile, &parsed.name);
                        return error_response(StatusCode(400), &e.to_string());
                    }
                };
            let meta = build_ssh_field_meta(auth_type, has_key_passphrase);
            create_credential_with_fields(
                &store,
                &parsed.profile,
                &parsed.name,
                &args,
                fields,
                Some(meta),
                reveal_ref,
            )
        } else {
            let pw = parsed
                .password
                .filter(|s| !s.is_empty())
                .map(SecretString::new)
                .ok_or_else(|| BrokreError::Vault("password is required".into()));
            match pw {
                Ok(password) => create_credential(
                    &store,
                    &parsed.profile,
                    &parsed.name,
                    &args,
                    password,
                    reveal_ref,
                ),
                Err(e) => {
                    audit_manage("manage/denied", &parsed.profile, &parsed.name);
                    return error_response(StatusCode(400), &e.to_string());
                }
            }
        };
        match create_result {
            Ok(id) => {
                audit_manage("manage/create", &parsed.profile, &parsed.name);
                let resp = serde_json::json!({ "id": id }).to_string();
                json_response(StatusCode(201), &resp)
            }
            Err(e) => {
                audit_manage("manage/denied", &parsed.profile, &parsed.name);
                error_response(StatusCode(400), &e.to_string())
            }
        }
    } else if *method == tiny_http::Method::Post && path == "/api/onboard/complete" {
        if !check_write_auth(&state, req) {
            return unauthorized();
        }
        if mark_onboard_complete().is_err() {
            return error_response(StatusCode(500), "failed to mark onboard complete");
        }
        empty_response(StatusCode(204))
    } else if *method == tiny_http::Method::Get && path == "/api/audit" {
        let params = parse_query_params(query.unwrap_or(""));
        let q = audit_query_from_params(&params);
        match list(q) {
            Ok(result) => match serde_json::to_string(&result) {
                Ok(body) => json_response(StatusCode(200), &body),
                Err(e) => error_response(StatusCode(500), &e.to_string()),
            },
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        }
    } else if *method == tiny_http::Method::Get && path == "/api/audit/verify" {
        let key = match get_or_init_audit_hmac_key() {
            Ok(k) => k,
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        match verify_with_stats(&audit_path(), &key) {
            Ok(stats) => match serde_json::to_string(&stats) {
                Ok(body) => json_response(StatusCode(200), &body),
                Err(e) => error_response(StatusCode(500), &e.to_string()),
            },
            Err(e) => error_response(StatusCode(500), &e.to_string()),
        }
    } else if path.starts_with("/api/bastion") {
        if let Some(resp) = handle_bastion_routes(&state, req, method, path) {
            resp
        } else {
            error_response(StatusCode(404), "not found")
        }
    } else if let Some((profile, name, suffix)) = parse_credential_path(path) {
        handle_credential_route(state, req, method, &profile, &name, suffix)
    } else {
        error_response(StatusCode(404), "not found")
    }
}

fn handle_credential_route(
    state: Arc<ManageState>,
    req: &mut Request,
    method: &tiny_http::Method,
    profile: &str,
    name: &str,
    suffix: Option<&str>,
) -> HttpResponse {
    if !check_write_auth(&state, req) {
        audit_manage("manage/denied", profile, name);
        return unauthorized();
    }

    if *method == tiny_http::Method::Put && suffix == Some("password") {
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        let parsed: RotateBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        if parsed.new_password.is_empty() {
            return error_response(StatusCode(400), "new_password is required");
        }
        if parsed.reveal_passphrase.is_empty() {
            return error_response(StatusCode(400), "reveal_passphrase is required");
        }
        let store = match VaultStore::open() {
            Ok(s) => s,
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        match rotate_password(
            &store,
            profile,
            name,
            SecretString::new(parsed.new_password),
            &SecretString::new(parsed.reveal_passphrase),
        ) {
            Ok(()) => {
                audit_manage("manage/password_rotate", profile, name);
                empty_response(StatusCode(204))
            }
            Err(BrokreError::PolicyDenied) => {
                audit_manage("manage/denied", profile, name);
                error_response(StatusCode(403), "authentication failed")
            }
            Err(e) => error_response(StatusCode(400), &e.to_string()),
        }
    } else if *method == tiny_http::Method::Put && suffix == Some("meta") {
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        let parsed: MetaBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        let store = match VaultStore::open() {
            Ok(s) => s,
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        let mut rec = match store.get(profile, name) {
            Ok(Some(r)) => r,
            Ok(None) => return error_response(StatusCode(404), "not found"),
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        if let Some(labels) = parsed.labels {
            rec.labels = labels;
        }
        if let Some(host) = parsed.host_alias {
            rec.host_alias = if host.is_empty() { None } else { Some(host) };
        }
        rec.updated_at = Utc::now();
        match store.update(rec) {
            Ok(()) => empty_response(StatusCode(204)),
            Err(e) => error_response(StatusCode(400), &e.to_string()),
        }
    } else if *method == tiny_http::Method::Delete && suffix.is_none() {
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        let parsed: AuthBody = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return error_response(StatusCode(400), &e.to_string()),
        };
        if parsed.reveal_passphrase.is_empty() {
            return error_response(StatusCode(400), "reveal_passphrase is required");
        }
        let store = match VaultStore::open() {
            Ok(s) => s,
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        let rec = match store.get(profile, name) {
            Ok(Some(r)) => r,
            Ok(None) => return error_response(StatusCode(404), "not found"),
            Err(e) => return error_response(StatusCode(500), &e.to_string()),
        };
        if !verify_reveal_auth(&rec, &SecretString::new(parsed.reveal_passphrase)) {
            audit_manage("manage/denied", profile, name);
            return error_response(StatusCode(403), "authentication failed");
        }
        match store.delete(profile, name) {
            Ok(()) => {
                audit_manage("manage/delete", profile, name);
                empty_response(StatusCode(204))
            }
            Err(e) => error_response(StatusCode(400), &e.to_string()),
        }
    } else {
        error_response(StatusCode(404), "not found")
    }
}

#[cfg(test)]
mod tests {
    use crate::manage::server::{
        run_manage_server, run_manage_server_with_state, ManageServerOptions,
    };
    use crate::security::secret::SecretString;
    use crate::vault::service::create_credential;
    use crate::vault::store::VaultStore;
    use std::env;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn with_temp_home<F: FnOnce()>(f: F) {
        let tmp = tempfile::tempdir().unwrap();
        let old_home = env::var_os("HOME");
        let old_fallback = env::var_os("BROKRE_ALLOW_FILE_KEYCHAIN");
        env::set_var("HOME", tmp.path());
        env::set_var("BROKRE_ALLOW_FILE_KEYCHAIN", "1");
        f();
        match old_home {
            Some(v) => env::set_var("HOME", v),
            None => env::remove_var("HOME"),
        }
        match old_fallback {
            Some(v) => env::set_var("BROKRE_ALLOW_FILE_KEYCHAIN", v),
            None => env::remove_var("BROKRE_ALLOW_FILE_KEYCHAIN"),
        }
    }

    fn http_request(
        port: u16,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect localhost");
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let payload = body.unwrap_or("");
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        if let Some(t) = token {
            req.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        if body.is_some() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
        }
        req.push_str("\r\n");
        req.push_str(payload);
        stream.write_all(req.as_bytes()).unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        let resp = String::from_utf8_lossy(&buf).into_owned();
        let status = resp
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body_start = resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
        (status, resp[body_start..].to_string())
    }

    #[test]
    #[serial_test::serial]
    fn list_response_has_no_password_field() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            create_credential(
                &store,
                "ssh",
                "test-host",
                &["root@10.0.0.1".into()],
                SecretString::new("secret123".into()),
                Some(&SecretString::new("reveal-pass".into())),
            )
            .unwrap();

            let server = run_manage_server(false).unwrap();
            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/credentials",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            assert!(!body.contains("secret123"));
            assert!(!body.contains("\"password\":"));
            assert!(body.contains("auth_methods"));
        });
    }

    #[test]
    #[serial_test::serial]
    fn write_without_token_is_unauthorized() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let body = r#"{"profile":"ssh","name":"x","host":"h","password":"p"}"#;
            let (status, _) =
                http_request(server.port, "POST", "/api/credentials", None, Some(body));
            assert_eq!(status, 401);
        });
    }

    #[test]
    #[serial_test::serial]
    fn delete_wrong_passphrase_denied() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            create_credential(
                &store,
                "ssh",
                "del-me",
                &["root@10.0.0.2".into()],
                SecretString::new("pw".into()),
                Some(&SecretString::new("good-pass".into())),
            )
            .unwrap();

            let server = run_manage_server(false).unwrap();
            let (status, _) = http_request(
                server.port,
                "DELETE",
                "/api/credentials/ssh/del-me",
                Some(&server.token),
                Some(r#"{"reveal_passphrase":"wrong"}"#),
            );
            assert_eq!(status, 403);
        });
    }

    #[test]
    #[serial_test::serial]
    fn delete_yes_denied_when_reveal_protected() {
        with_temp_home(|| {
            let store = VaultStore::open().unwrap();
            create_credential(
                &store,
                "ssh",
                "protected",
                &["root@10.0.0.3".into()],
                SecretString::new("pw".into()),
                Some(&SecretString::new("good-pass".into())),
            )
            .unwrap();

            let server = run_manage_server(false).unwrap();
            let (status, _) = http_request(
                server.port,
                "DELETE",
                "/api/credentials/ssh/protected",
                Some(&server.token),
                Some(r#"{"reveal_passphrase":"YES"}"#),
            );
            assert_eq!(status, 403);
        });
    }

    #[test]
    fn localhost_binding() {
        assert!(crate::manage::server::bind_address_is_localhost(
            crate::manage::server::MANAGE_PORTS_PREFERRED[0]
        ));
    }

    #[test]
    #[serial_test::serial]
    fn running_server_registers_singleton() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let found = crate::manage::instance::find_running_instance()
                .expect("manage.json should describe live server");
            assert_eq!(found.port, server.port);
            assert_eq!(found.token, server.token);
            assert_eq!(found.pid, std::process::id());
            crate::manage::instance::unregister_instance();
        });
    }

    #[test]
    #[serial_test::serial]
    fn profiles_endpoint_lists_groups() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/profiles",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let groups: Vec<crate::manage::profiles::ProfileGroupInfo> =
                serde_json::from_str(&body).unwrap();
            assert!(groups.iter().any(|g| g.id == "ssh"));
            assert!(groups.iter().any(|g| g.id == "ftp"));
            if which::which("ssh").is_ok() {
                let ssh = groups.iter().find(|g| g.id == "ssh").unwrap();
                assert!(ssh.available);
                assert_eq!(ssh.create_profile, "ssh");
            }
        });
    }

    #[test]
    #[serial_test::serial]
    fn create_ssh_requires_user() {
        with_temp_home(|| {
            if which::which("ssh").is_err() {
                return;
            }
            let server = run_manage_server(false).unwrap();
            let body = r#"{"profile":"ssh","name":"x","host":"10.0.0.1","password":"p"}"#;
            let (status, resp) = http_request(
                server.port,
                "POST",
                "/api/credentials",
                Some(&server.token),
                Some(body),
            );
            assert_eq!(status, 400);
            assert!(resp.contains("user is required"));
        });
    }

    #[test]
    #[serial_test::serial]
    fn create_rejects_unavailable_cli() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let body = r#"{"profile":"definitely-not-a-real-brokre-cli-xyz","name":"x","host":"h","password":"p"}"#;
            let (status, resp) = http_request(
                server.port,
                "POST",
                "/api/credentials",
                Some(&server.token),
                Some(body),
            );
            assert_eq!(status, 400);
            assert!(resp.contains("not installed") || resp.contains("CLI"));
        });
    }

    #[test]
    fn parse_path_supports_slash_in_alias() {
        let (profile, name, suffix) =
            super::parse_credential_path("/api/credentials/ssh/foo/bar/password").unwrap();
        assert_eq!(profile, "ssh");
        assert_eq!(name, "foo/bar");
        assert_eq!(suffix, Some("password"));
    }

    #[test]
    #[serial_test::serial]
    fn create_mysql_with_port_via_api() {
        with_temp_home(|| {
            if which::which("mysql").is_err() {
                return;
            }
            let server = run_manage_server(false).unwrap();
            let body = r#"{"profile":"mysql","name":"db","host":"10.0.0.2","user":"app","port":3307,"password":"secret"}"#;
            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/credentials",
                Some(&server.token),
                Some(body),
            );
            assert_eq!(status, 201);
            let store = VaultStore::open().unwrap();
            let rec = store.get("mysql", "db").unwrap().unwrap();
            assert_eq!(
                rec.saved_args,
                vec!["-h", "10.0.0.2", "-P", "3307", "-u", "app"]
            );
            assert_eq!(rec.host_alias.as_deref(), Some("10.0.0.2:3307"));
        });
    }

    #[test]
    #[serial_test::serial]
    fn create_ssh_with_port_via_api() {
        with_temp_home(|| {
            if which::which("ssh").is_err() {
                return;
            }
            let server = run_manage_server(false).unwrap();
            let body = r#"{"profile":"ssh","name":"bastion","host":"10.0.0.1","user":"root","port":9000,"password":"secret"}"#;
            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/credentials",
                Some(&server.token),
                Some(body),
            );
            assert_eq!(status, 201);
            let store = VaultStore::open().unwrap();
            let rec = store.get("ssh", "bastion").unwrap().unwrap();
            assert_eq!(rec.saved_args, vec!["-p", "9000", "root@10.0.0.1"]);
            assert_eq!(rec.host_alias.as_deref(), Some("10.0.0.1:9000"));
        });
    }

    #[test]
    #[serial_test::serial]
    fn create_with_extra_args_via_api() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let body = r#"{"profile":"mysql","name":"qdb","host":"db.local","user":"u","password":"p","extra_args":["-e","SHOW TABLES"]}"#;
            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/credentials",
                Some(&server.token),
                Some(body),
            );
            assert_eq!(status, 201);
            let store = VaultStore::open().unwrap();
            let rec = store.get("mysql", "qdb").unwrap().unwrap();
            assert!(rec
                .saved_args
                .windows(2)
                .any(|w| w == ["-e", "SHOW TABLES"]));
        });
    }

    #[test]
    fn infer_host_works_for_psql_profile() {
        let args = vec!["-h".into(), "db.local".into(), "-U".into(), "admin".into()];
        assert_eq!(
            crate::vault::service::infer_host("psql", &args).as_deref(),
            Some("db.local")
        );
    }

    #[test]
    #[serial_test::serial]
    fn audit_list_without_token_is_unauthorized() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let (status, _) = http_request(server.port, "GET", "/api/audit", None, None);
            assert_eq!(status, 401);
        });
    }

    #[test]
    #[serial_test::serial]
    fn audit_list_with_token_returns_json() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/audit?limit=10",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(parsed.get("total_matched").is_some());
            assert!(parsed.get("events").is_some());
        });
    }

    #[test]
    #[serial_test::serial]
    fn audit_verify_with_token_ok_on_empty_log() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/audit/verify",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["ok"], true);
            assert_eq!(parsed["count"], 0);
        });
    }

    #[test]
    #[serial_test::serial]
    fn bastion_enable_list_and_disable() {
        with_temp_home(|| {
            if which::which("ssh").is_err() {
                return;
            }
            let store = VaultStore::open().unwrap();
            create_credential(
                &store,
                "ssh",
                "b150",
                &["root@10.0.0.150".into()],
                SecretString::new("pw".into()),
                Some(&SecretString::new("reveal".into())),
            )
            .unwrap();

            let server = run_manage_server(false).unwrap();
            let (status, body) = http_request(
                server.port,
                "POST",
                "/api/bastion/enable",
                Some(&server.token),
                Some(r#"{"alias":"b150"}"#),
            );
            assert_eq!(status, 201);
            assert!(body.contains("b150"));

            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/bastion",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["bastions"].as_array().unwrap().len(), 1);

            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/bastion/disable",
                Some(&server.token),
                Some(r#"{"alias":"b150"}"#),
            );
            assert_eq!(status, 204);
        });
    }

    #[test]
    #[serial_test::serial]
    fn bastion_auth_page_always_serves_html() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let (status, body) = http_request(server.port, "GET", "/bastion-auth", None, None);
            assert_eq!(status, 200);
            assert!(body.contains("brokre bastion unlock"));
            assert!(body.contains(r#"id="source-box""#));
            assert!(!body.contains(r#"{"error":"unauthorized"}"#));

            let path = format!("/bastion-auth?t={}", server.token);
            let (status, body) = http_request(server.port, "GET", &path, None, None);
            assert_eq!(status, 200);
            assert!(body.contains("brokre bastion unlock"));
        });
    }

    #[test]
    #[serial_test::serial]
    fn bastion_set_key_mismatch_and_lock() {
        with_temp_home(|| {
            let server = run_manage_server(false).unwrap();
            let (status, resp) = http_request(
                server.port,
                "POST",
                "/api/bastion/set-key",
                Some(&server.token),
                Some(r#"{"passphrase":"a","confirm":"b"}"#),
            );
            assert_eq!(status, 400);
            assert!(resp.contains("do not match"));

            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/bastion/set-key",
                Some(&server.token),
                Some(r#"{"passphrase":"test-key","confirm":"test-key"}"#),
            );
            assert_eq!(status, 200);

            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/bastion/unlock",
                Some(&server.token),
                Some(r#"{"passphrase":"test-key"}"#),
            );
            assert_eq!(status, 200);

            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/bastion/status",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["unlocked"], true);
            assert!(parsed.get("idle_expires_at").is_some());

            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/bastion/lock",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 204);

            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/bastion/status",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["unlocked"], false);
        });
    }

    #[test]
    #[serial_test::serial]
    fn bastion_unlock_does_not_revive_expired_manage_session() {
        with_temp_home(|| {
            let (server, state) =
                run_manage_server_with_state(ManageServerOptions::default()).unwrap();
            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/bastion/set-key",
                Some(&server.token),
                Some(r#"{"passphrase":"test-key","confirm":"test-key"}"#),
            );
            assert_eq!(status, 200);

            state.session_expired.store(true, Ordering::Release);

            let (status, _) = http_request(
                server.port,
                "POST",
                "/api/bastion/unlock",
                Some(&server.token),
                Some(r#"{"passphrase":"test-key"}"#),
            );
            assert_eq!(status, 200);

            let (status, body) = http_request(
                server.port,
                "GET",
                "/api/bastion/status",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 200);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["unlocked"], true);

            let (status, _) = http_request(
                server.port,
                "GET",
                "/api/credentials",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 401);
        });
    }

    #[test]
    #[serial_test::serial]
    fn bastion_sync_locked_returns_423() {
        with_temp_home(|| {
            if which::which("ssh").is_err() {
                return;
            }
            let store = VaultStore::open().unwrap();
            create_credential(
                &store,
                "ssh",
                "b150",
                &["root@10.0.0.150".into()],
                SecretString::new("pw".into()),
                Some(&SecretString::new("reveal".into())),
            )
            .unwrap();

            let server = run_manage_server(false).unwrap();
            http_request(
                server.port,
                "POST",
                "/api/bastion/set-key",
                Some(&server.token),
                Some(r#"{"passphrase":"k","confirm":"k"}"#),
            );
            http_request(
                server.port,
                "POST",
                "/api/bastion/enable",
                Some(&server.token),
                Some(r#"{"alias":"b150"}"#),
            );

            let (status, resp) = http_request(
                server.port,
                "GET",
                "/api/bastion/sync/b150",
                Some(&server.token),
                None,
            );
            assert_eq!(status, 423);
            assert!(resp.contains("unlock"));
        });
    }
}
