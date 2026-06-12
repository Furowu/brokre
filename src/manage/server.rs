use crate::manage::api::{handle_request, ManageState};
use crate::manage::auth::generate_session_token;
use crate::manage::instance::{register_instance, unregister_instance};
use crate::utils::errors::{BrokreError, Result};
use std::net::{TcpListener, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tiny_http::Server;

const IDLE_LIMIT_SECS: u64 = 900;

/// Distinctive localhost ports (avoid ephemeral 49152+ range used by many tools).
pub const MANAGE_PORTS_PREFERRED: &[u16] = &[
    56777, 56789, 56778, 56779, 56780, 56781, 56782, 56783, 56784, 56785,
];

const MANAGE_PORT_RANGE_START: u16 = 56777;
const MANAGE_PORT_RANGE_END: u16 = 56877;

pub struct ManageServer {
    pub port: u16,
    pub token: String,
    pub url: String,
}

/// What to do when the manage UI has been idle too long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleBehavior {
    /// Standalone `brokre manage` — exit the whole process.
    ExitProcess,
    /// Embedded in `brokre mcp` — invalidate session; MCP keeps running.
    LogOnly,
}

pub struct ManageServerOptions {
    pub onboard: bool,
    pub idle_behavior: IdleBehavior,
}

impl Default for ManageServerOptions {
    fn default() -> Self {
        Self {
            onboard: false,
            idle_behavior: IdleBehavior::ExitProcess,
        }
    }
}

pub fn run_manage_server(onboard: bool) -> Result<ManageServer> {
    run_manage_server_with(ManageServerOptions {
        onboard,
        ..Default::default()
    })
}

pub fn run_manage_server_with(options: ManageServerOptions) -> Result<ManageServer> {
    let token = generate_session_token();
    let listener = bind_localhost_listener()?;
    let port = listener.local_addr().map_err(BrokreError::Io)?.port();
    let server = Server::from_listener(listener, None)
        .map_err(|e| BrokreError::Runtime(e.to_string()))?;

    let state = Arc::new(ManageState {
        token: token.clone(),
        onboard: options.onboard,
        last_activity: std::sync::Mutex::new(std::time::Instant::now()),
        session_expired: AtomicBool::new(false),
    });

    let url = format!("http://127.0.0.1:{}/?t={}", port, token);
    let log_full_url = options.idle_behavior == IdleBehavior::ExitProcess;
    if log_full_url {
        eprintln!("brokre manage: {}", url);
        eprintln!(
            "brokre manage: press Ctrl+C to stop (idle timeout {} min)",
            IDLE_LIMIT_SECS / 60
        );
    } else {
        eprintln!(
            "brokre manage: http://127.0.0.1:{}/ (session token omitted from logs — use browser)",
            port
        );
        eprintln!(
            "brokre manage: idle timeout {} min (embedded — session expires, MCP keeps running)",
            IDLE_LIMIT_SECS / 60
        );
    }

    let state_requests = state.clone();
    thread::spawn(move || {
        for request in server.incoming_requests() {
            handle_request(state_requests.clone(), request);
        }
    });

    let idle_behavior = options.idle_behavior;
    let state_idle = state.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(30));
            if state_idle.idle_secs() >= IDLE_LIMIT_SECS {
                match idle_behavior {
                    IdleBehavior::ExitProcess => {
                        eprintln!("brokre manage: idle timeout — shutting down");
                        unregister_instance();
                        std::process::exit(0);
                    }
                    IdleBehavior::LogOnly => {
                        state_idle.session_expired.store(true, Ordering::Release);
                        eprintln!(
                            "brokre manage: idle timeout — session expired (embedded server no longer accepts auth)"
                        );
                        break;
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    register_instance(port, &token)?;

    Ok(ManageServer { port, token, url })
}

fn bind_localhost_listener() -> Result<TcpListener> {
    for port in MANAGE_PORTS_PREFERRED {
        if let Ok(listener) = try_bind(*port) {
            if *port != MANAGE_PORTS_PREFERRED[0] {
                eprintln!(
                    "brokre manage: port {} in use — using {}",
                    MANAGE_PORTS_PREFERRED[0],
                    port
                );
            }
            return Ok(listener);
        }
    }
    for port in MANAGE_PORT_RANGE_START..=MANAGE_PORT_RANGE_END {
        if MANAGE_PORTS_PREFERRED.contains(&port) {
            continue;
        }
        if let Ok(listener) = try_bind(port) {
            return Ok(listener);
        }
    }
    for port in 49152u16..=65535 {
        if (MANAGE_PORT_RANGE_START..=MANAGE_PORT_RANGE_END).contains(&port) {
            continue;
        }
        if let Ok(listener) = try_bind(port) {
            return Ok(listener);
        }
    }
    Err(BrokreError::Runtime("no free localhost port".into()))
}

fn try_bind(port: u16) -> Result<TcpListener> {
    let addr = format!("127.0.0.1:{}", port);
    TcpListener::bind(&addr).map_err(BrokreError::Io)
}

pub fn bind_address_is_localhost(port: u16) -> bool {
    format!("127.0.0.1:{}", port)
        .to_socket_addrs()
        .map(|mut addrs| addrs.any(|a| a.ip().is_loopback()))
        .unwrap_or(false)
}
