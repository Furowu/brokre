use crate::bastion::model::{BastionListItem, ProbeStatus};
use crate::utils::errors::Result;
use crate::vault::model::SecretRecord;
use crate::vault::service::{infer_cli_port, infer_host};
use chrono::Utc;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_PROBE_TIMEOUT_MS: u64 = 400;
const DEFAULT_PROBE_CACHE_SECS: u64 = 5;
const DEFAULT_PROBE_CONCURRENCY: usize = 16;

static PROBE_CACHE: OnceLock<Mutex<HashMap<String, (Instant, ProbeStatus)>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, (Instant, ProbeStatus)>> {
    PROBE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub struct ProbeOptions {
    pub timeout: Duration,
    pub source: String,
    pub use_cache: bool,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(probe_timeout_ms()),
            source: "local".into(),
            use_cache: true,
        }
    }
}

pub fn probe_timeout_ms() -> u64 {
    std::env::var("BROKRE_PROBE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PROBE_TIMEOUT_MS)
}

pub fn probe_cache_secs() -> u64 {
    std::env::var("BROKRE_PROBE_CACHE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PROBE_CACHE_SECS)
}

pub fn probe_concurrency() -> usize {
    std::env::var("BROKRE_PROBE_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PROBE_CONCURRENCY)
}

pub fn default_port_for_profile(profile: &str) -> u16 {
    match profile.rsplit('/').next().unwrap_or(profile) {
        "ssh" | "scp" | "sftp" => 22,
        "mysql" | "mariadb" => 3306,
        "postgres" | "psql" => 5432,
        "redis" | "redis-cli" => 6379,
        "ftp" => 21,
        "clickhouse" | "clickhouse-client" => 9000,
        _ => 22,
    }
}

fn is_ssh_probe_profile(profile: &str) -> bool {
    matches!(
        profile.rsplit('/').next().unwrap_or(profile),
        "ssh" | "scp" | "sftp"
    )
}

pub fn endpoint_for_record(rec: &SecretRecord) -> Option<(String, u16)> {
    let host = infer_host(&rec.profile, &rec.saved_args)?;
    let port = infer_cli_port(&rec.profile, &rec.saved_args)
        .unwrap_or_else(|| default_port_for_profile(&rec.profile));
    Some((host, port))
}

/// RFC 4253 identification string: `SSH-protoversion-softwareversion`.
pub fn is_valid_ssh_ident(line: &str) -> bool {
    let line = line.trim();
    let Some(rest) = line.strip_prefix("SSH-") else {
        return false;
    };
    let Some((proto, _)) = rest.split_once('-') else {
        return false;
    };
    proto == "2.0" || proto == "1.99" || proto == "1.5"
}

fn resolve_socket_addrs(host: &str, port: u16) -> std::result::Result<Vec<SocketAddr>, String> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    if addrs.is_empty() {
        return Err("no addresses resolved".into());
    }
    Ok(addrs)
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> std::result::Result<TcpStream, String> {
    let addrs = resolve_socket_addrs(host, port)?;
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(last_err.unwrap_or_else(|| "connect failed".into()))
}

fn remaining_timeout(started: Instant, total: Duration) -> Duration {
    total
        .saturating_sub(started.elapsed())
        .max(Duration::from_millis(1))
}

fn read_ssh_server_banner(
    stream: &TcpStream,
    timeout: Duration,
) -> std::result::Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            "SSH banner timeout".into()
        } else {
            e.to_string()
        }
    })?;
    if n == 0 {
        return Err("connection closed before SSH banner".into());
    }
    let ident = line.trim_end_matches(['\r', '\n']);
    if is_valid_ssh_ident(ident) {
        Ok(())
    } else {
        Err(format!("invalid SSH banner: {ident}"))
    }
}

fn probe_status(started: Instant, reachable: bool, error: Option<String>) -> ProbeStatus {
    ProbeStatus {
        reachable,
        probe_ms: Some(started.elapsed().as_millis() as u64),
        checked_at: Utc::now().to_rfc3339(),
        error,
        source: String::new(),
    }
}

pub fn probe_tcp(host: &str, port: u16, timeout: Duration) -> ProbeStatus {
    let started = Instant::now();
    match connect_tcp(host, port, timeout) {
        Ok(_) => probe_status(started, true, None),
        Err(e) => probe_status(started, false, Some(e)),
    }
}

pub fn probe_ssh(host: &str, port: u16, timeout: Duration) -> ProbeStatus {
    let started = Instant::now();
    let stream = match connect_tcp(host, port, timeout) {
        Ok(s) => s,
        Err(e) => return probe_status(started, false, Some(e)),
    };
    let banner_timeout = remaining_timeout(started, timeout);
    match read_ssh_server_banner(&stream, banner_timeout) {
        Ok(()) => probe_status(started, true, None),
        Err(e) => probe_status(started, false, Some(e)),
    }
}

pub fn probe_endpoint(host: &str, port: u16, profile: &str, timeout: Duration) -> ProbeStatus {
    if is_ssh_probe_profile(profile) {
        probe_ssh(host, port, timeout)
    } else {
        probe_tcp(host, port, timeout)
    }
}

fn cached_probe(addr: &str, opts: &ProbeOptions) -> Option<ProbeStatus> {
    if !opts.use_cache {
        return None;
    }
    let ttl = Duration::from_secs(probe_cache_secs());
    let guard = cache().lock().ok()?;
    guard.get(addr).and_then(|(t, status)| {
        if t.elapsed() < ttl {
            let mut s = status.clone();
            s.source = opts.source.clone();
            Some(s)
        } else {
            None
        }
    })
}

fn store_cache(addr: &str, status: &ProbeStatus) {
    if let Ok(mut guard) = cache().lock() {
        guard.insert(addr.to_string(), (Instant::now(), status.clone()));
    }
}

pub fn probe_record(rec: &SecretRecord, opts: &ProbeOptions) -> ProbeStatus {
    let addr = rec.name.clone();
    if let Some(cached) = cached_probe(&addr, opts) {
        return cached;
    }
    let mut status = match endpoint_for_record(rec) {
        Some((host, port)) => probe_endpoint(&host, port, &rec.profile, opts.timeout),
        None => ProbeStatus {
            reachable: false,
            probe_ms: None,
            checked_at: Utc::now().to_rfc3339(),
            error: Some("no host inferred".into()),
            source: opts.source.clone(),
        },
    };
    status.source = opts.source.clone();
    store_cache(&addr, &status);
    status
}

pub fn probe_items(items: &mut [BastionListItem], opts: &ProbeOptions) -> Result<()> {
    let work: Vec<(usize, String, u16, String)> = items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            let host_alias = item.host_alias.as_deref()?;
            let (host, port) = parse_host_port_alias(host_alias, &item.profile)?;
            Some((idx, host, port, item.profile.clone()))
        })
        .collect();

    let opts = std::sync::Arc::new(opts.clone());
    let concurrency = probe_concurrency();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::scope(|scope| {
        let active = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        for (idx, host, port, profile) in work {
            let tx = tx.clone();
            let opts = opts.clone();
            let active = active.clone();
            scope.spawn(move || {
                loop {
                    {
                        let mut g = active.lock().unwrap();
                        if *g >= concurrency {
                            drop(g);
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        *g += 1;
                    }
                    break;
                }
                let mut status = probe_endpoint(&host, port, &profile, opts.timeout);
                status.source = opts.source.clone();
                let _ = tx.send((idx, status));
                let mut g = active.lock().unwrap();
                *g -= 1;
            });
        }
        drop(tx);
    });

    for (idx, status) in rx {
        items[idx].status = Some(status);
    }
    Ok(())
}

fn parse_host_port_alias(host_alias: &str, profile: &str) -> Option<(String, u16)> {
    if let Some((host, port_str)) = host_alias.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some((host.to_string(), port));
        }
    }
    Some((host_alias.to_string(), default_port_for_profile(profile)))
}

impl Clone for ProbeOptions {
    fn clone(&self) -> Self {
        Self {
            timeout: self.timeout,
            source: self.source.clone(),
            use_cache: self.use_cache,
        }
    }
}

pub fn probe_items_from_records(records: &[SecretRecord], opts: &ProbeOptions) -> Vec<ProbeStatus> {
    records.iter().map(|r| probe_record(r, opts)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_closed_port_fast() {
        let status = probe_tcp("127.0.0.1", 65534, Duration::from_millis(200));
        assert!(!status.reachable);
        assert!(status.probe_ms.unwrap() < 500);
    }

    #[test]
    fn probe_ssh_closed_port_fast() {
        let status = probe_ssh("127.0.0.1", 65534, Duration::from_millis(200));
        assert!(!status.reachable);
        assert!(status.probe_ms.unwrap() < 500);
    }

    #[test]
    fn is_valid_ssh_ident_accepts_protocol_versions() {
        assert!(is_valid_ssh_ident("SSH-2.0-OpenSSH_9.0"));
        assert!(is_valid_ssh_ident("SSH-1.99-Cisco-1.25"));
        assert!(is_valid_ssh_ident("SSH-1.5-legacy\r"));
        assert!(!is_valid_ssh_ident("HTTP/1.1 200 OK"));
        assert!(!is_valid_ssh_ident(""));
    }

    #[test]
    fn parse_host_port_alias_with_port() {
        let (h, p) = parse_host_port_alias("10.0.0.1:2222", "ssh").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 2222);
    }

    #[test]
    fn probe_endpoint_uses_ssh_for_openssh_profiles() {
        assert!(is_ssh_probe_profile("ssh"));
        assert!(is_ssh_probe_profile("tools/ssh"));
        assert!(!is_ssh_probe_profile("mysql"));
    }
}
