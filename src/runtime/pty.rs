//! Transparent PTY pass-through with optional password capture / injection.
//!
//! Cross-platform implementation using portable-pty + crossterm.
//! On Unix, saved credentials use a short-lived `brokre --internal-injector` child
//! so the parent never holds decrypted passwords (T1 mitigation).

use crate::security::secret::SecretString;
use crate::utils::errors::{BrokreError, Result};
use crossterm::terminal;
use portable_pty::{CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use regex::bytes::Regex;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::RawFd;

use uuid::Uuid;

/// How to satisfy a password prompt for the wrapped CLI.
#[derive(Clone, Copy)]
pub enum PtyCredential<'a> {
    None,
    /// Decrypt in a short-lived child and write once to the PTY (Unix only).
    #[cfg(unix)]
    VaultRecord(Uuid),
    /// In-process injection (Windows always; Unix only with `--features in_proc_inject`).
    #[cfg(any(not(unix), feature = "in_proc_inject"))]
    Secret(&'a SecretString),
    /// Binds `'a` when Unix builds omit `Secret` (e.g. `--no-default-features`).
    #[cfg(all(unix, not(feature = "in_proc_inject")))]
    #[doc(hidden)]
    _Reserved(std::marker::PhantomData<&'a ()>),
}

impl<'a> PtyCredential<'a> {
    fn should_scan(&self, stdin_is_tty: bool) -> bool {
        let inject = match self {
            PtyCredential::None => false,
            #[cfg(unix)]
            PtyCredential::VaultRecord(_) => true,
            #[cfg(any(not(unix), feature = "in_proc_inject"))]
            PtyCredential::Secret(_) => true,
            #[cfg(all(unix, not(feature = "in_proc_inject")))]
            PtyCredential::_Reserved(_) => false,
        };
        inject || stdin_is_tty
    }

    fn preset_injection(&self) -> bool {
        match self {
            PtyCredential::None => false,
            #[cfg(unix)]
            PtyCredential::VaultRecord(_) => true,
            #[cfg(any(not(unix), feature = "in_proc_inject"))]
            PtyCredential::Secret(_) => true,
            #[cfg(all(unix, not(feature = "in_proc_inject")))]
            PtyCredential::_Reserved(_) => false,
        }
    }
}

/// After SSH prints a normal post-login banner, MOTD / help text may contain lines
/// that end with `password:` and would otherwise re-trigger the prompt scanner,
/// wiping an already-captured password buffer before `PtyRunResult` is assembled.
fn ssh_post_auth_indicated(buf: &[u8]) -> bool {
    if contains_ascii_case_insensitive(buf, b"last login")
        || contains_ascii_case_insensitive(buf, b"welcome to ")
    {
        return true;
    }
    // Common bash/zsh prompt after login (e.g. [root@host ~]#).
    let lower: Vec<u8> = buf.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower.windows(3).any(|w| w == b"]# " || w == b"]$ ")
        || lower.ends_with(b"]#")
        || lower.ends_with(b"]#\r\n")
        || lower.ends_with(b"]#\n")
        || lower.ends_with(b"]# \r\n")
        || lower.ends_with(b"]# \n")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|win| {
        win.iter()
            .zip(needle_lower.iter())
            .all(|(b, n)| b.to_ascii_lowercase() == *n)
    })
}

/// Map PTY output to the vault field that should be injected.
fn field_for_prompt(window: &[u8], available: &[String]) -> Option<String> {
    if available.is_empty() {
        return None;
    }
    let lower = window
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let text = String::from_utf8_lossy(&lower);
    if text.contains("passphrase") && available.iter().any(|f| f == "key_passphrase") {
        return Some("key_passphrase".into());
    }
    if text.contains("password") && available.iter().any(|f| f == "password") {
        return Some("password".into());
    }
    if available.len() == 1 {
        return Some(available[0].clone());
    }
    None
}

#[derive(Clone, Default)]
pub struct PtyRunOptions {
    /// First hop of `bastion::inner`: inject only this hop's SSH login; inner brokre owns sudo/su.
    pub bastion_outer_hop: bool,
    /// Hold local stdin until nested SSH/sudo setup finishes (routed privileged sessions).
    pub defer_stdin_forward: bool,
    /// Mac vault record for the routed inner alias — outer injects inner SSH/sudo from local vault.
    pub inner_vault_record: Option<uuid::Uuid>,
    /// Host alias / address of the inner target (disambiguate nested SSH login prompts).
    pub inner_host_hint: Option<String>,
    /// Inner brokre on bastion (`BROKRE_ROUTED_INNER=1`): PTY pass-through only, no vault inject.
    pub inject_disabled: bool,
    /// Inner brokre: Mac outer injects nested SSH login; inner keeps sudo/su inject locally.
    pub passive_inner_ssh: bool,
}

/// Prompt context for [`should_arm_vault_inject`] (keeps arity within clippy limits).
#[derive(Debug, Clone, Copy)]
pub(crate) struct VaultInjectPrompt<'a> {
    pub is_elevation_prompt: bool,
    pub is_ssh_login_prompt: bool,
    pub is_inner_hop_ssh_prompt: bool,
    pub field: &'a str,
    pub ssh_login_done: bool,
    pub inner_ssh_login_done: bool,
    pub elevation_attempts: usize,
    pub auth_failed_visible: bool,
}

/// Whether to arm vault injection for a matched prompt (unit-tested policy).
pub(crate) fn should_arm_vault_inject(
    options: &PtyRunOptions,
    prompt: &VaultInjectPrompt<'_>,
) -> bool {
    if prompt.field != "password" {
        return false;
    }
    if options.bastion_outer_hop {
        if prompt.is_ssh_login_prompt {
            if options.inner_vault_record.is_some() {
                let second_ssh_hop = prompt.ssh_login_done && !prompt.inner_ssh_login_done;
                if prompt.is_inner_hop_ssh_prompt || second_ssh_hop {
                    return !prompt.inner_ssh_login_done;
                }
                if !prompt.ssh_login_done {
                    return true;
                }
                return false;
            }
            if !prompt.ssh_login_done {
                return true;
            }
            return false;
        }
        if options.inner_vault_record.is_some() && prompt.is_elevation_prompt {
            // After direct-inner SSH login, sudo/su on the inner host uses the Mac inner vault.
            if prompt.inner_ssh_login_done {
                if prompt.elevation_attempts == 0 {
                    return true;
                }
                return prompt.auth_failed_visible && prompt.elevation_attempts == 1;
            }
            // Remote brokre on the bastion handles nested elevation locally.
            return false;
        }
        return false;
    }
    // Headless inner brokre on the bastion (`BROKRE_ROUTED_INNER=1`): inject SSH login from
    // the bastion vault. Mac outer-hop PTY inject is a separate path on the client.
    if options.passive_inner_ssh && prompt.is_ssh_login_prompt {
        return !prompt.ssh_login_done;
    }
    if prompt.is_elevation_prompt {
        if prompt.elevation_attempts == 0 {
            return true;
        }
        return prompt.auth_failed_visible && prompt.elevation_attempts == 1;
    }
    if prompt.is_ssh_login_prompt {
        return !prompt.ssh_login_done;
    }
    // Generic CLI password prompt (mysql, psql, sh harness, etc.).
    true
}

fn sudo_auth_failed_in_window(buf: &[u8]) -> bool {
    contains_ascii_case_insensitive(buf, b"authentication failed")
        || contains_ascii_case_insensitive(buf, b"sorry, try again")
}

/// Brief wait so the remote readline finishes drawing before password bytes are written.
fn inject_settle_delay(is_elevation: bool, bastion_outer: bool) -> Duration {
    let base = if is_elevation { 50 } else { 35 };
    let nested = if bastion_outer && is_elevation { 80 } else { 0 };
    Duration::from_millis(base + nested)
}

fn prompt_targets_inner_host(window: &[u8], hint: &str) -> bool {
    if hint.is_empty() {
        return false;
    }
    let lower = String::from_utf8_lossy(window).to_ascii_lowercase();
    let hint_l = hint.to_ascii_lowercase();
    if lower.contains(&hint_l) {
        return true;
    }
    // `dev-host` saved as alias while OpenSSH prints `user@10.0.0.7's password:`.
    hint_l
        .split('@')
        .next_back()
        .is_some_and(|host| !host.is_empty() && lower.contains(host))
}

#[cfg(unix)]
fn pty_master_readable(fd: RawFd, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 && (pfd.revents & libc::POLLIN) != 0 }
}

/// OpenSSH login password prompt (`user@host's password:`), not sudo/su.
fn is_ssh_login_password_prompt(buf: &[u8]) -> bool {
    if crate::runtime::prompts::is_remote_sudo_password_prompt(buf)
        || crate::runtime::prompts::is_remote_su_password_prompt(buf)
    {
        return false;
    }
    let lower: Vec<u8> = buf.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower.windows(11).any(|w| w == b"'s password:")
        || lower.ends_with(b"password: ")
        || lower.ends_with(b"password:\r\n")
        || lower.ends_with(b"password:\n")
}

#[derive(Default)]
pub struct PtyRunResult {
    pub exit_code: i32,
    pub captured_password: Option<SecretString>,
    pub had_prompt: bool,
    pub injector_pid: Option<u32>,
    pub injector_dur_ms: Option<u64>,
    pub injector_outcome: Option<String>,
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Self {
        let _ = terminal::enable_raw_mode();
        Self
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn try_enable_interactive_raw(raw_mode: &Mutex<Option<RawModeGuard>>, stdin_is_tty: bool, ready: bool) {
    if !stdin_is_tty || !ready {
        return;
    }
    let mut guard = raw_mode.lock().unwrap();
    if guard.is_none() {
        *guard = Some(RawModeGuard::enable());
    }
}

/// Vault preset blocks stdin until inject completes, except on bastion inner hops where SSH
/// login inject is disabled (`passive_inner_ssh`) and bytes must pass through immediately.
fn initial_stdin_forward_enabled(
    stdin_is_tty: bool,
    preset_some: bool,
    passive_inner_ssh: bool,
    defer_stdin: bool,
) -> bool {
    let blocks_initial_stdin = preset_some && !passive_inner_ssh;
    stdin_is_tty && !blocks_initial_stdin && !defer_stdin
}

fn tty_raw_mode_ready(pending_capture: bool, pending_inject: bool) -> bool {
    !pending_capture && !pending_inject
}

#[cfg(unix)]
fn open_stdin_read_source() -> Box<dyn Read + Send> {
    std::fs::File::open("/dev/tty")
        .map(|f| Box::new(f) as Box<dyn Read + Send>)
        .unwrap_or_else(|_| Box::new(std::io::stdin()) as Box<dyn Read + Send>)
}

#[cfg(not(unix))]
fn open_stdin_read_source() -> Box<dyn Read + Send> {
    Box::new(std::io::stdin())
}

fn spawn_stdin_reader(
    pipe_eof: Arc<AtomicBool>,
    stdin_is_pipe: bool,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    const STDIN_CHANNEL_CAP: usize = 8;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(STDIN_CHANNEL_CAP);
    let pipe_eof_reader = pipe_eof.clone();
    thread::spawn(move || {
        let mut source = open_stdin_read_source();
        let mut buf = [0u8; 65536];
        loop {
            match source.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if stdin_is_pipe {
            pipe_eof_reader.store(true, Ordering::Release);
        }
    });
    rx
}

#[cfg(unix)]
struct SigintForwardGuard {
    flag: Arc<AtomicBool>,
    registration: signal_hook::SigId,
}

#[cfg(unix)]
impl SigintForwardGuard {
    fn register() -> Option<Self> {
        let flag = Arc::new(AtomicBool::new(false));
        let registration =
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag)).ok()?;
        Some(Self { flag, registration })
    }

    fn take_pending(&self) -> bool {
        self.flag.swap(false, Ordering::AcqRel)
    }
}

#[cfg(unix)]
impl Drop for SigintForwardGuard {
    fn drop(&mut self) {
        let _ = signal_hook::low_level::unregister(self.registration);
    }
}

pub fn run(
    binary: &str,
    args: &[String],
    cred: PtyCredential<'_>,
    prompt_patterns: &[Regex],
    options: PtyRunOptions,
) -> Result<PtyRunResult> {
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| BrokreError::Runtime(format!("openpty: {}", e)))?;

    let master = pair.master;
    #[cfg(unix)]
    let master_raw_fd: Option<RawFd> = MasterPty::as_raw_fd(&*master);
    #[cfg(not(unix))]
    let master_raw_fd: Option<i32> = None;

    let mut cmd = CommandBuilder::new(binary);
    for a in args {
        cmd.arg(a);
    }
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| BrokreError::Runtime(format!("spawn: {}", e)))?;

    drop(pair.slave);

    let mut reader = master
        .try_clone_reader()
        .map_err(|e| BrokreError::Runtime(format!("clone reader: {}", e)))?;
    let mut writer = master
        .take_writer()
        .map_err(|e| BrokreError::Runtime(format!("take writer: {}", e)))?;

    let stdin_is_tty = crate::security::tty::stdin_is_real_tty();
    let stdin_is_pipe = crate::security::tty::stdin_is_pipe();
    let preset_inject = !options.inject_disabled && cred.preset_injection();
    // First-time capture enables raw mode immediately; vault inject defers until
    // stdin forwarding opens so arrow keys / Ctrl+C behave like plain ssh.
    let raw_mode: Arc<Mutex<Option<RawModeGuard>>> = Arc::new(Mutex::new(None));
    if stdin_is_tty && !options.inject_disabled && !preset_inject {
        *raw_mode.lock().unwrap() = Some(RawModeGuard::enable());
    }

    #[cfg(unix)]
    let sigint_forward = if stdin_is_tty {
        SigintForwardGuard::register()
    } else {
        None
    };

    // Shared state for password capture / injection.
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let pending_capture = Arc::new(AtomicBool::new(false));
    let pending_inject = Arc::new(AtomicBool::new(false));
    let had_prompt = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let inject_completed = Arc::new(AtomicBool::new(false));

    #[cfg(unix)]
    let inject_fields: Arc<Vec<String>> = match cred {
        PtyCredential::VaultRecord(id) => Arc::new(
            crate::vault::store::VaultStore::open()
                .ok()
                .and_then(|s| s.get_by_id(&id).ok().flatten())
                .map(|r| crate::runtime::ssh_identity::injectable_field_names(&r))
                .unwrap_or_else(|| vec!["password".into()]),
        ),
        _ => Arc::new(Vec::new()),
    };
    #[cfg(not(unix))]
    let inject_fields: Arc<Vec<String>> = Arc::new(Vec::new());

    let pending_field: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let injected_fields: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let inject_done_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let elevation_attempts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let ssh_login_done: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let inner_ssh_login_done: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let pending_is_elevation: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let pending_record_id: Arc<Mutex<Option<Uuid>>> = Arc::new(Mutex::new(None));
    let suppress_stdout: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let suppress_until_post_auth: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let rescan_after_inject: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let defer_stdin = options.defer_stdin_forward;
    let bastion_outer_hop = options.bastion_outer_hop;
    let passive_inner_ssh = options.passive_inner_ssh;
    let inner_vault_record = options.inner_vault_record;
    let inner_host_hint = options.inner_host_hint.clone();
    let dual_ssh_inject = options.bastion_outer_hop && options.inner_vault_record.is_some();

    let should_scan = !options.inject_disabled && cred.should_scan(stdin_is_tty);
    let preset_some = preset_inject && !options.inject_disabled;

    // Gate stdin -> PTY forwarding so pipe data cannot arrive before password injection.
    let stdin_forward_enabled = Arc::new(AtomicBool::new(initial_stdin_forward_enabled(
        stdin_is_tty,
        preset_some,
        passive_inner_ssh,
        defer_stdin,
    )));
    let stdin_forward_a = stdin_forward_enabled.clone();

    let bin_base = binary
        .rsplit('/')
        .next()
        .unwrap_or(binary)
        .to_ascii_lowercase();
    let track_ssh_post_auth = matches!(bin_base.as_str(), "ssh" | "scp" | "sftp");
    let expect_su_elevation = std::env::var_os("BROKRE_MCP_ELEVATED").is_some_and(|v| v == "su");

    // ---- thread A: PTY -> stdout + optional prompt scanner ----
    let patterns: Vec<Regex> = prompt_patterns.to_vec();
    let cap_a = captured.clone();
    let pending_cap_a = pending_capture.clone();
    let pending_inj_a = pending_inject.clone();
    let had_a = had_prompt.clone();
    let done_a = done.clone();
    let post_auth = Arc::new(AtomicBool::new(false));
    let post_auth_a = post_auth.clone();
    let inject_fields_a = inject_fields.clone();
    let pending_field_a = pending_field.clone();
    let injected_fields_a = injected_fields.clone();
    let bastion_outer_a = options.bastion_outer_hop;
    let passive_inner_ssh_a = passive_inner_ssh;
    let elevation_attempts_a = elevation_attempts.clone();
    let ssh_login_done_a = ssh_login_done.clone();
    let inner_ssh_login_done_a = inner_ssh_login_done.clone();
    let pending_is_elevation_a = pending_is_elevation.clone();
    let pending_record_id_a = pending_record_id.clone();
    let inner_vault_record_a = inner_vault_record;
    let inner_host_hint_a = inner_host_hint;
    let suppress_stdout_a = suppress_stdout.clone();
    let suppress_until_post_auth_a = suppress_until_post_auth.clone();
    let defer_stdin_a = defer_stdin;
    let rescan_after_inject_a = rescan_after_inject.clone();
    #[cfg(unix)]
    let scanner_pty_fd = master_raw_fd;

    let scanner = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut window: Vec<u8> = Vec::with_capacity(2048);
        let stdout = std::io::stdout();

        let arm_prompt_if_needed = |window: &mut Vec<u8>| {
            if pending_cap_a.load(Ordering::Acquire) || pending_inj_a.load(Ordering::Acquire) {
                return;
            }
            'prompt_scan: for re in &patterns {
                if re.is_match(window) {
                    let is_sudo_prompt = track_ssh_post_auth
                        && (preset_some || (bastion_outer_a && inner_vault_record_a.is_some()))
                        && crate::runtime::prompts::is_remote_sudo_password_prompt(window);
                    let is_su_prompt = track_ssh_post_auth
                        && preset_some
                        && expect_su_elevation
                        && crate::runtime::prompts::is_remote_su_password_prompt(window);
                    let is_elevation_prompt = is_sudo_prompt || is_su_prompt;
                    let is_ssh_login_prompt = is_ssh_login_password_prompt(window);
                    let is_inner_hop_ssh = is_ssh_login_prompt
                        && inner_host_hint_a
                            .as_deref()
                            .is_some_and(|h| prompt_targets_inner_host(window, h));
                    if !preset_some && track_ssh_post_auth && post_auth_a.load(Ordering::Acquire) {
                        window.clear();
                        break 'prompt_scan;
                    }
                    had_a.store(true, Ordering::Release);
                    if preset_some {
                        if inject_fields_a.is_empty() {
                            // PtyCredential::Secret (in-proc preset) — any matched prompt.
                            pending_inj_a.store(true, Ordering::Release);
                            window.clear();
                            break 'prompt_scan;
                        }
                        if let Some(field) = field_for_prompt(window, &inject_fields_a) {
                            let ssh_done = ssh_login_done_a.load(Ordering::Acquire)
                                || injected_fields_a
                                    .lock()
                                    .map(|g| g.contains(&field))
                                    .unwrap_or(false);
                            let inner_ssh_done = inner_ssh_login_done_a.load(Ordering::Acquire);
                            let elev_attempts = elevation_attempts_a.load(Ordering::Acquire);
                            let auth_failed = sudo_auth_failed_in_window(window);
                            let already = injected_fields_a
                                .lock()
                                .map(|g| g.contains(&field))
                                .unwrap_or(true);
                            let allow_elevation_reinject =
                                already && field == "password" && is_elevation_prompt;
                            let second_ssh_hop = is_ssh_login_prompt
                                && ssh_done
                                && !inner_ssh_done;
                            let allow_bastion_second_ssh = bastion_outer_a
                                && inner_vault_record_a.is_some()
                                && second_ssh_hop
                                && field == "password";
                            if should_arm_vault_inject(
                                &PtyRunOptions {
                                    bastion_outer_hop: bastion_outer_a,
                                    defer_stdin_forward: defer_stdin_a,
                                    inner_vault_record: inner_vault_record_a,
                                    inner_host_hint: inner_host_hint_a.clone(),
                                    inject_disabled: false,
                                    passive_inner_ssh: passive_inner_ssh_a,
                                    ..Default::default()
                                },
                                &VaultInjectPrompt {
                                    is_elevation_prompt,
                                    is_ssh_login_prompt,
                                    is_inner_hop_ssh_prompt: is_inner_hop_ssh,
                                    field: &field,
                                    ssh_login_done: ssh_done,
                                    inner_ssh_login_done: inner_ssh_done,
                                    elevation_attempts: elev_attempts,
                                    auth_failed_visible: auth_failed,
                                },
                            ) && (!already || allow_elevation_reinject || allow_bastion_second_ssh)
                            {
                                let use_inner = bastion_outer_a
                                    && inner_vault_record_a.is_some()
                                    && (is_inner_hop_ssh
                                        || second_ssh_hop
                                        || (is_elevation_prompt && inner_ssh_done));
                                if let Ok(mut rid) = pending_record_id_a.lock() {
                                    *rid = if use_inner {
                                        inner_vault_record_a
                                    } else {
                                        None
                                    };
                                }
                                pending_is_elevation_a
                                    .store(is_elevation_prompt, Ordering::Release);
                                suppress_stdout_a.store(true, Ordering::Release);
                                if is_ssh_login_prompt {
                                    suppress_until_post_auth_a.store(true, Ordering::Release);
                                }
                                if let Ok(mut pf) = pending_field_a.lock() {
                                    *pf = Some(field);
                                }
                                pending_inj_a.store(true, Ordering::Release);
                                window.clear();
                                break 'prompt_scan;
                            }
                        }
                    } else {
                        pending_cap_a.store(true, Ordering::Release);
                        let mut g = cap_a.lock().unwrap();
                        *g = Some(String::new());
                        window.clear();
                        break 'prompt_scan;
                    }
                    break 'prompt_scan;
                }
            }
        };

        loop {
            if rescan_after_inject_a.swap(false, Ordering::AcqRel) {
                arm_prompt_if_needed(&mut window);
            }

            #[cfg(unix)]
            let data_ready = scanner_pty_fd
                .map(|fd| pty_master_readable(fd, 50))
                .unwrap_or(true);
            #[cfg(not(unix))]
            let data_ready = true;

            if !data_ready {
                continue;
            }

            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = &buf[..n];

                    if should_scan {
                        window.extend_from_slice(data);
                        if window.len() > 4096 {
                            let drop_n = window.len() - 2048;
                            window.drain(..drop_n);
                        }

                        if track_ssh_post_auth
                            && !post_auth_a.load(Ordering::Acquire)
                            && ssh_post_auth_indicated(&window)
                        {
                            post_auth_a.store(true, Ordering::Release);
                            suppress_until_post_auth_a.store(false, Ordering::Release);
                            if bastion_outer_a {
                                ssh_login_done_a.store(true, Ordering::Release);
                            }
                            if !defer_stdin_a {
                                stdin_forward_a.store(true, Ordering::Release);
                            }
                        }

                        arm_prompt_if_needed(&mut window);
                    }

                    let suppress_auth_transition = should_scan
                        && suppress_until_post_auth_a.load(Ordering::Acquire);
                    let suppress_this_chunk = suppress_stdout_a.swap(false, Ordering::AcqRel)
                        || suppress_auth_transition;
                    if !suppress_this_chunk {
                        let mut out = stdout.lock();
                        let _ = out.write_all(data);
                        let _ = out.flush();
                    }
                }
                Err(_) => break,
            }
        }
        done_a.store(true, Ordering::Release);
    });

    // ---- thread B: handle password injection (vault subprocess or in-proc secret) ----
    let pending_inj_b = pending_inject.clone();
    let done_b = done.clone();
    #[cfg_attr(all(unix, not(feature = "in_proc_inject")), allow(unused_variables))]
    let (inject_tx, inject_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    let inject_meta: Arc<Mutex<Option<(u32, u64, String)>>> = Arc::new(Mutex::new(None));

    #[cfg(unix)]
    let vault_id: Option<Uuid> = match cred {
        PtyCredential::VaultRecord(id) => Some(id),
        PtyCredential::None => None,
        #[cfg(feature = "in_proc_inject")]
        PtyCredential::Secret(_) => None,
        #[cfg(all(unix, not(feature = "in_proc_inject")))]
        PtyCredential::_Reserved(_) => None,
    };

    #[cfg_attr(all(unix, not(feature = "in_proc_inject")), allow(unused_variables))]
    let preset_for_inj: Option<String> = match cred {
        PtyCredential::None => None,
        #[cfg(unix)]
        PtyCredential::VaultRecord(_) => None,
        #[cfg(any(not(unix), feature = "in_proc_inject"))]
        PtyCredential::Secret(s) => Some(s.expose().to_string()),
        #[cfg(all(unix, not(feature = "in_proc_inject")))]
        PtyCredential::_Reserved(_) => None,
    };

    let meta_for_thread = inject_meta.clone();
    let inject_completed_b = inject_completed.clone();
    let stdin_forward_b = stdin_forward_enabled.clone();
    let pending_field_b = pending_field.clone();
    let injected_fields_b = injected_fields.clone();
    let inject_fields_b = inject_fields.clone();
    let inject_done_count_b = inject_done_count.clone();
    let elevation_attempts_b = elevation_attempts.clone();
    let ssh_login_done_b = ssh_login_done.clone();
    let inner_ssh_login_done_b = inner_ssh_login_done.clone();
    let pending_record_id_b = pending_record_id.clone();
    let pending_is_elevation_b = pending_is_elevation.clone();
    let suppress_stdout_b = suppress_stdout.clone();
    let suppress_until_post_auth_b = suppress_until_post_auth.clone();
    let bastion_outer_b = bastion_outer_hop;
    let dual_ssh_inject_b = dual_ssh_inject;
    let rescan_after_inject_b = rescan_after_inject.clone();
    let injector = thread::spawn(move || {
        while !done_b.load(Ordering::Acquire) {
            if pending_inj_b.swap(false, Ordering::AcqRel) {
                let is_elevation = pending_is_elevation_b.load(Ordering::Acquire);
                thread::sleep(inject_settle_delay(is_elevation, bastion_outer_b));
                #[cfg(unix)]
                if let Some(fd) = master_raw_fd {
                    let field = pending_field_b
                        .lock()
                        .ok()
                        .and_then(|mut g| g.take())
                        .unwrap_or_else(|| "password".into());
                    let rid = pending_record_id_b
                        .lock()
                        .ok()
                        .and_then(|mut g| g.take())
                        .or(vault_id);
                    if let Some(rid) = rid {
                        match crate::runtime::injector_child::spawn_injector_child(rid, fd, &field)
                        {
                            Ok((code, dur, pid, out)) => {
                                if let Ok(mut g) = meta_for_thread.lock() {
                                    *g = Some((pid.unwrap_or(0), dur, out.clone()));
                                }
                                if code == 0 {
                                    if let Ok(mut g) = injected_fields_b.lock() {
                                        g.insert(field.clone());
                                    }
                                    if is_elevation {
                                        elevation_attempts_b.fetch_add(1, Ordering::AcqRel);
                                    } else if ssh_login_done_b.load(Ordering::Acquire) {
                                        inner_ssh_login_done_b.store(true, Ordering::Release);
                                    } else {
                                        ssh_login_done_b.store(true, Ordering::Release);
                                    }
                                    crate::runtime::pty_drain::ensure_pty_echo_on(fd);
                                    suppress_until_post_auth_b.store(false, Ordering::Release);
                                    if !is_elevation {
                                        let suppress_until = suppress_until_post_auth_b.clone();
                                        thread::spawn(move || {
                                            thread::sleep(Duration::from_millis(250));
                                            suppress_until.store(false, Ordering::Release);
                                        });
                                    }
                                    thread::sleep(Duration::from_millis(if is_elevation {
                                        45
                                    } else {
                                        35
                                    }));
                                    suppress_stdout_b.store(false, Ordering::Release);
                                    rescan_after_inject_b.store(true, Ordering::Release);
                                    let n = inject_done_count_b.fetch_add(1, Ordering::AcqRel) + 1;
                                    let inner_done =
                                        inner_ssh_login_done_b.load(Ordering::Acquire);
                                    let dual_hop_pending =
                                        dual_ssh_inject_b && !inner_done;
                                    if !dual_hop_pending && n >= inject_fields_b.len() {
                                        inject_completed_b.store(true, Ordering::Release);
                                    }
                                    stdin_forward_b.store(true, Ordering::Release);
                                } else {
                                    let _ = std::io::stderr().write_all(
                                        format!("brokre: injector exited {} ({})\n", code, out)
                                            .as_bytes(),
                                    );
                                }
                            }
                            Err(e) => {
                                let _ = std::io::stderr().write_all(
                                    format!("brokre: injector failed: {}\n", e).as_bytes(),
                                );
                            }
                        }
                        continue;
                    }
                }

                #[cfg(any(not(unix), feature = "in_proc_inject"))]
                if let Some(ref pw) = preset_for_inj {
                    let mut payload = pw.as_bytes().to_vec();
                    payload.push(b'\r');
                    let _ = inject_tx.send(payload);
                    inject_completed_b.store(true, Ordering::Release);
                    stdin_forward_b.store(true, Ordering::Release);
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    // ---- thread C: stdin -> channel (TTY or pipe) ----
    let pipe_eof = Arc::new(AtomicBool::new(false));
    let pipe_eof_sent = Arc::new(AtomicBool::new(false));
    let stdin_rx_slot: Arc<Mutex<Option<std::sync::mpsc::Receiver<Vec<u8>>>>> =
        Arc::new(Mutex::new(None));
    if stdin_is_pipe || stdin_is_tty {
        *stdin_rx_slot.lock().unwrap() = Some(spawn_stdin_reader(
            pipe_eof.clone(),
            stdin_is_pipe,
        ));
    }

    let cap_main = captured.clone();
    let pending_cap_main = pending_capture.clone();
    let stdin_forward_main = stdin_forward_enabled.clone();
    let post_auth_main = post_auth.clone();
    let elevation_attempts_main = elevation_attempts.clone();
    let defer_stdin_main = defer_stdin;
    let bastion_outer_main = bastion_outer_hop;
    let spawn_instant = Instant::now();
    let raw_mode_main = raw_mode.clone();
    let stdin_rx_slot_main = stdin_rx_slot.clone();

    loop {
        #[cfg(unix)]
        if let Some(ref sig) = sigint_forward {
            if sig.take_pending() {
                if pending_cap_main.load(Ordering::Acquire) {
                    pending_cap_main.store(false, Ordering::Release);
                    let mut g = cap_main.lock().unwrap();
                    *g = None;
                }
                let _ = writer.write_all(&[0x03]);
                let _ = writer.flush();
            }
        }

        while let Ok(payload) = inject_rx.try_recv() {
            let _ = writer.write_all(&payload);
            let _ = writer.flush();
        }

        // Open stdin forwarding once injection succeeded or SSH post-auth is visible.
        if !stdin_forward_main.load(Ordering::Acquire) {
            let enable = if defer_stdin_main {
                if bastion_outer_main {
                    // Inner brokre on the bastion owns sudo/su; forward stdin after outer SSH login.
                    post_auth_main.load(Ordering::Acquire)
                        && !pending_inject.load(Ordering::Acquire)
                        && spawn_instant.elapsed() >= Duration::from_secs(1)
                } else {
                    post_auth_main.load(Ordering::Acquire)
                        && elevation_attempts_main.load(Ordering::Acquire) >= 1
                        && !pending_inject.load(Ordering::Acquire)
                        && spawn_instant.elapsed() >= Duration::from_secs(1)
                }
            } else {
                inject_completed.load(Ordering::Acquire)
                    || (preset_some && post_auth_main.load(Ordering::Acquire))
                    || (preset_some
                        && !pending_inject.load(Ordering::Acquire)
                        && spawn_instant.elapsed() >= Duration::from_secs(2))
                    || (!preset_some
                        && !pending_capture.load(Ordering::Acquire)
                        && !pending_inject.load(Ordering::Acquire)
                        && spawn_instant.elapsed() >= Duration::from_secs(1))
            };
            if enable {
                stdin_forward_main.store(true, Ordering::Release);
            }
        }

        let tty_raw_ready = tty_raw_mode_ready(
            pending_cap_main.load(Ordering::Acquire),
            pending_inject.load(Ordering::Acquire),
        );
        try_enable_interactive_raw(&raw_mode_main, stdin_is_tty, tty_raw_ready);

        let stdin_rx = stdin_rx_slot_main.lock().unwrap();
        if stdin_forward_main.load(Ordering::Acquire) {
            if let Some(ref rx) = *stdin_rx {
                while let Ok(data) = rx.try_recv() {
                    if stdin_is_tty {
                        for &b in &data {
                            if pending_cap_main.load(Ordering::Acquire) {
                                if b == b'\r' || b == b'\n' {
                                    pending_cap_main.store(false, Ordering::Release);
                                } else if b == 0x7f || b == 0x08 {
                                    let mut g = cap_main.lock().unwrap();
                                    if let Some(s) = g.as_mut() {
                                        s.pop();
                                    }
                                } else if b >= 0x20 {
                                    let mut g = cap_main.lock().unwrap();
                                    if let Some(s) = g.as_mut() {
                                        s.push(b as char);
                                    }
                                }
                            }
                        }
                    }
                    let _ = writer.write_all(&data);
                    let _ = writer.flush();
                }
                // Pipe EOF: signal EOT to PTY so remote readers (cat, tar) terminate.
                if stdin_is_pipe
                    && pipe_eof.load(Ordering::Acquire)
                    && !pipe_eof_sent.load(Ordering::Acquire)
                    && matches!(
                        rx.try_recv(),
                        Err(std::sync::mpsc::TryRecvError::Disconnected)
                    )
                {
                    pipe_eof_sent.store(true, Ordering::Release);
                    let _ = writer.write_all(&[0x04]);
                    let _ = writer.flush();
                }
            }
        }

        match child.try_wait() {
            Ok(Some(_status)) => {
                let deadline = std::time::Instant::now() + Duration::from_millis(150);
                while !done.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    while let Ok(payload) = inject_rx.try_recv() {
                        let _ = writer.write_all(&payload);
                        let _ = writer.flush();
                    }
                    if stdin_forward_main.load(Ordering::Acquire) {
                        if let Some(ref rx) = *stdin_rx_slot_main.lock().unwrap() {
                            while let Ok(data) = rx.try_recv() {
                                let _ = writer.write_all(&data);
                                let _ = writer.flush();
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }

        thread::sleep(Duration::from_millis(15));
    }

    let exit_status = child
        .wait()
        .map_err(|e| BrokreError::Runtime(format!("child wait: {}", e)))?;
    let exit_code = exit_status.exit_code() as i32;

    done.store(true, Ordering::Release);
    drop(master);
    // scanner thread may be stuck in a blocking read() after master is dropped;
    // don't wait forever — cap at 500 ms.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while !scanner.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let _ = injector.join();
    // stdin thread intentionally not joined — it may be blocked on stdin read.
    // The process (or test) will terminate and reap it.

    let captured_pw = captured.lock().unwrap().take().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(SecretString::new(s))
        }
    });
    let had = had_prompt.load(Ordering::Acquire);

    let (inj_pid, inj_dur, inj_out) = inject_meta
        .lock()
        .unwrap()
        .take()
        .map(|(p, d, o)| (Some(p), Some(d), Some(o)))
        .unwrap_or((None, None, None));

    Ok(PtyRunResult {
        exit_code,
        captured_password: captured_pw,
        had_prompt: had,
        injector_pid: inj_pid,
        injector_dur_ms: inj_dur,
        injector_outcome: inj_out,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        contains_ascii_case_insensitive, initial_stdin_forward_enabled, should_arm_vault_inject,
        ssh_post_auth_indicated, tty_raw_mode_ready, PtyRunOptions, VaultInjectPrompt,
    };

    fn pw_prompt(
        is_elevation: bool,
        is_ssh_login: bool,
        is_inner_hop: bool,
        ssh_done: bool,
        inner_done: bool,
        elev_attempts: usize,
        auth_failed: bool,
    ) -> VaultInjectPrompt<'static> {
        VaultInjectPrompt {
            is_elevation_prompt: is_elevation,
            is_ssh_login_prompt: is_ssh_login,
            is_inner_hop_ssh_prompt: is_inner_hop,
            field: "password",
            ssh_login_done: ssh_done,
            inner_ssh_login_done: inner_done,
            elevation_attempts: elev_attempts,
            auth_failed_visible: auth_failed,
        }
    }

    #[test]
    fn bastion_outer_hop_injects_bastion_ssh_then_inner_from_mac_vault() {
        let outer = PtyRunOptions {
            bastion_outer_hop: true,
            ..Default::default()
        };
        assert!(should_arm_vault_inject(
            &outer,
            &pw_prompt(false, true, false, false, false, 0, false),
        ));
        assert!(!should_arm_vault_inject(
            &outer,
            &pw_prompt(true, false, false, true, false, 0, false),
        ));
        let outer_inner = PtyRunOptions {
            bastion_outer_hop: true,
            inner_vault_record: Some(uuid::Uuid::new_v4()),
            inner_host_hint: Some("10.0.0.7".into()),
            ..Default::default()
        };
        assert!(should_arm_vault_inject(
            &outer_inner,
            &pw_prompt(false, true, false, false, false, 0, false),
        ));
        assert!(should_arm_vault_inject(
            &outer_inner,
            &pw_prompt(false, true, true, false, false, 0, false),
        ));
        assert!(should_arm_vault_inject(
            &outer_inner,
            &pw_prompt(false, true, false, true, false, 0, false),
        ));
        assert!(!should_arm_vault_inject(
            &outer_inner,
            &pw_prompt(false, true, false, true, true, 0, false),
        ));
        assert!(!should_arm_vault_inject(
            &outer_inner,
            &pw_prompt(true, false, false, true, false, 0, false),
        ));
        assert!(should_arm_vault_inject(
            &outer_inner,
            &pw_prompt(true, false, false, true, true, 0, false),
        ));
    }

    #[test]
    fn passive_inner_injects_headless_ssh_from_bastion_vault() {
        let inner = PtyRunOptions {
            passive_inner_ssh: true,
            ..Default::default()
        };
        assert!(should_arm_vault_inject(
            &inner,
            &pw_prompt(false, true, false, false, false, 0, false),
        ));
        assert!(!should_arm_vault_inject(
            &inner,
            &pw_prompt(false, true, false, true, false, 0, false),
        ));
        assert!(should_arm_vault_inject(
            &inner,
            &pw_prompt(true, false, false, true, false, 0, false),
        ));
    }

    #[test]
    fn elevation_retry_only_after_auth_failed() {
        let direct = PtyRunOptions::default();
        assert!(should_arm_vault_inject(
            &direct,
            &pw_prompt(true, false, false, true, false, 0, false),
        ));
        assert!(!should_arm_vault_inject(
            &direct,
            &pw_prompt(true, false, false, true, false, 1, false),
        ));
        assert!(should_arm_vault_inject(
            &direct,
            &pw_prompt(true, false, false, true, false, 1, true),
        ));
        assert!(!should_arm_vault_inject(
            &direct,
            &pw_prompt(true, false, false, true, false, 2, true),
        ));
    }

    #[test]
    fn direct_ssh_allows_first_elevation_inject() {
        let direct = PtyRunOptions::default();
        assert!(should_arm_vault_inject(
            &direct,
            &pw_prompt(true, false, false, true, false, 0, false),
        ));
    }

    #[test]
    fn post_auth_detects_ubuntu_welcome() {
        assert!(ssh_post_auth_indicated(
            b" * Documentation:  https://help.ubuntu.com\nWelcome to Ubuntu 25.10 (GNU/Linux)\n"
        ));
    }

    #[test]
    fn post_auth_detects_last_login() {
        assert!(ssh_post_auth_indicated(
            b"Last login: Mon May 18 08:41:12 2026 from 198.51.100.1\n"
        ));
    }

    #[test]
    fn motd_line_ending_password_not_post_auth_alone() {
        let line = b"Configure your account password: ";
        assert!(!ssh_post_auth_indicated(line));
        assert!(contains_ascii_case_insensitive(line, b"password"));
    }

    #[test]
    fn post_auth_detects_root_shell_prompt() {
        assert!(ssh_post_auth_indicated(b"[root@sc ~]# "));
    }

    #[test]
    fn interactive_raw_ready_without_capture_or_inject() {
        assert!(!tty_raw_mode_ready(true, false));
        assert!(!tty_raw_mode_ready(false, true));
        assert!(tty_raw_mode_ready(false, false));
    }

    #[test]
    fn passive_inner_enables_immediate_stdin_forward() {
        assert!(!initial_stdin_forward_enabled(true, true, false, false));
        assert!(initial_stdin_forward_enabled(true, true, true, false));
        assert!(!initial_stdin_forward_enabled(true, true, true, true));
        assert!(initial_stdin_forward_enabled(true, false, false, false));
    }
}
