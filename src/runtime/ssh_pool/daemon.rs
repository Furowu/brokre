//! Sidecar daemon: Unix socket ↔ one persistent SSH remote script loop.

use crate::runtime::pipe_exec;
use crate::runtime::prompts::patterns_for;
use crate::runtime::ssh_identity::{
    build_mux_session_argv, insert_default_ssh_timeouts, insert_identity_arg_for_profile,
    insert_mux_options, materialize_identity, openssh_connection_target_index_for_profile,
};
use crate::runtime::ssh_pool::pool::pool_pid_path;
use crate::utils::errors::{BrokreError, Result};
use crate::vault::model::SecretRecord;
use crate::vault::store::VaultStore;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::io::{AsRawFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const IDLE_SECS: u64 = 600;
const REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(60);

struct SshBridge {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    _askpass: crate::runtime::pipe_exec::AskpassGuard,
}

impl SshBridge {
    fn call(&mut self, method: &str, params: &Value) -> Result<String> {
        let params_line =
            serde_json::to_string(params).map_err(|e| BrokreError::Runtime(e.to_string()))?;
        self.stdin
            .write_all(format!("{method}\n{params_line}\n").as_bytes())
            .map_err(BrokreError::Io)?;
        self.stdin.flush().map_err(BrokreError::Io)?;

        let line = read_line_with_timeout(&mut self.stdout, REMOTE_READ_TIMEOUT)?;
        if line.trim().is_empty() {
            return Err(BrokreError::Runtime(
                "ssh pool: empty line from remote".into(),
            ));
        }
        Ok(line)
    }
}

pub fn serve(record_id: Uuid, script: &str, socket: &Path) -> Result<()> {
    let store = VaultStore::open()?;
    let rec = store
        .get_by_id(&record_id)?
        .ok_or_else(|| BrokreError::Runtime("ssh pool: vault record not found".into()))?;

    let pid_path = pool_pid_path(&rec.name);
    let _ = fs::write(&pid_path, std::process::id().to_string());

    if socket.exists() {
        let _ = fs::remove_file(socket);
    }
    let listener = UnixListener::bind(socket).map_err(BrokreError::Io)?;
    listener.set_nonblocking(true).map_err(BrokreError::Io)?;

    let mut bridge = open_ssh_bridge(&rec, script)?;
    bridge.call("health", &json!({}))?;
    let bridge = Arc::new(Mutex::new(bridge));
    let last_active = Arc::new(Mutex::new(Instant::now()));

    loop {
        {
            let last = last_active.lock().map_err(|_| lock_err())?;
            if last.elapsed() > Duration::from_secs(idle_secs()) {
                break;
            }
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                *last_active.lock().map_err(|_| lock_err())? = Instant::now();
                if let Err(e) = handle_client(&bridge, &mut stream) {
                    eprintln!("brokre: ssh pool client error: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(BrokreError::Io(e)),
        }
    }

    if let Ok(mut guard) = bridge.lock() {
        let _ = guard.child.kill();
        let _ = guard.child.wait();
    }
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(pid_path);
    Ok(())
}

fn read_line_with_timeout(
    reader: &mut BufReader<std::process::ChildStdout>,
    timeout: Duration,
) -> Result<String> {
    let fd = reader.get_ref().as_raw_fd();
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
    let n = poll(
        &mut fds,
        PollTimeout::try_from(timeout).unwrap_or(PollTimeout::NONE),
    )
    .map_err(|e| BrokreError::Runtime(format!("ssh pool poll: {e}")))?;
    if n == 0 {
        return Err(BrokreError::Runtime("ssh pool: remote read timeout".into()));
    }
    let mut line = String::new();
    reader.read_line(&mut line).map_err(BrokreError::Io)?;
    Ok(line)
}

fn idle_secs() -> u64 {
    std::env::var("BROKRE_SSH_POOL_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(IDLE_SECS)
}

fn lock_err() -> BrokreError {
    BrokreError::Runtime("ssh pool bridge lock poisoned".into())
}

fn handle_client(bridge: &Arc<Mutex<SshBridge>>, stream: &mut UnixStream) -> Result<()> {
    stream
        .set_read_timeout(Some(REMOTE_READ_TIMEOUT))
        .map_err(BrokreError::Io)?;
    stream
        .set_write_timeout(Some(REMOTE_READ_TIMEOUT))
        .map_err(BrokreError::Io)?;
    let mut req_line = String::new();
    {
        let mut reader = BufReader::new(stream.try_clone().map_err(BrokreError::Io)?);
        reader.read_line(&mut req_line).map_err(BrokreError::Io)?;
    }
    let req: Value = serde_json::from_str(req_line.trim())
        .map_err(|e| BrokreError::Runtime(format!("ssh pool bad request: {e}")))?;
    let method = req
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrokreError::Runtime("ssh pool request missing method".into()))?;
    let params = req
        .get("params")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    let resp_line = {
        let mut guard = bridge.lock().map_err(|_| lock_err())?;
        guard.call(method, &params)?
    };
    stream
        .write_all(resp_line.as_bytes())
        .map_err(BrokreError::Io)?;
    if !resp_line.ends_with('\n') {
        stream.write_all(b"\n").map_err(BrokreError::Io)?;
    }
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}

fn open_ssh_bridge(rec: &SecretRecord, script: &str) -> Result<SshBridge> {
    let remote_loop = remote_pool_shell(script);
    let mut argv = rec.saved_args.clone();
    insert_default_ssh_timeouts("ssh", &mut argv);
    insert_mux_options(&mut argv);
    let _key_guard = match materialize_identity(rec)? {
        Some(guard) => {
            insert_identity_arg_for_profile("ssh", &mut argv, &guard.path);
            Some(guard)
        }
        None => None,
    };
    let target_idx = openssh_connection_target_index_for_profile("ssh", &argv);
    argv.insert(target_idx, "-T".into());
    argv.push("bash".into());
    argv.push("-c".into());
    argv.push(remote_loop);

    let patterns = patterns_for("ssh");
    pipe_exec::ensure_ssh_mux_master_for_argv("ssh", &argv, rec.id, &patterns)?;

    let session_argv = build_mux_session_argv(&argv);
    let bin =
        which::which("ssh").map_err(|_| BrokreError::Runtime("ssh: command not found".into()))?;
    let mut cmd = Command::new(bin);
    for a in &session_argv {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let askpass = pipe_exec::configure_askpass_for_command(&mut cmd, rec.id)?;

    let mut child = cmd
        .spawn()
        .map_err(|e| BrokreError::Runtime(format!("ssh pool spawn: {e}")))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| BrokreError::Runtime("ssh stdin missing".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BrokreError::Runtime("ssh stdout missing".into()))?;

    Ok(SshBridge {
        child,
        stdin,
        stdout: BufReader::new(stdout),
        _askpass: askpass,
    })
}

fn remote_pool_shell(script: &str) -> String {
    let script_q = crate::bastion::route::shell_escape(script);
    format!(
        "RPC={script_q}; \
while IFS= read -r method; do \
[ -z \"$method\" ] && continue; \
IFS= read -r params || params='{{}}'; \
printf '%s' \"$params\" | bash \"$RPC\" \"$method\"; \
done"
    )
}
