use crate::utils::errors::{BrokreError, Result};
use std::path::PathBuf;
use std::process::Command;

pub fn run() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| crate::utils::errors::BrokreError::Runtime(e.to_string()))?;
    rt.block_on(crate::mcp::run_mcp_server())
}

/// Re-run npm `brokre-setup-mcp` — register brokre in detected IDEs.
pub fn run_setup(dry_run: bool, force: bool) -> Result<()> {
    let mut extra = Vec::new();
    if dry_run {
        extra.push("--dry-run");
    }
    if force {
        extra.push("--force");
    }

    if let Ok(bin) = which::which("brokre-setup-mcp") {
        let mut cmd = Command::new(bin);
        return run_command(&mut cmd, &extra);
    }

    if let Some(script) = resolve_setup_script() {
        let node = which::which("node").map_err(|_| missing_node_error())?;
        let mut cmd = Command::new(node);
        cmd.arg(script);
        return run_command(&mut cmd, &extra);
    }

    let npx = which::which("npx").map_err(|_| missing_node_error())?;
    let mut cmd = Command::new(npx);
    cmd.args(["-y", "--package=brokre@latest", "brokre-setup-mcp"]);
    run_command(&mut cmd, &extra)
}

fn run_command(cmd: &mut Command, extra: &[&str]) -> Result<()> {
    cmd.args(extra);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    let status = cmd
        .status()
        .map_err(|e| BrokreError::Runtime(format!("mcp setup: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(BrokreError::Runtime(format!(
            "mcp setup exited with {}",
            status.code().unwrap_or(-1)
        )))
    }
}

fn missing_node_error() -> BrokreError {
    BrokreError::Runtime(
        "mcp setup requires Node.js (node + npx) or brokre-setup-mcp on PATH — \
         install: npm install -g brokre"
            .into(),
    )
}

/// Locate `packages/brokre-mcp/setup-mcp.js` (dev tree) or `BROKRE_MCP_SETUP_SCRIPT`.
fn resolve_setup_script() -> Option<PathBuf> {
    if let Ok(raw) = std::env::var("BROKRE_MCP_SETUP_SCRIPT") {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("packages/brokre-mcp/setup-mcp.js");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let mut dir = exe.parent()?.to_path_buf();
    for _ in 0..6 {
        let candidate = dir.join("packages/brokre-mcp/setup-mcp.js");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_setup_script_finds_repo_file() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let expected = manifest.join("packages/brokre-mcp/setup-mcp.js");
        assert!(
            expected.is_file(),
            "missing {}",
            expected.display()
        );
        std::env::set_var(
            "BROKRE_MCP_SETUP_SCRIPT",
            expected.to_string_lossy().as_ref(),
        );
        let resolved = resolve_setup_script().expect("BROKRE_MCP_SETUP_SCRIPT");
        assert_eq!(resolved, expected);
        std::env::remove_var("BROKRE_MCP_SETUP_SCRIPT");
    }
}
