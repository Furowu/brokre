# Orphan SSH Cleanup Implementation Plan

> Executed 2026-08-19. Do not leave MCP `brokre_list --probe` SSH children as PPID=1 orphans.

**Goal:** MCP/CLI cancel or timeout kills the whole `brokre → ssh` process group; remote commands do not attach to mux; stale `askpass_*` files are pruned.

**Architecture:** Per-call `SessionTracker` + `SessionChildGuard` (`setpgid` / `killpg`). `run_on_bastion` and MCP list use 60s timeouts. MCP exec uses `process_group(0)` + `kill(-pid)`. Remote commands inject `ControlPath=none`. Askpass state stays an invocation counter; owner pid lives in a `.owner` sidecar.

**Tech Stack:** Rust, libc/nix killpg, tokio process, OpenSSH argv injection

## Global Constraints

- Cargo only from `/Volumes/EXDATA01/dbk/rust`
- Examples/tests: `b150`, `10.0.0.x`, `user@10.0.0.1` — no real intranet hosts
- List timeout must not call process-wide `terminate_process_sessions` (would kill concurrent exec)
- Do not kill ControlPersist mux masters (`ssh -N -f`)

## Locked defaults

- `BROKRE_BASTION_RPC_TIMEOUT` = 60
- `BROKRE_MCP_LIST_TIMEOUT` = 60
- `BROKRE_MCP_EXEC_TIMEOUT` = 120
