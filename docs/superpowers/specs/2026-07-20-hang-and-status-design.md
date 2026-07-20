# Hang Resilience & List Status Design

**Date:** 2026-07-20  
**Status:** approved — code landed; awaiting EXDATA cargo build/test  
**Scope:** CLI + MCP (no new UI pages)

## Problem

1. **SSH / MCP “卡死”**：对不可达主机，brokre 不注入 `ConnectTimeout`，OpenSSH 在路由黑洞时可傻等 ~75s；MCP `brokre_exec` 亦无总体超时。
2. **`status=unknown`**：探测已实现，但默认关闭；`brokre list` / `brokre_list` 不探测时永远 unknown。开启 `--probe` 时又默认隐藏不可达，体验像“没探测能力”。
3. **次要**：mux 残留 / `Shared connection closed` 后退出挂起；堡垒解锁 poll 最长 90s 时像卡死。

## Goals

- 不可达主机在 **≤5s** 内失败返回，不出现分钟级傻等。
- `brokre list` 默认给出可用的 reachability `status`（available / unavailable / unknown）。
- MCP exec 有明确总超时与可操作错误。
- mux / exit 路径不再因复用会话而挂死。
- 堡垒解锁超时错误可操作（含 auth 提示），不无声阻塞。

## Non-Goals

- 不重写 PTY/mux 为全异步运行时。
- 不默认强制“probe 失败则禁止 SSH”（可作为后续可选开关）。
- 不新增 Manage UI 页面。
- 不改变 vault / 凭据注入安全模型。

## Decisions (locked)

| 项 | 决定 |
|----|------|
| SSH `ConnectTimeout` 默认 | **5 秒**（用户确认：超过 5s 无必要再连） |
| 覆盖方式 | 用户已传 `-o ConnectTimeout=…` 或 env 覆盖时不二次注入 |
| List 默认探测 | **默认开启**本地 TCP/SSH-banner 探测 |
| List 过滤 | 默认**显示全部**；仅显式 `--reachable-only`（MCP 同名）才隐藏不可达 |
| MCP exec 总超时 | 默认 **120s**（覆盖多跳/sudo 会话；与 5s 连接超时正交） |
| 方案基线 | 方案 1：超时护栏 + list UX + mux 收尾（不做强门禁 / 不大改异步） |

## Architecture

```
brokre list / brokre_list
  → resolve_list_options (probe=true by default; reachable_only only if flag)
  → probe_items (400ms, concurrency 16, cache 5s) + DNS resolve timeout
  → format_status_display → available|unavailable|unknown

brokre ssh / brokre_exec
  → insert_default_ssh_timeouts (ConnectTimeout=5, ServerAlive*)
  → insert_mux_options / prune_stale_mux_sockets
  → remote command ⇒ prefer ControlMaster=no (no mux attach)
  → MCP: tokio::time::timeout(BROKRE_MCP_EXEC_TIMEOUT) around run_brokre_cli
  → on timeout: SIGTERM process group via child_guard, return JSON error
```

## Component Changes

### 1. OpenSSH connect timeouts

**Where:** `src/runtime/ssh_identity.rs`（与 `insert_mux_options` 同层，例如 `insert_default_ssh_timeouts`）

**Inject when missing:**

- `-o ConnectTimeout=5`（`BROKRE_SSH_CONNECT_TIMEOUT`，默认 `5`）
- `-o ServerAliveInterval=15`
- `-o ServerAliveCountMax=2`（存活探测约 30s 上界，防半开连接挂死）

**Rules:**

- 扫描 argv 已有同名 `-o` 则跳过该项。
- 仅作用于 OpenSSH 系 profile（`ssh` / `scp` / `sftp`）。
- 在 mux 插入之前或之后均可，但必须在 spawn 前完成。

### 2. MCP exec wall-clock timeout

**Where:** `src/mcp/server.rs` → `run_brokre_cli`（及 elevated 走 CLI 的路径）

- `BROKRE_MCP_EXEC_TIMEOUT` 默认 `120`（秒）。
- `tokio::time::timeout` 包裹 `Command::output()`；超时杀子进程树，返回：
  - `exit_code: -1`（或约定码）
  - `stderr` / 错误字段含 `exec timed out after Ns`
- elevated session 的 per-command 超时已有 `BROKRE_MCP_SESSION_CMD_TIMEOUT`（默认 120）——保持，并在文档中并列说明。

### 3. List status defaults

**Where:** `src/bastion/list_policy.rs`, `src/cli/list.rs`, `src/main.rs`, `src/mcp/server.rs`

| 字段 | 旧默认 | 新默认 |
|------|--------|--------|
| `probe` | `false` | `true` |
| `reachable_only` | `probe && !show_all` | `false`，仅 `--reachable-only` / MCP `reachable_only=true` |
| `--all` / `all` | 在 probe 时取消过滤 | 保留为兼容别名：等价于“不要 reachable_only”（与新默认重叠时无害） |
| `--no-probe` | 无 | **新增**：显式关闭探测（快列元数据） |

`unknown` 仅当无法推断 host:port（或探测被 `--no-probe` 关闭）。

CLI 帮助与 MCP tool description 同步更新。

### 4. Mux / exit hardening

**Where:** `src/runtime/ssh_identity.rs`, `src/runtime/pipe_exec.rs`, `src/runtime/pty.rs`, `src/cli/exec.rs`

- 每次 OpenSSH 执行前：`prune_stale_mux_sockets`。
- 存在 **remote command**（非空 trailing，且非仅交互登录）时：强制 `ControlMaster=no`（不 attach 既有 master），避免 `Shared connection … closed` 后 `child.wait` 挂起。
- PTY 与 pipe/MCP 路径统一：检测到 `Shared connection` + `closed` 则尽快结束 wait（已有 PTY 逻辑则补齐 pipe）。
- 不删除 ControlPersist 复用（交互登录仍可受益）。

### 5. Bastion unlock UX

**Where:** `src/bastion/mcp_gate.rs`, `src/bastion/gate.rs`

- 默认 poll **90s** 不变（`BROKRE_BASTION_POLL_SECS`）。
- 超时错误文案固定包含：auth URL 提示 + “retry after unlock”。
- 不在本轮缩短默认，以免正常浏览器解锁被误杀。

### 6. Probe DNS safety

**Where:** `src/bastion/probe.rs`

- `to_socket_addrs` 放入带超时的线程/select（上限 = probe timeout），避免 DNS 挂死整个 `list --probe`。

## Environment Variables

| Var | Default | Purpose |
|-----|---------|---------|
| `BROKRE_SSH_CONNECT_TIMEOUT` | `5` | OpenSSH ConnectTimeout 秒 |
| `BROKRE_MCP_EXEC_TIMEOUT` | `120` | MCP `brokre_exec` 总超时秒 |
| `BROKRE_PROBE_TIMEOUT_MS` | `400` | 已有 |
| `BROKRE_PROBE_CONCURRENCY` | `16` | 已有 |
| `BROKRE_PROBE_CACHE_SECS` | `5` | 已有 |
| `BROKRE_BASTION_POLL_SECS` | `90` | 已有 |
| `BROKRE_MCP_SESSION_CMD_TIMEOUT` | `120` | 已有（elevated） |

## Feature Change Table

| 类型 | 功能 | 说明 |
|------|------|------|
| 修改 | CLI `brokre list` | 默认探测；默认显示不可达；新增 `--no-probe` / `--reachable-only` |
| 修改 | MCP `brokre_list` | 默认 probe；新增 `reachable_only`；`no_probe` 或 `probe:false` |
| 修改 | CLI OpenSSH 包装 | 默认 ConnectTimeout=5 + ServerAlive |
| 修改 | MCP `brokre_exec` | 总超时 120s + 杀进程树 |
| 修改 | mux / PTY / pipe | prune + remote-command 不 attach + exit 收尾 |
| 修改 | 堡垒解锁错误 | 超时文案可操作 |
| 修改 | probe DNS | 解析超时 |
| 新增 | env 文档 | `BROKRE_SSH_CONNECT_TIMEOUT` / `BROKRE_MCP_EXEC_TIMEOUT` |
| 删除 | 无页面删除 | 删除的是“默认不探测 + probe 时隐藏不可达”的组合默认行为 |

## Testing

1. **单元：** argv 注入跳过已有 ConnectTimeout；`resolve_list_options` 新默认；DNS 超时返回 unreachable。
2. **集成（本机）：** 对黑洞/不可达 IP，`brokre ssh alias true` 在 ≤6s 内退出非 0；`brokre list` 无 flag 即出现 available/unavailable。
3. **MCP：** `brokre_exec` 对不可达 alias 快速失败；人为长命令验证 120s 总超时（可用短 env 测）。
4. **回归：** 可达主机（如当前 available 的 bastion）仍可在 ConnectTimeout=5 内连上；用户 `-o ConnectTimeout=30` 不被覆盖。
5. **mux：** remote command 后进程退出；无残留卡死 sock（或可被 prune）。

## Risks

| 失败模式 | 缓解 |
|----------|------|
| 高延迟链路 5s 内 TCP 未建成就失败 | `BROKRE_SSH_CONNECT_TIMEOUT` 或 `-o ConnectTimeout=` 覆盖；README 写明 |
| list 默认探测拖慢大量 alias | 400ms + 并发 16 + 5s 缓存；`--no-probe` 逃生 |
| remote-command 禁用 mux 使密集脚本变慢 | 可接受；交互登录仍复用；文档说明 |
| MCP 120s 仍长于“体感卡死” | 连接层已是 5s；120s 只挡长命令/sudo；可调 env |

## Rollout

1. 实现 + 单测。
2. 本地用现有 vault alias 验证不可达快失败、list status。
3. 更新 README / packages/brokre-mcp README 默认行为说明。
4. 发版 notes 标明 **breaking UX**：`list` 默认变慢一点但有 status；`--probe` 不再隐含过滤。
