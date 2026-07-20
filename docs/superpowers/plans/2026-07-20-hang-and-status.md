# Hang Resilience & List Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 不可达 SSH ≤5s 失败；list 默认有 status；MCP exec 有总超时；mux/exit 与堡垒超时文案加固。

**Architecture:** 在 OpenSSH argv 注入 ConnectTimeout=5；list_policy 默认 probe 且不隐藏不可达；MCP `run_brokre_cli` 加 wall-clock timeout；remote-command 禁用 mux attach；probe DNS 带超时。

**Tech Stack:** Rust, clap, tokio, OpenSSH options

## Global Constraints

- `BROKRE_SSH_CONNECT_TIMEOUT` 默认 `5`
- List 默认 `probe=true`，`reachable_only` 仅显式开启
- MCP exec 默认超时 `120` 秒
- 编译仅允许 `/Volumes/EXDATA01/dbk/rust` cargo；不可用时不得私自下载
- 开源隐私：示例/测试用虚构 host（`10.0.0.x` / `example.com`）

## Feature Change Table

| 类型 | 功能 | 说明 |
|------|------|------|
| 修改 | CLI/MCP list | 默认探测；`--no-probe` / `--reachable-only` |
| 修改 | OpenSSH argv | ConnectTimeout=5 + ServerAlive |
| 修改 | MCP exec | 120s 总超时 |
| 修改 | mux/pipe | prune + remote-command 不 attach |
| 修改 | probe DNS | 解析超时 |
| 修改 | bastion unlock 错误 | 可操作文案 |

---

### Task 1: SSH ConnectTimeout 注入

**Files:** `src/runtime/ssh_identity.rs`, call sites in `src/cli/exec.rs` / pipe paths

- [ ] 实现 `has_openssh_option(argv, prefix)` + `insert_default_ssh_timeouts(profile, argv)`
- [ ] 单测：默认注入 5；已有 ConnectTimeout 不覆盖
- [ ] 在 mux 插入同路径调用

### Task 2: List 默认探测策略

**Files:** `src/bastion/list_policy.rs`, `src/cli/list.rs`, `src/main.rs`, `src/mcp/server.rs`

- [ ] `reachable_only` 仅显式 flag；默认 probe true
- [ ] CLI `--no-probe` / `--reachable-only`；MCP 字段对齐
- [ ] 更新单测

### Task 3: MCP exec 超时

**Files:** `src/mcp/server.rs`

- [ ] `BROKRE_MCP_EXEC_TIMEOUT` + timeout + kill + 错误 JSON

### Task 4: Mux / DNS / bastion 文案

**Files:** `src/runtime/ssh_identity.rs`, `src/runtime/pipe_exec.rs`, `src/bastion/probe.rs`, `src/bastion/mcp_gate.rs`

- [ ] remote command → ControlMaster=no；prune 调用齐全
- [ ] DNS resolve 超时
- [ ] unlock timeout 文案

### Task 5: 文档 + 验证

**Files:** `README.md`, `README.zh-CN.md`, `packages/brokre-mcp/README.md`

- [ ] 文档默认行为
- [ ] cargo test / clippy（需 EXDATA volume）
- [ ] 本机 `brokre list` / 不可达 ssh 实测
