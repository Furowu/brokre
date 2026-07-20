# brokre

MCP launcher for [brokre](https://github.com/Furowu/brokre) — a **local credential broker for AI agents**. Use it with Cursor, Claude Code, Kimi Code, Trae, OpenClaw, Hermes Agent, ChatClaw, and other MCP-capable clients to run `ssh` / `mysql` / `psql` and more — **passwords never enter AI context, environment variables, or `ps` output**. Agents list credential aliases and execute saved connections via MCP **without exposing passwords to the AI**.

Developed by [Techinone](https://www.tio.tech) (成都同创合一科技有限公司).

**Current version: 0.2.17** · [npm](https://www.npmjs.com/package/brokre)

## What's New in 0.2.17

### Default SessionRelay routes + safer list behavior

```bash
npm install -g brokre
# or use without global install:
npx -y brokre@latest
```

| Feature | Behavior |
|---------|----------|
| **SessionRelay by default** | Routed SSH aliases such as `b150::db` use `brokre tunnel agent --stdio` over SSH by default. Inner credentials stay on the bastion; the laptop only relays terminal bytes. |
| **Multi-hop routed SSH** | Routes such as `b1::b2::db` peel one hop per agent: the laptop starts the agent on `b1`, then `b1` continues with `b2::db`. Default route depth is 2 unless configured. |
| **Local-only list by default** | `brokre_list` no longer SSHs to bastions or triggers bastion unlock unless `include_bastions=true` is set. Cursor startup can list local metadata without opening bastion auth. |
| **Legacy escape hatch** | Set `BROKRE_TUNNEL=0` on the MCP server process only for emergency rollback to the old routed SSH path. |
| **Auto MCP registration** | `postinstall` → `brokre-setup-mcp`. Detects **installed** IDEs only; merges `npx -y brokre@latest` into global MCP config. Idempotent — no duplicate entries, no writes for missing software. |
| **Auto binary upgrade** | Each MCP start compares npm version vs `~/.brokre/bin/brokre` / `PATH`; downloads matching release when needed. |
| **Manual controls** | `brokre mcp setup` · `npx brokre-setup-mcp` · `--dry-run` · `--force` · skip: `BROKRE_MCP_SKIP_SETUP=1` |

**IDEs with auto-setup** (global config paths):

| IDE | Config file |
|-----|-------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `…/Code/User/mcp.json` |
| VS Code Insiders | `…/Code - Insiders/User/mcp.json` |
| Claude Code | `~/.claude.json` |
| Claude Desktop | `…/Claude/claude_desktop_config.json` |
| Trae | `…/Trae/User/mcp.json` |
| Kimi Code | `~/.kimi-code/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| OpenClaw | `~/.openclaw/openclaw.json` (`mcp.servers`) |

### Bastion broker — cluster management

Operate **many inner hosts through one jump box** — passwords stay on the bastion, not in AI context.

| Advantage | What it means in practice |
|-----------|----------------------------|
| **Single control plane** | Register bastion alias `b150`, sync inner aliases, drive cluster via `brokre_list` |
| **Smart routing** | `b150::db`, multi-hop `b1::b2::inner` — separator `::`; routed SSH uses SessionRelay by default |
| **Secrets on bastion** | Routed exec uses remote `~/.brokre/bin/brokre`; laptop holds metadata + gate only |
| **Human gate** | Unlock via TTY, `/bastion-auth`, or MCP URL elicitation; survives manage UI idle expiry |
| **Cluster-safe list** | Local-only by default; explicit bastion discovery, loop detection, audit `route`/`bastion` |
| **Privileged over routes** | `brokre_exec_elevated`, `sudo`/`sudo -i` through bastions with session reuse |

**Gate policy (default vs strict)** — inactive until `brokre bastion set-key`. **Default**: unlock only for bastion outbound (`::` routes, registered bastion SSH, bastion list discovery). **Strict**: every exec requires unlock; list remains local-only unless `include_bastions=true`. CLI: `brokre bastion strict on|off|status` · MCP: `brokre_bastion_policy`. Config: `~/.brokre/bastion/policy.json`. See main [README](../../README.md#bastion-gate-policy-default-vs-strict).

Typical MCP flow:

```json
{ "binary": "ssh", "args": ["b150::db", "uname", "-a"] }
```

CLI setup:

```bash
brokre bastion enable b150
brokre bastion sync b150 --json
brokre bastion unlock
brokre list --include-bastions --json
```

See [`brokre_list` — local-first list](#brokre_list--local-first-list) below.

## Prerequisites

- **Node.js 18+** (for `npx`)
- **No Rust required** — downloads or upgrades a prebuilt `brokre` from [GitHub Releases](https://github.com/Furowu/brokre/releases) into `~/.brokre/bin/` when the local binary is missing or older than the npm package version.
- **Elevated session pool** (persistent `sudo`/`su` shells): Unix only (`macOS` / `Linux`).

Optional — install the CLI yourself (recommended for production):

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokre/main/install.sh | bash
```

Re-run the same command to upgrade; the script skips download when already up to date.

## Supported clients

Any tool with **stdio MCP** support can use brokre — configure `npx -y brokre@latest` (or `brokre mcp` after CLI install) as the MCP server command. Tested and documented below for Cursor and Claude Code; the same pattern applies to Kimi Code, Trae, OpenClaw, Hermes Agent, ChatClaw, and similar agents.

## Cursor

**One-click install:** [Install brokre in Cursor](cursor://anysphere.cursor-deeplink/mcp/install?name=brokre&config=eyJicm9rcmUiOnsiY29tbWFuZCI6Im5weCIsImFyZ3MiOlsiLXkiLCJicm9rcmVAbGF0ZXN0Il19fQ==)

Or add to `~/.cursor/mcp.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "brokre": {
      "command": "npx",
      "args": ["-y", "brokre@latest"]
    }
  }
}
```

Or use the native binary directly (no Node, after CLI install):

```json
{
  "mcpServers": {
    "brokre": {
      "command": "brokre",
      "args": ["mcp"]
    }
  }
}
```

## Claude Code

Project scope (`.mcp.json` at repo root):

```json
{
  "mcpServers": {
    "brokre": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "brokre@latest"]
    }
  }
}
```

CLI:

```bash
claude mcp add --scope project brokre -- npx -y brokre@latest
```

### Auto-update

Recommended: `npx -y brokre@latest` so the npm launcher stays current (package version **0.2.17**).

On each MCP start, this package compares the **npm package version** with any local `brokre` binary (on `PATH` or in `~/.brokre/bin/`). If the binary is missing or older, it downloads the matching release from GitHub into `~/.brokre/bin/` and uses that — even when an older `brokre` is already on `PATH`.

### Auto MCP registration (`npm i brokre`, 0.2.8+)

On `npm install brokre` (local or global), `postinstall` runs `brokre-setup-mcp`, which **detects installed IDEs** (app bundle, CLI, or real usage artifacts — not empty directories) and merges a global brokre MCP entry (`npx -y brokre@latest`) into each client's config file. **Does not create config files for software that is not installed.** Existing non-brokre servers are preserved; duplicate brokre aliases under other names are not added.

| IDE | Global config path |
|-----|-------------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` (macOS) |
| VS Code Insiders | `…/Code - Insiders/User/mcp.json` |
| Claude Code | `~/.claude.json` (`mcpServers`) |
| Claude Desktop | `…/Claude/claude_desktop_config.json` |
| Trae | `…/Trae/User/mcp.json` |
| Kimi Code | `~/.kimi-code/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| OpenClaw | `~/.openclaw/openclaw.json` (`mcp.servers`) |

Manual re-run: `brokre mcp setup` or `npx brokre-setup-mcp` (add `--dry-run` to preview, `--force` to overwrite). Skip on install: `BROKRE_MCP_SKIP_SETUP=1`.

**CLI on PATH:** On first download, `brokre-mcp` adds `~/.brokre/bin` to your shell profile (`~/.zshrc`, etc.) and tries to symlink `/usr/local/bin/brokre` when writable. Open a **new terminal** (or `source ~/.zshrc`) so `brokre manage` works.

**Empty vault:** Each MCP connect while the vault has no credentials starts `brokre manage` in the background and opens `http://127.0.0.1:56777/?t=…` (or the next free port) in your default browser. Session tokens are never returned to the AI.

Manual CLI install (`install.sh`) does the same version check: re-run the script to upgrade when a newer release is available.

## First connection

When the vault is empty, `brokre mcp` automatically opens **brokre manage** in your browser (e.g. `http://127.0.0.1:56777/?t=…`) so you can add accounts. Session tokens are **never** returned to the AI — only your browser receives them.

Disable auto-open: `BROKRE_MCP_NO_AUTO_OPEN=1`

## MCP tools

| Tool | Purpose |
|------|---------|
| `brokre_list` | Saved local aliases (metadata only) by default; set `include_bastions=true` to discover `bastion::inner` routes, which may require unlock |
| `brokre_exec` | Run a saved connection (`binary` + `args`); `ssh` + `shell_command` for remote scripts; `ssh` + `sudo`/`su` auto-reuses elevated session |
| `brokre_exec_elevated` | Remote privileged command (`alias`, `command`, `mode`); default `session=reuse` |
| `brokre_setup` | Open manage UI in browser for the human |
| `brokre_audit_list` | Query audit history (metadata only — args redacted) |
| `brokre_audit_verify` | Verify tamper-evident audit log chain |
| `brokre_bastion_policy` | Read/set gate mode: `default` (bastion outbound only) or `strict` (all exec; list remains local-only unless `include_bastions=true`); returns `key_set`, `unlocked` |

**Not exposed:** `reveal`, password export, or manage session tokens.

## CLI basics

The npm package launches MCP, but the underlying tool is the **brokre CLI** (`~/.brokre/bin/brokre` or `PATH`). Humans and agents debugging in a terminal use the same vault.

**Always prefix `brokre`** — bare `ssh prod` / `mysql prod` does **not** inject saved passwords.

```bash
brokre list --json                    # list aliases (metadata only)
brokre ssh prod uname -a              # SSH one-shot (split argv after alias)
brokre mysql prod-db -e "SHOW TABLES"
brokre ssh prod sh -c 'echo hi > /tmp/f'   # remote script ( -c script is one arg )
brokre manage --open                  # add credentials in browser
brokre ssh user@10.0.0.1              # first-time save (TTY; type password when prompted)
```

Run `brokre --help` for pass-through syntax and subcommands (`list`, `manage`, `mcp`, `bastion`, …).

### MCP ↔ CLI mapping

| Task | MCP | CLI |
|------|-----|-----|
| List aliases | `brokre_list` | `brokre list --json` |
| SSH command | `brokre_exec` `binary=ssh`, `args=["prod","uname","-a"]` | `brokre ssh prod uname -a` |
| Other CLI | `brokre_exec` `binary=mysql`, `args=[…]` | `brokre mysql <alias> …` |
| Remote script | `shell_command="…"` | `brokre ssh <alias> sh -c '…'` |
| Privileged | `brokre_exec_elevated` | `brokre ssh <alias> sudo …` |
| Setup | `brokre_setup` | `brokre manage --open` |

**AI antipatterns:** `ssh prod cmd` (missing brokre); MCP `args=["prod","cmd arg"]` (use argv tokens or `shell_command`).

### `brokre_list` — local-first list

By default, `brokre_list` reads local metadata only. It does **not** SSH to bastions, does **not** discover remote aliases, and does **not** trigger bastion unlock. It **does** run local reachability probes by default so each item has `status` / `availability`.

Set `probe: false` to skip probes. Set `reachable_only: true` to hide unavailable aliases. Set `include_bastions: true` only when the user needs cross-network routed aliases. Then brokre:

1. SSHs to registered bastions after bastion gate unlock when configured
2. Merges routed entries like `b150::db` (`route: ["b150"]`, `access: "via_b150"`)
3. Can return multi-hop entries such as `b1::b2::db` when the bastion catalogs expose them

Prefer routed aliases only when they are actually listed and needed. MCP `brokre_exec` wall-clock timeout defaults to 120s (`BROKRE_MCP_EXEC_TIMEOUT`); SSH connect timeout defaults to 5s (`BROKRE_SSH_CONNECT_TIMEOUT`).

**Example response** (cross-network via VPN to bastion `b150`):

```json
{
  "items": [
    {
      "profile": "ssh",
      "name": "db",
      "addr": "b150::db",
      "route": ["b150"],
      "kind": "inner",
      "access": "via_b150",
      "host_alias": "10.0.0.20",
      "availability": "available",
      "status": {
        "reachable": true,
        "probe_ms": 3,
        "source": "b150",
        "checked_at": "2026-06-21T12:00:00Z"
      }
    }
  ],
  "bastion_gate": {
    "required": true,
    "unlocked_during_call": true,
    "idle_expires_at": "2026-06-21T12:10:00Z"
  }
}
```

**Execute routed alias:**

```json
{ "binary": "ssh", "args": ["b150::db", "uname", "-a"] }
```

Multi-hop uses the same argv layout when every hop has the next bastion registered:

```json
{ "binary": "ssh", "args": ["b1::b2::db", "uname", "-a"] }
```

When both direct and routed paths work, both appear — `access: "direct"` vs `access: "via_b150"`.

**SessionRelay tunnel (default):** routed `ssh` aliases such as `b150::db` use SessionRelay by default. The laptop starts `brokre tunnel agent --stdio` on `b150`; the agent runs `brokre ssh db` using the bastion vault, so inner credentials stay on the bastion. Multi-hop routes peel one hop per agent: `b1::b2::db` starts on `b1`, then `b1` continues with `b2::db`. Routed `brokre_exec` responses include:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "tunnel": { "mode": "session_relay", "active": true }
}
```

Set `BROKRE_TUNNEL=0` on the MCP server process only as a temporary legacy escape hatch. TcpForward, endpoint sync, Manage UI controls, and persistent `tunneld` are later phases.

### Bastion gate policy (`default` vs `strict`)

| Mode | Unlock required when key is set |
|------|----------------------------------|
| **default** (`strict_mode: false`) | Bastion outbound only: `b150::db` routes, SSH to registered bastion aliases, `brokre_list` only when `include_bastions=true`. Local `brokre_list` / `brokre_exec` — no unlock. |
| **strict** (`strict_mode: true`) | Every `brokre_exec`; `brokre_list` remains local-only unless `include_bastions=true`. |

```bash
brokre bastion set-key           # gate inactive until this
brokre bastion strict status
brokre bastion strict on         # strict
brokre bastion strict off        # default
brokre bastion unlock
```

```json
{ "strict_mode": true }
```

MCP `brokre_bastion_policy` (omit `strict_mode` to read). Unlock TTL defaults: 30 min idle / 8 h max — env `BROKRE_BASTION_IDLE_SECS`, `BROKRE_BASTION_MAX_SECS`. List/exec include `bastion_gate` in responses.

### Elevated sessions (`brokre_exec_elevated`)

Runs a command on a saved SSH host with `sudo`, `sudo -i` environment (`sudo_login`), or `su`. By default the MCP server **reuses** a background elevated shell (same `alias` + `mode` + `user`) so sudo is not re-prompted every call.

```json
{
  "alias": "prod",
  "command": "systemctl restart nginx",
  "mode": "sudo_login",
  "session": "reuse"
}
```

| Field | Values |
|-------|--------|
| `mode` | `sudo`, `sudo_login` (aliases: `sudo-i`), `su` |
| `session` | `reuse` (default), `new`, `close` (use `command: ""`) |
| `user` | Target user for `su`; default `root` |

**Response** (session pool enabled): `exit_code`, `stdout`, `stderr`, `session_reused`, `session_idle_expires_at`. The expiry field is a rolling idle-window hint, not a fixed deadline. With `BROKRE_MCP_SESSION=0`, only the first three fields are returned (one-shot subprocess).

**`brokre_exec` shortcut:** `binary=ssh`, `args=["prod","sudo","systemctl","status","nginx"]` uses the same pool (always `reuse`; cannot pass `session=new|close`).

### Writing remote scripts (`shell_command`)

For scripts or file writes with complex quoting, use `shell_command` (ssh only). Pass only the alias in `args`; brokre runs `sh -c <shell_command>` on the remote host.

```json
{
  "binary": "ssh",
  "args": ["prod"],
  "shell_command": "cat > /tmp/deploy.sh <<'EOF'\n#!/bin/sh\necho ok\nEOF"
}
```

**Do not:** put `sh -c '...'` in `args`, split `printf`/redirects across argv tokens, or rely on line-by-line `echo >>` workarounds. For privileged paths use `brokre_exec_elevated.command`. Bastion routes: `args=["b150::db"]` with the same `shell_command` field.

**Limits:** idle teardown 10 min, max lifetime 30 min, per-command timeout 120 s (configurable via env below). No interactive `sudo -i` without a command, no `vim`/`top`. Sudo password must match vault `password`.

## Environment

| Variable | Description |
|----------|-------------|
| `BROKRE_MCP_SKIP_SETUP` | Set to `1` to skip auto MCP registration on `npm install` |
| `BROKRE_BIN` | Pin a specific `brokre` binary (skips version check and auto-download) |
| `BROKRE_VERSION` | Release version to download (default: npm package version) |
| `BROKRE_SKIP_AUTO_INSTALL` | Set to `1` to use `PATH` only, no GitHub download |
| `BROKRE_MCP_NO_AUTO_OPEN` | Set to `1` to skip browser on empty vault |
| `BROKRE_MCP_SESSION` | Set to `0` to disable elevated session pool (default: enabled on Unix) |
| `BROKRE_MCP_SESSION_IDLE_SECS` | Idle session teardown (default: `600`) |
| `BROKRE_MCP_SESSION_MAX_SECS` | Max session lifetime (default: `1800`) |
| `BROKRE_MCP_SESSION_CMD_TIMEOUT` | Per remote command timeout in seconds (default: `120`) |
| `BROKRE_BASTION_NO_AUTO_OPEN` | Set to `1` to skip browser on bastion gate unlock (non-TTY) |
| `BROKRE_BASTION_IDLE_SECS` | Bastion unlock idle timeout in seconds (default: `1800`) |
| `BROKRE_BASTION_MAX_SECS` | Bastion unlock max session lifetime in seconds (default: `28800`) |

## License

MIT · [Techinone](https://www.tio.tech)
