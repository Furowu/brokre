# brokre

MCP launcher for [brokre](https://github.com/Furowu/brokre) — a **local credential broker for AI agents**. Use it with Cursor, Claude Code, Kimi Code, Trae, OpenClaw, Hermes Agent, ChatClaw, and other MCP-capable clients to run `ssh` / `mysql` / `psql` and more — **passwords never enter AI context, environment variables, or `ps` output**. Agents list credential aliases and execute saved connections via MCP **without exposing passwords to the AI**.

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

Recommended: `npx -y brokre@latest` so the npm launcher stays current.

On each MCP start, this package compares the **npm package version** with any local `brokre` binary (on `PATH` or in `~/.brokre/bin/`). If the binary is missing or older, it downloads the matching release from GitHub into `~/.brokre/bin/` and uses that — even when an older `brokre` is already on `PATH`.

**CLI on PATH:** On first download, `brokre-mcp` adds `~/.brokre/bin` to your shell profile (`~/.zshrc`, etc.) and tries to symlink `/usr/local/bin/brokre` when writable. Open a **new terminal** (or `source ~/.zshrc`) so `brokre manage` works.

**Empty vault:** Each MCP connect while the vault has no credentials starts `brokre manage` in the background and opens `http://127.0.0.1:56777/?t=…` (or the next free port) in your default browser. Session tokens are never returned to the AI.

Manual CLI install (`install.sh`) does the same version check: re-run the script to upgrade when a newer release is available.

## First connection

When the vault is empty, `brokre mcp` automatically opens **brokre manage** in your browser (e.g. `http://127.0.0.1:56777/?t=…`) so you can add accounts. Session tokens are **never** returned to the AI — only your browser receives them.

Disable auto-open: `BROKRE_MCP_NO_AUTO_OPEN=1`

## MCP tools

| Tool | Purpose |
|------|---------|
| `brokre_list` | List saved aliases (metadata only) |
| `brokre_exec` | Run a saved connection (`binary` + `args`); `ssh` + `sudo`/`su` auto-reuses elevated session |
| `brokre_exec_elevated` | Remote privileged command (`alias`, `command`, `mode`); default `session=reuse` |
| `brokre_setup` | Open manage UI in browser for the human |
| `brokre_audit_list` | Query audit history (metadata only — args redacted) |
| `brokre_audit_verify` | Verify tamper-evident audit log chain |

**Not exposed:** `reveal`, password export, or manage session tokens.

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

**Limits:** idle teardown 10 min, max lifetime 30 min, per-command timeout 120 s (configurable via env below). No interactive `sudo -i` without a command, no `vim`/`top`. Sudo password must match vault `password`.

## Environment

| Variable | Description |
|----------|-------------|
| `BROKRE_BIN` | Pin a specific `brokre` binary (skips version check and auto-download) |
| `BROKRE_VERSION` | Release version to download (default: npm package version) |
| `BROKRE_SKIP_AUTO_INSTALL` | Set to `1` to use `PATH` only, no GitHub download |
| `BROKRE_MCP_NO_AUTO_OPEN` | Set to `1` to skip browser on empty vault |
| `BROKRE_MCP_SESSION` | Set to `0` to disable elevated session pool (default: enabled on Unix) |
| `BROKRE_MCP_SESSION_IDLE_SECS` | Idle session teardown (default: `600`) |
| `BROKRE_MCP_SESSION_MAX_SECS` | Max session lifetime (default: `1800`) |
| `BROKRE_MCP_SESSION_CMD_TIMEOUT` | Per remote command timeout in seconds (default: `120`) |

## License

MIT
