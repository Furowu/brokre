# brokre

MCP launcher for [brokre](https://github.com/Furowu/brokre) — lets Cursor, Claude Code, and other MCP clients list credential aliases and run `ssh` / `mysql` / `psql` **without exposing passwords to the AI**.

## Prerequisites

- **Node.js 18+** (for `npx`)
- **No Rust required** — downloads or upgrades a prebuilt `brokre` from [GitHub Releases](https://github.com/Furowu/brokre/releases) into `~/.brokre/bin/` when the local binary is missing or older than the npm package version.

Optional — install the CLI yourself (recommended for production):

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokre/main/install.sh | bash
```

Re-run the same command to upgrade; the script skips download when already up to date.

## Cursor

Add to `~/.cursor/mcp.json` or `.cursor/mcp.json`:

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
| `brokre_exec` | Run a saved connection (`binary` + `args`) |
| `brokre_setup` | Open manage UI in browser for the human |

**Not exposed:** `reveal`, password export, or session tokens.

## Environment

| Variable | Description |
|----------|-------------|
| `BROKRE_BIN` | Pin a specific `brokre` binary (skips version check and auto-download) |
| `BROKRE_VERSION` | Release version to download (default: npm package version) |
| `BROKRE_SKIP_AUTO_INSTALL` | Set to `1` to use `PATH` only, no GitHub download |
| `BROKRE_MCP_NO_AUTO_OPEN` | Set to `1` to skip browser on empty vault |

## License

MIT
