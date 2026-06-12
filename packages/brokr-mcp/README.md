# @techinone/brokr

MCP launcher for [brokr](https://github.com/Furowu/brokr) — lets Cursor, Claude Code, and other MCP clients list credential aliases and run `ssh` / `mysql` / `psql` **without exposing passwords to the AI**.

## Prerequisites

- **Node.js 18+** (for `npx`)
- **No Rust required** — downloads or upgrades a prebuilt `brokr` from [GitHub Releases](https://github.com/Furowu/brokr/releases) into `~/.brokr/bin/` when the local binary is missing or older than the npm package version.

Optional — install the CLI yourself (recommended for production):

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokr/main/install.sh | bash
```

Re-run the same command to upgrade; the script skips download when already up to date.

## Cursor

Add to `~/.cursor/mcp.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "brokr": {
      "command": "npx",
      "args": ["-y", "@techinone/brokr@latest"]
    }
  }
}
```

Or use the native binary directly (no Node, after CLI install):

```json
{
  "mcpServers": {
    "brokr": {
      "command": "brokr",
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
    "brokr": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@techinone/brokr@latest"]
    }
  }
}
```

CLI:

```bash
claude mcp add --scope project brokr -- npx -y @techinone/brokr@latest
```

### Auto-update

Recommended: `npx -y @techinone/brokr@latest` so the npm launcher stays current.

On each MCP start, this package compares the **npm package version** with any local `brokr` binary (on `PATH` or in `~/.brokr/bin/`). If the binary is missing or older, it downloads the matching release from GitHub into `~/.brokr/bin/` and uses that — even when an older `brokr` is already on `PATH`.

Manual CLI install (`install.sh`) does the same version check: re-run the script to upgrade when a newer release is available.

## First connection

When the vault is empty, `brokr mcp` automatically opens **brokr manage** in your browser (e.g. `http://127.0.0.1:56777/?t=…`) so you can add accounts. Session tokens are **never** returned to the AI — only your browser receives them.

Disable auto-open: `BROKR_MCP_NO_AUTO_OPEN=1`

## MCP tools

| Tool | Purpose |
|------|---------|
| `brokr_list` | List saved aliases (metadata only) |
| `brokr_exec` | Run a saved connection (`binary` + `args`) |
| `brokr_setup` | Open manage UI in browser for the human |

**Not exposed:** `reveal`, password export, or session tokens.

## Environment

| Variable | Description |
|----------|-------------|
| `BROKR_BIN` | Pin a specific `brokr` binary (skips version check and auto-download) |
| `BROKR_VERSION` | Release version to download (default: npm package version) |
| `BROKR_SKIP_AUTO_INSTALL` | Set to `1` to use `PATH` only, no GitHub download |
| `BROKR_MCP_NO_AUTO_OPEN` | Set to `1` to skip browser on empty vault |

## License

MIT
