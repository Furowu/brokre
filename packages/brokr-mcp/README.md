# @techinone/brokr

MCP launcher for [brokr](https://github.com/Furowu/brokr) — lets Cursor, Claude Code, and other MCP clients list credential aliases and run `ssh` / `mysql` / `psql` **without exposing passwords to the AI**.

## Prerequisites

Install the `brokr` CLI first:

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokr/main/install.sh | bash
```

## Cursor

Add to `~/.cursor/mcp.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "brokr": {
      "command": "npx",
      "args": ["-y", "@techinone/brokr"]
    }
  }
}
```

Or use the native binary directly (no Node):

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
      "args": ["-y", "@techinone/brokr"]
    }
  }
}
```

CLI:

```bash
claude mcp add --scope project brokr -- npx -y @techinone/brokr
```

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
| `BROKR_BIN` | Path to `brokr` if not on `PATH` |
| `BROKR_MCP_NO_AUTO_OPEN` | Set to `1` to skip browser on empty vault |

## License

MIT
