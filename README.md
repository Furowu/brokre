# brokr — AI-safe Credential Broker

<!-- README-I18N:START -->

**English** | [简体中文](README.zh-CN.md)

<!-- README-I18N:END -->

`brokr` is a **local credential broker** for AI agents and humans. It wraps **any CLI on your `PATH`** — not only SSH or MySQL — and injects saved passwords at the prompt **without exposing plaintext** to the AI process, shell history, `ps`, or process environment.

Developed by [Techinone](https://www.tio.tech) (成都同创合一科技有限公司).

## CLI security (core)

brokr is built around one rule: **secrets stay out of the AI's reach and out of observable process state.**

| Layer | What brokr does |
|-------|-----------------|
| **No env / `ps` leakage** | Injection is PTY prompt-based — passwords are never passed via `-p`, `SSHPASS`, `MYSQL_PWD`, or exported env vars |
| **Parent never holds plaintext** (Unix) | Saved passwords decrypt in a short-lived `brokr --internal-injector` child, written once to the PTY, then the child exits |
| **AI cannot `reveal`** | `brokr reveal` requires a real TTY + master passphrase; unavailable in the web UI and **not exposed via MCP** |
| **Vault at rest** | Per-field AES-256-GCM; DEK wrapped with OS keyring (Linux) or `~/.brokr/.master_kek` (macOS) + optional Argon2id reveal passphrase |
| **MCP boundary** | MCP exposes metadata (`brokr_list`) and exec (`brokr_exec`) only — no passwords, session tokens, or `reveal` |
| **Manage UI** | Binds `127.0.0.1` only; passwords are **write-only**; session token printed in your terminal, never returned to AI |
| **Audit** | HMAC-chained JSONL; `brokr audit verify` detects tampering |
| **OS hardening** | Core dumps disabled, ptrace checks (Linux), optional `mlockall` — see [docs/HARDENING.md](docs/HARDENING.md) |

Full threat model: [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md).

## Any CLI on `PATH` (generic by design)

brokr is **not** a fixed list of database/SSH wrappers. The core model is:

```bash
brokr <any-cli-on-PATH> [args...]
```

First connection: run verbatim, capture the password you type at the prompt, offer to save as an alias.  
Next time: `brokr <cli> <alias> …` auto-injects — AI and scripts only see the alias name.

**Preset prompt patterns** ship for common tools (ssh, mysql, psql, redis-cli, ftp, clickhouse, git, docker, kubectl, sudo, …). **Everything else** uses a generic `password:` / `passphrase:` matcher — no code changes required.

```bash
brokr gsql prod-cluster -c "SELECT 1"    # any proprietary CLI on PATH
brokr kubectl get pods                   # if your cluster CLI prompts for a password
brokr my-internal-tool --host db.internal
```

Customize when needed:

- `~/.brokr/prompts.toml` — per-binary prompt regex overrides
- `~/.brokr/manage.toml` — custom sections in the manage UI (e.g. GaussDB, internal tools)

Built-in manage UI tabs (when the binary is installed) include SSH, FTP, MySQL, PostgreSQL, Redis, ClickHouse, MinIO — convenience only; the **PTY wrapper works for any CLI**.

## Install (MCP first — recommended for AI)

The npm package [`@techinone/brokr`](https://www.npmjs.com/package/@techinone/brokr) is the MCP launcher for Cursor, Claude Code, and other MCP clients. It spawns the local `brokr mcp` server over stdio.

### 1. Add brokr to your AI editor

**Cursor** — `~/.cursor/mcp.json` or project `.cursor/mcp.json`:

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

**Claude Code** — project `.mcp.json`:

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

Or via CLI:

```bash
claude mcp add --scope project brokr -- npx -y @techinone/brokr
```

Optional — install the launcher globally (avoids repeated `npx` downloads):

```bash
npm install -g @techinone/brokr
```

Then use `"command": "brokr-mcp"` in MCP config instead of `npx`.

**No Node** — point MCP directly at the native binary:

```json
{ "command": "brokr", "args": ["mcp"] }
```

| MCP tool | Purpose |
|----------|---------|
| `brokr_list` | Saved aliases (metadata only — profile, name, host) |
| `brokr_exec` | Run **any** saved CLI alias (`binary` + `args`) |
| `brokr_setup` | Open manage UI in browser for the human to add creds |

On first connect with an **empty vault**, brokr opens **manage** in your browser (`http://127.0.0.1:56777/?t=…`). Session tokens stay on localhost — never returned to the AI. Set `BROKR_MCP_NO_AUTO_OPEN=1` to disable auto-open.

More detail: [packages/brokr-mcp/README.md](packages/brokr-mcp/README.md).

### 2. Install the brokr CLI (required backend)

The MCP launcher calls `brokr mcp` on your machine — install the CLI once:

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokr/main/install.sh | bash
```

Or via Homebrew (macOS / Linux):

```bash
brew tap Furowu/brokr
brew install brokr
```

## Quick Start

### Add credentials

After CLI install, the manager opens on first run (`brokr manage --onboard --open`). Or anytime:

```bash
brokr manage --open
```

Or save on first interactive connection (any CLI):

```bash
brokr ssh root@10.0.0.1
brokr my-tool --host internal.corp
```

### Use (AI-safe)

```bash
brokr mysql prod-db -e "SHOW TABLES"
brokr ssh prod-bastion uname -a
brokr <your-cli> <alias> [args...]
```

### List metadata (safe for AI / scripts)

```bash
brokr list --json
```

### Reveal / delete (human-only, real TTY)

```bash
brokr reveal mysql prod-db --field password
brokr rm ssh prod-bastion
```

### Manage UI security

- **127.0.0.1** only; session token in terminal
- Passwords: create / rotate only — no read API
- Delete / rotate require reveal passphrase (or `YES` for auto-saved records)
- 15-minute idle timeout

## Architecture

```
┌─────────┐     ┌──────────┐     ┌─────────────┐     ┌────────────┐
│ AI/User │────▶│ brokr CLI│────▶│ OS Keychain │────▶│ Vault File │
└─────────┘     └──────────┘     └─────────────┘     └────────────┘
                      │
                      ▼
               ┌─────────────┐
               │  PTY + inj. │──▶ any CLI on PATH (ssh, mysql, gsql, …)
               └─────────────┘
```

- **Double encryption**: unique DEK per field; wrapped for `exec` and `reveal` separately.
- **Vault metadata**: `profile`, `name`, `host_alias`, `saved_args` in cleartext beside ciphertext ([THREAT_MODEL.md](THREAT_MODEL.md) T3).
- **SSH private keys**: `0600` temp file + `-i` for the session ([docs/HARDENING.md](docs/HARDENING.md)).

## Preset manage UI groups

Convenience tabs when the binary is on `PATH`:

| Group | Binaries |
|-------|----------|
| SSH | `ssh`, `scp`, `sftp` (shared creds) |
| FTP | `ftp`, `lftp` |
| MySQL | `mysql`, `mariadb` |
| PostgreSQL | `psql`, `postgres` |
| Redis | `redis-cli`, `redis` |
| ClickHouse | `clickhouse-client`, `clickhouse` |
| MinIO | `mc`, `minio` |

## Roadmap

**Today:** generic PTY wrapper + `manage.toml` groups + `prompts.toml` overrides.

**Planned:** full TOML connector profiles under `~/.brokr/profiles/` with per-tool injection strategies.

## Piped stdin and OpenSSH sharing

- **Piped stdin** (`tar | brokr ssh host 'tar xf -'`): pipe data forwards only after injection completes.
- **OpenSSH family** (`ssh`, `scp`, `sftp`): shared saved credentials when the host matches. Interactive save required first (TTY).

## Development

```bash
cargo test    # unit tests in src/ only (no tests/ integration suite in this repo)
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release   # binary: target/release/brokr
```

Release version is declared in [`VERSION`](VERSION) (also reflected in `Cargo.toml` and `packages/brokr-mcp/package.json`). Official binaries and npm packages are published by [TechinOne](https://www.tio.tech) via GitHub Releases and CI — not part of this open-source tree.

## License

MIT — see [LICENSE](LICENSE).

---

[Techinone](https://www.tio.tech) · 成都同创合一科技有限公司
