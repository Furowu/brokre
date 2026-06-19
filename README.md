# brokre — AI-safe Credential Broker

<!-- README-I18N:START -->

**English** | [简体中文](README.zh-CN.md)

<!-- README-I18N:END -->

`brokre` is a **local credential broker** for AI agents and humans. Use it with Cursor, Claude Code, Kimi Code, Trae, OpenClaw, Hermes Agent, ChatClaw, and other MCP-capable clients to run `ssh`, `mysql`, `psql`, and more — **passwords never enter AI context, environment variables, or `ps` output**. It wraps **any CLI on your `PATH`** — not only SSH or MySQL — and injects saved passwords at the prompt **without exposing plaintext** to the AI process, shell history, or process environment.

Developed by [Techinone](https://www.tio.tech) (成都同创合一科技有限公司).

## CLI security (core)

brokre is built around one rule: **secrets stay out of the AI's reach and out of observable process state.**

| Layer | What brokre does |
|-------|-----------------|
| **No env / `ps` leakage** | Injection is PTY prompt-based — passwords are never passed via `-p`, `SSHPASS`, `MYSQL_PWD`, or exported env vars |
| **Parent never holds plaintext** (Unix) | Saved passwords decrypt in a short-lived `brokre --internal-injector` child, written once to the PTY, then the child exits |
| **AI cannot `reveal`** | `brokre reveal` requires a real TTY + master passphrase; unavailable in the web UI and **not exposed via MCP** |
| **Vault at rest** | Per-field AES-256-GCM; DEK wrapped with OS keyring (Linux) or `~/.brokre/.master_kek` (macOS) + optional Argon2id reveal passphrase |
| **Audit** | HMAC-chained JSONL at `~/.brokre/audit/audit.log`; `brokre audit list` queries history (metadata only); `brokre audit verify` detects tampering |
| **MCP boundary** | MCP exposes metadata (`brokre_list`), exec (`brokre_exec`), and read-only audit (`brokre_audit_list`, `brokre_audit_verify`) — no passwords, session tokens, or `reveal` |
| **Manage UI** | Binds `127.0.0.1` only; passwords are **write-only**; audit log tab for history; session token printed in your terminal, never returned to AI |
| **OS hardening** | Core dumps disabled, ptrace checks (Linux), optional `mlockall` — see [docs/HARDENING.md](docs/HARDENING.md) |

Full threat model: [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md).

## Any CLI on `PATH` (generic by design)

brokre is **not** a fixed list of database/SSH wrappers. The core model is:

```bash
brokre <any-cli-on-PATH> [args...]
```

First connection: run verbatim, capture the password you type at the prompt, offer to save as an alias.  
Next time: `brokre <cli> <alias> …` auto-injects — AI and scripts only see the alias name.

**Preset prompt patterns** ship for common tools (ssh, mysql, psql, redis-cli, ftp, clickhouse, git, docker, kubectl, sudo, …). **Everything else** uses a generic `password:` / `passphrase:` matcher — no code changes required.

```bash
brokre gsql prod-cluster -c "SELECT 1"    # any proprietary CLI on PATH
brokre kubectl get pods                   # if your cluster CLI prompts for a password
brokre my-internal-tool --host db.internal
```

Customize when needed:

- `~/.brokre/prompts.toml` — per-binary prompt regex overrides
- `~/.brokre/manage.toml` — custom sections in the manage UI (e.g. GaussDB, internal tools)

Built-in manage UI tabs (when the binary is installed) include SSH, FTP, MySQL, PostgreSQL, Redis, ClickHouse, MinIO — convenience only; the **PTY wrapper works for any CLI**.

## Install (MCP first — recommended for AI)

The npm package [`brokre`](https://www.npmjs.com/package/brokre) is the MCP launcher for Cursor, Claude Code, Kimi Code, Trae, OpenClaw, Hermes Agent, ChatClaw, and other **MCP clients**. It spawns the local `brokre mcp` server over stdio. Any agent or IDE with stdio MCP support can use the same setup.

### 1. Add brokre to your AI editor

**Cursor** — one-click install (opens Cursor and adds the MCP server):

[Install brokre in Cursor](cursor://anysphere.cursor-deeplink/mcp/install?name=brokre&config=eyJicm9rcmUiOnsiY29tbWFuZCI6Im5weCIsImFyZ3MiOlsiLXkiLCJicm9rcmVAbGF0ZXN0Il19fQ==)

Or add manually to `~/.cursor/mcp.json` or project `.cursor/mcp.json`:

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

Regenerate the install link after config changes: `node scripts/generate-cursor-install-link.js`

**Claude Code** — project `.mcp.json`:

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

Or via CLI:

```bash
claude mcp add --scope project brokre -- npx -y brokre@latest
```

Use `npx -y brokre@latest` so both the npm launcher and binary stay current. On each MCP start, if the local `brokre` (`PATH` or `~/.brokre/bin/`) is older than the npm package version, a matching release is downloaded into `~/.brokre/bin/` — even when an older `brokre` is already on `PATH`.

**No Node** — point MCP directly at the native binary:

```json
{ "command": "brokre", "args": ["mcp"] }
```

| MCP tool | Purpose |
|----------|---------|
| `brokre_list` | Saved aliases (metadata only — profile, name, host) |
| `brokre_exec` | Run **any** saved CLI alias (`binary` + `args`); `ssh` + `sudo`/`su` auto-reuses elevated session |
| `brokre_exec_elevated` | Remote privileged command (`alias`, `command`, `mode`); default `session=reuse` (10 min idle timeout) |
| `brokre_setup` | Open manage UI in browser for the human to add creds |
| `brokre_audit_list` | Query audit history (metadata only — args redacted) |
| `brokre_audit_verify` | Verify tamper-evident audit log chain |

On first connect with an **empty vault**, brokre opens **manage** in your browser (`http://127.0.0.1:56777/?t=…`). Session tokens stay on localhost — never returned to the AI. Set `BROKRE_MCP_NO_AUTO_OPEN=1` to disable auto-open.

**No separate CLI install required**: `npx -y brokre@latest` downloads or upgrades `~/.brokre/bin/brokre` from GitHub Releases when needed (Node 18+), including when an older `brokre` is on `PATH`. Disable auto-download: `BROKRE_SKIP_AUTO_INSTALL=1`; pin a binary: `BROKRE_BIN=/path/to/brokre`.

More detail: [packages/brokre-mcp/README.md](packages/brokre-mcp/README.md).

[MCP Registry](https://registry.modelcontextprotocol.io) metadata: `io.github.Furowu/brokre` — published automatically with `./d npm` / `./d release` (or `./d registry` after npm; set `BROKRE_SKIP_MCP_REGISTRY=1` to skip).

### 2. Install the brokre CLI (optional — MCP can auto-download)

You can also install the CLI system-wide (recommended for production):

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokre/main/install.sh | bash
```

Re-run the same command to upgrade; the script detects the installed version, reinstalls when a newer release is available, and skips when already up to date.

Or via Homebrew (macOS / Linux):

```bash
brew tap Furowu/brokre
brew install brokre
```

## Quick Start

### Add credentials

After CLI install, the manager opens on first run (`brokre manage --onboard --open`). Or anytime:

```bash
brokre manage --open
```

Or save on first interactive connection (any CLI):

```bash
brokre ssh root@10.0.0.1
brokre my-tool --host internal.corp
```

### Use (AI-safe)

```bash
brokre mysql prod-db -e "SHOW TABLES"
brokre ssh prod-bastion uname -a
brokre <your-cli> <alias> [args...]
```

### List metadata (safe for AI / scripts)

```bash
brokre list --json
```

### Reveal / delete (human-only, real TTY)

```bash
brokre reveal mysql prod-db --field password
brokre rm ssh prod-bastion
```

### Audit log (metadata only)

```bash
brokre audit list --profile ssh --action exec --json
brokre audit verify --json
```

Events are stored at `~/.brokre/audit/audit.log` (HMAC-chained). Command arguments are uniformly redacted as `<REDACTED>`. New events include a `source` field (`cli`, `mcp`, or `manage`). The manage UI **Audit log** tab and MCP `brokre_audit_list` expose the same metadata.

### Manage UI security

- **127.0.0.1** only; session token in terminal
- Passwords: create / rotate only — no read API
- Delete / rotate require reveal passphrase (or `YES` for auto-saved records)
- 15-minute idle timeout

## Architecture

```
┌─────────┐     ┌──────────┐     ┌─────────────┐     ┌────────────┐
│ AI/User │────▶│ brokre CLI│────▶│ OS Keychain │────▶│ Vault File │
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

**Planned:** full TOML connector profiles under `~/.brokre/profiles/` with per-tool injection strategies.

## Piped stdin and OpenSSH sharing

- **Piped stdin** (`tar | brokre ssh host 'tar xf -'`): pipe data forwards only after injection completes.
- **OpenSSH family** (`ssh`, `scp`, `sftp`): shared saved credentials when the host matches. Interactive save required first (TTY).

## Development

```bash
cargo test    # unit tests in src/ only (no tests/ integration suite in this repo)
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release   # binary: target/release/brokre
```

Release version is declared in [`VERSION`](VERSION) (also reflected in `Cargo.toml` and `packages/brokre-mcp/package.json`). Official binaries and npm packages are published by [TechinOne](https://www.tio.tech) via GitHub Releases and CI — not part of this open-source tree.

## License

MIT — see [LICENSE](LICENSE).

---

[Techinone](https://www.tio.tech) · 成都同创合一科技有限公司
