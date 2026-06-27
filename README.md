# brokre — AI-safe Credential Broker

<!-- README-I18N:START -->

**English** | [简体中文](README.zh-CN.md)

<!-- README-I18N:END -->

`brokre` is a **local credential broker** for AI agents and humans. Use it with Cursor, Claude Code, Kimi Code, Trae, OpenClaw, Hermes Agent, ChatClaw, and other MCP-capable clients to run `ssh`, `mysql`, `psql`, and more — **passwords never enter AI context, environment variables, or `ps` output**. It wraps **any CLI on your `PATH`** — not only SSH or MySQL — and injects saved passwords at the prompt **without exposing plaintext** to the AI process, shell history, or process environment.

Developed by [Techinone](https://www.tio.tech) (成都同创合一科技有限公司).

## What's New in 0.2.17

**0.2.17** is the current release: **SessionRelay routed SSH by default**, **multi-hop bastion routes**, **local-only list by default**, and the existing **one-command npm install / auto MCP registration / auto binary upgrade** flow.

### npm — install, auto-update, auto MCP setup

```bash
npm install -g brokre          # or: npx -y brokre@latest
```

| Capability | What happens |
|------------|----------------|
| **Auto MCP registration** | `postinstall` runs `brokre-setup-mcp` — detects **installed** IDEs only and merges `npx -y brokre@latest` into each global MCP config. Re-run: `brokre mcp setup` or `npx brokre-setup-mcp`. Skip: `BROKRE_MCP_SKIP_SETUP=1`. |
| **Auto binary upgrade** | On each MCP start, compares npm package version with `PATH` / `~/.brokre/bin/brokre`; downloads matching [GitHub Release](https://github.com/Furowu/brokre/releases) when missing or older. |
| **CLI without npm** | `brokre version` / `brokre upgrade` for install.sh users; `brokre mcp setup` to register MCP after installing IDEs. |
| **Supported IDEs** | Cursor, VS Code, VS Code Insiders, Claude Code, Claude Desktop, Trae, Kimi Code, Windsurf, OpenClaw — see [packages/brokre-mcp/README.md](packages/brokre-mcp/README.md). |

Recommended MCP config (also applied by auto-setup):

```json
{ "command": "npx", "args": ["-y", "brokre@latest"] }
```

### Bastion broker — cluster management

The bastion layer lets AI agents operate **many hosts behind one jump box** without copying vault passwords into context or scattering secrets on the laptop.

| Advantage | What it means in practice |
|-----------|----------------------------|
| **Single control plane** | Register a bastion SSH alias (`b150`), sync inner aliases from remote brokre, and drive the whole cluster from `brokre list` / MCP `brokre_list` |
| **Smart routing** | `b150::db`, `b150::app-01`, multi-hop `b1::b2::inner` — route separator `::`; routed SSH uses SessionRelay by default |
| **Secrets stay on the bastion** | Routed exec runs `~/.brokre/bin/brokre` on the jump host; laptop holds metadata and session gate, not inner-host passwords |
| **Human gate, agent-friendly** | Bastion outbound requires unlock (TTY, `/bastion-auth`, or MCP URL elicitation); gate auth survives manage UI idle expiry so long MCP runs keep working |
| **Cluster-safe defaults** | Local-only list by default; explicit bastion discovery; reachability probes with ms timeouts and concurrency caps; loop detection and audit `route`/`bastion` fields |
| **Privileged ops over routes** | `brokre_exec_elevated` and `sudo`/`sudo -i` paths work through bastions with session reuse and PTY hardening |

Typical flow for a K8s / DB / batch cluster behind one entry host:

```bash
brokre bastion enable b150
brokre bastion sync b150 --json          # pull inner alias catalog
brokre bastion unlock
brokre list --include-bastions --json    # b150::db, b150::worker-01, …
brokre ssh b150::db systemctl status   # MCP: brokre_exec with routed alias
```

MCP equivalent:

```json
{ "binary": "ssh", "args": ["b150::db", "uname", "-a"] }
```

**Gate policy (default vs strict)** — see [Bastion gate policy](#bastion-gate-policy-default-vs-strict) below. Gate is inactive until `brokre bastion set-key`; then **default** unlocks only bastion outbound paths; **strict** requires unlock for every exec while list remains local-only unless bastion discovery is requested.

See [Cross-network list inheritance](#cross-network-list-inheritance-bastion-broker) and [Bastion proxy](#bastion-proxy-cross-network--intranet-entry) below for setup details.

## CLI security (core)

brokre is built around one rule: **secrets stay out of the AI's reach and out of observable process state.**

| Layer | What brokre does |
|-------|-----------------|
| **No env / `ps` leakage** | Injection is PTY prompt-based — passwords are never passed via `-p`, `SSHPASS`, `MYSQL_PWD`, or exported env vars |
| **Parent never holds plaintext** (Unix) | Saved passwords decrypt in a short-lived `brokre --internal-injector` child, written once to the PTY, then the child exits |
| **AI cannot `reveal`** | `brokre reveal` requires a real TTY + master passphrase; unavailable in the web UI and **not exposed via MCP** |
| **Vault at rest** | Per-field AES-256-GCM; DEK wrapped with OS keyring (Linux) or `~/.brokre/.master_kek` (macOS) + optional Argon2id reveal passphrase |
| **Audit** | HMAC-chained JSONL at `~/.brokre/audit/audit.log`; `brokre audit list` queries history (metadata only); `brokre audit verify` detects tampering |
| **MCP boundary** | MCP exposes metadata (`brokre_list`), exec (`brokre_exec`, `brokre_exec_elevated`), `brokre_setup`, and read-only audit (`brokre_audit_list`, `brokre_audit_verify`) — no passwords, session tokens, or `reveal` |
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

The npm package [`brokre`](https://www.npmjs.com/package/brokre) launches the local `brokre mcp` server over stdio for Cursor, Claude Code, Kimi Code, Trae, OpenClaw, Windsurf, VS Code, and other MCP clients.

### Choose your install path

| Path | Best for | Install | MCP in IDEs | CLI upgrade |
|------|----------|---------|-------------|-------------|
| **npm** (recommended) | AI users; want one command | `npm install -g brokre` | **Automatic** on install (`postinstall`) | npm + auto-download on each MCP start |
| **install.sh / Homebrew** | Production; no Node for daily use | `curl … \| bash` or `brew install brokre` | Run `brokre mcp setup` after IDE install | `brokre version` / `brokre upgrade` |
| **Manual MCP JSON** | Custom layouts only | CLI or npm already present | Edit IDE config by hand | Depends on how CLI was installed |

**Recommended MCP entry** (also what auto-setup writes):

```json
{ "command": "npx", "args": ["-y", "brokre@latest"] }
```

No Node — point MCP at the native binary: `{ "command": "brokre", "args": ["mcp"] }`.

### Path A — npm one-liner (0.2.8+)

```bash
npm install -g brokre
# or without global install:
npx -y brokre@latest
```

On `npm install`, three things happen automatically:

1. **MCP launcher** — `brokre-mcp` / `npx -y brokre@latest` spawns `brokre mcp`.
2. **IDE auto-registration** — `postinstall` runs `brokre-setup-mcp`: detects **installed** IDEs only (app, CLI, or real usage artifacts — not empty folders) and merges the MCP entry above into each global config. Idempotent; preserves your other MCP servers.
3. **Binary auto-upgrade** — on each MCP start, if `PATH` or `~/.brokre/bin/brokre` is older than the npm package, the matching [GitHub Release](https://github.com/Furowu/brokre/releases) is downloaded.

**IDEs covered by auto-setup**

| IDE | Global config |
|-----|----------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code / Insiders | `…/Code/User/mcp.json` |
| Claude Code | `~/.claude.json` |
| Claude Desktop | `…/Claude/claude_desktop_config.json` |
| Trae | `…/Trae/User/mcp.json` |
| Kimi Code | `~/.kimi-code/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| OpenClaw | `~/.openclaw/openclaw.json` (`mcp.servers`) |

**Re-run registration** (e.g. you installed brokre before Cursor, then installed Cursor later):

```bash
brokre mcp setup              # via CLI — same logic as postinstall
npx brokre-setup-mcp          # via npm
brokre mcp setup --dry-run    # preview only
brokre mcp setup --force      # overwrite existing brokre entry
```

Skip auto-registration on `npm install`: `BROKRE_MCP_SKIP_SETUP=1`. Disable binary auto-download: `BROKRE_SKIP_AUTO_INSTALL=1`. Pin a binary: `BROKRE_BIN=/path/to/brokre`.

Requires **Node.js 18+** for the npm path.

### Path B — Native CLI (install.sh / Homebrew, no npm)

```bash
curl -fsSL https://raw.githubusercontent.com/Furowu/brokre/main/install.sh | bash
```

```bash
brew tap Furowu/brokre
brew install brokre
```

**Version and upgrade** (built into the CLI — no npm required):

```bash
brokre version                # version, binary path, install type
brokre version --check        # compare with latest GitHub release
brokre version --check --json
brokre upgrade                # download latest release (curl + tar)
brokre upgrade --check        # exit 1 if an update is available
brokre upgrade 0.2.10         # install a specific version
brokre upgrade --force        # reinstall even when up to date
```

Re-run `install.sh` also upgrades when a newer release exists.

**Register MCP after CLI install** (needs Node for the setup script, or `npx` fallback):

```bash
brokre mcp setup
```

### Manual per-IDE setup (optional)

Use this only if you skip auto-setup or need project-scoped config.

**Cursor** — [one-click install](cursor://anysphere.cursor-deeplink/mcp/install?name=brokre&config=eyJicm9rcmUiOnsiY29tbWFuZCI6Im5weCIsImFyZ3MiOlsiLXkiLCJicm9rcmVAbGF0ZXN0Il19fQ==), or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "brokre": { "command": "npx", "args": ["-y", "brokre@latest"] }
  }
}
```

**Claude Code** — user scope in `~/.claude.json` or `claude mcp add --scope user brokre -- npx -y brokre@latest`. Project scope: `.mcp.json` with `"type": "stdio"`.

More clients and env vars: [packages/brokre-mcp/README.md](packages/brokre-mcp/README.md). [MCP Registry](https://registry.modelcontextprotocol.io) ID: `io.github.Furowu/brokre`.

### MCP tools and usage

| MCP tool | Purpose |
|----------|---------|
| `brokre_list` | Saved local aliases by default; set `include_bastions=true` to discover routed aliases (`b150::db`), which may require bastion unlock; includes `access`/`availability`/`bastion_gate` |
| `brokre_exec` | Run **any** saved CLI alias (`binary` + `args`); `ssh` supports `shell_command` for remote scripts; `ssh` + `sudo`/`su` auto-reuses elevated session |
| `brokre_exec_elevated` | Remote privileged command (`alias`, `command`, `mode`); default `session=reuse` (10 min idle timeout) |
| `brokre_setup` | Open manage UI in browser for the human to add creds |
| `brokre_audit_list` | Query audit history (metadata only — args redacted) |
| `brokre_audit_verify` | Verify tamper-evident audit log chain |
| `brokre_bastion_policy` | Read or set bastion gate mode (`default` / `strict`); returns `key_set`, `unlocked` |

#### MCP vs CLI (essential for AI agents)

brokre is **not** a drop-in for `ssh` / `mysql` — you must prefix with `brokre` for vault injection.

| Task | MCP (in IDE) | CLI (terminal / debugging) |
|------|--------------|----------------------------|
| List aliases | `brokre_list` | `brokre list --json` |
| SSH remote command | `brokre_exec` `binary=ssh`, `args=["prod","uname","-a"]` | `brokre ssh prod uname -a` |
| Any CLI | `brokre_exec` `binary=mysql`, `args=["prod-db","-e","SHOW TABLES"]` | `brokre mysql prod-db -e "SHOW TABLES"` |
| Write remote script | `shell_command="…"` (ssh only) | `brokre ssh prod sh -c '…'` (whole script as one `-c` arg) |
| Privileged exec | `brokre_exec_elevated` `command="…"` | `brokre ssh prod sudo …` (MCP has session pool; CLI uses fresh PTY each time) |
| Add credentials | `brokre_setup` (opens browser) | `brokre manage --open` |
| First-time save | **not available** (human TTY required) | `brokre ssh user@10.0.0.1` |

**Common mistakes (AI agents)**

| Wrong | Right |
|-------|-------|
| `ssh prod uptime` | `brokre ssh prod uptime` |
| MCP `args=["prod","uname -a"]` (one shell string) | `args=["prod","uname","-a"]` (argv tokens) |
| MCP `args=["prod","sh -c 'echo hi'"]` | `shell_command="echo hi"` or `args=["prod","sh","-c","echo hi"]` |
| bare `mysql -h … -p` | `brokre mysql <saved-alias> …` |

For remote SSH: tokens after the alias are **argv slices**, not one shell command. Use split tokens for simple commands; use `shell_command` for complex scripts.

#### MCP elevated sessions (`sudo` / `su`, Unix)

By default, `brokre mcp` reuses a background elevated shell per `(alias, mode, user)` so sudo passwords are not re-prompted on every call.

**`brokre_exec_elevated`** (preferred for privilege escalation):

```json
{
  "alias": "prod",
  "command": "systemctl status nginx",
  "mode": "sudo_login",
  "session": "reuse"
}
```

| Field | Description |
|-------|-------------|
| `mode` | `sudo`, `sudo_login` (or `sudo-i`), `su` |
| `session` | `reuse` (default), `new` (close old session and open fresh), `close` (end session; pass `command: ""`) |
| `user` | `su` mode only; default `root` |

When the session pool is enabled, responses include `session_reused` and `session_idle_expires_at` in addition to `exit_code` / `stdout` / `stderr`. `session_idle_expires_at` is a **rolling idle-window hint** refreshed on each call, not a fixed expiry timestamp. `stderr` is usually empty on the pool path.

**`brokre_exec`**: `binary=ssh` with `sudo`/`su` in `args` auto-uses the same pool (always `reuse`; no `session=new|close`). Example: `args=["prod","sudo","whoami"]`.

**Writing remote scripts/files** (`shell_command`, `binary=ssh` only): pass only the alias in `args`; put the full shell script in `shell_command` (brokre normalizes to `sh -c`). Do not embed `sh -c '...'` in `args` or split `printf`/redirects across argv tokens. For privileged system paths use `brokre_exec_elevated.command`.

```json
{
  "binary": "ssh",
  "args": ["prod"],
  "shell_command": "cat > /tmp/deploy.sh <<'EOF'\n#!/bin/sh\necho ok\nEOF"
}
```

Bastion routes work the same: `args=["b150::db"]` with `shell_command` as the remote script.

#### SessionRelay tunnel (default)

`brokre ssh b150::db` uses the SessionRelay path by default: the laptop starts `brokre tunnel agent --stdio` on `b150` over SSH, and the agent runs `brokre ssh db` on the bastion. Multi-hop routes peel one hop per agent (`b1::b2::db` starts on `b1`, then `b1` continues with `b2::db`). Inner credentials stay in the bastion vault; the laptop only relays terminal bytes. `BROKRE_TUNNEL=0` is a temporary legacy escape hatch for emergency rollback.

```bash
brokre tunnel doctor b150
brokre ssh b150::db uname -a
```

MCP `brokre_exec` responses for routed SSH include `tunnel: { mode, active }`. TcpForward, endpoint sync, Manage UI tunnel controls, and persistent `tunneld` are later phases.

| Control | Default |
|---------|---------|
| Idle teardown | 10 minutes |
| Max lifetime | 30 minutes |
| Per-command timeout | 120 seconds |

| Variable | Default | Meaning |
|----------|---------|---------|
| `BROKRE_MCP_SESSION` | `1` | `0` disables the pool; falls back to one-shot subprocess exec |
| `BROKRE_MCP_SESSION_IDLE_SECS` | `600` | Idle timeout (seconds) |
| `BROKRE_MCP_SESSION_MAX_SECS` | `1800` | Max session lifetime (seconds) |
| `BROKRE_MCP_SESSION_CMD_TIMEOUT` | `120` | Remote command timeout (seconds) |

Not supported: interactive `sudo -i` without a command, `vim`/`top`, or sudo passwords different from the vault `password` field. See [THREAT_MODEL.md](THREAT_MODEL.md) T12.

On first connect with an **empty vault**, brokre opens **manage** in your browser (`http://127.0.0.1:56777/?t=…`). Session tokens stay on localhost — never returned to the AI. Set `BROKRE_MCP_NO_AUTO_OPEN=1` to disable auto-open.

| MCP tool | Purpose |

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
brokre list --json              # no bastions: local aliases only; with bastions: smart list (below)
brokre list --all --json        # include unreachable aliases (debugging)
brokre list --no-bastion-discovery   # local only — no SSH, no probe
```

When bastions are registered, `brokre list` **stays local-only by default** and does not SSH to bastions or trigger bastion unlock. Use `brokre list --include-bastions` (MCP: `include_bastions=true`) when you actually need routed aliases such as `b150::db`; that remote discovery may require unlock.

### Cross-network list inheritance (bastion broker)

For **cross-network** access — travel, VPN, public entry points — when direct LAN aliases are unreachable locally but reachable via a bastion running brokre.

**Prerequisites**

1. Laptop: `brokre bastion enable b150` (`b150` is a saved SSH alias)
2. Bastion host runs brokre at `~/.brokre/bin/brokre` (standard install / `npx` path) with inner aliases saved (e.g. `db`)

**Routed list**

```bash
brokre bastion unlock            # if bastion key is set
brokre list --include-bastions   # includes b150::db (route=b150, access=via_b150)
```

When cross-network, use `--include-bastions` when you need routed aliases. Plain `brokre list` stays local-only and does not unlock or SSH to bastions.

**Execute**

```bash
brokre ssh b150::db uname -a
# MCP: brokre_exec binary=ssh, args=["b150::db", "uname", "-a"]
```

When both paths work, the list shows **both** `db` (`direct`) and `b150::db` (`via_b150`) — distinguish by `access`.

### Bastion proxy (cross-network / intranet entry)

Promote **any** saved SSH alias whose remote host runs brokre into a bastion broker. Secrets stay on the bastion; the laptop caches metadata and executes via SSH passthrough.

```bash
brokre bastion enable b150        # register ssh alias b150 as bastion
brokre bastion set-key              # set bastion unlock key (TTY)
brokre bastion unlock               # unlock outbound session (TTL, 30 min idle default)
brokre list --include-bastions --json # discover bastion-routed aliases
brokre ssh b150::db uname -a        # routed exec via b150 remote brokre
brokre bastion sync b150 --json     # fetch alias list from one bastion
```

- Route separator **`::`** (`:` is illegal in alias names): `db` (local), `b150::db` (via bastion), `b1::b2::inner` (multi-hop, default depth ≤2).
- **Remote brokre**: routed exec invokes `~/.brokre/bin/brokre` on the bastion (with `BROKRE_SOFT_MEMLOCK=1`, `BROKRE_ALLOW_FILE_KEYCHAIN=1`, `BROKRE_ROUTED_INNER=1` for headless Linux). Interactive commands (e.g. `sudo -i`) automatically get `-tt`.
- **Guardrails**: probe concurrency cap, ms timeouts, short cache, loop detection, audit `route`/`bastion` (HMAC v4).
- **Manage UI**: `brokre manage` **Bastion** tab — register/disable bastions, Web set-key and unlock/lock, strict-mode toggle, sync remote aliases; non-TTY still auto-opens `/bastion-auth`. Audit tab filters by `bastion`/`source` and shows route fields.

### Bastion gate policy (default vs strict)

The bastion **gate** is a human unlock step before sensitive operations. It is **off until you set a bastion key** (`brokre bastion set-key`). After a key exists, unlock establishes a local TTL session (`brokre bastion unlock`, TTY passphrase, manage UI `/bastion-auth`, or MCP browser elicitation).

Policy is stored at `~/.brokre/bastion/policy.json` (`strict_mode`, default `false`).

| Mode | `gate_mode` | When unlock is required (key must be set) |
|------|-------------|-------------------------------------------|
| **default** | `default` | **Bastion outbound only** — `b150::inner` routed exec; SSH/scp/sftp to a **registered** bastion alias; `brokre list` / `brokre_list` when bastion discovery SSHs to bastions. Purely **local** exec (e.g. `brokre ssh lan-db`) does **not** require unlock. |
| **strict** | `strict` | **Every** `brokre exec` / MCP `brokre_exec`; metadata-only `brokre list` stays local-only, while `--include-bastions` still requires unlock. Use when you want a human in the loop for agent execution while a bastion key is configured. |

**Examples (default mode, key set, session locked)**

| Operation | Unlock needed? |
|-----------|----------------|
| `brokre ssh prod uname -a` (local alias) | No |
| `brokre ssh b150::db uname -a` | Yes |
| `brokre ssh b150 uptime` (registered bastion) | Yes |
| `brokre list --include-bastions` | Yes |
| `brokre list` (local only) | No |

In **strict** mode, exec rows require unlock; metadata-only `brokre list` remains local-only and does not unlock unless `--include-bastions` is used.

**Set gate mode**

```bash
brokre bastion strict status    # default | strict
brokre bastion strict on        # strict — all exec gated; list stays local-only unless discovery is requested
brokre bastion strict off       # default — bastion outbound only
```

| Surface | How |
|---------|-----|
| CLI | `brokre bastion strict on\|off\|status` |
| Manage UI | **Bastion** tab — strict mode toggle |
| MCP | `brokre_bastion_policy` — read current policy, or pass `{"strict_mode": true}` / `false` |

MCP read response includes `strict_mode`, `gate_mode`, `key_set`, `unlocked`. List/exec responses include `bastion_gate` (`required`, `unlocked_during_call`, `idle_expires_at`).

**Unlock session TTL** (defaults): **30 min idle** (`BROKRE_BASTION_IDLE_SECS`), **8 h max lifetime** (`BROKRE_BASTION_MAX_SECS`). Idle window **renews** on each gated call while unlocked (shared across CLI, MCP, and manage UI via `~/.brokre/run/bastion_session.json`). Bastion gate auth is independent of manage UI session idle expiry. Disable auto-open browser on MCP unlock: `BROKRE_BASTION_NO_AUTO_OPEN=1`.

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
