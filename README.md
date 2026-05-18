# brokr — AI-safe Credential Broker

`brokr` is a local credential broker that lets AI agents spawn connections to databases, SSH servers, and other CLI tools **without ever exposing plaintext secrets** to the AI process, shell history, or `ps` output.

## Why brokr?

| Problem | Existing tool | brokr solution |
|---|---|---|
| Secrets in `ps` / `env` | `sshpass`, env exports | Secure injection via fd, tempfile, or ephemeral ssh-agent |
| AI can read secrets | 1Password CLI exports to env | Double-factor reveal (TTY + passphrase) |
| Unknown CLI tools | Hard-coded wrappers | Extensible TOML profile engine |
| Audit tampering | None | HMAC-chained audit logs |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/brokr/brokr/main/install.sh | bash
```

Or via Homebrew (macOS/Linux):

```bash
brew tap brokr/brokr
brew install brokr
```

## Quick Start

### 1. Initialize a credential

```bash
brokr init prod-db
# prompts for host, user, password...
# performs trial login before encrypting
```

### 2. Use it (AI-safe)

```bash
brokr exec mysql prod-db -- -e "SHOW TABLES"
# or shorthand:
brokr mysql prod-db -e "SHOW TABLES"
```

### 3. List metadata (AI-friendly)

```bash
brokr list --json
# Only outputs profile, name, labels, host — never passwords
```

### 4. Reveal (human-only)

```bash
brokr reveal mysql prod-db --field password
# Requires real TTY + master passphrase
```

## Architecture

```
┌─────────┐     ┌──────────┐     ┌─────────────┐     ┌────────────┐
│ AI/User │────▶│ brokr CLI│────▶│ OS Keychain │────▶│ Vault File │
└─────────┘     └──────────┘     └─────────────┘     └────────────┘
                      │
                      ▼
               ┌─────────────┐
               │ Secure Inject│──▶ ssh / mysql / psql / redis-cli / mc
               └─────────────┘
```

- **Double encryption**: Each secret is encrypted with a unique DEK. The DEK is wrapped separately for `exec` (OS keychain on Linux, file-backed on macOS) and `reveal` (passphrase-derived Argon2id key).
- **Secure injection strategies**: Env (subprocess-only), Stdin, TempFile (0600 + unlink), SSH_ASKPASS, ephemeral ssh-agent, or custom profile-driven injection.
- **Audit**: Every action is logged to an HMAC-chained JSONL file.

## Built-in Connectors

- `ssh` — password via SSH_ASKPASS, private key via ephemeral ssh-agent
- `mysql` — `--defaults-extra-file` via secure tempfile
- `postgres` — `PGPASSFILE` via secure tempfile
- `clickhouse` — `--password-file` via secure tempfile
- `redis` — `REDISCLI_AUTH` env (subprocess only)
- `minio` — temporary `MC_CONFIG_DIR`

## Custom Profiles

Create `~/.brokr/profiles/docker-registry.toml`:

```toml
[profile]
name = "docker-registry"
display = "Docker Registry"
binary = "docker"

[fields]
host     = { prompt = "Registry host", required = true }
username = { prompt = "Username", required = true }
password = { prompt = "Password", secret = true, required = true }

[injection]
strategy = "stdin"
args     = ["login", "{{host}}", "-u", "{{username}}", "--password-stdin"]

[verify]
args             = ["login", "{{host}}", "-u", "{{username}}", "--password-stdin"]
expect_exit_code = 0
```

Then `brokr init --profile docker-registry myreg`.

## Security

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## License

MIT
