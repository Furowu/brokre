# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

Please report security vulnerabilities privately via email to `security@brokre.dev`.
Include a GPG-encrypted message if possible.

## Key Security Properties

1. **No plaintext in process listings**: Secrets are never passed as command-line arguments.
2. **No env pollution**: Environment injection is subprocess-only; the parent `brokre` process does not export secrets.
3. **Double-factor reveal**: `brokre reveal` requires both a real TTY and a master passphrase.
4. **Double encryption**: Secrets are encrypted with AES-256-GCM. The DEK is wrapped with both an OS keychain key and a passphrase-derived key.
5. **Audit integrity**: Audit logs are HMAC-chained (v2 covers `name`, redacted args, hardening, and injector metadata; v1 logs remain verifiable). Tampering is detectable via `brokre audit verify`.
6. **Unix T1 hardening**: Optional `mlockall`, no core dumps, reduced ptrace/dump surface; vault passwords are injected via a short `brokre --internal-injector` child (see [docs/HARDENING.md](docs/HARDENING.md)).
7. **Manage UI**: `brokre manage` serves a loopback-only web UI with terminal-printed session token; password fields are write-only (no HTTP reveal). See [THREAT_MODEL.md](THREAT_MODEL.md) T10.

## Cross-platform Security Matrix

| Capability         | macOS           | Linux            | Windows                  |
|--------------------|-----------------|------------------|--------------------------|
| Master / audit keys | File `~/.brokre/.master_kek` (0600) by default; `BROKRE_USE_KEYCHAIN=1` for Keychain | OS keyring (Secret Service) | Credential Manager |
| Secure Tempfile    | 0600 + unlink   | 0600 + unlink    | DeleteOnClose + ACL      |
| SSH Agent Bridge   | Unix socket     | Unix socket      | Named pipe (experimental)|
| SSH_ASKPASS        | Native          | Native           | Requires DISPLAY/PowerShell |
| Signal Cleanup     | SIGTERM         | SIGTERM          | ConsoleCtrlHandler       |
| OS / memory hardening | PT_DENY_ATTACH, core limit | prctl dumpable, core limit, mlockall, TracerPid | N/A (see roadmap) |
| Vault PTY inject   | Subprocess injector | Subprocess injector | In-process decrypt + PTY write |

## Key Lifecycle

- **master_kek**: 32-byte random, generated on first run. **Linux**: stored in the OS keyring. **macOS (default)**: stored in `~/.brokre/.master_kek` (mode 0600) to avoid repeated Keychain prompts for ad-hoc-signed binaries; set `BROKRE_USE_KEYCHAIN=1` to use Keychain Services instead.
- **audit_hmac_key**: Same storage rules as `master_kek` (`~/.brokre/.audit_hmac` on macOS by default).
- **reveal passphrase**: User-defined, never stored. Derived via Argon2id (m=64MiB, t=3, p=1).
- **DEK per record**: 32-byte random, unique per secret record.
