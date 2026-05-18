# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

Please report security vulnerabilities privately via email to `security@brokr.dev`.
Include a GPG-encrypted message if possible.

## Key Security Properties

1. **No plaintext in process listings**: Secrets are never passed as command-line arguments.
2. **No env pollution**: Environment injection is subprocess-only; the parent `brokr` process does not export secrets.
3. **Double-factor reveal**: `brokr reveal` requires both a real TTY and a master passphrase.
4. **Double encryption**: Secrets are encrypted with AES-256-GCM. The DEK is wrapped with both an OS keychain key and a passphrase-derived key.
5. **Audit integrity**: Audit logs are HMAC-chained. Tampering is detectable via `brokr audit verify`.

## Cross-platform Security Matrix

| Capability         | macOS           | Linux            | Windows                  |
|--------------------|-----------------|------------------|--------------------------|
| OS Keychain        | Keychain Services | Secret Service | Credential Manager       |
| Secure Tempfile    | 0600 + unlink   | 0600 + unlink    | DeleteOnClose + ACL      |
| SSH Agent Bridge   | Unix socket     | Unix socket      | Named pipe (experimental)|
| SSH_ASKPASS        | Native          | Native           | Requires DISPLAY/PowerShell |
| Signal Cleanup     | SIGTERM         | SIGTERM          | ConsoleCtrlHandler       |

## Key Lifecycle

- **master_kek**: 32-byte random, generated on first run, stored in OS keychain. Never leaves keychain.
- **audit_hmac_key**: 32-byte random, generated on first run, stored in OS keychain.
- **reveal passphrase**: User-defined, never stored. Derived via Argon2id (m=64MiB, t=3, p=1).
- **DEK per record**: 32-byte random, unique per secret record.
