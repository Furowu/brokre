# OS hardening & injector (`T1` mitigation)

This document describes runtime hardening, environment overrides, and how the vault injector subprocess interacts with tests and production.

## Goals

- Shrink the window where decrypted passwords exist in the **long-lived** `brokre` parent (Unix: parent never decrypts for saved records; a short `brokre --internal-injector` child decrypts and writes once to the PTY).
- Reduce core dumps / casual ptrace visibility (`PR_SET_DUMPABLE` / `RLIMIT_CORE` on Linux, `PT_DENY_ATTACH` + core limit on macOS).
- Optional `mlockall` on Linux to lower swap pressure for in-memory secrets (may fail in containers — see below).

## Environment variables

| Variable | Effect |
|----------|--------|
| `BROKRE_DISABLE_HARDENING=1` | Skips OS hardening in the main process and **refuses vault injector** (injector exits; no password injection). |
| `BROKRE_SOFT_MEMLOCK=1` (Linux only) | If `mlockall` fails under `Enforce`, allow startup with a warning instead of exiting. |
| `BROKRE_INJECTOR_EXE` (Unix, advanced) | Path to the `brokre` binary used to spawn `--internal-injector`. Defaults to `std::env::current_exe()`. Integration tests set this when the PTY runs inside a non-`brokre` test harness so the real CLI binary is executed. |

## Build profiles

- **Debug** (`cargo build` / `cargo test`): `HardeningMode::WarnOnly` — hardening failures are warnings where possible (e.g. `mlockall`).
- **Release** (`cargo build --release`): `HardeningMode::Enforce` — Linux `TracerPid != 0` or `mlockall` failure (without `BROKRE_SOFT_MEMLOCK`) aborts startup.

## Cargo features

- **`in_proc_inject` (default)** — Enables `PtyCredential::Secret` for in-process PTY injection (used by `e2e_pty_auto_inject` and optional tooling). **Strict** builds can use:

  ```bash
  cargo build --release --no-default-features
  ```

  On Unix, saved-record injection still uses the subprocess injector; only the `Secret` test path is removed.

## Platform matrix

| Mechanism | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| Vault subprocess injector | Yes | Yes | N/A (password held only for `PtyCredential::Secret` path) |
| `TracerPid` ptrace detection | Yes | No (see note) | N/A |
| `PR_SET_DUMPABLE` | Yes | N/A | N/A |
| `PT_DENY_ATTACH` | N/A | Yes | N/A |
| Core limit `RLIMIT_CORE` | Yes | Yes | N/A |
| `mlockall` | Yes (optional soft via env) | No (not used) | N/A |

**macOS note:** `libc` does not reliably expose `kinfo_proc` / `P_TRACED` for Rust targets; traced-process detection is Linux-only. macOS still applies `PT_DENY_ATTACH` and core limits.

## Manual verification checklist

1. **Linux release + memlock:** `cargo build --release && ./target/release/brokre list` — expect failure if `mlockall` cannot lock and `BROKRE_SOFT_MEMLOCK` is unset; success with `BROKRE_SOFT_MEMLOCK=1`.
2. **Linux core:** After a normal `brokre ssh` session, `gcore $(pidof brokre)` should fail or produce a core without vault password strings (parent never decrypts on Unix).
3. **macOS debugger:** Release `brokre` should resist casual `lldb` attach after `PT_DENY_ATTACH` (SIP / permissions may still allow root).
4. **Container:** If `mlockall` fails, set `BROKRE_SOFT_MEMLOCK=1` or raise `memlock` ulimit / `IPC_LOCK` capability.

## Residual risk (unchanged)

Root (`CAP_SYS_PTRACE` / memory forensics) can still capture plaintext in the **injector child** during its short lifetime. This design reduces exposure in the parent and removes long-lived decrypted buffers there; it does not defeat a fully compromised kernel/host.

## SSH private keys (T1 scope note)

On Unix, **vault passwords** for saved records are decrypted in a short-lived `brokre --internal-injector` child. **SSH private keys** stored in the vault are still decrypted in the long-lived parent via `decrypt_for_exec` when materializing `-i` key files (`src/runtime/ssh_identity.rs`). Key material exists in parent memory only for the duration of the SSH session; temp files are `0600` and unlinked on drop.

**Planned hardening:** move key materialization into the injector subprocess model (same as passwords). Until then, treat SSH-key records as a slightly wider T1 window than password-only records.
