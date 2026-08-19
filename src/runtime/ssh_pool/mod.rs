#[cfg(unix)]
pub mod daemon;

#[cfg(unix)]
pub mod pool;

#[cfg(unix)]
pub use pool::{
    cleanup_stale_pool, maybe_exec_via_ssh_pool, pool_pid_path, pool_socket_path,
    run_internal_daemon, SshPoolOutcome,
};
