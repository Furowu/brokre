use is_terminal::IsTerminal;

pub fn stdin_is_real_tty() -> bool {
    std::io::stdin().is_terminal() && nix_isatty(0)
}

pub fn stdout_is_real_tty() -> bool {
    std::io::stdout().is_terminal() && nix_isatty(1)
}

/// True when stdin is a pipe or file redirect worth forwarding to a child (not a TTY, not `/dev/null`).
pub fn stdin_is_pipe() -> bool {
    !stdin_is_real_tty()
        && !std::io::stdin().is_terminal()
        && !stdin_points_to_dev_null()
}

/// True when stdin should be forwarded to OpenSSH (real pipe or file, not `/dev/null`).
pub fn stdin_should_forward_to_child() -> bool {
    stdin_is_pipe()
}

#[cfg(unix)]
fn stdin_points_to_dev_null() -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    let null = match std::fs::File::open("/dev/null") {
        Ok(f) => f,
        Err(_) => return false,
    };
    let null_fd = null.as_raw_fd();
    unsafe {
        let mut st_in: libc::stat = std::mem::zeroed();
        let mut st_null: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st_in) != 0 {
            return false;
        }
        if libc::fstat(null_fd, &mut st_null) != 0 {
            return false;
        }
        st_in.st_dev == st_null.st_dev && st_in.st_ino == st_null.st_ino
    }
}

#[cfg(not(unix))]
fn stdin_points_to_dev_null() -> bool {
    false
}

#[cfg(unix)]
fn nix_isatty(fd: std::os::fd::RawFd) -> bool {
    nix::unistd::isatty(fd).unwrap_or(false)
}

#[cfg(not(unix))]
fn nix_isatty(_fd: i32) -> bool {
    // On non-Unix we rely solely on is-terminal.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_check_runs() {
        // In CI this may be false; we just ensure it doesn't panic.
        let _ = stdin_is_real_tty();
        let _ = stdout_is_real_tty();
        let _ = stdin_is_pipe();
    }
}
