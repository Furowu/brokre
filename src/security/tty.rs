use is_terminal::IsTerminal;

pub fn stdin_is_real_tty() -> bool {
    std::io::stdin().is_terminal() && nix_isatty(0)
}

pub fn stdout_is_real_tty() -> bool {
    std::io::stdout().is_terminal() && nix_isatty(1)
}

/// True when stdin is a pipe or redirect (readable, but not an interactive TTY).
pub fn stdin_is_pipe() -> bool {
    !stdin_is_real_tty() && !std::io::stdin().is_terminal()
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
