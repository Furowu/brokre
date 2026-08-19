//! PTY read-side drain after password injection (prevents secrets echoing into interactive shells).

/// Re-enable echo on the PTY master without restoring a stale termios snapshot.
#[cfg(unix)]
pub fn ensure_pty_echo_on(fd: libc::c_int) {
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return;
        }
        term.c_lflag |= libc::ECHO;
        let _ = libc::tcsetattr(fd, libc::TCSANOW, &term);
    }
}

#[cfg(not(unix))]
pub fn ensure_pty_echo_on(_fd: i32) {}

/// Disable echo on the PTY master without restoring a stale termios snapshot.
#[cfg(unix)]
pub fn ensure_pty_echo_off(fd: libc::c_int) {
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return;
        }
        term.c_lflag &= !libc::ECHO;
        let _ = libc::tcsetattr(fd, libc::TCSANOW, &term);
    }
}

#[cfg(not(unix))]
pub fn ensure_pty_echo_off(_fd: i32) {}

#[cfg(unix)]
pub fn drain_pty_master(fd: libc::c_int) {
    unsafe {
        // Non-blocking read drain only — never tcflush (can drop injected password bytes).
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return;
        }
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
        }
        libc::fcntl(fd, libc::F_SETFL, flags);
    }
}

#[cfg(not(unix))]
pub fn drain_pty_master(_fd: i32) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use portable_pty::{MasterPty, NativePtySystem, PtySize, PtySystem};

    #[test]
    fn ensure_pty_echo_off_clears_echo_flag() {
        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let fd = MasterPty::as_raw_fd(&*pair.master).expect("master fd");
        ensure_pty_echo_on(fd);
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut term), 0);
            assert_ne!(
                term.c_lflag & libc::ECHO,
                0,
                "echo should be on after ensure_pty_echo_on"
            );
        }
        ensure_pty_echo_off(fd);
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut term), 0);
            assert_eq!(term.c_lflag & libc::ECHO, 0, "echo should be off");
        }
        drop(pair);
    }
}
