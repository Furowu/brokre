//! PTY read-side drain after password injection (prevents secrets echoing into interactive shells).

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
