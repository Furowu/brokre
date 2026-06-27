use crate::tunnel::protocol::{read_frame, write_frame, Frame};
use crate::utils::errors::{BrokreError, Result};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
pub fn terminal_size() -> (u16, u16) {
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) == 0 };
    if ok && size.ws_col > 0 && size.ws_row > 0 {
        (size.ws_col, size.ws_row)
    } else {
        (80, 24)
    }
}

#[cfg(not(unix))]
pub fn terminal_size() -> (u16, u16) {
    (80, 24)
}

#[cfg(unix)]
struct RawModeGuard;

#[cfg(unix)]
impl RawModeGuard {
    fn enable_if_tty() -> Option<Self> {
        if crate::security::tty::stdin_is_real_tty() {
            let _ = crossterm::terminal::enable_raw_mode();
            Some(Self)
        } else {
            None
        }
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

pub fn run_local_session<R, W>(
    reader: R,
    writer: W,
    inner: String,
    trailing: Vec<String>,
    forward_stdin: bool,
) -> Result<i32>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let (cols, rows) = terminal_size();
    let reader = Arc::new(Mutex::new(reader));
    let writer = Arc::new(Mutex::new(writer));

    {
        let mut w = writer
            .lock()
            .map_err(|_| BrokreError::Runtime("tunnel writer lock poisoned during hello".into()))?;
        write_frame(&mut *w, &Frame::hello())?;
    }
    match read_locked(&reader)? {
        Some(Frame::HelloAck { version }) => crate::tunnel::protocol::require_version(version)?,
        Some(Frame::Error { message }) => return Err(BrokreError::Runtime(message)),
        Some(other) => {
            return Err(BrokreError::Runtime(format!(
                "unexpected tunnel frame during hello: {other:?}"
            )))
        }
        None => {
            return Err(BrokreError::Runtime(
                "tunnel agent closed during hello".into(),
            ))
        }
    }

    {
        let mut w = writer
            .lock()
            .map_err(|_| BrokreError::Runtime("tunnel writer lock poisoned during exec".into()))?;
        write_frame(
            &mut *w,
            &Frame::ExecSession {
                inner,
                trailing,
                cols,
                rows,
            },
        )?;
    }

    #[cfg(unix)]
    let _raw = RawModeGuard::enable_if_tty();

    if forward_stdin {
        let writer_for_stdin = writer.clone();
        let _stdin_thread = thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        if let Ok(mut w) = writer_for_stdin.lock() {
                            let _ = write_frame(
                                &mut *w,
                                &Frame::Signal {
                                    signal: "EOF".into(),
                                },
                            );
                        }
                        break;
                    }
                    Ok(n) => {
                        let Ok(mut w) = writer_for_stdin.lock() else {
                            break;
                        };
                        if write_frame(
                            &mut *w,
                            &Frame::SessionData {
                                data: buf[..n].to_vec(),
                            },
                        )
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    } else {
        let mut w = writer.lock().map_err(|_| {
            BrokreError::Runtime("tunnel writer lock poisoned during stdin eof".into())
        })?;
        write_frame(
            &mut *w,
            &Frame::Signal {
                signal: "EOF".into(),
            },
        )?;
    }

    let mut exit_code = 1;
    loop {
        match read_locked(&reader)? {
            Some(Frame::SessionData { data }) => {
                std::io::stdout()
                    .write_all(&data)
                    .map_err(BrokreError::Io)?;
                std::io::stdout().flush().map_err(BrokreError::Io)?;
            }
            Some(Frame::Exit { code }) => {
                exit_code = code;
                break;
            }
            Some(Frame::Error { message }) => return Err(BrokreError::Runtime(message)),
            Some(_) => {}
            None => break,
        }
    }
    Ok(exit_code)
}

fn read_locked<R: Read>(reader: &Arc<Mutex<R>>) -> Result<Option<Frame>> {
    let mut r = reader
        .lock()
        .map_err(|_| BrokreError::Runtime("tunnel reader lock poisoned".into()))?;
    read_frame(&mut *r)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|win| {
        win.iter()
            .zip(needle_lower.iter())
            .all(|(b, n)| b.to_ascii_lowercase() == *n)
    })
}

#[cfg(unix)]
pub fn run_agent_session<W, R>(
    writer: Arc<Mutex<W>>,
    reader: Arc<Mutex<R>>,
    inner: String,
    trailing: Vec<String>,
    cols: u16,
    rows: u16,
) -> Result<i32>
where
    W: Write + Send + 'static,
    R: Read + Send + 'static,
{
    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| BrokreError::Runtime(format!("tunnel openpty: {e}")))?;

    let exit_on_shared_connection_closed =
        crate::runtime::elevated::parse_elevated_trailing(&trailing).is_some();
    let mut cmd = CommandBuilder::new(std::env::current_exe().map_err(BrokreError::Io)?);
    cmd.env("BROKRE_ROUTED_INNER", "1");
    cmd.env("BROKRE_TUNNEL_AGENT_INNER", "1");
    cmd.env("BROKRE_BASTION_SOURCE", "bastion");
    cmd.env("BROKRE_SOFT_MEMLOCK", "1");
    cmd.env("BROKRE_ALLOW_FILE_KEYCHAIN", "1");
    cmd.arg("ssh");
    cmd.arg(inner);
    for arg in trailing {
        cmd.arg(arg);
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| BrokreError::Runtime(format!("tunnel spawn inner brokre: {e}")))?;
    drop(pair.slave);

    let master = Arc::new(Mutex::new(pair.master));
    let mut pty_reader = master
        .lock()
        .map_err(|_| BrokreError::Runtime("tunnel pty lock poisoned".into()))?
        .try_clone_reader()
        .map_err(|e| BrokreError::Runtime(format!("tunnel clone pty reader: {e}")))?;
    let mut pty_writer = master
        .lock()
        .map_err(|_| BrokreError::Runtime("tunnel pty lock poisoned".into()))?
        .take_writer()
        .map_err(|e| BrokreError::Runtime(format!("tunnel take pty writer: {e}")))?;

    let writer_for_pty = writer.clone();
    let shared_connection_closed = Arc::new(AtomicBool::new(false));
    let shared_connection_closed_for_pty = shared_connection_closed.clone();
    let pty_to_tunnel = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut window: Vec<u8> = Vec::with_capacity(2048);
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if exit_on_shared_connection_closed {
                        window.extend_from_slice(&buf[..n]);
                        if window.len() > 4096 {
                            let drop_n = window.len() - 2048;
                            window.drain(..drop_n);
                        }
                        if contains_ascii_case_insensitive(&window, b"shared connection")
                            && contains_ascii_case_insensitive(&window, b"closed")
                        {
                            shared_connection_closed_for_pty.store(true, Ordering::Release);
                        }
                    }
                    let Ok(mut w) = writer_for_pty.lock() else {
                        break;
                    };
                    if write_frame(
                        &mut *w,
                        &Frame::SessionData {
                            data: buf[..n].to_vec(),
                        },
                    )
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let master_for_resize = master.clone();
    let tunnel_to_pty = thread::spawn(move || loop {
        let frame = {
            let Ok(mut r) = reader.lock() else {
                break;
            };
            read_frame(&mut *r)
        };
        match frame {
            Ok(Some(Frame::SessionData { data })) => {
                if pty_writer.write_all(&data).is_err() {
                    break;
                }
                let _ = pty_writer.flush();
            }
            Ok(Some(Frame::Resize { cols, rows })) => {
                if let Ok(master) = master_for_resize.lock() {
                    let _ = master.resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    });
                }
            }
            Ok(Some(Frame::Signal { signal })) if signal.eq_ignore_ascii_case("INT") => {
                let _ = pty_writer.write_all(&[0x03]);
                let _ = pty_writer.flush();
            }
            Ok(Some(Frame::Signal { signal })) if signal.eq_ignore_ascii_case("EOF") => break,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    });

    let code = loop {
        if shared_connection_closed.load(Ordering::Acquire) {
            let _ = child.kill();
            break 0;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| BrokreError::Runtime(format!("tunnel wait inner brokre: {e}")))?
        {
            break status.exit_code() as i32;
        }
        thread::sleep(Duration::from_millis(15));
    };
    let _ = pty_to_tunnel.thread().id();
    let _ = tunnel_to_pty.thread().id();
    Ok(code)
}

#[cfg(not(unix))]
pub fn run_agent_session<W, R>(
    _writer: Arc<Mutex<W>>,
    _reader: Arc<Mutex<R>>,
    _inner: String,
    _trailing: Vec<String>,
    _cols: u16,
    _rows: u16,
) -> Result<i32>
where
    W: Write + Send + 'static,
    R: Read + Send + 'static,
{
    Err(BrokreError::Runtime(
        "tunnel SessionRelay agent requires Unix".into(),
    ))
}
