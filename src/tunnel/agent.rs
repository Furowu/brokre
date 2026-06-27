use crate::tunnel::protocol::{read_frame, require_version, write_frame, Frame};
use crate::utils::errors::{BrokreError, Result};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub fn run_stdio() -> Result<()> {
    run(std::io::stdin(), std::io::stdout())
}

pub fn run<R, W>(reader: R, writer: W) -> Result<()>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let reader = Arc::new(Mutex::new(reader));
    let writer = Arc::new(Mutex::new(writer));

    let first = read_next(&reader)?
        .ok_or_else(|| BrokreError::Runtime("tunnel client closed before hello".into()))?;
    match first {
        Frame::Hello { version } => {
            require_version(version)?;
            write_next(&writer, &Frame::hello_ack())?;
        }
        other => {
            return Err(BrokreError::Runtime(format!(
                "expected tunnel hello, got {other:?}"
            )))
        }
    }

    let Some(exec) = read_next(&reader)? else {
        return Ok(());
    };
    let (inner, trailing, cols, rows) = match exec {
        Frame::ExecSession {
            inner,
            trailing,
            cols,
            rows,
        } => (inner, trailing, cols, rows),
        other => {
            return Err(BrokreError::Runtime(format!(
                "expected tunnel exec session, got {other:?}"
            )))
        }
    };

    let code = match crate::tunnel::session_relay::run_agent_session(
        writer.clone(),
        reader.clone(),
        inner,
        trailing,
        cols,
        rows,
    ) {
        Ok(code) => code,
        Err(e) => {
            let _ = write_next(
                &writer,
                &Frame::Error {
                    message: e.to_string(),
                },
            );
            return Err(e);
        }
    };
    write_next(&writer, &Frame::Exit { code })?;
    Ok(())
}

fn read_next<R: Read>(reader: &Arc<Mutex<R>>) -> Result<Option<Frame>> {
    let mut r = reader
        .lock()
        .map_err(|_| BrokreError::Runtime("tunnel agent reader lock poisoned".into()))?;
    read_frame(&mut *r)
}

fn write_next<W: Write>(writer: &Arc<Mutex<W>>, frame: &Frame) -> Result<()> {
    let mut w = writer
        .lock()
        .map_err(|_| BrokreError::Runtime("tunnel agent writer lock poisoned".into()))?;
    write_frame(&mut *w, frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::protocol::Frame;
    use std::io::Cursor;

    #[test]
    fn rejects_non_hello_first_frame() {
        let mut input = Vec::new();
        crate::tunnel::protocol::write_frame(
            &mut input,
            &Frame::ExecSession {
                inner: "db".into(),
                trailing: Vec::new(),
                cols: 80,
                rows: 24,
            },
        )
        .unwrap();
        let err = run(Cursor::new(input), Vec::<u8>::new()).unwrap_err();
        assert!(err.to_string().contains("expected tunnel hello"));
    }

    #[test]
    fn hello_then_eof_is_clean_doctor_smoke() {
        let mut input = Vec::new();
        crate::tunnel::protocol::write_frame(&mut input, &Frame::hello()).unwrap();
        run(Cursor::new(input), Vec::<u8>::new()).unwrap();
    }
}
