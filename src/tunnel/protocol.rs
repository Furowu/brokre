use crate::tunnel::PROTOCOL_VERSION;
use crate::utils::errors::{BrokreError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Hello {
        version: u16,
    },
    HelloAck {
        version: u16,
    },
    ExecSession {
        inner: String,
        trailing: Vec<String>,
        cols: u16,
        rows: u16,
    },
    SessionData {
        data: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Signal {
        signal: String,
    },
    Exit {
        code: i32,
    },
    Error {
        message: String,
    },
}

impl Frame {
    pub fn hello() -> Self {
        Self::Hello {
            version: PROTOCOL_VERSION,
        }
    }

    pub fn hello_ack() -> Self {
        Self::HelloAck {
            version: PROTOCOL_VERSION,
        }
    }
}

pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<()> {
    let payload = serde_json::to_vec(frame)
        .map_err(|e| BrokreError::Runtime(format!("tunnel frame encode: {e}")))?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(BrokreError::Runtime("tunnel frame too large".into()));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(BrokreError::Io)?;
    writer.write_all(&payload).map_err(BrokreError::Io)?;
    writer.flush().map_err(BrokreError::Io)?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Frame>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(BrokreError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(BrokreError::Runtime(format!(
            "tunnel frame too large: {len} bytes"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(BrokreError::Io)?;
    let frame = serde_json::from_slice(&payload)
        .map_err(|e| BrokreError::Runtime(format!("tunnel frame decode: {e}")))?;
    Ok(Some(frame))
}

pub fn require_version(version: u16) -> Result<()> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(BrokreError::Runtime(format!(
            "tunnel protocol mismatch: local={}, remote={version}",
            PROTOCOL_VERSION
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_frame() {
        let frame = Frame::ExecSession {
            inner: "db".into(),
            trailing: vec!["uname".into(), "-a".into()],
            cols: 120,
            rows: 40,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(buf)).unwrap(), Some(frame));
    }

    #[test]
    fn rejects_version_mismatch() {
        assert!(require_version(PROTOCOL_VERSION).is_ok());
        assert!(require_version(PROTOCOL_VERSION + 1).is_err());
    }

    #[test]
    fn handles_clean_eof() {
        let mut input = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_frame(&mut input).unwrap(), None);
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut input = Cursor::new(((MAX_FRAME_LEN as u32) + 1).to_be_bytes().to_vec());
        assert!(read_frame(&mut input).is_err());
    }

    #[test]
    fn preserves_session_data_order() {
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame::SessionData {
                data: b"one".to_vec(),
            },
        )
        .unwrap();
        write_frame(
            &mut buf,
            &Frame::SessionData {
                data: b"two".to_vec(),
            },
        )
        .unwrap();
        let mut input = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut input).unwrap(),
            Some(Frame::SessionData {
                data: b"one".to_vec()
            })
        );
        assert_eq!(
            read_frame(&mut input).unwrap(),
            Some(Frame::SessionData {
                data: b"two".to_vec()
            })
        );
    }
}
