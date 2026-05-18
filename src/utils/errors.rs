use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokrError {
    #[error("vault error: {0}")]
    Vault(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("profile error: {0}")]
    Profile(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("cli error: {0}")]
    Cli(String),
    #[error("no tty available")]
    NoTty,
    #[error("policy denied")]
    PolicyDenied,
    #[error("audit error: {0}")]
    Audit(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, BrokrError>;
