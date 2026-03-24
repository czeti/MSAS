use std::{error::{Error}, fmt::Display, io};

#[derive(Debug)]
pub enum MsasError {
    Io(io::Error),
    Parse(String),
    Ftp(String),
    ScriptFailed(String),
    Other(String)
}

impl Display for MsasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O Error occurred: {}", e),
            Self::Parse(e) => write!(f, "Failed to parse: {}", e),
            Self::Ftp(e) => write!(f, "FTP error occurred: {}", e),
            Self::ScriptFailed(e) => write!(f, "Script failed: {}", e),
            Self::Other(e) => write!(f, "Error occurred: {}", e)
        }
    }
}

impl Error for MsasError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None
        }
    }
}

impl From<io::Error> for MsasError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}