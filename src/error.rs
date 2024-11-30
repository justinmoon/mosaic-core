use std::convert::Infallible;
use std::error::Error as StdError;

/// A Mosaic error
#[derive(Debug)]
pub enum Error {
    Base64(base64::DecodeError),
    Ed25519(ed25519_dalek::ed25519::Error),
    KeyLength,
    General(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Base64(e) => write!(f, "Base64 decode error: {e}"),
            Error::Ed25519(e) => write!(f, "ed25519 Error: {e}"),
            Error::KeyLength => write!(f, "Data length is not 32 bytes"),
            Error::General(s) => write!(f, "General Error: {s}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Base64(e) => Some(e),
            Error::Ed25519(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        panic!("INFALLIBLE")
    }
}

impl From<()> for Error {
    fn from((): ()) -> Self {
        Error::General("Error".to_owned())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Error {
        Error::Base64(e)
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(e: ed25519_dalek::ed25519::Error) -> Error {
        Error::Ed25519(e)
    }
}
