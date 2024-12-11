use std::convert::Infallible;
use std::error::Error as StdError;

/// A Mosaic error
#[derive(Debug)]
pub enum Error {
    BadScheme(String),
    Base64(base64::DecodeError),
    DhtPutError,
    DhtWasShutdown,
    Ed25519(ed25519_dalek::ed25519::Error),
    HashMismatch,
    KeyLength,
    General(String),
    IdZerosAreNotZero,
    InvalidServerBootstrapString,
    InvalidUserBootstrapString,
    InvalidUri(http::uri::InvalidUri),
    InvalidUriParts(http::uri::InvalidUriParts),
    MissingScheme,
    RecordSectionLengthMismatch,
    RecordTooLong,
    RecordTooShort,
    ReferenceLength,
    ReservedFlagsUsed,
    ReservedSpaceUsed,
    SystemTime(std::time::SystemTimeError),
    TimeIsBeyondLeapSecondData,
    TimeOutOfRange,
    Utf8(std::str::Utf8Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadScheme(s) => write!(f, "Unsupported scheme: {s}"),
            Error::Base64(e) => write!(f, "Base64 decode error: {e}"),
            Error::DhtPutError => write!(f, "DHT put error"),
            Error::DhtWasShutdown => write!(f, "DHT was shutdown"),
            Error::Ed25519(e) => write!(f, "ed25519 Error: {e}"),
            Error::HashMismatch => write!(f, "Hash mismatch"),
            Error::KeyLength => write!(f, "Data length is not 32 bytes"),
            Error::General(s) => write!(f, "General Error: {s}"),
            Error::IdZerosAreNotZero => write!(f, "ID zeroes are not zero"),
            Error::InvalidServerBootstrapString => write!(f, "Invalid ServerBootstrap String"),
            Error::InvalidUserBootstrapString => write!(f, "Invalid UserBootstrap String"),
            Error::InvalidUri(e) => write!(f, "Invalid URI: {e}"),
            Error::InvalidUriParts(e) => write!(f, "Invalid URI parts: {e}"),
            Error::MissingScheme => write!(f, "Missing scheme"),
            Error::RecordSectionLengthMismatch => write!(f, "Record section length mismatch"),
            Error::RecordTooLong => write!(f, "Record too long"),
            Error::RecordTooShort => write!(f, "Record too short"),
            Error::ReferenceLength => write!(f, "Data length is not 48 bytes"),
            Error::ReservedFlagsUsed => write!(f, "Reserved flags used"),
            Error::ReservedSpaceUsed => write!(f, "Reserved space used"),
            Error::SystemTime(e) => write!(f, "Time Error: {e}"),
            Error::TimeIsBeyondLeapSecondData => {
                write!(f, "Time is beyond available leap second data")
            }
            Error::TimeOutOfRange => write!(f, "Time is out of range"),
            Error::Utf8(e) => write!(f, "UTF-8 error: {e}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Base64(e) => Some(e),
            Error::Ed25519(e) => Some(e),
            Error::InvalidUri(e) => Some(e),
            Error::InvalidUriParts(e) => Some(e),
            Error::SystemTime(e) => Some(e),
            Error::Utf8(e) => Some(e),
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

impl From<http::uri::InvalidUri> for Error {
    fn from(e: http::uri::InvalidUri) -> Error {
        Error::InvalidUri(e)
    }
}

impl From<http::uri::InvalidUriParts> for Error {
    fn from(e: http::uri::InvalidUriParts) -> Error {
        Error::InvalidUriParts(e)
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(e: std::time::SystemTimeError) -> Error {
        Error::SystemTime(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf8(e)
    }
}
