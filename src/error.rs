use std::convert::Infallible;
use std::error::Error as StdError;
use std::panic::Location;

/// A Mosaic error
#[derive(Debug)]
pub struct Error {
    /// The error itself
    pub inner: InnerError,
    location: &'static Location<'static>,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}", self.inner, self.location)
    }
}

/// Errors that can occur in this crate
#[derive(Debug)]
pub enum InnerError {
    /// Unsupported URI scheme
    BadScheme(String),

    /// Base64 decode error
    Base64(base64::DecodeError),

    /// DHT put error
    DhtPutError,

    /// DHT was shutdown
    DhtWasShutdown,

    /// ed25519 error
    Ed25519(ed25519_dalek::ed25519::Error),

    /// Hash mismatch
    HashMismatch,

    /// Key data length is not 32 bytes
    KeyLength,

    /// General error
    General(String),

    /// ID zeroes are not zero
    IdZerosAreNotZero,

    /// Invalid `ServerBootstrap` String
    InvalidServerBootstrapString,

    /// Invalid `UserBootstrap` String
    InvalidUserBootstrapString,

    /// Invalid URI
    InvalidUri(http::uri::InvalidUri),

    /// Invalid URI parts
    InvalidUriParts(http::uri::InvalidUriParts),

    /// Missing scheme
    MissingScheme,

    /// Record section length mismatch
    RecordSectionLengthMismatch,

    /// Record too long
    RecordTooLong,

    /// Record too short
    RecordTooShort,

    /// Reference data length is not 48 bytes
    ReferenceLength,

    /// Reserved flags used
    ReservedFlagsUsed,

    /// Reserved space used
    ReservedSpaceUsed,

    /// Time error
    SystemTime(std::time::SystemTimeError),

    /// Time is beyond available leap second data
    TimeIsBeyondLeapSecondData,

    /// Time is out of range
    TimeOutOfRange,

    /// UTF-8 error
    Utf8(std::str::Utf8Error),
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::BadScheme(s) => write!(f, "Unsupported URI scheme: {s}"),
            InnerError::Base64(e) => write!(f, "Base64 decode error: {e}"),
            InnerError::DhtPutError => write!(f, "DHT put error"),
            InnerError::DhtWasShutdown => write!(f, "DHT was shutdown"),
            InnerError::Ed25519(e) => write!(f, "ed25519 Error: {e}"),
            InnerError::HashMismatch => write!(f, "Hash mismatch"),
            InnerError::KeyLength => write!(f, "Key data length is not 32 bytes"),
            InnerError::General(s) => write!(f, "General Error: {s}"),
            InnerError::IdZerosAreNotZero => write!(f, "ID zeroes are not zero"),
            InnerError::InvalidServerBootstrapString => write!(f, "Invalid ServerBootstrap String"),
            InnerError::InvalidUserBootstrapString => write!(f, "Invalid UserBootstrap String"),
            InnerError::InvalidUri(e) => write!(f, "Invalid URI: {e}"),
            InnerError::InvalidUriParts(e) => write!(f, "Invalid URI parts: {e}"),
            InnerError::MissingScheme => write!(f, "Missing scheme"),
            InnerError::RecordSectionLengthMismatch => write!(f, "Record section length mismatch"),
            InnerError::RecordTooLong => write!(f, "Record too long"),
            InnerError::RecordTooShort => write!(f, "Record too short"),
            InnerError::ReferenceLength => write!(f, "Reference data length is not 48 bytes"),
            InnerError::ReservedFlagsUsed => write!(f, "Reserved flags used"),
            InnerError::ReservedSpaceUsed => write!(f, "Reserved space used"),
            InnerError::SystemTime(e) => write!(f, "Time Error: {e}"),
            InnerError::TimeIsBeyondLeapSecondData => {
                write!(f, "Time is beyond available leap second data")
            }
            InnerError::TimeOutOfRange => write!(f, "Time is out of range"),
            InnerError::Utf8(e) => write!(f, "UTF-8 error: {e}"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::Base64(e) => Some(e),
            InnerError::Ed25519(e) => Some(e),
            InnerError::InvalidUri(e) => Some(e),
            InnerError::InvalidUriParts(e) => Some(e),
            InnerError::SystemTime(e) => Some(e),
            InnerError::Utf8(e) => Some(e),
            _ => None,
        }
    }
}

// Note: we impl Into because our typical pattern is InnerError::Variant.into()
//       when we tried implementing From, the location was deep in rust code's
//       blanket into implementation, which wasn't the line number we wanted.
//
//       As for converting other error types, the try! macro uses From so it
//       is correct.
#[allow(clippy::from_over_into)]
impl Into<Error> for InnerError {
    #[track_caller]
    fn into(self) -> Error {
        Error {
            inner: self,
            location: Location::caller(),
        }
    }
}

// Use this to avoid complex type qualification
impl InnerError {
    /// Convert an `InnerError` into an `Error`
    #[track_caller]
    #[must_use]
    pub fn into_err(self) -> Error {
        Error {
            inner: self,
            location: Location::caller(),
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}

impl From<Infallible> for Error {
    #[track_caller]
    fn from(_: Infallible) -> Self {
        panic!("INFALLIBLE")
    }
}

impl From<()> for Error {
    #[track_caller]
    fn from((): ()) -> Self {
        Error {
            inner: InnerError::General("Error".to_owned()),
            location: Location::caller(),
        }
    }
}

impl From<base64::DecodeError> for Error {
    #[track_caller]
    fn from(e: base64::DecodeError) -> Error {
        Error {
            inner: InnerError::Base64(e),
            location: Location::caller(),
        }
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    #[track_caller]
    fn from(e: ed25519_dalek::ed25519::Error) -> Error {
        Error {
            inner: InnerError::Ed25519(e),
            location: Location::caller(),
        }
    }
}

impl From<http::uri::InvalidUri> for Error {
    #[track_caller]
    fn from(e: http::uri::InvalidUri) -> Error {
        Error {
            inner: InnerError::InvalidUri(e),
            location: Location::caller(),
        }
    }
}

impl From<http::uri::InvalidUriParts> for Error {
    #[track_caller]
    fn from(e: http::uri::InvalidUriParts) -> Error {
        Error {
            inner: InnerError::InvalidUriParts(e),
            location: Location::caller(),
        }
    }
}

impl From<std::time::SystemTimeError> for Error {
    #[track_caller]
    fn from(e: std::time::SystemTimeError) -> Error {
        Error {
            inner: InnerError::SystemTime(e),
            location: Location::caller(),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    #[track_caller]
    fn from(e: std::str::Utf8Error) -> Error {
        Error {
            inner: InnerError::Utf8(e),
            location: Location::caller(),
        }
    }
}
