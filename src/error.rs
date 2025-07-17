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
    /// Bad Encrypted Secret Key
    BadEncryptedSecretKey,

    /// Bad Password
    BadPassword,

    /// Unsupported URI scheme
    BadScheme(String),

    /// Data too long
    DataTooLong,

    /// DHT put error
    DhtPutError,

    /// DHT was shutdown
    DhtWasShutdown,

    /// ed25519 error
    Ed25519(ed25519_dalek::ed25519::Error),

    /// End of Input
    EndOfInput,

    /// End of Output
    EndOfOutput,

    /// Excessive scrypt `LOG_N` parameter
    ExcessiveScryptLogNParameter(u8),

    /// Filter element is too long
    FilterElementTooLong,

    /// Hash mismatch
    HashMismatch,

    /// Key data length is not 32 bytes
    KeyLength,

    /// General error
    General(String),

    /// Integer too big
    IntTooBig(std::num::TryFromIntError),

    /// Invalid Address bytes
    InvalidAddressBytes,

    /// Invalid filter element
    InvalidFilterElement,

    /// Invalid filter element for function
    InvalidFilterElementForFunction,

    /// Invalid ID bytes
    InvalidIdBytes,

    /// Invalid length
    InvalidLength,

    /// Invalid message
    InvalidMessage,

    /// Invalid printable data
    InvalidPrintable,

    /// Invalid `ServerBootstrap` String
    InvalidServerBootstrapString,

    /// Invalid Tag
    InvalidTag,

    /// Invalid `UserBootstrap` String
    InvalidUserBootstrapString,

    /// Invalid URI
    InvalidUri(http::uri::InvalidUri),

    /// Invalid URI parts
    InvalidUriParts(http::uri::InvalidUriParts),

    /// Json Error
    #[cfg(feature = "json")]
    Json(serde_json::Error),

    /// Missing scheme
    MissingScheme,

    /// Reference is not an Address
    NotAnAddress,

    /// Reference is not an ID
    NotAnId,

    /// The bytes are padding
    Padding,

    /// Parse Integer error
    ParseInt(std::num::ParseIntError),

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

    /// Scrypt error
    Scrypt(scrypt::errors::InvalidParams),

    /// Slice error
    SliceError(std::array::TryFromSliceError),

    /// Time error
    SystemTime(std::time::SystemTimeError),

    /// Tag too long
    TagTooLong,

    /// Time is beyond available leap second data
    TimeIsBeyondLeapSecondData,

    /// Time is out of range
    TimeOutOfRange,

    /// Timestamp Mismatch
    TimestampMismatch,

    /// Too many data elements
    TooManyDataElements(usize),

    /// Unknown filter element
    UnknownFilterElement(u8),

    /// Unsupported Encrypted Secret Key Version
    UnsupportedEncryptedSecretKeyVersion(u8),

    /// UTF-8 error
    Utf8(std::str::Utf8Error),

    /// Z32 error
    Z32(z32::Z32Error),
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::BadEncryptedSecretKey => write!(f, "Bad encrypted secret key"),
            InnerError::BadPassword => write!(f, "Bad password"),
            InnerError::BadScheme(s) => write!(f, "Unsupported URI scheme: {s}"),
            InnerError::DataTooLong => write!(f, "Data too long"),
            InnerError::DhtPutError => write!(f, "DHT put error"),
            InnerError::DhtWasShutdown => write!(f, "DHT was shutdown"),
            InnerError::Ed25519(e) => write!(f, "ed25519 Error: {e}"),
            InnerError::EndOfInput => write!(f, "End of input"),
            InnerError::EndOfOutput => write!(f, "End of output"),
            InnerError::ExcessiveScryptLogNParameter(l) => {
                write!(f, "Computationally excessive scrypt LOG_N parameter: {l}")
            }
            InnerError::FilterElementTooLong => write!(f, "Filter element too long"),
            InnerError::HashMismatch => write!(f, "Hash mismatch"),
            InnerError::KeyLength => write!(f, "Key data length is not 32 bytes"),
            InnerError::General(s) => write!(f, "General Error: {s}"),
            InnerError::IntTooBig(e) => write!(f, "Integer too big: {e}"),
            InnerError::InvalidAddressBytes => write!(f, "Invalid Address bytes"),
            InnerError::InvalidFilterElement => write!(f, "Invalid filter element"),
            InnerError::InvalidFilterElementForFunction => write!(
                f,
                "Invalid filter element for function (received dates not available in Record)"
            ),
            InnerError::InvalidIdBytes => write!(f, "Invalid ID bytes"),
            InnerError::InvalidLength => write!(f, "Invalid length"),
            InnerError::InvalidMessage => write!(f, "Invalid message"),
            InnerError::InvalidPrintable => write!(f, "Printable data is invalid"),
            InnerError::InvalidServerBootstrapString => write!(f, "Invalid ServerBootstrap String"),
            InnerError::InvalidTag => write!(f, "Invalid Tag"),
            InnerError::InvalidUserBootstrapString => write!(f, "Invalid UserBootstrap String"),
            InnerError::InvalidUri(e) => write!(f, "Invalid URI: {e}"),
            InnerError::InvalidUriParts(e) => write!(f, "Invalid URI parts: {e}"),
            #[cfg(feature = "json")]
            InnerError::Json(e) => write!(f, "JSON: {e}"),
            InnerError::MissingScheme => write!(f, "Missing scheme"),
            InnerError::NotAnAddress => write!(f, "Reference is not an address"),
            InnerError::NotAnId => write!(f, "Reference is not an ID"),
            InnerError::Padding => write!(f, "The bytes are padding"),
            InnerError::ParseInt(e) => write!(f, "Parse integer error: {e}"),
            InnerError::RecordSectionLengthMismatch => write!(f, "Record section length mismatch"),
            InnerError::RecordTooLong => write!(f, "Record too long"),
            InnerError::RecordTooShort => write!(f, "Record too short"),
            InnerError::ReferenceLength => write!(f, "Reference data length is not 48 bytes"),
            InnerError::ReservedFlagsUsed => write!(f, "Reserved flags used"),
            InnerError::ReservedSpaceUsed => write!(f, "Reserved space used"),
            InnerError::Scrypt(e) => write!(f, "Scrypt: {e}"),
            InnerError::SliceError(e) => write!(f, "Slice (size) error: {e}"),
            InnerError::SystemTime(e) => write!(f, "Time Error: {e}"),
            InnerError::TagTooLong => write!(f, "Tag too long"),
            InnerError::TimeIsBeyondLeapSecondData => {
                write!(f, "Time is beyond available leap second data")
            }
            InnerError::TimeOutOfRange => write!(f, "Time is out of range"),
            InnerError::TimestampMismatch => write!(f, "Timestamp mismatch"),
            InnerError::TooManyDataElements(c) => write!(f, "Too many data elements. Max is {c}"),
            InnerError::UnknownFilterElement(u) => write!(f, "Unknown filter element: {u}"),
            InnerError::UnsupportedEncryptedSecretKeyVersion(v) => {
                write!(f, "Unsupported Encrypted Secret Key Version: {v}")
            }
            InnerError::Utf8(e) => write!(f, "UTF-8 error: {e}"),
            InnerError::Z32(e) => write!(f, "zbase32 error: {e}"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::Ed25519(e) => Some(e),
            InnerError::IntTooBig(e) => Some(e),
            InnerError::InvalidUri(e) => Some(e),
            InnerError::InvalidUriParts(e) => Some(e),
            #[cfg(feature = "json")]
            InnerError::Json(e) => Some(e),
            InnerError::ParseInt(e) => Some(e),
            InnerError::Scrypt(e) => Some(e),
            InnerError::SliceError(e) => Some(e),
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

impl From<std::num::TryFromIntError> for Error {
    #[track_caller]
    fn from(e: std::num::TryFromIntError) -> Error {
        Error {
            inner: InnerError::IntTooBig(e),
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

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    #[track_caller]
    fn from(e: serde_json::Error) -> Error {
        Error {
            inner: InnerError::Json(e),
            location: Location::caller(),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    #[track_caller]
    fn from(e: std::num::ParseIntError) -> Error {
        Error {
            inner: InnerError::ParseInt(e),
            location: Location::caller(),
        }
    }
}

impl From<scrypt::errors::InvalidParams> for Error {
    #[track_caller]
    fn from(e: scrypt::errors::InvalidParams) -> Error {
        Error {
            inner: InnerError::Scrypt(e),
            location: Location::caller(),
        }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    #[track_caller]
    fn from(e: std::array::TryFromSliceError) -> Error {
        Error {
            inner: InnerError::SliceError(e),
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

impl From<z32::Z32Error> for Error {
    #[track_caller]
    fn from(e: z32::Z32Error) -> Error {
        Error {
            inner: InnerError::Z32(e),
            location: Location::caller(),
        }
    }
}
