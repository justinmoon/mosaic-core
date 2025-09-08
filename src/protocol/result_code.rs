/// A code describing the result of a client message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResultCode {
    /// Undefined
    Undefined(u8) = 0,

    /// Generic success message
    Success = 1,

    /// Accepted a submission
    Accepted = 2,

    /// A record submitted is a duplicate of an existing record
    Duplicate = 3,

    /// Ephemeral record had no consumers
    NoConsumers = 4,

    /// Record or BLOB was not found
    NotFound = 16,

    /// Rejected as the request requires authentication
    RequiresAuthentication = 32,

    /// Rejected as the pubkey is not authorized for the action
    Unauthorized = 33,

    /// Request was invalid
    Invalid = 36,

    /// A Query or Subscribe was too open, potentially matching too many records
    TooOpen = 37,

    /// The submission (or the result) is too large
    TooLarge = 38,

    /// Requests are coming in too fast from this client (or of this type).
    TooFast = 39,

    /// IP address is temporarily banned
    IpTempBanned = 48,

    /// IP address is permanently banned
    IpPermBanned = 49,

    /// Pubkey is temporarily banned
    PubkeyTempBanned = 50,

    /// Pubkey is permanently banned
    PubkeyPermBanned = 51,

    /// Server is shutting down
    ShuttingDown = 64,

    /// Temporary server error
    TemporaryError = 65,

    /// Persistent server error
    PersistentError = 66,

    /// General server error
    GeneralError = 67,
}

impl ResultCode {
    /// Create a `ResultCode` from a `u8`
    #[must_use]
    pub fn from_u8(u: u8) -> Self {
        match u {
            1 => Self::Success,
            2 => Self::Accepted,
            3 => Self::Duplicate,
            4 => Self::NoConsumers,
            16 => Self::NotFound,
            32 => Self::RequiresAuthentication,
            33 => Self::Unauthorized,
            36 => Self::Invalid,
            37 => Self::TooOpen,
            38 => Self::TooLarge,
            39 => Self::TooFast,
            48 => Self::IpTempBanned,
            49 => Self::IpPermBanned,
            50 => Self::PubkeyTempBanned,
            51 => Self::PubkeyPermBanned,
            64 => Self::ShuttingDown,
            65 => Self::TemporaryError,
            66 => Self::PersistentError,
            67 => Self::GeneralError,
            u => Self::Undefined(u),
        }
    }

    /// Convert to a u8
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Success => 1,
            Self::Accepted => 2,
            Self::Duplicate => 3,
            Self::NoConsumers => 4,
            Self::NotFound => 16,
            Self::RequiresAuthentication => 32,
            Self::Unauthorized => 33,
            Self::Invalid => 36,
            Self::TooOpen => 37,
            Self::TooLarge => 38,
            Self::TooFast => 39,
            Self::IpTempBanned => 48,
            Self::IpPermBanned => 49,
            Self::PubkeyTempBanned => 50,
            Self::PubkeyPermBanned => 51,
            Self::ShuttingDown => 64,
            Self::TemporaryError => 65,
            Self::PersistentError => 66,
            Self::GeneralError => 67,
            Self::Undefined(u) => u,
        }
    }

    /// Is the result a success?
    #[must_use]
    pub fn is_a_success(&self) -> bool {
        self.to_u8() < 8
    }

    /// Is the result a user error?
    #[must_use]
    pub fn is_a_user_error(&self) -> bool {
        self.to_u8() >= 32 && self.to_u8() < 48
    }

    /// Is the result a user rejection?
    #[must_use]
    pub fn is_a_user_rejection(&self) -> bool {
        self.to_u8() >= 48 && self.to_u8() < 56
    }

    /// Is the result a server error?
    #[must_use]
    pub fn is_a_server_error(&self) -> bool {
        self.to_u8() >= 64 && self.to_u8() < 80
    }
}
