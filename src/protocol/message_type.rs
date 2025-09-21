/// A protocol message type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Client hello
    Hello = 0x10,

    /// Client response to Hello
    HelloAuth = 0x11,

    /// Client request for records specified by references
    Get = 0x1,

    /// Client request for records specified by a filter, closed on completion
    Query = 0x2,

    /// Client request for records specified by a filter, held open for
    /// future results
    Subscribe = 0x3,

    /// Client request to close an existing subscription
    Unsubscribe = 0x4,

    /// Client submission of a record
    Submission = 0x5,

    /// BLOB Get
    BlobGet = 0x8,

    /// BLOB Submission
    BlobSubmission = 0x7,

    /// DHT Lookup
    DhtLookup = 0x6,

    /// Server response to Hello
    HelloAck = 0x90,

    /// Server closing
    Closing = 0xFE,

    /// Server response with a record
    Record = 0x80,

    /// Server response indicating that a query is locally complete
    LocallyComplete = 0x81,

    /// Server response indicating that a query is closed
    QueryClosed = 0x82,

    /// Server response indicating the status of a submission
    SubmissionResult = 0x83,

    /// BLOB result
    BlobResult = 0x86,

    /// BLOB Submission result
    BlobSubmissionResult = 0x85,

    /// DHT Response
    DhtResponse = 0x84,

    /// Unrecognized
    Unrecognized = 0xF0,

    /// Undefined
    Undefined(u8),
}

impl MessageType {
    /// Create a `MessageType` from a `u8`
    #[must_use]
    pub fn from_u8(u: u8) -> Self {
        match u {
            0x10 => Self::Hello,
            0x11 => Self::HelloAuth,
            0x1 => Self::Get,
            0x2 => Self::Query,
            0x3 => Self::Subscribe,
            0x4 => Self::Unsubscribe,
            0x5 => Self::Submission,
            0x8 => Self::BlobGet,
            0x7 => Self::BlobSubmission,
            0x6 => Self::DhtLookup,

            0x90 => Self::HelloAck,
            0xFE => Self::Closing,
            0x80 => Self::Record,
            0x81 => Self::LocallyComplete,
            0x82 => Self::QueryClosed,
            0x83 => Self::SubmissionResult,
            0x86 => Self::BlobResult,
            0x85 => Self::BlobSubmissionResult,
            0x84 => Self::DhtResponse,

            0xF0 => Self::Unrecognized,

            u => Self::Undefined(u),
        }
    }

    /// Convert to a u8
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Hello => 0x10,
            Self::HelloAuth => 0x11,
            Self::Get => 0x1,
            Self::Query => 0x2,
            Self::Subscribe => 0x3,
            Self::Unsubscribe => 0x4,
            Self::Submission => 0x5,
            Self::BlobGet => 0x8,
            Self::BlobSubmission => 0x7,
            Self::DhtLookup => 0x6,

            Self::HelloAck => 0x90,
            Self::Closing => 0xFE,
            Self::Record => 0x80,
            Self::LocallyComplete => 0x81,
            Self::QueryClosed => 0x82,
            Self::SubmissionResult => 0x83,
            Self::BlobResult => 0x86,
            Self::BlobSubmissionResult => 0x85,
            Self::DhtResponse => 0x84,

            Self::Unrecognized => 0xF0,

            Self::Undefined(u) => u,
        }
    }

    /// If the message has a 1 byte result code at byte 1
    #[must_use]
    pub fn has_result_code(self) -> bool {
        matches!(
            self,
            Self::HelloAck
                | Self::Closing
                | Self::QueryClosed
                | Self::SubmissionResult
                | Self::BlobResult
                | Self::BlobSubmissionResult
                | Self::DhtResponse
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LengthCharacteristic {
    /// Message has a fixed length
    Fixed(usize),

    /// Chunked (header, chunk size)
    Chunked(usize, usize),

    /// Variable (header, minimum variable part)
    Variable(usize, usize),
}

impl MessageType {
    /// Get the length characteristic of the messsage type
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn len_characteristic(self) -> LengthCharacteristic {
        match self {
            Self::Hello => LengthCharacteristic::Chunked(8, 4),
            Self::HelloAuth => LengthCharacteristic::Variable(8, 0), // FIXME not yet defined
            Self::Get => LengthCharacteristic::Chunked(8, 48),
            Self::Query => LengthCharacteristic::Variable(16, 8), // min filter is 8?
            Self::Subscribe => LengthCharacteristic::Variable(16, 8), // min filter is 8?
            Self::Unsubscribe => LengthCharacteristic::Fixed(8),
            Self::Submission => LengthCharacteristic::Variable(8, 152), // min record is 152?
            Self::BlobGet => LengthCharacteristic::Fixed(40),
            Self::BlobSubmission => LengthCharacteristic::Variable(40, 0),
            Self::DhtLookup => LengthCharacteristic::Fixed(40),

            Self::HelloAck => LengthCharacteristic::Chunked(8, 4),
            Self::Closing => LengthCharacteristic::Fixed(8),
            Self::Record => LengthCharacteristic::Variable(8, 152), // min record is 152?
            Self::LocallyComplete => LengthCharacteristic::Fixed(8),
            Self::QueryClosed => LengthCharacteristic::Fixed(8),
            Self::SubmissionResult => LengthCharacteristic::Fixed(40),
            Self::BlobResult => LengthCharacteristic::Variable(40, 0),
            Self::BlobSubmissionResult => LengthCharacteristic::Fixed(40),
            Self::DhtResponse => LengthCharacteristic::Variable(8, 0),

            Self::Unrecognized => LengthCharacteristic::Fixed(8),

            Self::Undefined(_) => LengthCharacteristic::Variable(8, 0),
        }
    }
}
