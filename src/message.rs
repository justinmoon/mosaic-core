use crate::{Error, Filter, Id, InnerError, Record, Reference};

/// A protocol message type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Client hello
    Hello = 0x10,

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

    /// Server response to Hello
    HelloAck = 0x90,

    /// Server response with a record
    Record = 0x80,

    /// Server response indicating that a query is locally complete
    LocallyComplete = 0x81,

    /// Server response indicating that a query is closed
    QueryClosed = 0x82,

    /// Server response indicating the status of a submission
    SubmissionResult = 0x83,

    /// Unrecognized
    Unrecognized = 0xF0,
}

impl MessageType {
    /// Create a `MessageType` from a `u8`
    #[must_use]
    pub fn from_u8(u: u8) -> Option<MessageType> {
        match u {
            0x1 => Some(MessageType::Get),
            0x2 => Some(MessageType::Query),
            0x3 => Some(MessageType::Subscribe),
            0x4 => Some(MessageType::Unsubscribe),
            0x5 => Some(MessageType::Submission),
            0x10 => Some(MessageType::Hello),
            0x80 => Some(MessageType::Record),
            0x81 => Some(MessageType::LocallyComplete),
            0x82 => Some(MessageType::QueryClosed),
            0x83 => Some(MessageType::SubmissionResult),
            0x90 => Some(MessageType::HelloAck),
            0xF0 => Some(MessageType::Unrecognized),
            _ => None,
        }
    }
}

/// A 2-byte `QueryId` used in `Message`s
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryId([u8; 2]);

impl QueryId {
    /// Create a `QueryId` from bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> QueryId {
        QueryId(bytes)
    }

    /// Get at the inner bytes
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 2] {
        self.0
    }
}

/// A code describing why a query was closed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QueryClosedCode {
    /// Query was closed in response to an Unsubscribe request
    OnRequest = 0x1,

    /// Query is invalid
    RejectedInvalid = 0x10,

    /// Query is too broad, matching too many records
    RejectedTooOpen = 0x11,

    /// Queries (or messages) are coming too quickly. Slow down
    RejectedTooFast = 0x12,

    /// Client is temporarily banned from querying.
    RejectedTempBanned = 0x13,

    /// Client is permanently banned from querying.
    RejectedPermBanned = 0x14,

    /// The server is shutting down
    ShuttingDown = 0x30,

    /// The server has encountered an internal error
    InternalError = 0xF0,

    /// Other reason, or not specified
    Other = 0xFF,
}

impl QueryClosedCode {
    /// Create a `QueryClosedCode` from a `u8`
    #[must_use]
    pub fn from_u8(u: u8) -> Option<QueryClosedCode> {
        match u {
            0x1 => Some(QueryClosedCode::OnRequest),
            0x10 => Some(QueryClosedCode::RejectedInvalid),
            0x11 => Some(QueryClosedCode::RejectedTooOpen),
            0x12 => Some(QueryClosedCode::RejectedTooFast),
            0x13 => Some(QueryClosedCode::RejectedTempBanned),
            0x14 => Some(QueryClosedCode::RejectedPermBanned),
            0x30 => Some(QueryClosedCode::ShuttingDown),
            0xF0 => Some(QueryClosedCode::InternalError),
            0xFF => Some(QueryClosedCode::Other),
            _ => None,
        }
    }
}

/// A code describing the result of a submitted record
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SubmissionResultCode {
    /// Record submission was accepted
    Ok = 0x1,

    /// Record is a duplicate
    Duplicate = 0x2,

    /// Ephemeral record had No consumers
    NoConsumers = 0x3,

    /// Record is invalid
    RejectedInvalid = 0x10,

    /// Submissions (or messages) are coming too quickly. Slow down
    RejectedTooFast = 0x12,

    /// Client is temporarily banned from submissions.
    RejectedTempBanned = 0x13,

    /// Client is permanently banned from submissions.
    RejectedPermBanned = 0x14,

    /// Submission requires authentication
    RejectedRequiresAuthn = 0x15,

    /// Submission requires authorization
    RejectedRequiresAuthz = 0x16,

    /// The server has encountered an internal error
    InternalError = 0xF0,

    /// Other reason, or not specified
    Other = 0xFF,
}

impl SubmissionResultCode {
    /// Create a `SubmissionResultCode` from a `u8`
    #[must_use]
    pub fn from_u8(u: u8) -> Option<SubmissionResultCode> {
        match u {
            0x1 => Some(SubmissionResultCode::Ok),
            0x2 => Some(SubmissionResultCode::Duplicate),
            0x3 => Some(SubmissionResultCode::NoConsumers),
            0x10 => Some(SubmissionResultCode::RejectedInvalid),
            0x12 => Some(SubmissionResultCode::RejectedTooFast),
            0x13 => Some(SubmissionResultCode::RejectedTempBanned),
            0x14 => Some(SubmissionResultCode::RejectedPermBanned),
            0x15 => Some(SubmissionResultCode::RejectedRequiresAuthn),
            0x16 => Some(SubmissionResultCode::RejectedRequiresAuthz),
            0xF0 => Some(SubmissionResultCode::InternalError),
            0xFF => Some(SubmissionResultCode::Other),
            _ => None,
        }
    }
}

/// A protocol message
// safety invariant: 0 must always be at least 4 bytes long (type and length)
// safety invariant: type must be one of the defined types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message(Vec<u8>);

impl Message {
    /// Interpret bytes as a `Message`
    ///
    /// Does not tolerates trailing bytes after the data in the `input`.
    ///
    /// # Errors
    ///
    /// Returns an Err if the bytes contain invalid data
    #[allow(clippy::missing_panics_doc)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Message, Error> {
        if bytes.len() < 8 {
            Err(InnerError::InvalidMessage.into())
        } else {
            let len =
                (bytes[1] as usize) + ((bytes[2] as usize) << 8) + ((bytes[3] as usize) << 16);
            if len == bytes.len() {
                let t = MessageType::from_u8(bytes[0])
                    .ok_or::<Error>(InnerError::InvalidMessage.into())?;
                #[allow(clippy::match_same_arms)]
                match t {
                    MessageType::Hello => {
                        if len % 4 != 0 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                    }
                    MessageType::Get => {
                        if (len - 8) % 48 != 0 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                        let mut i = 8;
                        while i < bytes.len() {
                            let _ = Reference::from_bytes(bytes[i..i + 48].try_into().unwrap())?;
                            i += 48;
                        }
                    }
                    MessageType::Query => {
                        let _ = Filter::from_bytes(&bytes[8..])?;
                    }
                    MessageType::Subscribe => {
                        let _ = Filter::from_bytes(&bytes[8..])?;
                    }
                    MessageType::Unsubscribe
                    | MessageType::LocallyComplete
                    | MessageType::Unrecognized => {
                        if bytes.len() != 8 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                    }
                    MessageType::Submission => {
                        let _ = Record::from_bytes(&bytes[8..])?;
                    }
                    MessageType::HelloAck => {
                        if len % 4 != 0 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                    }
                    MessageType::Record => {
                        let _ = Record::from_bytes(&bytes[8..])?;
                    }
                    MessageType::QueryClosed => {
                        if bytes.len() != 8 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                        let _ = QueryClosedCode::from_u8(bytes[6])
                            .ok_or::<Error>(InnerError::InvalidMessage.into())?;
                    }
                    MessageType::SubmissionResult => {
                        if bytes.len() != 40 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                        let _ = SubmissionResultCode::from_u8(bytes[4])
                            .ok_or::<Error>(InnerError::InvalidMessage.into())?;
                        if bytes[8] & (1 << 7) != 0 {
                            return Err(InnerError::InvalidMessage.into());
                        }
                    }
                }
                Ok(Message(bytes))
            } else {
                Err(InnerError::InvalidMessage.into())
            }
        }
    }

    /// Interpret bytes as a `Message`
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `Message`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(bytes: Vec<u8>) -> Message {
        Message(bytes)
    }

    /// As bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// get the `MessageType`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn message_type(&self) -> MessageType {
        MessageType::from_u8(self.0[0]).unwrap()
    }

    /// Get the length
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        (self.0[1] as usize) + ((self.0[2] as usize) << 8) + ((self.0[3] as usize) << 16)
    }

    /// Create a new `Hello` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if there are too many application IDs
    pub fn new_hello(max_version: u32, applications: &[u32]) -> Result<Message, Error> {
        let len = 8 + 4 * applications.len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Hello as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..8].copy_from_slice(max_version.to_le_bytes().as_slice());
        for (i, app) in applications.iter().enumerate() {
            bytes[8 + i * 4..8 + (i + 1) * 4].copy_from_slice(app.to_le_bytes().as_slice());
        }
        Ok(Message(bytes))
    }

    /// Create a new `Get` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if there are too many references (more than 349525)
    pub fn new_get(query_id: QueryId, references: &[&Reference]) -> Result<Message, Error> {
        let len = 8 + 48 * references.len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Get as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        for (i, r) in references.iter().enumerate() {
            bytes[8 + i * 48..8 + (i + 1) * 48].copy_from_slice(r.as_bytes().as_slice());
        }
        Ok(Message(bytes))
    }

    /// Create a new `Query` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if the filter is longer than 16777208 bytes.
    pub fn new_query(query_id: QueryId, filter: &Filter, limit: u16) -> Result<Message, Error> {
        let len = 8 + filter.as_bytes().len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Query as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[6..8].copy_from_slice(limit.to_le_bytes().as_slice());
        bytes[8..].copy_from_slice(filter.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `Subscribe` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if the filter is longer than 16777208 bytes.
    pub fn new_subscribe(query_id: QueryId, filter: &Filter, limit: u16) -> Result<Message, Error> {
        let len = 8 + filter.as_bytes().len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Subscribe as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[6..8].copy_from_slice(limit.to_le_bytes().as_slice());
        bytes[8..].copy_from_slice(filter.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `Unsubscribe` `Message`
    #[must_use]
    pub fn new_unsubscribe(query_id: QueryId) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Unsubscribe as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        Message(bytes)
    }

    /// Create a new `Submission` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if the record is longer than 16777208 bytes (which should
    /// not be possible)
    pub fn new_submission(record: &Record) -> Result<Message, Error> {
        let len = 8 + record.as_bytes().len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Submission as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[8..].copy_from_slice(record.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `HelloAck` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if there are too many application IDs
    pub fn new_hello_ack(max_version: u32, applications: &[u32]) -> Result<Message, Error> {
        let len = 8 + 4 * applications.len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::HelloAck as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..8].copy_from_slice(max_version.to_le_bytes().as_slice());
        for (i, app) in applications.iter().enumerate() {
            bytes[8 + i * 4..8 + (i + 1) * 4].copy_from_slice(app.to_le_bytes().as_slice());
        }
        Ok(Message(bytes))
    }

    /// Create a new `Record` `Message`
    ///
    /// # Errors
    ///
    /// Returns an error if the record is longer than 16777208 bytes (which should
    /// not be possible)
    pub fn new_record(query_id: QueryId, record: &Record) -> Result<Message, Error> {
        let len = 8 + record.as_bytes().len();
        if len >= 1 << 24 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Record as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[8..].copy_from_slice(record.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `LocallyComplete` `Message`
    #[must_use]
    pub fn new_locally_complete(query_id: QueryId) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::LocallyComplete as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        Message(bytes)
    }

    /// Create a new `QueryClosed` `Message`
    #[must_use]
    pub fn new_query_closed(query_id: QueryId, code: QueryClosedCode) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::QueryClosed as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4..6].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[6] = code as u8;
        Message(bytes)
    }

    /// Create a new `SubmissionResult` `Message`
    #[must_use]
    pub fn new_submission_result(code: SubmissionResultCode, id: Id) -> Message {
        let len = 40;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::SubmissionResult as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        bytes[4] = code as u8;
        bytes[8..].copy_from_slice(&id.as_bytes()[..32]);
        Message(bytes)
    }

    /// Create a new `Unrecognized` `Message`
    #[must_use]
    pub fn new_unrecognized() -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Unrecognized as u8;
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (len as u32).to_le_bytes();
        bytes[1..4].copy_from_slice(&len_bytes.as_slice()[..3]);
        Message(bytes)
    }

    /// Get the `QueryId` if the `Message` has one
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn query_id(&self) -> Option<QueryId> {
        match self.message_type() {
            MessageType::Get
            | MessageType::Query
            | MessageType::Subscribe
            | MessageType::Unsubscribe
            | MessageType::Record
            | MessageType::LocallyComplete
            | MessageType::QueryClosed => {
                Some(QueryId::from_bytes(self.0[4..6].try_into().unwrap()))
            }
            _ => None,
        }
    }

    /// Get the references from a `MessageType::Get`
    ///
    /// Returns an error if an internal Reference is not valid.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn references(&self) -> Option<Vec<Reference>> {
        if self.message_type() == MessageType::Get {
            let mut references: Vec<Reference> = Vec::with_capacity((self.len() - 8) / 48);
            let mut i = 8;
            while i < self.len() {
                let reference =
                    Reference::from_bytes(self.0[i..i + 48].try_into().unwrap()).unwrap();
                references.push(reference);
                i += 48;
            }
            Some(references)
        } else {
            None
        }
    }

    /// Get the limit from a `MessageType::Query` or `MessageType::Subscribe`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn limit(&self) -> Option<u16> {
        match self.message_type() {
            MessageType::Query | MessageType::Subscribe => {
                Some(u16::from_le_bytes(self.0[6..8].try_into().unwrap()))
            }
            _ => None,
        }
    }

    /// Get the `Filter` from a `MessageType::Query` or `MessageType::Subscribe`
    ///
    /// Returns an error if the internal Filter is not valid.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn filter(&self) -> Option<&Filter> {
        match self.message_type() {
            MessageType::Query | MessageType::Subscribe => {
                Some(Filter::from_bytes(&self.0[8..]).unwrap())
            }
            _ => None,
        }
    }

    /// Get the `Record` from a `MessageType::Submission` or `MessageType::Record`
    ///
    /// Returns an error if the internal Record is not valid.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn record(&self) -> Option<&Record> {
        match self.message_type() {
            MessageType::Submission | MessageType::Record => {
                Some(Record::from_bytes(&self.0[8..]).unwrap())
            }
            _ => None,
        }
    }

    /// Get the `QueryClosedCode` of a `MessageType::QueryClosed`
    #[must_use]
    pub fn query_closed_code(&self) -> Option<QueryClosedCode> {
        if self.message_type() == MessageType::QueryClosed {
            QueryClosedCode::from_u8(self.0[6])
        } else {
            None
        }
    }

    /// Get the `Id` prefix of a `MessageType::SubmissionResult`
    #[must_use]
    pub fn id_prefix(&self) -> Option<&[u8]> {
        if self.message_type() == MessageType::SubmissionResult {
            Some(&self.0[8..40])
        } else {
            None
        }
    }

    /// Get the `SubmissionResultCode` of a `MessageType::SubmissionResult`
    #[must_use]
    pub fn submission_result_code(&self) -> Option<SubmissionResultCode> {
        if self.message_type() == MessageType::SubmissionResult {
            SubmissionResultCode::from_u8(self.0[4])
        } else {
            None
        }
    }

    /// Get the max Mosaic major version of a `Hello` or `HelloAck`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn mosaic_major_version(&self) -> Option<u32> {
        if self.message_type() == MessageType::Hello || self.message_type() == MessageType::HelloAck
        {
            Some(u32::from_le_bytes(self.0[4..8].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Get the Application IDs of a `Hello` or `HelloAck`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn application_ids(&self) -> Option<Vec<u32>> {
        if self.message_type() == MessageType::Hello || self.message_type() == MessageType::HelloAck
        {
            let num = (self.len() - 8) / 4;
            let mut v: Vec<u32> = Vec::with_capacity(num);
            for _ in 0..num {
                let app_id =
                    u32::from_le_bytes(self.0[8 + num * 4..8 + (num + 1) * 4].try_into().unwrap());
                v.push(app_id);
            }
            Some(v)
        } else {
            None
        }
    }
}
