use super::{LengthCharacteristic, MessageType, QueryId, ResultCode};
use crate::{Blake3, Error, Filter, Id, InnerError, PublicKey, Record, Reference};

/// A protocol message
// safety invariant: self.0 must always be at least 8 bytes long.
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
            return Err(InnerError::DataTooShort.into());
        }

        let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;

        // Validate the actual byte length that we have matches the length field
        if len != bytes.len() {
            return Err(InnerError::WrongLength.into());
        }

        let t = MessageType::from_u8(bytes[0]);

        // Validate the length is appropriate for the message type
        let lc = t.len_characteristic();
        match lc {
            LengthCharacteristic::Fixed(expected_len) => {
                if len != expected_len {
                    return Err(InnerError::WrongLength.into());
                }
            }
            LengthCharacteristic::Chunked(header_len, chunk_len) => {
                if (len - header_len) % chunk_len != 0 {
                    return Err(InnerError::WrongLength.into());
                }
            }
            LengthCharacteristic::Variable(header_len, min_data_len) => {
                if len < header_len + min_data_len {
                    return Err(InnerError::DataTooShort.into());
                }
            }
        }

        // Validate result code
        if t.has_result_code() && matches!(ResultCode::from_u8(bytes[1]), ResultCode::Undefined(_))
        {
            return Err(InnerError::InvalidResultCode.into());
        }

        // per-type validation
        match t {
            MessageType::Get => {
                // Validate references
                let mut i = 8;
                while i < bytes.len() {
                    let _ = Reference::from_bytes(bytes[i..i + 48].try_into().unwrap())?;
                    i += 48;
                }
            }
            MessageType::Query | MessageType::Subscribe => {
                // Validate filter
                let _ = Filter::from_bytes(&bytes[16..])?;
            }
            MessageType::Submission => {
                // Validate record
                let _ = Record::from_bytes(&bytes[8..])?;
            }
            MessageType::BlobSubmission | MessageType::BlobResult => {
                // Verify the hash
                let mut hasher = Blake3::new();
                let mut hash: [u8; 32] = [0; 32];
                hasher.hash(&bytes[40..], hash.as_mut_slice());
                if hash.as_slice() != &bytes[8..40] {
                    return Err(InnerError::WrongLength.into());
                }
            }
            MessageType::DhtLookup => {
                // Validate serv byte
                if bytes[1] > 1 {
                    return Err(InnerError::InvalidMessage.into());
                }
            }
            MessageType::Record => {
                // Validate record
                let _ = Record::from_bytes(&bytes[8..])?;
            }
            MessageType::SubmissionResult => {
                // Validate id prefix (must not start with a 1 bit)
                if bytes[8] & (1 << 7) != 0 {
                    return Err(InnerError::InvalidMessage.into());
                }
            }
            _ => {}
        }

        Ok(Message(bytes))
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
        MessageType::from_u8(self.0[0])
    }

    /// Get the length
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    #[allow(clippy::missing_panics_doc)]
    pub fn len(&self) -> usize {
        u32::from_le_bytes(self.0[4..8].try_into().unwrap()) as usize
    }

    /// Create a new `Message` of type `MessageType::Hello`
    ///
    /// # Errors
    ///
    /// Returns an error if there are too many application IDs
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_hello(max_version: u8, applications: &[u32]) -> Result<Message, Error> {
        let len = 8 + 4 * applications.len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Hello.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[3] = max_version;
        for (i, app) in applications.iter().enumerate() {
            bytes[8 + i * 4..8 + (i + 1) * 4].copy_from_slice(app.to_le_bytes().as_slice());
        }
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::HelloAuth`
    ///
    /// # Errors
    ///
    /// Returns an error always because it is not yet defined in the spec
    pub fn new_hello_auth() -> Result<(), Error> {
        // Not yet defined in the spec
        todo!()
    }

    /// Create a new `Message` of type `MessageType::Get`
    ///
    /// # Errors
    ///
    /// Returns an error if there are too many references (more than 349525)
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_get(query_id: QueryId, references: &[&Reference]) -> Result<Message, Error> {
        let len = 8 + 48 * references.len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Get.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        for (i, r) in references.iter().enumerate() {
            bytes[8 + i * 48..8 + (i + 1) * 48].copy_from_slice(r.as_bytes().as_slice());
        }
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::Query`
    ///
    /// # Errors
    ///
    /// Returns an error if the filter is longer than 16777208 bytes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_query(query_id: QueryId, filter: &Filter, limit: u16) -> Result<Message, Error> {
        let len = 16 + filter.as_bytes().len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Query.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[8..10].copy_from_slice(limit.to_le_bytes().as_slice());
        bytes[16..].copy_from_slice(filter.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::Subscribe`
    ///
    /// # Errors
    ///
    /// Returns an error if the filter is longer than 16777208 bytes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_subscribe(query_id: QueryId, filter: &Filter, limit: u16) -> Result<Message, Error> {
        let len = 16 + filter.as_bytes().len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Subscribe.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[8..10].copy_from_slice(limit.to_le_bytes().as_slice());
        bytes[16..].copy_from_slice(filter.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::Unsubscribe`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_unsubscribe(query_id: QueryId) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Unsubscribe.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::Submission`
    ///
    /// # Errors
    ///
    /// Returns an error if the record is longer than 16777208 bytes (which should
    /// not be possible)
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_submission(record: &Record) -> Result<Message, Error> {
        let len = 8 + record.as_bytes().len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Submission.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[8..].copy_from_slice(record.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::BlobGet`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_blob_get(hash: [u8; 32]) -> Message {
        let len = 40;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::BlobGet.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[8..40].copy_from_slice(hash.as_slice());
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::BlobSubmission`
    ///
    /// # Errors
    ///
    /// Returns an Err if data is too long
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_blob_submission(blob: &[u8]) -> Result<Message, Error> {
        let len = 40 + blob.len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::BlobSubmission.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());

        let mut hasher = Blake3::new();
        hasher.hash(blob, &mut bytes[8..40]);

        bytes[40..len].copy_from_slice(blob);

        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::DhtLookup`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_dht_lookup(key: PublicKey, server: bool) -> Message {
        let len = 40;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::DhtLookup.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = u8::from(server);
        bytes[8..40].copy_from_slice(key.as_bytes());
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::HelloAck`
    ///
    /// # Errors
    ///
    /// Returns an error if there are too many application IDs
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_hello_ack(
        result: ResultCode,
        max_version: u8,
        applications: &[u32],
    ) -> Result<Message, Error> {
        let len = 8 + 4 * applications.len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::HelloAck.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = result.to_u8();
        bytes[3] = max_version;
        for (i, app) in applications.iter().enumerate() {
            bytes[8 + i * 4..8 + (i + 1) * 4].copy_from_slice(app.to_le_bytes().as_slice());
        }
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::Closing`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_closing(result: ResultCode) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Closing.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = result.to_u8();
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::Record`
    ///
    /// # Errors
    ///
    /// Returns an error if the record is longer than 16777208 bytes (which should
    /// not be possible)
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_record(query_id: QueryId, record: &Record) -> Result<Message, Error> {
        let len = 8 + record.as_bytes().len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Record.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[8..].copy_from_slice(record.as_bytes());
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::LocallyComplete`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_locally_complete(query_id: QueryId) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::LocallyComplete.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::QueryClosed`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_query_closed(query_id: QueryId, result: ResultCode) -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::QueryClosed.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[2..4].copy_from_slice(query_id.as_bytes().as_slice());
        bytes[1] = result.to_u8();
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::SubmissionResult`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_submission_result(id: Id, result: ResultCode) -> Message {
        let len = 40;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::SubmissionResult.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = result.to_u8();
        bytes[8..40].copy_from_slice(&id.as_bytes()[..32]);
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::BlobResult`
    ///
    /// # Errors
    ///
    /// Returns an Err if data is too long
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_blob_result(blob: &[u8], result: ResultCode) -> Result<Message, Error> {
        let len = 40 + blob.len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::BlobResult.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = result.to_u8();

        let mut hasher = Blake3::new();
        hasher.hash(blob, &mut bytes[8..40]);

        bytes[40..len].copy_from_slice(blob);

        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::BlobSubmissionResult`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_blob_submission_result(hash: [u8; 40], result: ResultCode) -> Message {
        let len = 40;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::BlobSubmissionResult.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = result.to_u8();
        bytes[8..40].copy_from_slice(hash.as_slice());
        Message(bytes)
    }

    /// Create a new `Message` of type `MessageType::DhtResponse`
    ///
    /// # Errors
    ///
    /// Returns an Err if data is too long
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_dht_response(data: &[u8], result: ResultCode) -> Result<Message, Error> {
        let len = 8 + data.len();
        if len >= 1 << 32 {
            return Err(InnerError::DataTooLong.into());
        }
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::DhtResponse.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
        bytes[1] = result.to_u8();
        bytes[8..len].copy_from_slice(data);
        Ok(Message(bytes))
    }

    /// Create a new `Message` of type `MessageType::Unrecognized`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new_unrecognized() -> Message {
        let len = 8;
        let mut bytes = vec![0_u8; len];
        bytes[0] = MessageType::Unrecognized.to_u8();
        bytes[4..8].copy_from_slice((len as u32).to_le_bytes().as_slice());
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
                Some(QueryId::from_bytes(self.0[2..4].try_into().unwrap()))
            }
            _ => None,
        }
    }

    /// Get the `ResultCode` if the `Message` has one
    #[must_use]
    pub fn result_code(&self) -> Option<ResultCode> {
        match self.message_type() {
            MessageType::HelloAck
            | MessageType::Closing
            | MessageType::QueryClosed
            | MessageType::SubmissionResult
            | MessageType::BlobResult
            | MessageType::BlobSubmissionResult
            | MessageType::DhtResponse => Some(ResultCode::from_u8(self.0[1])),
            _ => None,
        }
    }

    /// Get the max Mosaic major version of a `Hello` or `HelloAck`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn mosaic_major_version(&self) -> Option<u8> {
        if matches!(
            self.message_type(),
            MessageType::Hello | MessageType::HelloAck
        ) {
            Some(self.0[3])
        } else {
            None
        }
    }

    /// Get the Application IDs of a `Hello` or `HelloAck`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn application_ids(&self) -> Option<Vec<u32>> {
        if matches!(
            self.message_type(),
            MessageType::Hello | MessageType::HelloAck
        ) {
            let num = (self.len() - 8) / 4;
            let mut v: Vec<u32> = Vec::with_capacity(num);
            for i in 0..num {
                let app_id =
                    u32::from_le_bytes(self.0[8 + i * 4..8 + (i + 1) * 4].try_into().unwrap());
                v.push(app_id);
            }
            Some(v)
        } else {
            None
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
        if matches!(
            self.message_type(),
            MessageType::Query | MessageType::Subscribe
        ) {
            Some(u16::from_le_bytes(self.0[8..10].try_into().unwrap()))
        } else {
            None
        }
    }

    /// Get the `Filter` from a `MessageType::Query` or `MessageType::Subscribe`
    ///
    /// Returns an error if the internal Filter is not valid.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn filter(&self) -> Option<&Filter> {
        if matches!(
            self.message_type(),
            MessageType::Query | MessageType::Subscribe
        ) {
            Some(Filter::from_bytes(&self.0[16..]).unwrap())
        } else {
            None
        }
    }

    /// Get the `Record` from a `MessageType::Submission` or `MessageType::Record`
    ///
    /// Returns an error if the internal Record is not valid.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn record(&self) -> Option<&Record> {
        if matches!(
            self.message_type(),
            MessageType::Submission | MessageType::Record
        ) {
            Some(Record::from_bytes(&self.0[8..]).unwrap())
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

    /// Get the hash from a `MessageType::BlobGet`, `MessageType::BlobSubmission`,
    /// `MessageType::BlobResult` or `MessageType::BlobSubmissionResult`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn hash(&self) -> Option<[u8; 32]> {
        if matches!(
            self.message_type(),
            MessageType::BlobGet
                | MessageType::BlobSubmission
                | MessageType::BlobResult
                | MessageType::BlobSubmissionResult
        ) {
            Some(self.0[8..40].try_into().unwrap())
        } else {
            None
        }
    }

    /// Get the blob from a `MessageType::BlobSubmission` or `MessageType::BlobResult`
    #[must_use]
    pub fn blob(&self) -> Option<&[u8]> {
        if matches!(
            self.message_type(),
            MessageType::BlobSubmission | MessageType::BlobResult
        ) {
            Some(&self.0[40..])
        } else {
            None
        }
    }

    /// Get the `PublicKey` form a `MessageType::DhtLookup`
    ///
    /// # Errors
    ///
    /// Returns an Err if the public key is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn pubkey(&self) -> Result<Option<PublicKey>, Error> {
        if matches!(self.message_type(), MessageType::DhtLookup) {
            Ok(Some(PublicKey::from_bytes(
                &self.0[8..40].try_into().unwrap(),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Get the server byte from a `MessageType::DhtLookup`
    /// 1 is for server, 0 is for user.
    #[must_use]
    pub fn server_byte(&self) -> Option<u8> {
        if matches!(self.message_type(), MessageType::DhtLookup) {
            Some(self.0[1])
        } else {
            None
        }
    }

    /// Get the DHT data from a `MessageType::DhtResponse`
    #[must_use]
    pub fn dht_data(&self) -> Option<&[u8]> {
        if matches!(self.message_type(), MessageType::DhtResponse) {
            Some(&self.0[8..])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        Address, Kind, OwnedFilter, OwnedFilterElement, OwnedRecord, RecordAddressData,
        RecordFlags, RecordParts, RecordSigningData, SecretKey, Timestamp, EMPTY_TAG_SET,
    };

    #[test]
    fn test_messages() {
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();
        let query_id = QueryId::from_bytes([0, 1]);
        let reference1 = Address::new_random(key1.public(), Kind::BLOG_POST).to_reference();
        let reference2 = Address::new_random(key2.public(), Kind::EXAMPLE).to_reference();
        let filter = OwnedFilter::new(&[
            &OwnedFilterElement::new_kinds(&[Kind::MICROBLOG_ROOT, Kind::REPLY_COMMENT]).unwrap(),
            &OwnedFilterElement::new_author_keys(&[key1.public(), key2.public()]).unwrap(),
        ])
        .unwrap();
        let record = OwnedRecord::new(&RecordParts {
            signing_data: RecordSigningData::SecretKey(key1.clone()),
            address_data: RecordAddressData::Random(key1.public(), Kind::KEY_SCHEDULE),
            timestamp: Timestamp::now().unwrap(),
            flags: RecordFlags::empty(),
            tag_set: &EMPTY_TAG_SET,
            payload: b"hello world",
        })
        .unwrap();

        // Hello
        let m = Message::new_hello(0, &[1]).unwrap();
        assert_eq!(m.mosaic_major_version(), Some(0));
        assert_eq!(m.application_ids(), Some(vec![1]));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // Get
        let m = Message::new_get(query_id, &[&reference1, &reference2]).unwrap();
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m.references(), Some(vec![reference1, reference2]));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // Query
        let m = Message::new_query(query_id, &filter, 50).unwrap();
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m.filter(), Some(&*filter));
        assert_eq!(m.limit(), Some(50));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // Subscribe
        let m = Message::new_subscribe(query_id, &filter, 50).unwrap();
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m.filter(), Some(&*filter));
        assert_eq!(m.limit(), Some(50));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // Unsubscribe
        let m = Message::new_unsubscribe(query_id);
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // Submission
        let m = Message::new_submission(&record).unwrap();
        assert_eq!(m.record(), Some(&*record));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // HelloAck
        let m = Message::new_hello_ack(ResultCode::TooFast, 0, &[1]).unwrap();
        assert_eq!(m.mosaic_major_version(), Some(0));
        assert_eq!(m.application_ids(), Some(vec![1]));
        assert_eq!(m.result_code(), Some(ResultCode::TooFast));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // Record
        let m = Message::new_record(query_id, &record).unwrap();
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m.record(), Some(&*record));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // LocallyComplete
        let m = Message::new_locally_complete(query_id);
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // QueryClosed
        let m = Message::new_query_closed(query_id, ResultCode::GeneralError);
        assert_eq!(m.query_id(), Some(query_id));
        assert_eq!(m.result_code(), Some(ResultCode::GeneralError));
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());

        // SubmissionResult
        let m = Message::new_submission_result(record.id(), ResultCode::Accepted);
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());
        assert_eq!(m.result_code(), Some(ResultCode::Accepted));
        assert_eq!(m.id_prefix(), Some(&record.id().as_bytes()[..32]));

        // Unrecognized
        let m = Message::new_unrecognized();
        assert_eq!(m, Message::from_bytes(m.as_bytes().to_vec()).unwrap());
    }
}
