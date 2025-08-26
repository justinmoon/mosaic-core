use crate::{
    Address, DuplicateHandling, Error, InnerError, OwnedRecord, OwnedTagSet, PublicKey, ReadAccess, Record,
    RecordAddressData, RecordFlags, RecordParts, RecordSigningData, Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct JsonKind {
    as_number: u64,
    as_bytes: Vec<u8>,
    application_id: u64,
    application_kind: u16,
    duplicate_handling: DuplicateHandling,
    read_access: ReadAccess,
    content_is_printable: bool,
}

#[derive(Serialize, Deserialize)]
struct JsonRecord {
    id: String,
    address: String,
    author_key: String,
    signing_key: String,
    kind: JsonKind,
    timestamp: u64,
    flags: RecordFlags,
    tags: OwnedTagSet,
    payload: Option<String>,
    z32_payload: Option<String>,
    signature: String,
}

impl Record {
    /// Export as a JSON string
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn as_json(&self) -> String {
        let json_record = self.as_json_record();
        serde_json::to_string(&json_record).unwrap()
    }

    /// Export as a JSON string
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn as_json_pretty(&self) -> String {
        let json_record = self.as_json_record();
        serde_json::to_string_pretty(&json_record).unwrap()
    }

    #[allow(clippy::cast_sign_loss)]
    fn as_json_record(&self) -> JsonRecord {
        JsonRecord {
            id: self.id().as_printable(),
            address: self.address().as_printable(),
            author_key: self.author_public_key().as_printable(),
            signing_key: self.signing_public_key().as_printable(),
            kind: JsonKind {
                as_number: self.kind().to_u64(),
                as_bytes: self.kind().to_bytes().to_vec(),
                application_id: self.kind().application_id(),
                application_kind: self.kind().application_specific_kind(),
                duplicate_handling: self.kind().duplicate_handling(),
                read_access: self.kind().read_access(),
                content_is_printable: self.kind().content_is_printable(),
            },
            timestamp: self.timestamp().as_nanoseconds() as u64,
            flags: self.flags(),
            tags: self.tag_set().to_owned(),
            payload: if self.kind().content_is_printable() {
                Some(String::from_utf8_lossy(self.payload_bytes()).to_string())
            } else {
                None
            },
            z32_payload: if self.kind().content_is_printable() {
                None
            } else {
                Some(z32::encode(self.payload_bytes()))
            },
            signature: z32::encode(self.signature().to_bytes().as_slice()),
        }
    }
}

impl OwnedRecord {
    /// Import from a JSON string
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the input is not valid Json or a valid Record.
    pub fn from_json(json: &str) -> Result<OwnedRecord, Error> {
        let json_record: JsonRecord = serde_json::from_str(json)?;

        let p: Vec<u8> = if let Some(p) = json_record.payload {
            p.as_bytes().to_owned()
        } else if let Some(b) = json_record.z32_payload {
            z32::decode(b.as_bytes())?.to_owned()
        } else {
            Vec::new()
        };

        let r = OwnedRecord::new(&RecordParts {
            signing_data: RecordSigningData::PublicKeyAndSignature(
                PublicKey::from_printable(&json_record.signing_key)?,
                ed25519_dalek::Signature::from_bytes(
                    z32::decode(json_record.signature.as_bytes())?
                        .as_slice()
                        .try_into()?,
                ),
            ),
            address_data: RecordAddressData::Address(Address::from_printable(
                &json_record.address,
            )?),
            timestamp: Timestamp::from_nanoseconds(json_record.timestamp as i64)?,
            flags: json_record.flags,
            tag_set: &json_record.tags,
            payload: &p,
        })?;

        // Verify the ID in the original JSON matches what was computed
        if r.id().as_printable() != json_record.id {
            return Err(InnerError::JsonIdIsIncorrect.into());
        }

        Ok(r)
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn test_record_to_json() {
        let mosec = "mosec0k7j6r5zqkjstzazck16acxf3mza3c4gsnocxqoif6f18h7s8pjry";
        let signing_secret_key = SecretKey::from_printable(mosec).unwrap();
        let public_key = signing_secret_key.public();
        let timestamp = Timestamp::from_nanoseconds(425201827868).unwrap();
        let r = OwnedRecord::new(&RecordParts {
            signing_data: RecordSigningData::SecretKey(signing_secret_key),
            address_data: RecordAddressData::Deterministic(
                public_key,
                Kind::EXAMPLE,
                vec![0, 0, 0, 0, 0, 0, 0, 0],
            ),
            timestamp,
            flags: RecordFlags::empty(),
            tag_set: &*EMPTY_TAG_SET, // FIXME get some real tags here
            payload: b"hello world",
        })
        .unwrap();

        let json = r.as_json();
        // println!("{}", json);

        assert_eq!(
            json,
            r#"{"id":"moref0yyyyyaayyryb3k67amzuz396jk3jjniyapb937on4y58ajzz9qoek7tor3xqdaer8gtens8jgx1or","address":"moref068okurmuk3runyyyybtoyyeyd1f5t9r8btz6r1kwcu3tawyyryqymjbcbd1hd8nwf1iwnaj6q8t31","author_key":"mopub0tqhx3bacp9tr1idr6cqfyybydon4emyehzy3aibcipysnxuthqco","signing_key":"mopub0tqhx3bacp9tr1idr6cqfyybydon4emyehzy3aibcipysnxuthqco","kind":{"as_number":425201827868,"as_bytes":[0,0,0,99,0,1,0,28],"application_id":99,"application_kind":1,"duplicate_handling":"Unique","read_access":"Everybody","content_is_printable":true},"timestamp":425201827868,"flags":0,"tags":[],"payload":"hello world","z32_payload":null,"signature":"hbjsaiwc8d3qnujt3koepuyzydqmfygn4wbpm5bt8baq8imt8pxr46xwhbr13fxx1gd9nkd9g353n8rz1nwbsbjdez9ndgb85uasebo"}"#
        );
    }

    #[test]
    fn test_record_from_json() {
        let json = r#"{"id":"moref0yyyyyaayyryb3k67amzuz396jk3jjniyapb937on4y58ajzz9qoek7tor3xqdaer8gtens8jgx1or","address":"moref068okurmuk3runyyyybtoyyeyd1f5t9r8btz6r1kwcu3tawyyryqymjbcbd1hd8nwf1iwnaj6q8t31","author_key":"mopub0tqhx3bacp9tr1idr6cqfyybydon4emyehzy3aibcipysnxuthqco","signing_key":"mopub0tqhx3bacp9tr1idr6cqfyybydon4emyehzy3aibcipysnxuthqco","kind":{"as_number":425201827868,"as_bytes":[0,0,0,99,0,1,0,28],"application_id":99,"application_kind":1,"duplicate_handling":"Unique","read_access":"Everybody","content_is_printable":true},"timestamp":425201827868,"flags":0,"tags":[],"payload":"hello world","z32_payload":null,"signature":"hbjsaiwc8d3qnujt3koepuyzydqmfygn4wbpm5bt8baq8imt8pxr46xwhbr13fxx1gd9nkd9g353n8rz1nwbsbjdez9ndgb85uasebo"}"#;

        let record = OwnedRecord::from_json(json).unwrap();

        let actual_record = {
            let mosec = "mosec0k7j6r5zqkjstzazck16acxf3mza3c4gsnocxqoif6f18h7s8pjry";
            let signing_secret_key = SecretKey::from_printable(mosec).unwrap();
            let public_key = signing_secret_key.public();
            let timestamp = Timestamp::from_nanoseconds(425201827868).unwrap();
            let r = OwnedRecord::new(&RecordParts {
                signing_data: RecordSigningData::SecretKey(signing_secret_key),
                address_data: RecordAddressData::Deterministic(
                    public_key,
                    Kind::EXAMPLE,
                    vec![0, 0, 0, 0, 0, 0, 0, 0],
                ),
                timestamp,
                flags: RecordFlags::empty(),
                tag_set: &*EMPTY_TAG_SET, // FIXME get some real tags here
                payload: b"hello world",
            })
            .unwrap();
            r
        };

        assert_eq!(record, actual_record);
    }
}
