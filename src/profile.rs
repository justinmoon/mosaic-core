use crate::{
    Error, InnerError, Kind, OwnedRecord, OwnedTagSet, Record, RecordAddressData, RecordFlags,
    RecordParts, RecordSigningData, SecretKey, Timestamp,
};
use minicbor_derive::{Decode, Encode};

/// A user Profile
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(map)]
pub struct Profile {
    /// User's typable name
    #[n(0)]
    pub name: String,

    /// User's display name
    #[n(1)]
    pub display_name: Option<String>,

    /// Blurb about the user
    #[n(2)]
    pub about: Option<String>,

    /// Avatar picture of the user
    #[n(3)]
    pub avatar: Option<Vec<u8>>,

    /// Website of the user
    #[n(4)]
    pub website: Option<String>,

    /// Background banner image for the user
    #[n(5)]
    pub banner: Option<Vec<u8>>,

    /// Whether this user is an organisation
    #[n(6)]
    pub org: Option<bool>,

    /// Whether this user is a bot
    #[n(7)]
    pub bot: Option<bool>,

    /// Bitcoin Lightning Address
    #[n(8)]
    pub lud16: Option<String>,
}

impl Profile {
    /// Create a new profile
    #[must_use]
    pub fn new(name: &str) -> Profile {
        Profile {
            name: name.to_string(),
            display_name: None,
            about: None,
            avatar: None,
            website: None,
            banner: None,
            org: None,
            bot: None,
            lud16: None,
        }
    }

    /// Convert into CBOR bytes (e.g. for a Profile record)
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        minicbor::to_vec(self).unwrap()
    }

    /// Convert from CBOR bytes (e.g. from a Profile record)
    ///
    /// # Errors
    ///
    /// Fails if the encoded data cannot be decoded
    pub fn from_cbor_bytes(cbor: &[u8]) -> Result<Self, Error> {
        // NOTE: this only throws an Error<Infallible> which can't happen
        Ok(minicbor::decode(cbor)?)
    }

    /// Create a new `OwnedRecord` based on this `Profile`
    ///
    /// # Errors
    ///
    /// This is unlikely to return an error.
    pub fn as_record(&self, secret_key: SecretKey) -> Result<OwnedRecord, Error> {
        let payload = self.to_cbor_bytes();
        let tag_set = OwnedTagSet::new();

        let public_key = secret_key.public();
        let parts = RecordParts {
            signing_data: RecordSigningData::SecretKey(secret_key),
            address_data: RecordAddressData::Random(public_key, Kind::PROFILE),
            timestamp: Timestamp::now()?,
            flags: RecordFlags::empty(),
            tag_set: &tag_set,
            payload: &payload,
        };

        let record = OwnedRecord::new(&parts)?;

        Ok(record)
    }

    /// Extract a `Profile` from a `Profile` `Record`
    ///
    /// # Errors
    ///
    /// Returns an error if the Record is the wrong kind, or doesn't validate,
    /// or the profile is invalid such as not having a name or being invalid
    /// CBOR.
    pub fn from_record(record: &Record) -> Result<Profile, Error> {
        record.verify()?;

        if record.kind() != Kind::PROFILE {
            return Err(InnerError::WrongKind.into());
        }

        Profile::from_cbor_bytes(record.payload_bytes())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_profile() {
        use crate::{Profile, SecretKey};

        // Generate a profile
        let mut profile = Profile::new("Mike Dilger");
        profile.display_name = Some("➡️ Black Sheep".to_owned());
        profile.avatar = Some(include_bytes!("bs.webp").to_vec());
        profile.org = Some(false);
        profile.bot = Some(false);

        // Convert to and from CBOR
        let bytes = profile.to_cbor_bytes();
        println!("Used {} bytes", bytes.len());
        let profile2 = Profile::from_cbor_bytes(&bytes).unwrap();
        assert_eq!(profile, profile2);

        // Convert to and from a Record
        let secret_key = SecretKey::generate();
        let record = profile.as_record(secret_key).unwrap();
        let profile3 = Profile::from_record(&record).unwrap();
        assert_eq!(profile2, profile3);
    }
}
