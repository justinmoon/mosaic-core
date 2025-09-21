use crate::{
    Error, InnerError, Kind, OwnedRecord, OwnedTag, OwnedTagSet, PublicKey, Record,
    RecordAddressData, RecordFlags, RecordParts, RecordSigningData, SecretKey, Timestamp,
};

/// Flags applying to a Subkey
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubkeyMarker {
    /// An active ed25519 key used for signing
    ActiveSigningKey = 0,

    /// An active x25519 key used for encryption
    ActiveEncryptionKey = 1,

    /// This key is revoked for ALL TIME
    RevokedAll = 0x40,

    /// This key is revoked for events before the timestamp
    RevokedPast = 0x41,

    /// This key is out of use as of the timestamp, but not revoked
    OutOfUse = 0x4F,

    /// This is an active nostr key, interpreted under secp256k1
    ActiveNostrKey = 0x80,

    /// Undefined
    Undefined(u16),
}

impl SubkeyMarker {
    /// Create a `MessageType` from a `u8`
    #[must_use]
    pub fn from_u16(u: u16) -> Self {
        match u {
            0 => Self::ActiveSigningKey,
            1 => Self::ActiveEncryptionKey,
            0x40 => Self::RevokedAll,
            0x41 => Self::RevokedPast,
            0x4F => Self::OutOfUse,
            0x80 => Self::ActiveNostrKey,
            u => Self::Undefined(u),
        }
    }

    /// Convert to a u16
    #[must_use]
    pub fn to_u16(self) -> u16 {
        match self {
            Self::ActiveSigningKey => 0,
            Self::ActiveEncryptionKey => 1,
            Self::RevokedAll => 0x40,
            Self::RevokedPast => 0x41,
            Self::OutOfUse => 0x4F,
            Self::ActiveNostrKey => 0x80,
            Self::Undefined(u) => u,
        }
    }

    /// If the marker requires a timestamp
    #[must_use]
    pub fn requires_a_timestamp(&self) -> bool {
        matches!(self, Self::RevokedAll | Self::RevokedPast)
    }

    /// If the marker uses a timestamp
    #[must_use]
    pub fn uses_a_timestamp(&self) -> bool {
        matches!(self, Self::RevokedAll | Self::RevokedPast | Self::OutOfUse)
    }
}

/// A `KeySchedule` Entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyScheduleEntry {
    /// The key being described
    pub public_key: PublicKey,

    /// A marker describing the key
    pub marker: SubkeyMarker,

    /// A timestamp relating to the marker, zeroed in certain cases
    pub timestamp: Timestamp,
}

impl KeyScheduleEntry {
    /// Verify that the entry is valid
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the subkey marker is undefined, or if a required timestamp is zero
    pub fn verify(&self) -> Result<(), Error> {
        if let SubkeyMarker::Undefined(u) = self.marker {
            Err(InnerError::UndefinedSubkeyMarker(u).into())
        } else if self.marker.requires_a_timestamp() && self.timestamp == Timestamp::ZERO {
            Err(InnerError::SubkeyMarkerRequiresATimestamp.into())
        } else {
            Ok(())
        }
    }

    /// Zero timestamp if it is present and the entry does not use it
    pub fn zero_timestamp_if_unnecessary(&mut self) {
        if !self.marker.uses_a_timestamp() && self.timestamp != Timestamp::ZERO {
            self.timestamp = Timestamp::ZERO;
        }
    }
}

/// `KeySchedule` data
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct KeySchedule(Vec<KeyScheduleEntry>);

impl KeySchedule {
    /// Create new `KeySchedule` data
    ///
    /// # Errors
    ///
    /// Return an `Err` if any of the entries are invalid.
    pub fn new(mut data: Vec<KeyScheduleEntry>) -> Result<KeySchedule, Error> {
        for e in &mut data {
            e.verify()?;
            e.zero_timestamp_if_unnecessary();
        }
        Ok(KeySchedule(data))
    }

    /// Get at the inner data
    #[must_use]
    pub fn inner(&self) -> &[KeyScheduleEntry] {
        &self.0
    }

    /// Take the inner `Record`
    #[must_use]
    pub fn into_inner(self) -> Vec<KeyScheduleEntry> {
        self.0
    }

    /// Create a new `OwnedRecord` based on this `KeySchedule`
    ///
    /// # Errors
    ///
    /// This is unlikely to return an error.
    pub fn as_record(&self, secret_key: SecretKey) -> Result<OwnedRecord, Error> {
        let mut payload = vec![0; 48 * self.0.len()];
        let mut tag_set = OwnedTagSet::new();

        for kse in &self.0 {
            tag_set.add_tag(&OwnedTag::new_subkey(&kse.public_key));
            payload.extend(kse.public_key.as_bytes().as_slice());
            payload.extend(kse.marker.to_u16().to_le_bytes().as_slice());
            payload.extend(&[0, 0, 0, 0, 0, 0]);
            payload.extend(kse.timestamp.to_bytes().as_slice());
        }

        let public_key = secret_key.public();
        let parts = RecordParts {
            signing_data: RecordSigningData::SecretKey(secret_key),
            address_data: RecordAddressData::Random(public_key, Kind::KEY_SCHEDULE),
            timestamp: Timestamp::now()?,
            flags: RecordFlags::empty(),
            tag_set: &tag_set,
            payload: &payload,
        };

        let record = OwnedRecord::new(&parts)?;

        Ok(record)
    }

    /// Extract a`KeySchedule` from a `KeySchedule` `Record`
    ///
    /// # Errors
    ///
    /// Returns an error if the Record is the wrong kind, or doesn't validate, or
    /// has other errors.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_record(record: &Record) -> Result<KeySchedule, Error> {
        record.verify()?;

        if record.kind() != Kind::KEY_SCHEDULE {
            return Err(InnerError::WrongKind.into());
        }

        if record.payload_len() % 48 != 0 {
            return Err("Invalid KeySchedule Record payload len".into());
        }

        let num_entries = record.payload_len() / 48;

        let mut entries: Vec<KeyScheduleEntry> = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let public_key = PublicKey::from_bytes(
                &record.payload_bytes()[i * 48..i * 48 + 32]
                    .try_into()
                    .unwrap(),
            )?;
            let marker = SubkeyMarker::from_u16(u16::from_le_bytes(
                record.payload_bytes()[i * 48 + 32..i * 48 + 34]
                    .try_into()
                    .unwrap(),
            ));
            let timestamp = Timestamp::from_bytes(
                record.payload_bytes()[i * 48 + 40..i * 48 + 48]
                    .try_into()
                    .unwrap(),
            )?;
            let entry = KeyScheduleEntry {
                public_key,
                marker,
                timestamp,
            };
            // Note: we don't verify these. Some may not verify as people may be using
            //       future standard items we don't understand yet.
            entries.push(entry);
        }

        Ok(KeySchedule(entries))
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[ignore = "temporarily skipped pending KeySchedule test implementation"]
    fn test_key_schedule() {
        todo!();
        //let mut key_schedule = KeySchedule::new(vec![]);
    }
}
