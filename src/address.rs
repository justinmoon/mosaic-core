use crate::{Error, Kind, PublicKey, Timestamp};
use base64::prelude::*;
use rand_core::{OsRng, RngCore};

/// An Address identifies a record group where the latest one in
/// the group is the current valid record and the previous ones
/// have been replaced.
///
/// Addresses sort in time order and contain a timestamp, a kind,
/// a nonce, and the master public key of the author.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 48]);

impl Address {
    /// Get as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Create from bytes
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid base64, if it is not
    /// encoding 48 bytes, or if those bytes don't represent a valid Id.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Address, Error> {
        Self::verify(bytes)?;
        Ok(Address(bytes.to_owned()))
    }

    pub(crate) fn from_bytes_no_verify(bytes: &[u8; 48]) -> Address {
        Address(bytes.to_owned())
    }

    pub(crate) fn from_owned_bytes_no_verify(bytes: [u8; 48]) -> Address {
        Address(bytes)
    }

    /// Create a new Address
    #[must_use]
    pub fn new(author_public_key: PublicKey, kind: Kind, timestamp: Timestamp) -> Address {
        let mut nonce: [u8; 8] = [0; 8];
        OsRng.fill_bytes(&mut nonce);
        Self::from_parts(author_public_key, kind, timestamp, &nonce)
    }

    /// Create an Address from parts
    #[must_use]
    pub fn from_parts(
        author_public_key: PublicKey,
        kind: Kind,
        timestamp: Timestamp,
        nonce: &[u8; 8],
    ) -> Address {
        let mut bytes: [u8; 48] = [0; 48];
        bytes[16..48].copy_from_slice(author_public_key.as_bytes().as_slice());
        bytes[8..16].copy_from_slice(nonce.as_slice());
        bytes[6..8].copy_from_slice(kind.0.to_le_bytes().as_slice());
        let mut ts = timestamp.to_be_bytes();
        ts[0] |= 0b10000000; // turn on MSBit
        bytes[0..6].copy_from_slice(ts.as_slice());
        Address(bytes)
    }

    /// Convert an `Address` into a base64 `String`
    #[must_use]
    pub fn printable(&self) -> String {
        BASE64_STANDARD.encode(self.as_ref())
    }

    /// Import an `Address` from a printable Address
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid base64, if it is not
    /// encoding 48 bytes, or if those bytes don't represent a valid Address.
    pub fn from_printable(s: &str) -> Result<Address, Error> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let bytes: [u8; 48] = bytes.try_into().map_err(|_| Error::ReferenceLength)?;
        Self::verify(&bytes)?;
        Ok(Address(bytes))
    }

    /// Extract timestamp from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn timestamp(&self) -> Timestamp {
        let mut ts: [u8; 6] = self.0[0..6].try_into().unwrap();
        ts[0] &= !0b10000000; // turn off MSbit
        Timestamp::from_be_bytes(&ts).unwrap()
    }

    /// Extract kind from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn kind(&self) -> Kind {
        Kind(u16::from_le_bytes(self.0[6..8].try_into().unwrap()))
    }

    /// Extract nonce from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn nonce(&self) -> &[u8; 8] {
        self.0[8..16].try_into().unwrap()
    }

    /// Extract Author master public key from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn author_public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0[16..48].try_into().unwrap()).unwrap()
    }

    pub(crate) fn verify(bytes: &[u8; 48]) -> Result<(), Error> {
        // Verify the timestamp
        let mut ts: [u8; 6] = bytes[0..6].try_into().unwrap();
        ts[0] &= !0b10000000; // turn off MSbit
        let _ = Timestamp::from_be_bytes(&ts)?;

        // Verify the public key
        let _ = PublicKey::from_bytes(bytes[16..48].try_into().unwrap())?;

        Ok(())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.printable())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_address() {
        /*
            let author_key_printable = "0Zmq+acq1dtzQX12EZx05pCJW1/iN/NZFdjcoylzrrU=";
            let author_key = PublicKey::from_printable(author_key_printable).unwrap();
        let addr0 = Address::new(
            author_key,
            Kind::KEY_SCHEDULE,
            Timestamp::from_unixtime(1733956467, 50).unwrap(),
        );
        println!("{}", addr0);
         */

        let printable = "gZO33GbKAQCYLNc7FNJMjNGZqvmnKtXbc0F9dhGcdOaQiVtf4jfzWRXY3KMpc661";
        let addr = Address::from_printable(printable).unwrap();
        let timestamp = addr.timestamp();
        assert_eq!(format!("{timestamp}"), "1733956495050");

        let author_key_printable = "0Zmq+acq1dtzQX12EZx05pCJW1/iN/NZFdjcoylzrrU=";
        let author_key = PublicKey::from_printable(author_key_printable).unwrap();
        assert_eq!(addr.author_public_key(), author_key);

        assert_eq!(addr.kind(), Kind::KEY_SCHEDULE);
    }
}
