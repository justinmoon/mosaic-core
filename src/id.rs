use crate::{Error, Timestamp};
use base64::prelude::*;

/// An Id uniquely identifies a record.
///
/// Ids sort in time order, and contain a timestamp and a hash prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; 48]);

impl Id {
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
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Id, Error> {
        let id = Id(bytes.to_owned());

        id.verify()?;

        Ok(id)
    }

    pub(crate) fn from_bytes_no_verify(bytes: &[u8; 48]) -> Id {
        Id(bytes.to_owned())
    }

    /// Convert an `Id` into a base64 `String`
    #[must_use]
    pub fn printable(&self) -> String {
        BASE64_STANDARD.encode(self.as_ref())
    }

    /// Import an `Id` from a printable Id
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid base64, if it is not
    /// encoding 48 bytes, or if those bytes don't represent a valid Id.
    pub fn from_printable(s: &str) -> Result<Id, Error> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let bytes: [u8; 48] = bytes.try_into().map_err(|_| Error::IdLength)?;

        let id = Id(bytes);

        id.verify()?;

        Ok(id)
    }

    /// Extract timestamp from the Id
    ///
    /// # Errors
    ///
    /// Returns an error if the data is out of range for a `Timestamp`
    #[allow(clippy::missing_panics_doc)]
    pub fn timestamp(&self) -> Result<Timestamp, Error> {
        Timestamp::from_be_bytes(&self.0[0..6].try_into().unwrap())
    }

    /// Extract the hash prefix from the Id
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn hash_prefix(&self) -> &[u8; 40] {
        self.0[8..48].try_into().unwrap()
    }

    fn verify(&self) -> Result<(), Error> {
        // Verify zeros
        if self.0[6] != 0 || self.0[7] != 0 {
            return Err(Error::IdZerosAreNotZero);
        }

        // Verify the timestamp
        let _ = self.timestamp()?;

        Ok(())
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.printable())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_id() {
        let printable = "AZO3sZiMAAApuH6dfAj9DHnCUgw0OIBW/tfZFR+CRgp2mJ6QeJiS7JKMU6/N4onu";
        let id = Id::from_printable(printable).unwrap();
        let timestamp = id.timestamp().unwrap();
        assert_eq!(format!("{}", timestamp), "1733953689740");
    }
}
