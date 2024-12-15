use crate::{Address, Error, Id};
use base64::prelude::*;

/// A Reference (either an Id or an Address)
///
/// References sort in time order, except all Addresses follow all Ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference([u8; 48]);

impl Reference {
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
    /// encoding 48 bytes, or if those bytes don't represent a valid Reference.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Reference, Error> {
        Self::verify(bytes)?;
        Ok(Reference(bytes.to_owned()))
    }

    //pub(crate) fn from_bytes_no_verify(bytes: &[u8; 48]) -> Reference {
    //    Reference(bytes.to_owned())
    //}

    /// Convert a `Reference` into a base64 `String`
    #[must_use]
    pub fn printable(&self) -> String {
        BASE64_STANDARD.encode(self.as_ref())
    }

    /// Import a `Reference` from a printable Reference
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid base64, if it is not
    /// encoding 48 bytes, or if those bytes don't represent a valid Reference.
    pub fn from_printable(s: &str) -> Result<Reference, Error> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let bytes: [u8; 48] = bytes.try_into().map_err(|_| Error::ReferenceLength)?;
        Self::verify(&bytes)?;
        Ok(Reference(bytes))
    }

    fn verify(bytes: &[u8; 48]) -> Result<(), Error> {
        if bytes[0] & 0b10000000 == 0 {
            Id::verify(bytes)
        } else {
            Address::verify(bytes)
        }
    }

    /// Is this an Id?
    #[must_use]
    pub fn is_id(&self) -> bool {
        self.0[0] & 0b10000000 == 0
    }

    /// Is this an Address?
    #[must_use]
    pub fn is_address(&self) -> bool {
        self.0[0] & 0b10000000 != 0
    }

    /// If an Id, returns it
    #[must_use]
    pub fn as_id(&self) -> Option<Id> {
        if self.is_id() {
            Some(Id::from_bytes_no_verify(&self.0))
        } else {
            None
        }
    }

    /// If an Address, returns it
    #[must_use]
    pub fn as_address(&self) -> Option<Address> {
        if self.is_address() {
            Some(Address::from_bytes_no_verify(&self.0))
        } else {
            None
        }
    }

    /// Convert into an Id without copying
    #[must_use]
    pub fn into_id(self) -> Option<Id> {
        if self.is_id() {
            Some(Id::from_owned_bytes_no_verify(self.0))
        } else {
            None
        }
    }

    /// Convert into an Address without copying
    #[must_use]
    pub fn into_address(self) -> Option<Address> {
        if self.is_address() {
            Some(Address::from_owned_bytes_no_verify(self.0))
        } else {
            None
        }
    }
}

impl AsRef<[u8]> for Reference {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.printable())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_reference() {
        let printable = "AZO3sZiMAAApuH6dfAj9DHnCUgw0OIBW/tfZFR+CRgp2mJ6QeJiS7JKMU6/N4onu";
        let refer = Reference::from_printable(printable).unwrap();
        assert!(refer.is_id());
        assert!(!refer.is_address());
        assert!(refer.as_id().is_some());
        assert!(refer.as_address().is_none());
        let id = refer.into_id().unwrap();
        assert_eq!(format!("{id}"), printable);

        let printable = "gZO33GbKAQCYLNc7FNJMjNGZqvmnKtXbc0F9dhGcdOaQiVtf4jfzWRXY3KMpc661";
        let refer = Reference::from_printable(printable).unwrap();
        assert!(!refer.is_id());
        assert!(refer.is_address());
        assert!(refer.as_id().is_none());
        assert!(refer.as_address().is_some());
        let addr = refer.into_address().unwrap();
        assert_eq!(format!("{addr}"), printable);
    }
}
