use crate::{Address, Error, Id, InnerError};

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
    /// Will return `Err` if the input is not valid.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Reference, Error> {
        Self::verify(bytes)?;
        Ok(Reference(bytes.to_owned()))
    }

    //pub(crate) fn from_bytes_no_verify(bytes: &[u8; 48]) -> Reference {
    //    Reference(bytes.to_owned())
    //}

    /// Convert a `Reference` into the human printable `moref0` form.
    #[must_use]
    pub fn printable(&self) -> String {
        format!("moref0{}", z32::encode(self.as_ref()))
    }

    /// Import a `Reference` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid.
    pub fn from_printable(s: &str) -> Result<Reference, Error> {
        if !s.starts_with("moref0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[6..])?;
        let bytes: [u8; 48] = bytes
            .try_into()
            .map_err(|_| InnerError::ReferenceLength.into_err())?;
        Self::verify(&bytes)?;
        Ok(Reference(bytes))
    }

    fn verify(bytes: &[u8; 48]) -> Result<(), Error> {
        if bytes[0] & (1 << 7) == 0 {
            Id::verify(bytes)
        } else {
            Address::verify(bytes)
        }
    }

    /// Is this an Id?
    #[must_use]
    pub fn is_id(&self) -> bool {
        self.0[0] & (1 << 7) == 0
    }

    /// Is this an Address?
    #[must_use]
    pub fn is_address(&self) -> bool {
        self.0[0] & (1 << 7) != 0
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
        let printable =
            "moref0ygmettbi4ayybx8cwuj1ucd86dcz86enodrbup44w6tqz93tjz9ougw1kdgw7wdacuenwk93kyob1";
        let refer = Reference::from_printable(printable).unwrap();
        assert!(refer.is_id());
        assert!(!refer.is_address());
        assert!(refer.as_id().is_some());
        assert!(refer.as_address().is_none());
        let id = refer.into_id().unwrap();
        assert_eq!(format!("{id}"), printable);

        let printable =
            "moref01ge91q91o36bcfrk7qfhpnydyyobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";
        let refer = Reference::from_printable(printable).unwrap();
        assert!(!refer.is_id());
        assert!(refer.is_address());
        assert!(refer.as_id().is_none());
        assert!(refer.as_address().is_some());
        let addr = refer.into_address().unwrap();
        assert_eq!(format!("{addr}"), printable);
    }
}
