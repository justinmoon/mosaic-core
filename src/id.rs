use crate::{Error, InnerError, Reference, Timestamp};

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
    /// Will return `Err` if the input is not valid.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Id, Error> {
        Self::verify(bytes)?;
        Ok(Id(bytes.to_owned()))
    }

    pub(crate) fn from_bytes_no_verify(bytes: &[u8; 48]) -> Id {
        Id(bytes.to_owned())
    }

    pub(crate) fn from_owned_bytes_no_verify(bytes: [u8; 48]) -> Id {
        Id(bytes)
    }

    /// Convert an `Id` into a human printable `moref0` form.
    #[must_use]
    pub fn printable(&self) -> String {
        format!("moref0{}", z32::encode(self.as_ref()))
    }

    /// Import an `Id` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not an `Id`, including if it is
    /// an address reference.
    pub fn from_printable(s: &str) -> Result<Id, Error> {
        if !s.starts_with("moref0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[6..])?;
        let bytes: [u8; 48] = bytes
            .try_into()
            .map_err(|_| InnerError::ReferenceLength.into_err())?;
        Self::verify(&bytes)?;
        Ok(Id(bytes))
    }

    /// Extract timestamp from the Id
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn timestamp(&self) -> Timestamp {
        Timestamp::from_be_bytes(&self.0[0..6].try_into().unwrap()).unwrap()
    }

    /// Extract the hash prefix from the Id
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn hash_prefix(&self) -> &[u8; 40] {
        self.0[8..48].try_into().unwrap()
    }

    pub(crate) fn verify(bytes: &[u8; 48]) -> Result<(), Error> {
        // Verify zeros
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err(InnerError::IdZerosAreNotZero.into());
        }

        // Verify the timestamp
        let _ = Timestamp::from_be_bytes(&bytes[0..6].try_into().unwrap())?;

        Ok(())
    }

    /// Convert into a `Reference`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_reference(&self) -> Reference {
        Reference::from_bytes(&self.0).unwrap()
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
        let printable =
            "moref0ygmettbi4ayybx8cwuj1ucd86dcz86enodrbup44w6tqz93tjz9ougw1kdgw7wdacuenwk93kyob1";
        let id = Id::from_printable(printable).unwrap();
        let timestamp = id.timestamp();
        assert_eq!(format!("{timestamp}"), "1746051282390");
    }
}
