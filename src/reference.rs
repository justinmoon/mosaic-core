use crate::{Address, Error, Id, InnerError};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

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

    /// Create from bytes
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `Reference`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8; 48]) -> Reference {
        Reference(bytes.to_owned())
    }

    /// Convert a `Reference` into the human printable `moref0` form.
    #[must_use]
    pub fn as_printable(&self) -> String {
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
        if bytes[0] & (1 << 7) != 0 {
            Address::verify(bytes)
        } else {
            Ok(())
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
    ///
    /// # Errors
    ///
    /// Returns an Err if the reference is an Address
    pub fn as_id(&self) -> Result<Id, Error> {
        if self.is_id() {
            Ok(Id::from_bytes(&self.0)?)
        } else {
            Err(InnerError::NotAnId.into())
        }
    }

    /// If an Address, returns it
    ///
    /// # Errors
    ///
    /// Returns an Err if the reference is an Id
    pub fn as_address(&self) -> Result<Address, Error> {
        if self.is_address() {
            Ok(Address::from_bytes(&self.0)?)
        } else {
            Err(InnerError::NotAnAddress.into())
        }
    }

    /// Convert into an Id without copying
    ///
    /// # Errors
    ///
    /// Returns an Err if the reference is an Address
    pub fn into_id(self) -> Result<Id, Error> {
        if self.is_id() {
            Ok(Id::from_owned_bytes(self.0)?)
        } else {
            Err(InnerError::NotAnId.into())
        }
    }

    /// Convert into an Address without copying
    ///
    /// # Errors
    ///
    /// Returns an Err if the reference is an Id
    pub fn into_address(self) -> Result<Address, Error> {
        if self.is_address() {
            Ok(Address::from_owned_bytes(self.0)?)
        } else {
            Err(InnerError::NotAnAddress.into())
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
        write!(f, "{}", self.as_printable())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Reference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_printable().as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Reference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ReferenceVisitor)
    }
}

#[cfg(feature = "serde")]
struct ReferenceVisitor;

#[cfg(feature = "serde")]
impl Visitor<'_> for ReferenceVisitor {
    type Value = Reference;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A printable Reference string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Reference::from_printable(s).map_err(|_| E::custom("Input is not a printable Reference"))
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
        assert!(refer.as_id().is_ok());
        assert!(refer.as_address().is_err());
        let id = refer.into_id().unwrap();
        assert_eq!(format!("{id}"), printable);

        let printable =
            "moref01ge91q91o36bcfrk7qfhpnydyyobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";
        let refer = Reference::from_printable(printable).unwrap();
        assert!(!refer.is_id());
        assert!(refer.is_address());
        assert!(refer.as_id().is_err());
        assert!(refer.as_address().is_ok());
        let addr = refer.into_address().unwrap();
        assert_eq!(format!("{addr}"), printable);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_reference_serde() {
        let printable =
            "moref0dbn9gp16bwuebm9hc6y1w6amfkxjze7ymkxkopdc8cwakurdwaeasm8kh3ojy3jsjn3ymgkzijyka";
        let r = Reference::from_printable(printable).unwrap();
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s.trim_matches(|c| c == '"'), printable);
        let r2 = serde_json::from_str(&s).unwrap();
        assert_eq!(r, r2);

        let printable =
            "moref047rad578begeoyyyyyyyyyeybaobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";
        let r = Reference::from_printable(printable).unwrap();
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s.trim_matches(|c| c == '"'), printable);
        let r2 = serde_json::from_str(&s).unwrap();
        assert_eq!(r, r2);
    }
}
