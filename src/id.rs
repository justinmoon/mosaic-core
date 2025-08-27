use crate::{Error, InnerError, Reference, Timestamp};
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

/// An Id uniquely identifies a record.
///
/// Ids sort in time order, and contain a timestamp and a hash prefix
//
// SAFETY: It must be impossible to create an Id that starts with a 1 bit
//         (which is invalid for the leading timestamp)
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
        if bytes[0] & (1 << 7) != 0 {
            Err(InnerError::InvalidIdBytes.into())
        } else {
            Ok(Id(bytes.to_owned()))
        }
    }

    /// Create from bytes
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `Id`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8; 48]) -> Id {
        Id(bytes.to_owned())
    }

    pub(crate) fn from_owned_bytes(bytes: [u8; 48]) -> Result<Id, Error> {
        if bytes[0] & (1 << 7) != 0 {
            Err(InnerError::InvalidIdBytes.into())
        } else {
            Ok(Id(bytes))
        }
    }

    /// Create an ID from a hash and a `Timestamp`
    #[must_use]
    pub fn from_parts(hash_prefix: &[u8; 40], timestamp: Timestamp) -> Id {
        let mut buffer: [u8; 48] = [0; 48];
        buffer[8..48].copy_from_slice(&hash_prefix[..40]);
        buffer[0..8].copy_from_slice(timestamp.to_bytes().as_slice());
        Id(buffer)
    }

    /// Convert an `Id` into a human printable `moref0` form.
    #[must_use]
    pub fn as_printable(&self) -> String {
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
        Id::from_owned_bytes(bytes)
    }

    /// Extract timestamp from the Id
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn timestamp(&self) -> Timestamp {
        // We can unwrap because Id is guaranteed to have a valid timestamp
        Timestamp::from_bytes(self.0[0..8].try_into().unwrap()).unwrap()
    }

    /// Extract the hash prefix from the Id
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn hash_prefix(&self) -> &[u8; 40] {
        self.0[8..48].try_into().unwrap()
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
        write!(f, "{}", self.as_printable())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_printable().as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(IdVisitor)
    }
}

#[cfg(feature = "serde")]
struct IdVisitor;

#[cfg(feature = "serde")]
impl Visitor<'_> for IdVisitor {
    type Value = Id;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A printable Id string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Id::from_printable(s).map_err(|_| E::custom("Input is not a printable Id"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_id() {
        /*
        use rand_core::{OsRng, RngCore};
        let mut hash_prefix: [u8; 40] = [0; 40];
        OsRng.fill_bytes(&mut hash_prefix);
        let id = Id::from_parts(&hash_prefix, Timestamp::now().unwrap());
        println!("NEW ID = {}", id);
         */

        let printable =
            "moref0dbn9gp16bwuebm9hc6y1w6amfkxjze7ymkxkopdc8cwakurdwaeasm8kh3ojy3jsjn3ymgkzijyka";
        let id = Id::from_printable(printable).unwrap();
        let timestamp = id.timestamp();
        assert_eq!(format!("{timestamp}"), "1749071445135009408");
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_id_serde() {
        let printable =
            "moref0dbn9gp16bwuebm9hc6y1w6amfkxjze7ymkxkopdc8cwakurdwaeasm8kh3ojy3jsjn3ymgkzijyka";
        let id = Id::from_printable(printable).unwrap();
        let s = serde_json::to_string(&id).unwrap();
        assert_eq!(s.trim_matches(|c| c == '"'), printable);
        let id2 = serde_json::from_str(&s).unwrap();
        assert_eq!(id, id2);
    }
}
