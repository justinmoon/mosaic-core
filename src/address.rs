use crate::{Blake3, Error, InnerError, Kind, PublicKey, Reference};
use rand::RngCore;
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

/// An Address identifies a record group where the latest one in
/// the group is the current valid record and the previous ones
/// have been replaced.
///
/// Addresses contain a nonce, a kind, and the master public key
/// of the author.

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
    /// Will return `Err` if the input is not valid or if those bytes don't
    /// represent a valid Id.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Address, Error> {
        Self::verify(bytes)?;
        Ok(Address(bytes.to_owned()))
    }

    /// Create from bytes
    ///
    /// # Safety
    ///
    /// Bytes must be a valid `Address`, otherwise undefined results can occur including
    /// panics
    #[must_use]
    pub unsafe fn from_bytes_unchecked(bytes: &[u8; 48]) -> Address {
        Address(bytes.to_owned())
    }

    pub(crate) fn from_owned_bytes(bytes: [u8; 48]) -> Result<Address, Error> {
        Self::verify(&bytes)?;
        Ok(Address(bytes))
    }

    /// Create a new Address with a random nonce
    #[must_use]
    pub fn new_random(author_public_key: PublicKey, kind: Kind) -> Address {
        let mut nonce: [u8; 8] = [0; 8];
        rand::rng().fill_bytes(&mut nonce);
        Self::from_parts(author_public_key, kind, &nonce)
    }

    /// Create a new Address with a deterministic nonce.
    ///
    /// This uses the first 8 bytes of BLAKE3 taken on the deterministic
    /// key to generate the nonce.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_deterministic(author_public_key: PublicKey, kind: Kind, key: &[u8]) -> Address {
        let mut bytes: [u8; 48] = [0; 48];
        bytes[16..48].copy_from_slice(author_public_key.as_bytes().as_slice());
        bytes[8..16].copy_from_slice(kind.to_bytes().as_slice());
        let mut hasher = Blake3::new();
        hasher.hash(key, &mut bytes[0..8]);
        bytes[0] |= 1 << 7; // Turn on MSBit
        Address(bytes)
    }

    /// Create an Address from parts
    #[must_use]
    pub fn from_parts(author_public_key: PublicKey, kind: Kind, nonce: &[u8; 8]) -> Address {
        let mut bytes: [u8; 48] = [0; 48];
        bytes[16..48].copy_from_slice(author_public_key.as_bytes().as_slice());
        bytes[8..16].copy_from_slice(kind.to_bytes().as_slice());
        bytes[0..8].copy_from_slice(nonce.as_slice());
        bytes[0] |= 1 << 7; // Turn on MSBit
        Address(bytes)
    }

    /// Convert an `Address` into the human printable `moref0` form.
    #[must_use]
    pub fn as_printable(&self) -> String {
        format!("moref0{}", z32::encode(self.as_ref()))
    }

    /// Import an `Address` from its printable form
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input not an `Address`, including if it is
    /// an ID reference.
    pub fn from_printable(s: &str) -> Result<Address, Error> {
        if !s.starts_with("moref0") {
            return Err(InnerError::InvalidPrintable.into_err());
        }
        let bytes = z32::decode(&s.as_bytes()[6..])?;
        let bytes: [u8; 48] = bytes
            .try_into()
            .map_err(|_| InnerError::ReferenceLength.into_err())?;
        Self::verify(&bytes)?;
        Ok(Address(bytes))
    }

    /// Extract kind from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn kind(&self) -> Kind {
        Kind::from_bytes(self.0[8..16].try_into().unwrap())
    }

    /// Extract nonce from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn nonce(&self) -> &[u8; 8] {
        self.0[0..8].try_into().unwrap()
    }

    /// Extract Author master public key from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn author_public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0[16..48].try_into().unwrap()).unwrap()
    }

    pub(crate) fn verify(bytes: &[u8; 48]) -> Result<(), Error> {
        if bytes[0] & (1 << 7) == 0 {
            return Err(InnerError::InvalidAddressBytes.into());
        }

        // Verify the public key
        let _ = PublicKey::from_bytes(bytes[16..48].try_into().unwrap())?;

        Ok(())
    }

    /// Convert into a `Reference`
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_reference(&self) -> Reference {
        Reference::from_bytes(&self.0).unwrap()
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_printable())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_printable().as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressVisitor)
    }
}

#[cfg(feature = "serde")]
struct AddressVisitor;

#[cfg(feature = "serde")]
impl Visitor<'_> for AddressVisitor {
    type Value = Address;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A printable Address string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Address::from_printable(s).map_err(|_| E::custom("Input is not a printable Address"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_address() {
        let author_key_printable = "mopub0ryxb374oujrfj4q9xh1g44ntkfhon8i3fjex881hohpp5fuqog7y";
        let author_key = PublicKey::from_printable(author_key_printable).unwrap();

        /* generate this test:
           let addr0 = Address::new_deterministic(
               author_key,
               Kind::KEY_SCHEDULE,
           b"hello world",
           );
           println!("{}", addr0);
        */

        let printable =
            "moref047rad578begeoyyyyyyyyyeybaobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";

        let addr = Address::from_printable(printable).unwrap();
        assert_eq!(addr.author_public_key(), author_key);
        assert_eq!(addr.kind(), Kind::KEY_SCHEDULE);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_address_serde() {
        let printable =
            "moref047rad578begeoyyyyyyyyyeybaobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";
        let addr = Address::from_printable(printable).unwrap();
        let s = serde_json::to_string(&addr).unwrap();
        assert_eq!(s.trim_matches(|c| c == '"'), printable);
        let addr2 = serde_json::from_str(&s).unwrap();
        assert_eq!(addr, addr2);
    }
}
