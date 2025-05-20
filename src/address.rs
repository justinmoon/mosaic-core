use crate::{Error, InnerError, Kind, PublicKey, Reference};
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
    /// Will return `Err` if the input is not valid or if those bytes don't
    /// represent a valid Id.
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

    /// Create a new Address with a random nonce
    #[must_use]
    pub fn new_random(author_public_key: PublicKey, kind: Kind) -> Address {
        let mut nonce: [u8; 14] = [0; 14];
        OsRng.fill_bytes(&mut nonce);
        Self::from_parts(author_public_key, kind, &nonce)
    }

    /// Create a new Address with a deterministic nonce.
    ///
    /// This uses the first 14 bytes of BLAKE3 taken on the deterministic
    /// key to generate the nonce.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_deterministic(author_public_key: PublicKey, kind: Kind, key: &[u8]) -> Address {
        let mut truehash: [u8; 64] = [0; 64];
        let mut hasher = blake3::Hasher::new();
        let _ = hasher.update(key);
        hasher.finalize_xof().fill(&mut truehash[..]);

        Self::from_parts(author_public_key, kind, truehash[0..14].try_into().unwrap())
    }

    /// Create an Address from parts
    #[must_use]
    pub fn from_parts(author_public_key: PublicKey, kind: Kind, nonce: &[u8; 14]) -> Address {
        let mut bytes: [u8; 48] = [0; 48];
        bytes[16..48].copy_from_slice(author_public_key.as_bytes().as_slice());
        bytes[14..16].copy_from_slice(kind.0.to_le_bytes().as_slice());
        bytes[0..14].copy_from_slice(nonce.as_slice());
        bytes[0] |= 1 << 7; // Turn on MSBit
        Address(bytes)
    }

    /// Convert an `Address` into the human printable `moref0` form.
    #[must_use]
    pub fn printable(&self) -> String {
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
        Kind(u16::from_le_bytes(self.0[14..16].try_into().unwrap()))
    }

    /// Extract nonce from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn nonce(&self) -> &[u8; 14] {
        self.0[0..14].try_into().unwrap()
    }

    /// Extract Author master public key from the Address
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn author_public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0[16..48].try_into().unwrap()).unwrap()
    }

    pub(crate) fn verify(bytes: &[u8; 48]) -> Result<(), Error> {
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
        write!(f, "{}", self.printable())
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
            "moref01ge91q91o36bcfrk7qfhpnydyyobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";

        let addr = Address::from_printable(printable).unwrap();
        assert_eq!(addr.author_public_key(), author_key);
        assert_eq!(addr.kind(), Kind::MICROBLOG_ROOT);
    }
}
