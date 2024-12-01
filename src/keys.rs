use crate::Error;
use base64::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};

/// A public signing key representing a server or user, whether a master key or subkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub VerifyingKey);

impl PublicKey {
    /// Convert this `PublicKey` into a `&[u8; 32]`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert a `&[u8; 32]` into a `PublicKey`
    ///
    /// # Errors
    ///
    /// Will return `Err` if the bytes do not represent a `CompressedEdwardsY` point on the curve.
    /// (not all bit sequences do)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, Error> {
        // FIXME - verify this is a CompressedEdwardsY on the curve
        // see ed25519-dalek docs
        Ok(PublicKey(VerifyingKey::from_bytes(bytes)?))
    }

    /// Convert a `PublicKey` into a base64 `String`
    #[must_use]
    pub fn printable(&self) -> String {
        BASE64_STANDARD.encode(self.0.as_bytes())
    }

    /// Convert a base64 `String` into a `PublicKey`
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid base64, if it is not 32 bytes long,
    /// or if the bytes do not represent a `CompressedEdwardsY` point on the curve.
    pub fn from_printable(s: &str) -> Result<PublicKey, Error> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::KeyLength)?;
        let vk = VerifyingKey::from_bytes(&bytes)?;
        Ok(PublicKey(vk))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.printable())
    }
}

/// A private signing key
#[derive(Debug, Clone)]
pub struct PrivateKey(pub SigningKey);

impl PrivateKey {
    /// Convert this `PrivateKey` into a `&[u8; 32]`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert a `&[u8; 32]` into a `PrivateKey`
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> PrivateKey {
        PrivateKey(SigningKey::from_bytes(bytes))
    }

    /// Generate a `PrivateKey`
    pub fn generate<R: rand_core::CryptoRngCore + ?Sized>(csprng: &mut R) -> PrivateKey {
        PrivateKey(SigningKey::generate(csprng))
    }

    /// Compute the `PublicKey` that matchies this `PrivateKey`
    #[must_use]
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Convert a `PrivateKey` into a base64 `String`
    #[must_use]
    pub fn printable(&self) -> String {
        BASE64_STANDARD.encode(self.0.as_bytes())
    }

    /// Convert a base64 `String` into a `PrivateKey`
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is not valid base64, if it is not 32 bytes long.
    pub fn from_printable(s: &str) -> Result<PrivateKey, Error> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::KeyLength)?;
        let sk = SigningKey::from_bytes(&bytes);
        Ok(PrivateKey(sk))
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.printable())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_generate() {
        use crate::PrivateKey;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;

        let private_key = PrivateKey::generate(&mut csprng);
        let public_key = private_key.public();

        println!("public: {}", public_key);
        println!("private: {}", private_key);
    }
}
