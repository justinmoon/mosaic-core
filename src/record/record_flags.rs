use bitflags::bitflags;
#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Server usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "json", derive(Deserialize, Serialize))]
pub struct RecordFlags(u16);

bitflags! {
    /// Record Flags
    impl RecordFlags: u16 {
        /// The payload is compressed with Zstd
        const ZSTD = 0x01;

        /// Servers SHOULD only accept the record from the author (requiring
        /// authentication)
        const FROM_AUTHOR = 0x04;
    }
}

impl Default for RecordFlags {
    fn default() -> RecordFlags {
        RecordFlags::empty()
    }
}

impl std::fmt::Display for RecordFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<&str> = vec![];
        if self.contains(RecordFlags::ZSTD) {
            parts.push("ZSTD");
        }
        if self.contains(RecordFlags::FROM_AUTHOR) {
            parts.push("FROM_AUTHOR");
        }
        match self.get_signature_scheme() {
            SignatureScheme::Ed25519 => parts.push("ED25519"),
            SignatureScheme::Secp256k1 => parts.push("SECP256K1"),
            _ => parts.push("INVALID_SIG_SCHEME"),
        }
        write!(f, "{}", parts.join(" | "))
    }
}

/// A signature scheme used to sign a `Record`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    #[allow(clippy::doc_markdown)]
    /// EdDSA ed25519
    Ed25519 = 0,

    /// secp256k1 schnorr signatures
    Secp256k1 = 1,

    /// Reserved
    Reserved2 = 2,

    /// Reserved
    Reserved3 = 3,
}

impl RecordFlags {
    const MASK: u16 = 0b1100_0000;

    /// Set the signature scheme
    pub fn set_signature_scheme(&mut self, scheme: SignatureScheme) {
        let bits: u16 = (scheme as u16) << 6;
        self.0 = (self.0 & !Self::MASK) | bits;
    }

    /// Get the signature scheme
    #[must_use]
    pub fn get_signature_scheme(&self) -> SignatureScheme {
        match (self.0 & Self::MASK) >> 6 {
            0 => SignatureScheme::Ed25519,
            1 => SignatureScheme::Secp256k1,
            2 => SignatureScheme::Reserved2,
            3 => SignatureScheme::Reserved3,
            _ => unreachable!(),
        }
    }
}
