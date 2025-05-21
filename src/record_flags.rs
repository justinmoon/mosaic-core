use bitflags::bitflags;

/// Server usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordFlags(u16);

bitflags! {
    /// Record Flags
    impl RecordFlags: u16 {
        /// The payload is compressed with Zstd
        const ZSTD = 0x01;

        /// The payload is printable and can be displayed to end users
        const PRINTABLE = 0x02;

        /// Servers SHOULD only accept the record from the author (requiring
        /// authentication)
        const FROM_AUTHOR = 0x04;

        /// Servers SHOULD only serve the record to people tagged (requiring
        /// authentication)
        const TO_RECIPIENTS = 0x08;

        /// The record is ephemeral; Servers should serve it to current
        /// subscribers and not keep it.
        const EPHEMERAL = 0x10;

        /// Among a group of records with the same address, only the latest one is
        /// valid, the others SHOULD be deleted or at least not served.
        const EDITABLE = 0x20;
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
        if self.contains(RecordFlags::PRINTABLE) {
            parts.push("PRINTABLE");
        }
        if self.contains(RecordFlags::FROM_AUTHOR) {
            parts.push("FROM_AUTHOR");
        }
        if self.contains(RecordFlags::TO_RECIPIENTS) {
            parts.push("TO_RECIPIENTS");
        }
        if self.contains(RecordFlags::EPHEMERAL) {
            parts.push("EPHEMERAL");
        }
        if self.contains(RecordFlags::EDITABLE) {
            parts.push("EDITABLE");
        }
        write!(f, "{}", parts.join(" | "))
    }
}

/// A signature scheme used to sign a `Record`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
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
    const MASK: u16 = 0b11000000;

    /// Set the signature scheme
    pub fn set_signature_scheme(&mut self, scheme: SignatureScheme) {
        let bits: u16 = (scheme as u16) << 6;
        self.0 = (self.0 & !Self::MASK) | bits;
    }

    /// Get the signature scheme
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
