use bitflags::bitflags;

/// How to handle events with duplicate Addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DuplicateHandling {
    /// Unique: All events should have unique addresses, however duplicates should be
    /// preserved and treated like `Versioned`
    Unique,

    /// Servers should serve such records only to current subscribers, but should not
    /// save the record nor serve it later to future subscribers.
    Ephemeral,

    /// Among records with the same address, only the one with the latest timestamp
    /// should be served by servers
    Replaceable,

    /// Among records with the same address, all of them remain relevant and should
    /// be seen as a version history
    Versioned,
}

impl DuplicateHandling {
    /// Create from a u16 (last 2 bits)
    #[must_use]
    pub fn from_u16(u: u16) -> DuplicateHandling {
        match u & 0b11 {
            0 => DuplicateHandling::Unique,
            1 => DuplicateHandling::Ephemeral,
            2 => DuplicateHandling::Replaceable,
            3 => DuplicateHandling::Versioned,
            _ => unreachable!(),
        }
    }

    /// Express as a u16 (last 2 bits)
    #[must_use]
    pub fn as_u16(&self) -> u16 {
        match self {
            DuplicateHandling::Unique => 0,
            DuplicateHandling::Ephemeral => 1,
            DuplicateHandling::Replaceable => 2,
            DuplicateHandling::Versioned => 3,
        }
    }
}

/// Who servers should allow to read this record
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadAccess {
    /// Only the author should be able to read back this record
    AuthorOnly,

    /// Only the author and tagged pubkeys should be able to read back this record
    AuthorAndTagged,

    /// Reserved
    Reserved,

    /// Everybody may read this record
    Everybody,
}

impl ReadAccess {
    /// Create from a u16 (last 2 bits)
    #[must_use]
    pub fn from_u16(u: u16) -> ReadAccess {
        match u & 0b11 {
            0 => ReadAccess::AuthorOnly,
            1 => ReadAccess::AuthorAndTagged,
            2 => ReadAccess::Reserved,
            3 => ReadAccess::Everybody,
            _ => unreachable!(),
        }
    }

    /// Express as a u16 (last 2 bits)
    #[must_use]
    pub fn as_u16(&self) -> u16 {
        match self {
            ReadAccess::AuthorOnly => 0,
            ReadAccess::AuthorAndTagged => 1,
            ReadAccess::Reserved => 2,
            ReadAccess::Everybody => 3,
        }
    }
}

/// Kind flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KindFlags(u16);

bitflags! {
    /// Kind flags
    impl KindFlags: u16 {
        /// Whether the event supports duplicates, or is replaceable or ephemeral.
        const DUPLICATE_HANDLING = 0b0000_0011;

        /// Who can read the record
        const READ_ACCESS = 0b0000_1100;

        /// If the payload is printable
        const CONTENT_IS_PRINTABLE = 0b0001_0000;

        // Any other bits might be set
        const _ = !0;
    }
}

impl Default for KindFlags {
    fn default() -> KindFlags {
        KindFlags::from_parts(DuplicateHandling::Unique, ReadAccess::Everybody, true)
    }
}

impl KindFlags {
    /// Create a `KindFlags` from flag parts
    #[must_use]
    pub fn from_parts(
        dh: DuplicateHandling,
        ra: ReadAccess,
        content_is_printable: bool,
    ) -> KindFlags {
        let mut s: KindFlags = KindFlags(0);
        s.set_duplicate_handling(dh);
        s.set_read_access(ra);
        s.set_content_is_printable(content_is_printable);
        s
    }

    /// Duplicate handling
    #[must_use]
    pub fn duplicate_handling(&self) -> DuplicateHandling {
        let mask_bits = Self::DUPLICATE_HANDLING.bits();
        let shift = mask_bits.trailing_zeros();
        DuplicateHandling::from_u16((self.bits() & mask_bits) >> shift)
    }

    /// Set Duplicate handling
    pub fn set_duplicate_handling(&mut self, dh: DuplicateHandling) {
        let mask_bits = Self::DUPLICATE_HANDLING.bits();
        let shift = mask_bits.trailing_zeros();
        let new_bits = dh.as_u16() << shift;
        self.0 = (self.0 & !mask_bits) | new_bits;
    }

    /// Read access
    #[must_use]
    pub fn read_access(&self) -> ReadAccess {
        let mask_bits = Self::READ_ACCESS.bits();
        let shift = mask_bits.trailing_zeros();
        ReadAccess::from_u16((self.bits() & mask_bits) >> shift)
    }

    /// Set Read access
    pub fn set_read_access(&mut self, ra: ReadAccess) {
        let mask_bits = Self::READ_ACCESS.bits();
        let shift = mask_bits.trailing_zeros();
        let new_bits = ra.as_u16() << shift;
        self.0 = (self.0 & !mask_bits) | new_bits;
    }

    /// Is Printable
    #[must_use]
    pub fn content_is_printable(&self) -> bool {
        self.contains(Self::CONTENT_IS_PRINTABLE)
    }

    /// Set Is Printable
    pub fn set_content_is_printable(&mut self, content_is_printable: bool) {
        self.set(Self::CONTENT_IS_PRINTABLE, content_is_printable);
    }
}
