/// A record kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kind([u8; 8]);

impl Kind {
    /// Key Schedule Record
    pub const KEY_SCHEDULE: Kind = Kind([0, 0, 0, 0, 0, 0, 1, 14]);

    /// Profile Record
    pub const PROFILE: Kind = Kind([0, 0, 0, 0, 0, 0, 2, 14]);

    /// Microblog Root Post Record
    pub const MICROBLOG_ROOT: Kind = Kind([0, 0, 0, 0, 1, 0, 1, 28]);

    /// Reply Comment Record
    pub const REPLY_COMMENT: Kind = Kind([0, 0, 0, 0, 1, 0, 2, 28]);

    /// Blog Post Record
    pub const BLOG_POST: Kind = Kind([0, 0, 0, 0, 1, 0, 3, 28]);

    /// Chat Message Record
    pub const CHAT_MESSAGE: Kind = Kind([0, 0, 0, 0, 1, 0, 4, 28]);
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Kind::KEY_SCHEDULE => write!(f, "Key Schedule"),
            Kind::PROFILE => write!(f, "Profile"),
            Kind::MICROBLOG_ROOT => write!(f, "Microblog Root"),
            Kind::REPLY_COMMENT => write!(f, "Reply Comment"),
            Kind::BLOG_POST => write!(f, "Blog Post"),
            Kind::CHAT_MESSAGE => write!(f, "Chat Message"),
            other => write!(
                f,
                "Kind(App={:?}, AppKind={:?}, Flags={:?})",
                &other.0[0..5],
                &other.0[5..7],
                other.0[7]
            ),
        }
    }
}

impl Kind {
    /// Converts to bytes in little-endian
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0
    }

    /// Creates from bytes in little-endian
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Kind {
        Kind(bytes)
    }

    /// Application Identifier
    #[must_use]
    pub fn application_id(&self) -> u64 {
        u64::from(self.0[4])
            + (u64::from(self.0[3]) << 8)
            + (u64::from(self.0[2]) << 16)
            + (u64::from(self.0[1]) << 24)
            + (u64::from(self.0[0]) << 32)
    }

    /// Application-specific kind
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn application_specific_kind(&self) -> u16 {
        u16::from_be_bytes(self.0[5..=6].try_into().unwrap())
    }

    /// Duplicate handling
    #[must_use]
    pub fn duplicate_handling(&self) -> DuplicateHandling {
        match self.0[7] & 0b11 {
            0 => DuplicateHandling::Unique,
            1 => DuplicateHandling::Ephemeral,
            2 => DuplicateHandling::Replaceable,
            3 => DuplicateHandling::Versioned,
            _ => unreachable!(),
        }
    }

    /// Read access
    #[must_use]
    pub fn read_access(&self) -> ReadAccess {
        match (self.0[7] & 0b1100) >> 2 {
            0 => ReadAccess::AuthorOnly,
            1 => ReadAccess::AuthorAndTagged,
            2 => ReadAccess::Reserved,
            3 => ReadAccess::Everybody,
            _ => unreachable!(),
        }
    }

    /// Is the content printable?
    #[must_use]
    pub fn is_printable(&self) -> bool {
        self.0[7] & 0b10000 != 0
    }
}

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kinds() {
        assert_eq!(Kind::KEY_SCHEDULE.application_id(), 0);
        assert_eq!(Kind::KEY_SCHEDULE.application_specific_kind(), 1);
        assert_eq!(
            Kind::KEY_SCHEDULE.duplicate_handling(),
            DuplicateHandling::Replaceable
        );
        assert_eq!(Kind::KEY_SCHEDULE.read_access(), ReadAccess::Everybody);
        assert_eq!(Kind::KEY_SCHEDULE.is_printable(), false);

        assert_eq!(Kind::PROFILE.application_id(), 0);
        assert_eq!(Kind::PROFILE.application_specific_kind(), 2);
        assert_eq!(
            Kind::PROFILE.duplicate_handling(),
            DuplicateHandling::Replaceable
        );
        assert_eq!(Kind::PROFILE.read_access(), ReadAccess::Everybody);
        assert_eq!(Kind::PROFILE.is_printable(), false);

        assert_eq!(Kind::MICROBLOG_ROOT.application_id(), 1);
        assert_eq!(Kind::MICROBLOG_ROOT.application_specific_kind(), 1);
        assert_eq!(
            Kind::MICROBLOG_ROOT.duplicate_handling(),
            DuplicateHandling::Unique
        );
        assert_eq!(Kind::MICROBLOG_ROOT.read_access(), ReadAccess::Everybody);
        assert_eq!(Kind::MICROBLOG_ROOT.is_printable(), true);

        assert_eq!(Kind::REPLY_COMMENT.application_id(), 1);
        assert_eq!(Kind::REPLY_COMMENT.application_specific_kind(), 2);
        assert_eq!(
            Kind::REPLY_COMMENT.duplicate_handling(),
            DuplicateHandling::Unique
        );
        assert_eq!(Kind::REPLY_COMMENT.read_access(), ReadAccess::Everybody);
        assert_eq!(Kind::REPLY_COMMENT.is_printable(), true);

        assert_eq!(Kind::BLOG_POST.application_id(), 1);
        assert_eq!(Kind::BLOG_POST.application_specific_kind(), 3);
        assert_eq!(
            Kind::BLOG_POST.duplicate_handling(),
            DuplicateHandling::Unique
        );
        assert_eq!(Kind::BLOG_POST.read_access(), ReadAccess::Everybody);
        assert_eq!(Kind::BLOG_POST.is_printable(), true);

        assert_eq!(Kind::CHAT_MESSAGE.application_id(), 1);
        assert_eq!(Kind::CHAT_MESSAGE.application_specific_kind(), 4);
        assert_eq!(
            Kind::CHAT_MESSAGE.duplicate_handling(),
            DuplicateHandling::Unique
        );
        assert_eq!(Kind::CHAT_MESSAGE.read_access(), ReadAccess::Everybody);
        assert_eq!(Kind::CHAT_MESSAGE.is_printable(), true);
    }
}
