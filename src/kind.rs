use crate::{DuplicateHandling, KindFlags, ReadAccess};

/// A record kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kind(u64);

impl Kind {
    /// Example Kind for use in examples
    pub const EXAMPLE: Kind = Kind(0x0000_0063_0001_000e);

    /// Key Schedule Record
    pub const KEY_SCHEDULE: Kind = Kind(0x0000_0000_0001_000e);

    /// Profile Record
    pub const PROFILE: Kind = Kind(0x0000_0000_0002_000e);

    /// Microblog Root Post Record
    pub const MICROBLOG_ROOT: Kind = Kind(0x0000_0001_0001_001c);

    /// Reply Comment Record
    pub const REPLY_COMMENT: Kind = Kind(0x0000_0001_0002_001c);

    /// Blog Post Record
    pub const BLOG_POST: Kind = Kind(0x0000_0001_0003_001c);

    /// Chat Message Record
    pub const CHAT_MESSAGE: Kind = Kind(0x0000_0001_0004_001c);
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Kind::EXAMPLE => write!(f, "Example"),
            Kind::KEY_SCHEDULE => write!(f, "Key Schedule"),
            Kind::PROFILE => write!(f, "Profile"),
            Kind::MICROBLOG_ROOT => write!(f, "Microblog Root"),
            Kind::REPLY_COMMENT => write!(f, "Reply Comment"),
            Kind::BLOG_POST => write!(f, "Blog Post"),
            Kind::CHAT_MESSAGE => write!(f, "Chat Message"),
            _other => write!(f, "Kind({:x?})", self.0),
        }
    }
}

impl Kind {
    /// Converts to bytes in little-endian
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Creates from bytes in little-endian
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Kind {
        Kind(u64::from_be_bytes(bytes))
    }

    /// Converts into u64
    #[must_use]
    pub fn to_u64(&self) -> u64 {
        self.0
    }

    /// Creates from u64
    #[must_use]
    pub fn from_u64(u: u64) -> Kind {
        Kind(u)
    }

    /// From parts
    #[must_use]
    pub fn from_parts(app_id: u64, app_kind: u16, flags: KindFlags) -> Kind {
        Kind((app_id << 32) | (u64::from(app_kind) << 16) | u64::from(flags.bits()))
    }

    /// Application Identifier
    #[must_use]
    pub fn application_id(&self) -> u64 {
        self.0 >> 32
    }

    /// Application-specific kind
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn application_specific_kind(&self) -> u16 {
        ((self.0 >> 16) & 0xFFFF) as u16
    }

    /// Flags
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn flags(&self) -> KindFlags {
        KindFlags::from_bits_retain((self.0 & 0xFFFF) as u16)
    }

    /// Duplicate handling
    #[must_use]
    pub fn duplicate_handling(&self) -> DuplicateHandling {
        self.flags().duplicate_handling()
    }

    /// Read access
    #[must_use]
    pub fn read_access(&self) -> ReadAccess {
        self.flags().read_access()
    }

    /// Is the content printable?
    #[must_use]
    pub fn is_printable(&self) -> bool {
        self.flags().is_printable()
    }
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
