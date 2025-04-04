/// A record kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kind(pub u16);

impl Kind {
    /// Key Schedule Record
    pub const KEY_SCHEDULE: Kind = Kind(0x1);

    /// Profile Record
    pub const PROFILE: Kind = Kind(0x2);

    /// Microblog Root Post Record
    pub const MICROBLOG_ROOT: Kind = Kind(0x3);

    /// Reply Comment Record
    pub const REPLY_COMMENT: Kind = Kind(0x4);

    /// Blog Post Record
    pub const BLOG_POST: Kind = Kind(0x5);

    /// Chat Message Record
    pub const CHAT_MESSAGE: Kind = Kind(0x6);
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0x1 => write!(f, "Key Schedule"),
            0x2 => write!(f, "Profile"),
            0x3 => write!(f, "Microblog Root"),
            0x4 => write!(f, "Reply Comment"),
            0x5 => write!(f, "Blog Post"),
            0x6 => write!(f, "Chat Message"),
            u => write!(f, "Kind({u})"),
        }
    }
}
