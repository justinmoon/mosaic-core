/// A record kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kind(pub u16);

impl Kind {
    pub const KEY_SCHEDULE: Kind = Kind(0x1);
    pub const PROFILE: Kind = Kind(0x2);
    pub const MICROBLOG_ROOT: Kind = Kind(0x3);
    pub const REPLY_COMMENT: Kind = Kind(0x4);
    pub const BLOG_POST: Kind = Kind(0x5);
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
