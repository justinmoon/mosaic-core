/// A record kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TagType(pub u16);

impl TagType {
    pub const PUBLIC_KEY: TagType = TagType(0x1);
    pub const REPLY_TO_HASH: TagType = TagType(0x2);
    pub const REPLY_TO_ADDR: TagType = TagType(0x3);
    pub const ROOT_HASH: TagType = TagType(0x4);
    pub const ROOT_ADDR: TagType = TagType(0x5);
    pub const QUOTE_BY_HASH: TagType = TagType(0x6);
    pub const QUOTE_BY_ADDR: TagType = TagType(0x7);
}

impl std::fmt::Display for TagType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0x1 => write!(f, "Public Key"),
            0x2 => write!(f, "Reply to Hash"),
            0x3 => write!(f, "Reply to Addr"),
            0x4 => write!(f, "Root Hash"),
            0x5 => write!(f, "Root Addr"),
            0x6 => write!(f, "Quote by Hash"),
            0x7 => write!(f, "Quote by Addr"),
            u => write!(f, "TagType({u})"),
        }
    }
}
