use bitflags::bitflags;

/// Server usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordFlags(u16);

bitflags! {
    /// Record Flags
    impl RecordFlags: u16 {
    const ZSTD = 0x01;
    const FROM_AUTHOR = 0x02;
    const TO_RECIPIENTS = 0x04;
    const NO_BRIDGE = 0x08;
    const EPHEMERAL = 0x10;
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
        if self.contains(RecordFlags::TO_RECIPIENTS) {
            parts.push("TO_RECIPIENTS");
        }
        if self.contains(RecordFlags::NO_BRIDGE) {
            parts.push("NO_BRIDGE");
        }
        if self.contains(RecordFlags::EPHEMERAL) {
            parts.push("EPHEMERAL");
        }
        write!(f, "{}", parts.join(" | "))
    }
}
