use bitflags::bitflags;

/// Server usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordFlags(u16);

bitflags! {
    /// Record Flags
    impl RecordFlags: u16 {
	/// The payload is compressed with Zstd
	const ZSTD = 0x01;

	/// Servers SHOULD only accept the record from the author (requiring
	/// authentication)
	const FROM_AUTHOR = 0x02;

	/// Servers SHOULD only serve the record to people tagged (requiring
	/// authentication)
	const TO_RECIPIENTS = 0x04;

	/// Bridges SHOULD NOT propogate the record to other networks (nostr,
	/// mastodon, etc)
	const NO_BRIDGE = 0x08;

	/// The record is ephemeral; Servers should serve it to current
	/// subscribers and not keep it.
	const EPHEMERAL = 0x10;
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
