/// A 2-byte `QueryId` used in `Message`s
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryId([u8; 2]);

impl QueryId {
    /// Create a `QueryId` from bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> QueryId {
        QueryId(bytes)
    }

    /// Get at the inner bytes
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 2] {
        self.0
    }
}
