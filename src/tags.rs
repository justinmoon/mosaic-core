use crate::{Error, Kind, PublicKey, Reference};

/// A type of tag
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TagType(pub u16);

impl TagType {
    /// [Notify Public Key](https://stevefarroll.github.io/mosaic-spec/core_tags/#notify-public-key)
    pub const NOTIFY_PUBLIC_KEY: TagType = TagType(0x1);

    /// [Reply](https://stevefarroll.github.io/mosaic-spec/core_tags/#reply)
    pub const REPLY: TagType = TagType(0x2);

    /// [Root](https://stevefarroll.github.io/mosaic-spec/core_tags/#root)
    pub const ROOT: TagType = TagType(0x3);

    /// [Nostr Sister Event](https://stevefarroll.github.io/mosaic-spec/core_tags/#nostr-sister-event)
    pub const NOSTR_SISTER: TagType = TagType(0x8);

    /// [Subkey](https://stevefarroll.github.io/mosaic-spec/core_tags/#subkey)
    pub const SUBKEY: TagType = TagType(0x10);

    /// [Content Segment: User Mention](https://stevefarroll.github.io/mosaic-spec/core_tags/#content-segment-user-mention)
    pub const CONTENT_SEGMENT_USER_MENTION: TagType = TagType(0x20);

    /// [Content Segment: Server Mention](https://stevefarroll.github.io/mosaic-spec/core_tags/#content-segment-server-mention)
    pub const CONTENT_SEGMENT_SERVER_MENTION: TagType = TagType(0x21);

    /// [Content Segment: Quote](https://stevefarroll.github.io/mosaic-spec/core_tags/#content-segment-quote)
    pub const CONTENT_SEGMENT_QUOTE: TagType = TagType(0x22);

    /// [Content Segment: Url](https://stevefarroll.github.io/mosaic-spec/core_tags/#content-segment-url)
    pub const CONTENT_SEGMENT_URL: TagType = TagType(0x24);

    /// [Content Segment: Image](https://stevefarroll.github.io/mosaic-spec/core_tags/#content-segment-image)
    pub const CONTENT_SEGMENT_IMAGE: TagType = TagType(0x25);

    /// [Content Segment: Video](https://stevefarroll.github.io/mosaic-spec/core_tags/#content-segment-video)
    pub const CONTENT_SEGMENT_VIDEO: TagType = TagType(0x26);
}

impl std::fmt::Display for TagType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single Tag
#[derive(Debug, Clone)]
pub struct Tag(Vec<u8>);

impl Tag {
    /// Create a new `NOTIFY_PUBLIC_KEY` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_notify_public_key(public_key: &PublicKey) -> Tag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(TagType::NOTIFY_PUBLIC_KEY.0.to_le_bytes().as_slice());
        bytes[2] = LEN as u8;
        bytes[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `REPLY` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_reply(refer: &Reference, kind: Kind) -> Tag {
        const LEN: usize = 56;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(TagType::REPLY.0.to_le_bytes().as_slice());
        bytes[2] = LEN as u8;
        bytes[6..8].copy_from_slice(kind.0.to_le_bytes().as_slice());
        bytes[8..LEN].copy_from_slice(refer.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `ROOT` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_root(refer: &Reference, kind: Kind) -> Tag {
        const LEN: usize = 56;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(TagType::ROOT.0.to_le_bytes().as_slice());
        bytes[2] = LEN as u8;
        bytes[6..8].copy_from_slice(kind.0.to_le_bytes().as_slice());
        bytes[8..LEN].copy_from_slice(refer.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `NOSTR_SISTER` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_nostr_sister(id: &[u8; 32]) -> Tag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(TagType::NOSTR_SISTER.0.to_le_bytes().as_slice());
        bytes[2] = LEN as u8;
        bytes[8..LEN].copy_from_slice(id.as_slice());
        Tag(bytes)
    }

    /// Create a new `SUBKEY` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_subkey(public_key: &PublicKey) -> Tag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(TagType::SUBKEY.0.to_le_bytes().as_slice());
        bytes[2] = LEN as u8;
        bytes[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_USER_MENTION` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_content_segment_user_mention(public_key: &PublicKey, offset: u32) -> Tag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(
            TagType::CONTENT_SEGMENT_USER_MENTION
                .0
                .to_le_bytes()
                .as_slice(),
        );
        bytes[2] = LEN as u8;
        bytes[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        bytes[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_SERVER_MENTION` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_content_segment_server_mention(public_key: &PublicKey, offset: u32) -> Tag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(
            TagType::CONTENT_SEGMENT_SERVER_MENTION
                .0
                .to_le_bytes()
                .as_slice(),
        );
        bytes[2] = LEN as u8;
        bytes[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        bytes[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_QUOTE` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_content_segment_quote(refer: &Reference, kind: Kind, offset: u32) -> Tag {
        const LEN: usize = 64;
        let mut bytes: Vec<u8> = vec![0; LEN];
        bytes[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_QUOTE.0.to_le_bytes().as_slice());
        bytes[2] = LEN as u8;
        bytes[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        bytes[14..16].copy_from_slice(kind.0.to_le_bytes().as_slice());
        bytes[16..LEN].copy_from_slice(refer.as_bytes().as_slice());
        Tag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_URL` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_content_segment_url(url: &str, offset: u32) -> Tag {
        let len: usize = 8 + url.len();
        let mut bytes: Vec<u8> = vec![0; len];
        bytes[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_URL.0.to_le_bytes().as_slice());
        bytes[2] = len as u8;
        bytes[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        bytes[8..len].copy_from_slice(url.as_bytes());
        Tag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_IMAGE` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_content_segment_image(url: &str, offset: u32) -> Tag {
        let len: usize = 8 + url.len();
        let mut bytes: Vec<u8> = vec![0; len];
        bytes[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_IMAGE.0.to_le_bytes().as_slice());
        bytes[2] = len as u8;
        bytes[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        bytes[8..len].copy_from_slice(url.as_bytes());
        Tag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_VIDEO` tag
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new_content_segment_video(url: &str, offset: u32) -> Tag {
        let len: usize = 8 + url.len();
        let mut bytes: Vec<u8> = vec![0; len];
        bytes[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_VIDEO.0.to_le_bytes().as_slice());
        bytes[2] = len as u8;
        bytes[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        bytes[8..len].copy_from_slice(url.as_bytes());
        Tag(bytes)
    }

    /// Get the type of tag this is
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn get_type(&self) -> TagType {
        TagType(u16::from_le_bytes(self.0[0..2].try_into().unwrap()))
    }

    /// Get the public key (for types that have one)
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the tag public key section is invalid
    #[allow(clippy::missing_panics_doc)]
    pub fn get_public_key(&self) -> Result<Option<PublicKey>, Error> {
        match self.get_type() {
            TagType::NOTIFY_PUBLIC_KEY
            | TagType::SUBKEY
            | TagType::CONTENT_SEGMENT_USER_MENTION
            | TagType::CONTENT_SEGMENT_SERVER_MENTION => Ok(Some(PublicKey::from_bytes(
                &self.0[8..40].try_into().unwrap(),
            )?)),
            _ => Ok(None),
        }
    }

    /// Get the reference (for types that have one)
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the tag reference section is invalid
    #[allow(clippy::missing_panics_doc)]
    pub fn get_reference(&self) -> Result<Option<Reference>, Error> {
        match self.get_type() {
            TagType::REPLY | TagType::ROOT => Ok(Some(Reference::from_bytes(
                self.0[8..56].try_into().unwrap(),
            )?)),
            TagType::CONTENT_SEGMENT_QUOTE => Ok(Some(Reference::from_bytes(
                self.0[16..64].try_into().unwrap(),
            )?)),
            _ => Ok(None),
        }
    }

    /// Get the nostr sister id (for `NOSTR_SISTER` tag only)
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn get_nostr_sister_id(&self) -> Option<[u8; 32]> {
        match self.get_type() {
            TagType::NOSTR_SISTER => Some(self.0[8..40].try_into().unwrap()),
            _ => None,
        }
    }

    /// Get the URL (for types that have one)
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the tag URL section is not UTF-8
    pub fn get_url(&self) -> Result<Option<&str>, Error> {
        match self.get_type() {
            TagType::CONTENT_SEGMENT_URL
            | TagType::CONTENT_SEGMENT_IMAGE
            | TagType::CONTENT_SEGMENT_VIDEO => Ok(Some(std::str::from_utf8(&self.0[8..])?)),
            _ => Ok(None),
        }
    }

    /// Get kind (for types that have one)
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn get_kind(&self) -> Option<Kind> {
        match self.get_type() {
            TagType::REPLY | TagType::ROOT => {
                Some(Kind(u16::from_le_bytes(self.0[6..8].try_into().unwrap())))
            }
            TagType::CONTENT_SEGMENT_QUOTE => {
                Some(Kind(u16::from_le_bytes(self.0[14..16].try_into().unwrap())))
            }
            _ => None,
        }
    }

    /// Get offset (for content segment tags)
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn get_offset(&self) -> Option<u32> {
        match self.get_type() {
            TagType::CONTENT_SEGMENT_USER_MENTION
            | TagType::CONTENT_SEGMENT_SERVER_MENTION
            | TagType::CONTENT_SEGMENT_QUOTE
            | TagType::CONTENT_SEGMENT_URL
            | TagType::CONTENT_SEGMENT_IMAGE
            | TagType::CONTENT_SEGMENT_VIDEO => {
                Some(u32::from_le_bytes(self.0[4..8].try_into().unwrap()))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
macro_rules! test_tag_type {
    ($new:expr, $typ:expr) => {{
        let value = $new;
        assert_eq!(value.get_type(), $typ);
        value
    }};
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keys::*;

    #[test]
    fn test_tags() {
        // Setup sample data
        let public_key = {
            use rand::rngs::OsRng;
            let mut csprng = OsRng;
            let secret_key = SecretKey::generate(&mut csprng);
            secret_key.public()
        };
        let reference = {
            let printable = "AZO3sZiMAAApuH6dfAj9DHnCUgw0OIBW/tfZFR+CRgp2mJ6QeJiS7JKMU6/N4onu";
            Reference::from_printable(printable).unwrap()
        };
        let url = "https://example.com/meme.jpg";
        let offset = 71;
        let id: [u8; 32] = [7; 32];
        let kind = Kind(1234);

        let v = test_tag_type!(
            Tag::new_notify_public_key(&public_key),
            TagType::NOTIFY_PUBLIC_KEY
        );
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);

        let v = test_tag_type!(Tag::new_reply(&reference, kind), TagType::REPLY);
        assert_eq!(v.get_reference().unwrap().unwrap(), reference);
        assert_eq!(v.get_kind().unwrap(), kind);

        let v = test_tag_type!(Tag::new_root(&reference, kind), TagType::ROOT);
        assert_eq!(v.get_reference().unwrap().unwrap(), reference);
        assert_eq!(v.get_kind().unwrap(), kind);

        let v = test_tag_type!(Tag::new_nostr_sister(&id), TagType::NOSTR_SISTER);
        assert_eq!(v.get_nostr_sister_id().unwrap(), id);

        let v = test_tag_type!(Tag::new_subkey(&public_key), TagType::SUBKEY);
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);

        let v = test_tag_type!(
            Tag::new_content_segment_user_mention(&public_key, offset),
            TagType::CONTENT_SEGMENT_USER_MENTION
        );
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            Tag::new_content_segment_server_mention(&public_key, offset),
            TagType::CONTENT_SEGMENT_SERVER_MENTION
        );
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            Tag::new_content_segment_quote(&reference, kind, offset),
            TagType::CONTENT_SEGMENT_QUOTE
        );
        assert_eq!(v.get_reference().unwrap().unwrap(), reference);
        assert_eq!(v.get_kind().unwrap(), kind);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            Tag::new_content_segment_url(&url, offset),
            TagType::CONTENT_SEGMENT_URL
        );
        assert_eq!(v.get_url().unwrap().unwrap(), url);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            Tag::new_content_segment_image(&url, offset),
            TagType::CONTENT_SEGMENT_IMAGE
        );
        assert_eq!(v.get_url().unwrap().unwrap(), url);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            Tag::new_content_segment_video(&url, offset),
            TagType::CONTENT_SEGMENT_VIDEO
        );
        assert_eq!(v.get_url().unwrap().unwrap(), url);
        assert_eq!(v.get_offset().unwrap(), offset);
    }
}
