use crate::{Error, InnerError, Kind, PublicKey, Reference};
use std::ops::{Deref, DerefMut};

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

impl TagType {
    fn into_u16(self) -> u16 {
        self.0
    }
}

/// A single `Tag`, unsized (borrowed)
///
/// See also `OwnedTag` for the owned variant.
//    0..2  Type
//    2..3  Length
//    3..   Value
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Tag([u8]);

impl Tag {
    // View a slice of bytes as a tag
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Tag {
        unsafe { &*(std::ptr::from_ref::<[u8]>(s.as_ref()) as *const Tag) }
    }

    // View a mutable slice of bytes as a tag
    fn from_inner_mut(inner: &mut [u8]) -> &mut Tag {
        // SAFETY: Tag is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Tag is safe.
        unsafe { &mut *(std::ptr::from_mut::<[u8]>(inner) as *mut Tag) }
    }

    /// Interpret a sequence of bytes as a `Tag`. Checks validity of the length.
    ///
    /// # Errors
    ///
    /// Errors if the input isn't long enough.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_bytes(input: &[u8]) -> Result<&Tag, Error> {
        if input.len() < 3 {
            return Err(InnerError::EndOfInput.into());
        }
        if input[0] == 0 && input[1] == 0 {
            return Err(InnerError::Padding.into());
        }
        let datalen = input[2] as usize;
        if datalen > 253 {
            return Err(InnerError::InvalidTag.into());
        }
        if input.len() < 3 + datalen {
            return Err(InnerError::EndOfInput.into());
        }
        Ok(Self::from_inner(&input[0..3 + datalen]))
    }

    /// Copy to an allocated owned data type
    #[must_use]
    pub fn to_owned(&self) -> OwnedTag {
        OwnedTag(self.0.to_owned())
    }

    /// As bytes (including the type and length bytes)
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// As data bytes
    #[must_use]
    pub fn data_bytes(&self) -> &[u8] {
        &self.0[3..]
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
            TagType::REPLY | TagType::ROOT | TagType::CONTENT_SEGMENT_QUOTE => Ok(Some(
                Reference::from_bytes(self.0[16..64].try_into().unwrap())?,
            )),
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
            TagType::REPLY | TagType::ROOT | TagType::CONTENT_SEGMENT_QUOTE => {
                Some(Kind::from_bytes(self.0[8..16].try_into().unwrap()))
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

    /// Write a new `NOTIFY_PUBLIC_KEY` tag to the buffer
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_notify_public_key<'a>(
        buffer: &'a mut [u8],
        public_key: &PublicKey,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 40;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::NOTIFY_PUBLIC_KEY.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Write a new `REPLY` tag to the buffer
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_reply<'a>(
        buffer: &'a mut [u8],
        refer: &Reference,
        kind: Kind,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 64;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::REPLY.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[3..8].fill(0);
        buffer[8..16].copy_from_slice(kind.to_bytes().as_slice());
        buffer[16..LEN].copy_from_slice(refer.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `ROOT` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_root<'a>(
        buffer: &'a mut [u8],
        refer: &Reference,
        kind: Kind,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 64;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::ROOT.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[3..8].fill(0);
        buffer[8..16].copy_from_slice(kind.to_bytes().as_slice());
        buffer[16..LEN].copy_from_slice(refer.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `NOSTR_SISTER` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_nostr_sister<'a>(buffer: &'a mut [u8], id: &[u8; 32]) -> Result<&'a Tag, Error> {
        const LEN: usize = 40;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::NOSTR_SISTER.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[8..LEN].copy_from_slice(id.as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `SUBKEY` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_subkey<'a>(
        buffer: &'a mut [u8],
        public_key: &PublicKey,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 40;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::SUBKEY.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `CONTENT_SEGMENT_USER_MENTION` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_content_segment_user_mention<'a>(
        buffer: &'a mut [u8],
        public_key: &PublicKey,
        offset: u32,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 40;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(
            TagType::CONTENT_SEGMENT_USER_MENTION
                .0
                .to_le_bytes()
                .as_slice(),
        );
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        buffer[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `CONTENT_SEGMENT_SERVER_MENTION` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_content_segment_server_mention<'a>(
        buffer: &'a mut [u8],
        public_key: &PublicKey,
        offset: u32,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 40;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(
            TagType::CONTENT_SEGMENT_SERVER_MENTION
                .0
                .to_le_bytes()
                .as_slice(),
        );
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        buffer[8..LEN].copy_from_slice(public_key.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `CONTENT_SEGMENT_QUOTE` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_content_segment_quote<'a>(
        buffer: &'a mut [u8],
        refer: &Reference,
        kind: Kind,
        offset: u32,
    ) -> Result<&'a Tag, Error> {
        const LEN: usize = 64;
        if buffer.len() < LEN {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_QUOTE.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (LEN - 3) as u8;
        }
        buffer[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        buffer[8..16].copy_from_slice(kind.to_bytes().as_slice());
        buffer[16..LEN].copy_from_slice(refer.as_bytes().as_slice());
        Ok(Tag::from_inner(&buffer[..LEN]))
    }

    /// Create a new `CONTENT_SEGMENT_URL` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_content_segment_url<'a>(
        buffer: &'a mut [u8],
        url: &str,
        offset: u32,
    ) -> Result<&'a Tag, Error> {
        let len: usize = 8 + url.len();
        if buffer.len() < len {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_URL.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (len - 3) as u8;
        }
        buffer[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        buffer[8..len].copy_from_slice(url.as_bytes());
        Ok(Tag::from_inner(&buffer[..len]))
    }

    /// Create a new `CONTENT_SEGMENT_IMAGE` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_content_segment_image<'a>(
        buffer: &'a mut [u8],
        url: &str,
        offset: u32,
    ) -> Result<&'a Tag, Error> {
        let len: usize = 8 + url.len();
        if buffer.len() < len {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_IMAGE.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (len - 3) as u8;
        }
        buffer[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        buffer[8..len].copy_from_slice(url.as_bytes());
        Ok(Tag::from_inner(&buffer[..len]))
    }

    /// Create a new `CONTENT_SEGMENT_VIDEO` tag
    ///
    /// # Errors
    ///
    /// Errors if the buffer isn't long enough.
    pub fn write_content_segment_video<'a>(
        buffer: &'a mut [u8],
        url: &str,
        offset: u32,
    ) -> Result<&'a Tag, Error> {
        let len: usize = 8 + url.len();
        if buffer.len() < len {
            return Err(InnerError::EndOfOutput.into());
        }
        buffer[0..2].copy_from_slice(TagType::CONTENT_SEGMENT_VIDEO.0.to_le_bytes().as_slice());
        #[allow(clippy::cast_possible_truncation)]
        {
            buffer[2] = (len - 3) as u8;
        }
        buffer[4..8].copy_from_slice(offset.to_le_bytes().as_slice());
        buffer[8..len].copy_from_slice(url.as_bytes());
        Ok(Tag::from_inner(&buffer[..len]))
    }
}

/// A single `OwnedTag`
///
/// See also `Tag` for the borrowed variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedTag(Vec<u8>);

impl OwnedTag {
    /// Create a new `OwnedTag` with given type and value.
    ///
    /// # Errors
    ///
    /// Errors if the value is too long (max is 253 bytes)
    #[allow(clippy::missing_panics_doc)]
    pub fn new<T: AsRef<[u8]>>(ty: TagType, value: &T) -> Result<OwnedTag, Error> {
        let datalen = value.as_ref().len();
        if datalen > 253 {
            return Err(InnerError::TagTooLong.into());
        }
        let mut buffer = vec![0; 3 + datalen];
        buffer[0..2].copy_from_slice(ty.into_u16().to_be_bytes().as_slice());
        buffer[2] = u8::try_from(datalen).unwrap();
        buffer[3..].copy_from_slice(value.as_ref());
        Ok(OwnedTag(buffer))
    }

    /// Create a new `NOTIFY_PUBLIC_KEY` tag
    ///
    /// To avoid copies, consider `Tag::write_notify_public_key()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_notify_public_key(public_key: &PublicKey) -> OwnedTag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_notify_public_key(&mut bytes, public_key).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `REPLY` tag
    ///
    /// To avoid copies, consider `Tag::write_reply()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_reply(refer: &Reference, kind: Kind) -> OwnedTag {
        const LEN: usize = 64;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_reply(&mut bytes, refer, kind).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `ROOT` tag
    //
    /// To avoid copies, consider `Tag::write_root()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_root(refer: &Reference, kind: Kind) -> OwnedTag {
        const LEN: usize = 64;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_root(&mut bytes, refer, kind).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `NOSTR_SISTER` tag
    ///
    /// To avoid copies, consider `Tag::write_nostr_sister()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_nostr_sister(id: &[u8; 32]) -> OwnedTag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_nostr_sister(&mut bytes, id).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `SUBKEY` tag
    ///
    /// To avoid copies, consider `Tag::write_subkey()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_subkey(public_key: &PublicKey) -> OwnedTag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_subkey(&mut bytes, public_key).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_USER_MENTION` tag
    ///
    /// To avoid copies, consider `Tag::write_content_segment_user_mention()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_content_segment_user_mention(public_key: &PublicKey, offset: u32) -> OwnedTag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_content_segment_user_mention(&mut bytes, public_key, offset).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_SERVER_MENTION` tag
    ///
    /// To avoid copies, consider `Tag::write_content_segment_server_mention()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_content_segment_server_mention(public_key: &PublicKey, offset: u32) -> OwnedTag {
        const LEN: usize = 40;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_content_segment_server_mention(&mut bytes, public_key, offset).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_QUOTE` tag
    ///
    /// To avoid copies, consider `Tag::write_content_segment_quote()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_content_segment_quote(refer: &Reference, kind: Kind, offset: u32) -> OwnedTag {
        const LEN: usize = 64;
        let mut bytes: Vec<u8> = vec![0; LEN];
        let _ = Tag::write_content_segment_quote(&mut bytes, refer, kind, offset).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_URL` tag
    ///
    /// To avoid copies, consider `Tag::write_content_segment_url()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_content_segment_url(url: &str, offset: u32) -> OwnedTag {
        let len: usize = 8 + url.len();
        let mut bytes: Vec<u8> = vec![0; len];
        let _ = Tag::write_content_segment_url(&mut bytes, url, offset).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_IMAGE` tag
    ///
    /// To avoid copies, consider `Tag::write_content_segment_image()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_content_segment_image(url: &str, offset: u32) -> OwnedTag {
        let len: usize = 8 + url.len();
        let mut bytes: Vec<u8> = vec![0; len];
        let _ = Tag::write_content_segment_image(&mut bytes, url, offset).unwrap();
        OwnedTag(bytes)
    }

    /// Create a new `CONTENT_SEGMENT_VIDEO` tag
    ///
    /// To avoid copies, consider `Tag::write_content_segment_video()`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_content_segment_video(url: &str, offset: u32) -> OwnedTag {
        let len: usize = 8 + url.len();
        let mut bytes: Vec<u8> = vec![0; len];
        let _ = Tag::write_content_segment_video(&mut bytes, url, offset).unwrap();
        OwnedTag(bytes)
    }
}

impl Deref for OwnedTag {
    type Target = Tag;

    fn deref(&self) -> &Self::Target {
        Tag::from_inner(&self.0)
    }
}

impl DerefMut for OwnedTag {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Tag::from_inner_mut(&mut self.0)
    }
}

impl AsRef<Tag> for OwnedTag {
    fn as_ref(&self) -> &Tag {
        Tag::from_inner(&self.0)
    }
}

impl AsMut<Tag> for OwnedTag {
    fn as_mut(&mut self) -> &mut Tag {
        Tag::from_inner_mut(&mut self.0)
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
            let printable = "moref01ge91q91o36bcfrk7qfhpnydyyobh88zknproi8j5791e5mekfez1ye6zrifbhh6m1dtizcsp4y5w";
            Reference::from_printable(printable).unwrap()
        };
        let url = "https://example.com/meme.jpg";
        let offset = 71;
        let id: [u8; 32] = [7; 32];
        let kind = Kind::from_bytes([0, 0, 0, 0, 99, 0, 1, 3]);

        let v = test_tag_type!(
            OwnedTag::new_notify_public_key(&public_key),
            TagType::NOTIFY_PUBLIC_KEY
        );
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);

        let v = test_tag_type!(OwnedTag::new_reply(&reference, kind), TagType::REPLY);
        assert_eq!(v.get_reference().unwrap().unwrap(), reference);
        assert_eq!(v.get_kind().unwrap(), kind);

        let v = test_tag_type!(OwnedTag::new_root(&reference, kind), TagType::ROOT);
        assert_eq!(v.get_reference().unwrap().unwrap(), reference);
        assert_eq!(v.get_kind().unwrap(), kind);

        let v = test_tag_type!(OwnedTag::new_nostr_sister(&id), TagType::NOSTR_SISTER);
        assert_eq!(v.get_nostr_sister_id().unwrap(), id);

        let v = test_tag_type!(OwnedTag::new_subkey(&public_key), TagType::SUBKEY);
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);

        let v = test_tag_type!(
            OwnedTag::new_content_segment_user_mention(&public_key, offset),
            TagType::CONTENT_SEGMENT_USER_MENTION
        );
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            OwnedTag::new_content_segment_server_mention(&public_key, offset),
            TagType::CONTENT_SEGMENT_SERVER_MENTION
        );
        assert_eq!(v.get_public_key().unwrap().unwrap(), public_key);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            OwnedTag::new_content_segment_quote(&reference, kind, offset),
            TagType::CONTENT_SEGMENT_QUOTE
        );
        assert_eq!(v.get_reference().unwrap().unwrap(), reference);
        assert_eq!(v.get_kind().unwrap(), kind);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            OwnedTag::new_content_segment_url(&url, offset),
            TagType::CONTENT_SEGMENT_URL
        );
        assert_eq!(v.get_url().unwrap().unwrap(), url);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            OwnedTag::new_content_segment_image(&url, offset),
            TagType::CONTENT_SEGMENT_IMAGE
        );
        assert_eq!(v.get_url().unwrap().unwrap(), url);
        assert_eq!(v.get_offset().unwrap(), offset);

        let v = test_tag_type!(
            OwnedTag::new_content_segment_video(&url, offset),
            TagType::CONTENT_SEGMENT_VIDEO
        );
        assert_eq!(v.get_url().unwrap().unwrap(), url);
        assert_eq!(v.get_offset().unwrap(), offset);
    }
}
