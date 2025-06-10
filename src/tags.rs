use crate::{Error, InnerError, Tag};
use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};

/// A sequence of `Tag`s, borrowed
///
/// See also `OwnedTags` for the owned variant.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Tags([u8]);

impl Tags {
    // View a slice of bytes as a Tags
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Tags {
        unsafe { &*(std::ptr::from_ref::<[u8]>(s.as_ref()) as *const Tags) }
    }

    // View a mutable slice of bytes as a Tags
    fn from_inner_mut(inner: &mut [u8]) -> &mut Tags {
        // SAFETY: Tags is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Tags is safe.
        unsafe { &mut *(std::ptr::from_mut::<[u8]>(inner) as *mut Tags) }
    }

    /// Interpret a sequence of bytes as a `Tags`.
    ///
    /// # Errors
    ///
    /// Returns an Err if the data is not valid.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_bytes(input: &[u8]) -> Result<&Tags, Error> {
        if input.len() < 3 {
            return Err(InnerError::EndOfInput.into());
        }
        let mut p = 0;
        loop {
            let tag = unsafe { Tag::from_bytes(&input[p..])? };
            let len = tag.as_bytes().len();
            match (p + len).cmp(&input.len()) {
                Ordering::Greater => return Err(InnerError::EndOfInput.into()),
                Ordering::Equal => return Ok(Self::from_inner(input)),
                Ordering::Less => (),
            }
            p += len;
        }
    }

    pub(crate) fn from_bytes_unchecked(input: &[u8]) -> &Tags {
        Self::from_inner(input)
    }

    /// Copy to an allocated owned data type
    #[must_use]
    pub fn to_owned(&self) -> OwnedTags {
        OwnedTags(self.0.to_owned())
    }

    /// As bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Iterator over tags
    #[must_use]
    pub fn iter(&self) -> TagsIter<'_> {
        TagsIter {
            bytes: &self.0,
            p: 0,
        }
    }
}

impl<'a> IntoIterator for &'a Tags {
    type Item = &'a Tag;
    type IntoIter = TagsIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator of `Tag`s in `Tags`
#[derive(Debug)]
pub struct TagsIter<'a> {
    bytes: &'a [u8],
    p: usize,
}

impl<'a> Iterator for TagsIter<'a> {
    type Item = &'a Tag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.p >= self.bytes.len() {
            None
        } else {
            let tag = unsafe { Tag::from_bytes(&self.bytes[self.p..]).unwrap() };
            self.p += tag.as_bytes().len();
            Some(tag)
        }
    }
}

/// An owned set of `Tag`s
///
/// See `Tags` for the borrowed variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedTags(Vec<u8>);

/// Empty Tags
pub const EMPTY_TAGS: OwnedTags = OwnedTags(vec![]);

impl OwnedTags {
    /// Create a new set of tags
    #[must_use]
    pub fn new() -> OwnedTags {
        OwnedTags(Vec::new())
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: &Tag) {
        self.0.extend(tag.as_bytes());
    }
}

impl Default for OwnedTags {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for OwnedTags {
    type Target = Tags;

    fn deref(&self) -> &Self::Target {
        Tags::from_inner(&self.0)
    }
}

impl DerefMut for OwnedTags {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Tags::from_inner_mut(&mut self.0)
    }
}

impl AsRef<Tags> for OwnedTags {
    fn as_ref(&self) -> &Tags {
        Tags::from_inner(&self.0)
    }
}

impl AsMut<Tags> for OwnedTags {
    fn as_mut(&mut self) -> &mut Tags {
        Tags::from_inner_mut(&mut self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tags() {
        use crate::{Kind, OwnedTag, Reference, SecretKey};

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
        let kind = Kind(1234);
        let offset = 71;

        let mut tags = OwnedTags::new();
        let t1 = OwnedTag::new_notify_public_key(&public_key);
        tags.add_tag(&t1);
        let t2 = OwnedTag::new_reply(&reference, kind);
        tags.add_tag(&t2);
        let t3 = OwnedTag::new_content_segment_image(&url, offset);
        tags.add_tag(&t3);

        let mut iter = tags.iter();
        assert_eq!(iter.next(), Some(&*t1));
        assert_eq!(iter.next(), Some(&*t2));
        assert_eq!(iter.next(), Some(&*t3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_tags_iterator() {
        use crate::TagType;

        let example: Vec<u8> = vec![
            1, 0, // type 1,
            4, // data length
            10, 9, 8, 7, // data
            2, 0, // type 2
            6, // data length
            1, 2, 3, 4, 5, 6, // data
            3, 1, // type
            3, // data length
            3, 4, 5, // data
        ];

        let tags = Tags::from_bytes(&*example).unwrap();
        let mut iter = tags.iter();

        let tag0 = iter.next().unwrap();
        let tag1 = iter.next().unwrap();
        let tag2 = iter.next().unwrap();
        assert_eq!(iter.next(), None);

        assert_eq!(tag0.data_bytes(), &[10, 9, 8, 7]);
        assert_eq!(tag0.get_type(), TagType(1));
        assert_eq!(tag1.data_bytes(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(tag1.get_type(), TagType(2));
        assert_eq!(tag2.data_bytes(), &[3, 4, 5]);
        assert_eq!(tag2.get_type(), TagType(259));
    }
}
