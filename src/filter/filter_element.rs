use crate::{Error, Id, InnerError, Kind, PublicKey, Record, Tag, Timestamp};
use std::ops::{Deref, DerefMut};

/// A type of filter element
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FilterElementType(pub u8);

impl FilterElementType {
    /// Matches all records authored by any of the listed keys
    /// [Author Keys](https://stevefarroll.github.io/mosaic-spec/filter.html#author-keys)
    pub const AUTHOR_KEYS: FilterElementType = FilterElementType(0x1);

    /// Matches all records signed by any of the listed keys
    /// [Signing Keys](https://stevefarroll.github.io/mosaic-spec/filter.html#signing-keys)
    pub const SIGNING_KEYS: FilterElementType = FilterElementType(0x2);

    /// Matches all records whieh are of any one of the listed kinds
    /// [Kinds](https://stevefarroll.github.io/mosaic-spec/filter.html#kinds)
    pub const KINDS: FilterElementType = FilterElementType(0x3);

    /// Matches all records that have any of the listed exact timestamps
    /// [Timestamps](https://stevefarroll.github.io/mosaic-spec/filter.html#timestamps)
    pub const TIMESTAMPS: FilterElementType = FilterElementType(0x4);

    /// Matches all records that contain any of the given tags
    /// [IncludedTags](https://stevefarroll.github.io/mosaic-spec/filter.html#includes-tag)
    pub const INCLUDED_TAGS: FilterElementType = FilterElementType(0x5);

    /// Matches all records with a timestamp greater than or equal to the given value.
    /// [Since](https://stevefarroll.github.io/mosaic-spec/filter.html#since)
    pub const SINCE: FilterElementType = FilterElementType(0x80);

    /// Matches all records with a timestamp less than the given value.
    /// [Until](https://stevefarroll.github.io/mosaic-spec/filter.html#until)
    pub const UNTIL: FilterElementType = FilterElementType(0x81);

    /// Matches all records that were received at or later than given value.
    /// [ReceivedSince](https://stevefarroll.github.io/mosaic-spec/filter.html#received-since)
    pub const RECEIVED_SINCE: FilterElementType = FilterElementType(0x82);

    /// Matches all records that were received before given value.
    /// [ReceivedUntil](https://stevefarroll.github.io/mosaic-spec/filter.html#received-until)
    pub const RECEIVED_UNTIL: FilterElementType = FilterElementType(0x83);

    /// Matches all records that do not have any of the given references
    /// [Exclude](https://stevefarroll.github.io/mosaic-spec/filter.html#exclude)
    pub const EXCLUDE: FilterElementType = FilterElementType(0x84);

    /// Matches all records that do not contain any of the given tags
    /// [ExcludedTags](https://stevefarroll.github.io/mosaic-spec/filter.html#excludes-tag)
    pub const EXCLUDED_TAGS: FilterElementType = FilterElementType(0x85);

    /// Is it narrow?
    #[must_use]
    pub fn is_narrow(&self) -> bool {
        matches!(
            *self,
            Self::AUTHOR_KEYS
                | Self::SIGNING_KEYS
                | Self::KINDS
                | Self::TIMESTAMPS
                | Self::INCLUDED_TAGS
        )
    }
}

impl std::fmt::Display for FilterElementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// An unsized (borrowed) seqeuence of bytes representing a Filter element
///
/// See also `OwnedFilterElement` for the owned variant.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct FilterElement([u8]);

impl FilterElement {
    // View a slice of bytes as a `FilterElement`
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &FilterElement {
        unsafe { &*(std::ptr::from_ref::<[u8]>(s.as_ref()) as *const FilterElement) }
    }

    // View a mutable slice of bytes as a `FilterElement`
    fn from_inner_mut(inner: &mut [u8]) -> &mut FilterElement {
        // SAFETY: FilterElement is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut FilterElement is safe.
        unsafe { &mut *(std::ptr::from_mut::<[u8]>(inner) as *mut FilterElement) }
    }

    fn verify_length(input: &[u8]) -> Result<usize, Error> {
        if input.len() < 8 {
            return Err(InnerError::EndOfInput.into());
        }
        let wordlen = input[1] as usize;
        let len = wordlen * 8;
        if input.len() < len {
            return Err(InnerError::InvalidLength.into());
        }
        Ok(len)
    }

    /// Interpret bytes as a `FilterElement`
    ///
    /// # Errors
    ///
    /// Errors if the input isn't long enough.
    ///
    /// # Safety
    ///
    /// Be sure the input is a valid `FilterElement`. We don't validate the data.
    pub unsafe fn from_bytes(input: &[u8]) -> Result<&FilterElement, Error> {
        let len = Self::verify_length(input)?;
        Ok(Self::from_inner(&input[0..len]))
    }

    /// Copy to an allocated owned data type
    #[must_use]
    pub fn to_owned(&self) -> OwnedFilterElement {
        OwnedFilterElement(self.0.to_owned())
    }

    /// As bytes (including the type and length bytes)
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the type of `FilterElement` this is
    #[must_use]
    pub fn get_type(&self) -> FilterElementType {
        FilterElementType(self.0[0])
    }

    /// Does this filter element match a given record?
    ///
    /// Does not work with `ReceivedSince` or `ReceivedUntil`.
    ///
    /// # Errors
    ///
    /// Throws an error if Self is `ReceivedSince` or `ReceivedUntil`.
    /// Throws an error if Self is `Kinds` and the internal length is wrong.
    /// Throws an error on any unknown `FilterElement`
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::too_many_lines)]
    pub fn matches(&self, record: &Record) -> Result<bool, Error> {
        match self.get_type() {
            FilterElementType::AUTHOR_KEYS => {
                let wordlen = self.0[1] as usize;
                let len = wordlen * 8;
                let pk = record.author_public_key();
                let mut i = 8;
                loop {
                    if i + 32 > len {
                        return Ok(false);
                    }
                    if &self.0[i..i + 32] == pk.as_bytes().as_slice() {
                        return Ok(true);
                    }
                    i += 32;
                }
            }
            FilterElementType::SIGNING_KEYS => {
                let wordlen = self.0[1] as usize;
                let len = wordlen * 8;
                let pk = record.signing_public_key();
                let mut i = 8;
                loop {
                    if i + 32 > len {
                        return Ok(false);
                    }
                    if &self.0[i..i + 32] == pk.as_bytes().as_slice() {
                        return Ok(true);
                    }
                    i += 32;
                }
            }
            FilterElementType::KINDS => {
                let wordlen = self.0[1] as usize;
                let len = wordlen * 8;
                let record_kind = record.kind();
                let count = self.0[7] as usize;
                if len < 8 + count * 2 {
                    return Err(InnerError::InvalidLength.into());
                }
                for n in 0..count {
                    let i = 8 + n * 2;
                    let kind = Kind::from_bytes(self.0[i..i + 2].try_into().unwrap());
                    if record_kind == kind {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            FilterElementType::TIMESTAMPS => {
                let wordlen = self.0[1] as usize;
                let ts_bytes = record.timestamp().to_bytes();
                for w in 0..wordlen - 1 {
                    let i = 8 + w * 8;
                    if &self.0[i..i + 8] == ts_bytes.as_slice() {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            FilterElementType::INCLUDED_TAGS => {
                let wordlen = self.0[1] as usize;
                let len = wordlen * 8;
                let mut i = 8;
                while len > i + 3 {
                    let taglen = self.0[i + 2] as usize;
                    for tag in record.tags() {
                        if tag.as_bytes() == &self.0[i..i + 3 + taglen] {
                            return Ok(true);
                        }
                    }
                    i += 3 + taglen;
                }
                Ok(false)
            }
            FilterElementType::SINCE => {
                let filter_ts = Timestamp::from_bytes(self.0[8..16].try_into().unwrap())?;
                Ok(record.timestamp() >= filter_ts)
            }
            FilterElementType::UNTIL => {
                let filter_ts = Timestamp::from_bytes(self.0[8..16].try_into().unwrap())?;
                Ok(record.timestamp() < filter_ts)
            }
            FilterElementType::RECEIVED_SINCE | FilterElementType::RECEIVED_UNTIL => {
                Err(InnerError::InvalidFilterElementForFunction.into())
            }
            FilterElementType::EXCLUDE => {
                let wordlen = self.0[1] as usize;
                for i in 1..wordlen {
                    if record.id().as_bytes()[..32] == self.0[i * 8..i * 8 + 8] {
                        return Ok(true);
                    }
                    if record.address().as_bytes()[..32] == self.0[i * 8..i * 8 + 8] {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            FilterElementType::EXCLUDED_TAGS => {
                let wordlen = self.0[1] as usize;
                let len = wordlen * 8;
                let mut i = 8;
                while len > i + 3 {
                    let taglen = self.0[i + 2] as usize;
                    for tag in record.tags() {
                        if tag.as_bytes() == &self.0[i..i + 3 + taglen] {
                            return Ok(false);
                        }
                    }
                    i += 3 + taglen;
                }
                Ok(true)
            }
            FilterElementType(u) => Err(InnerError::UnknownFilterElement(u).into()),
        }
    }

    /// Iterate over the keys
    #[must_use]
    pub fn keys(&self) -> Option<FeKeysIter> {
        match self.get_type() {
            FilterElementType::AUTHOR_KEYS | FilterElementType::SIGNING_KEYS => Some(FeKeysIter {
                fe: self,
                offset: 8,
            }),
            _ => None,
        }
    }

    /// Iterate over the `Kind`s
    #[must_use]
    pub fn kinds(&self) -> Option<FeKindsIter> {
        match self.get_type() {
            FilterElementType::KINDS => Some(FeKindsIter {
                fe: self,
                offset: 8,
            }),
            _ => None,
        }
    }

    /// Iterate over the `Timestamp`s
    #[must_use]
    pub fn timestamps(&self) -> Option<FeTimestampsIter> {
        match self.get_type() {
            FilterElementType::TIMESTAMPS => Some(FeTimestampsIter {
                fe: self,
                offset: 8,
            }),
            _ => None,
        }
    }

    /// Iterate over the `Tag`s
    #[must_use]
    pub fn tags(&self) -> Option<FeTagsIter> {
        match self.get_type() {
            FilterElementType::INCLUDED_TAGS | FilterElementType::EXCLUDED_TAGS => {
                Some(FeTagsIter {
                    fe: self,
                    offset: 8,
                })
            }
            _ => None,
        }
    }

    /// Get the since `Timestamp`
    ///
    /// # Errors
    ///
    /// Returns an Err if any Timestamp in the Filter is invalid
    #[allow(clippy::missing_panics_doc)]
    pub fn since(&self) -> Result<Option<Timestamp>, Error> {
        match self.get_type() {
            FilterElementType::SINCE | FilterElementType::RECEIVED_SINCE => Ok(Some(
                Timestamp::from_bytes(self.0[8..16].try_into().unwrap())?,
            )),
            _ => Ok(None),
        }
    }

    /// Get the until `Timestamp`
    ///
    /// # Errors
    ///
    /// Returns an Err if any Timestamp in the Filter is invalid
    #[allow(clippy::missing_panics_doc)]
    pub fn until(&self) -> Result<Option<Timestamp>, Error> {
        match self.get_type() {
            FilterElementType::UNTIL | FilterElementType::RECEIVED_UNTIL => Ok(Some(
                Timestamp::from_bytes(self.0[8..16].try_into().unwrap())?,
            )),
            _ => Ok(None),
        }
    }

    /// Iterate over the `Id`s
    #[must_use]
    pub fn ids(&self) -> Option<FeIdPrefixesIter> {
        match self.get_type() {
            FilterElementType::EXCLUDE => Some(FeIdPrefixesIter {
                fe: self,
                offset: 8,
            }),
            _ => None,
        }
    }
}

/// Iterator over the `Key`s of a `FilterElement::AUTHOR_KEYS` or a
/// `FilterElement::SIGNING_KEYS`
#[derive(Debug)]
pub struct FeKeysIter<'a> {
    fe: &'a FilterElement,
    offset: usize,
}

impl Iterator for FeKeysIter<'_> {
    type Item = PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        let bytelen = self.fe.0.len();
        if bytelen < self.offset + 32 {
            None
        } else {
            let bytes = self.fe.0[self.offset..self.offset + 32].try_into().unwrap();
            match PublicKey::from_bytes(bytes) {
                Ok(pk) => {
                    self.offset += 32;
                    Some(pk)
                }
                Err(_) => None,
            }
        }
    }
}

/// Iterator over the `Kind`s of a `FilterElement::KINDS`
#[derive(Debug)]
pub struct FeKindsIter<'a> {
    fe: &'a FilterElement,
    offset: usize,
}

impl Iterator for FeKindsIter<'_> {
    type Item = Kind;

    fn next(&mut self) -> Option<Self::Item> {
        let numkinds = self.fe.0[7] as usize;
        let bytelen = 8 + numkinds * 2;
        if bytelen < self.offset + 2 {
            None
        } else {
            let bytes = self.fe.0[self.offset..self.offset + 2].try_into().unwrap();
            self.offset += 2;
            Some(Kind::from_bytes(bytes))
        }
    }
}

/// Iterator over the `Timestamp`s of a `FilterElement::TIMESTAMPS`
#[derive(Debug)]
pub struct FeTimestampsIter<'a> {
    fe: &'a FilterElement,
    offset: usize,
}

impl Iterator for FeTimestampsIter<'_> {
    type Item = Timestamp;

    fn next(&mut self) -> Option<Self::Item> {
        let bytelen = self.fe.0.len();
        if bytelen < self.offset + 8 {
            None
        } else {
            let bytes = self.fe.0[self.offset..self.offset + 8].try_into().unwrap();
            match Timestamp::from_bytes(bytes) {
                Ok(ts) => {
                    self.offset += 8;
                    Some(ts)
                }
                Err(_) => None,
            }
        }
    }
}

/// Iterator over the `Tag`s of a `FilterElement::INCLUDED_TAGS` or a
/// `FilterElement::EXCLUDED_TAGS`
#[derive(Debug)]
pub struct FeTagsIter<'a> {
    fe: &'a FilterElement,
    offset: usize,
}

impl<'a> Iterator for FeTagsIter<'a> {
    type Item = &'a Tag;

    fn next(&mut self) -> Option<Self::Item> {
        let bytelen = self.fe.0.len();
        if bytelen < self.offset + 3 {
            None
        } else {
            let datalen = self.fe.0[self.offset + 2] as usize;
            if bytelen < self.offset + 3 + datalen {
                None
            } else {
                match unsafe { Tag::from_bytes(&self.fe.0[self.offset..self.offset + 3 + datalen]) }
                {
                    Ok(tag) => {
                        self.offset += 3 + datalen;
                        Some(tag)
                    }
                    Err(_) => None,
                }
            }
        }
    }
}

/// Iterator over the `Id`s of a `FilterElement::EXCLUDE`
#[derive(Debug)]
pub struct FeIdPrefixesIter<'a> {
    fe: &'a FilterElement,
    offset: usize,
}

impl Iterator for FeIdPrefixesIter<'_> {
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        let bytelen = self.fe.0.len();
        if bytelen < self.offset + 32 {
            None
        } else {
            let bytes = self.fe.0[self.offset..self.offset + 32].try_into().unwrap();
            self.offset += 32;
            Some(bytes)
        }
    }
}

/// A single `OwnedFilterElement`
///
/// See also `FilterElement` for the borrowed variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedFilterElement(Vec<u8>);

impl OwnedFilterElement {
    /// Create an `OwnedFilterElemnet::AuthorKeys`
    ///
    /// # Errors
    ///
    /// Returns an Err if you pass in more than 63 keys.
    pub fn new_author_keys(keys: &[PublicKey]) -> Result<OwnedFilterElement, Error> {
        let numkeys = keys.len();
        let numcells = 1 + numkeys * 4;
        if numcells > 255 {
            return Err(InnerError::TooManyDataElements(63).into());
        }

        let mut bytes: Vec<u8> = vec![0_u8; numcells * 8];
        bytes[0] = FilterElementType::AUTHOR_KEYS.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
        }
        for (i, key) in keys.iter().enumerate() {
            bytes[8 + i * 32..8 + i * 32 + 32].copy_from_slice(key.as_bytes().as_slice());
        }
        Ok(OwnedFilterElement(bytes))
    }

    /// Create an `OwnedFilterElement::SigningKeys`
    ///
    /// # Errors
    ///
    /// Returns an Err if you pass in more than 63 keys.
    pub fn new_signing_keys(keys: &[PublicKey]) -> Result<OwnedFilterElement, Error> {
        let numkeys = keys.len();
        let numcells = 1 + numkeys * 4;
        if numcells > 255 {
            return Err(InnerError::TooManyDataElements(63).into());
        }

        let mut bytes: Vec<u8> = vec![0_u8; numcells * 8];
        bytes[0] = FilterElementType::SIGNING_KEYS.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
        }
        for (i, key) in keys.iter().enumerate() {
            bytes[8 + i * 32..8 + i * 32 + 32].copy_from_slice(key.as_bytes().as_slice());
        }
        Ok(OwnedFilterElement(bytes))
    }

    /// Create an `OwnedFilterElement::Kinds`
    ///
    /// # Errors
    ///
    /// Returns an Err if you pass in more than 255 keys.
    pub fn new_kinds(kinds: &[Kind]) -> Result<OwnedFilterElement, Error> {
        let numkinds = kinds.len();
        if numkinds > 255 {
            return Err(InnerError::TooManyDataElements(255).into());
        }
        let numcells = 1 + padded_len!(numkinds * 2) / 8;

        let mut bytes: Vec<u8> = vec![0_u8; numcells * 8];
        bytes[0] = FilterElementType::KINDS.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
            bytes[7] = numkinds as u8;
        }
        for (i, kind) in kinds.iter().enumerate() {
            bytes[8 + i * 2..8 + i * 2 + 2].copy_from_slice(kind.to_bytes().as_slice());
        }
        Ok(OwnedFilterElement(bytes))
    }

    /// Create an `OwnedFilterElement::Timestamps`
    ///
    /// # Errors
    ///
    /// Returns an Err if you pass in more than 254 timestamps.
    pub fn new_timestamps(timestamps: &[Timestamp]) -> Result<OwnedFilterElement, Error> {
        let numstamps = timestamps.len();
        if numstamps > 254 {
            return Err(InnerError::TooManyDataElements(254).into());
        }
        let numcells = 1 + numstamps;

        let mut bytes: Vec<u8> = vec![0_u8; numcells * 8];
        bytes[0] = FilterElementType::TIMESTAMPS.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
        }
        for (i, stamp) in timestamps.iter().enumerate() {
            bytes[8 + i * 8..8 + i * 8 + 8].copy_from_slice(stamp.to_bytes().as_slice());
        }
        Ok(OwnedFilterElement(bytes))
    }

    /// Create an `OwnedFilterElement::IncludedTags`
    ///
    /// # Errors
    ///
    /// Returns an Err if the sum length of the tags exceeds 254 * 8.
    pub fn new_included_tags<T: AsRef<Tag>>(tags: &[T]) -> Result<OwnedFilterElement, Error> {
        let datalen: usize = tags.iter().map(|t| t.as_ref().as_bytes().len()).sum();
        if datalen > 254 * 8 {
            return Err(InnerError::FilterElementTooLong.into());
        }
        let numcells = 1 + padded_len!(datalen) / 8;

        let mut bytes: Vec<u8> = vec![0_u8; 8 + datalen];
        bytes[0] = FilterElementType::INCLUDED_TAGS.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
        }
        let mut i = 8;
        for t in tags {
            let b = t.as_ref().as_bytes();
            let l = b.len();
            bytes[i..i + l].copy_from_slice(b);
            i += l;
        }
        Ok(OwnedFilterElement(bytes))
    }

    /// Create an `OwnedFilterElement::Since`
    #[must_use]
    pub fn new_since(t: Timestamp) -> OwnedFilterElement {
        let mut bytes: Vec<u8> = vec![0_u8; 16];
        bytes[0] = FilterElementType::SINCE.0;
        bytes[1] = 2;
        bytes[8..16].copy_from_slice(t.to_bytes().as_slice());
        OwnedFilterElement(bytes)
    }

    /// Create an `OwnedFilterElement::Until`
    #[must_use]
    pub fn new_until(t: Timestamp) -> OwnedFilterElement {
        let mut bytes: Vec<u8> = vec![0_u8; 16];
        bytes[0] = FilterElementType::UNTIL.0;
        bytes[1] = 2;
        bytes[8..16].copy_from_slice(t.to_bytes().as_slice());
        OwnedFilterElement(bytes)
    }

    /// Create an `OwnedFilterElement::ReceivedSince`
    #[must_use]
    pub fn new_received_since(t: Timestamp) -> OwnedFilterElement {
        let mut bytes: Vec<u8> = vec![0_u8; 16];
        bytes[0] = FilterElementType::RECEIVED_SINCE.0;
        bytes[1] = 2;
        bytes[8..16].copy_from_slice(t.to_bytes().as_slice());
        OwnedFilterElement(bytes)
    }

    /// Create an `OwnedFilterElement::ReceivedUntil`
    #[must_use]
    pub fn new_received_until(t: Timestamp) -> OwnedFilterElement {
        let mut bytes: Vec<u8> = vec![0_u8; 16];
        bytes[0] = FilterElementType::RECEIVED_UNTIL.0;
        bytes[1] = 2;
        bytes[8..16].copy_from_slice(t.to_bytes().as_slice());
        OwnedFilterElement(bytes)
    }

    /// Create an `OwnedFilterElement::Exclude`
    ///
    /// # Errors
    ///
    /// Returns an Err if more then 63 `Id`s are passed in
    pub fn new_exclude(ids: &[Id]) -> Result<OwnedFilterElement, Error> {
        let num = ids.len();
        let numcells = 1 + num * 4;
        if numcells > 255 {
            return Err(InnerError::TooManyDataElements(63).into());
        }

        let mut bytes: Vec<u8> = vec![0_u8; numcells * 8];
        bytes[0] = FilterElementType::EXCLUDE.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
        }
        for (i, id) in ids.iter().enumerate() {
            bytes[8 + i * 32..8 + i * 32 + 32].copy_from_slice(&id.as_bytes().as_slice()[..32]);
        }
        Ok(OwnedFilterElement(bytes))
    }

    /// Create an `OwnedFilterElement::ExcludedTags`
    ///
    /// # Errors
    ///
    /// Returns an Err if the sum length of the tags exceeds 254 * 8.
    pub fn new_excluded_tags<T: AsRef<Tag>>(tags: &[T]) -> Result<OwnedFilterElement, Error> {
        let datalen: usize = tags.iter().map(|t| t.as_ref().as_bytes().len()).sum();
        if datalen > 254 * 8 {
            return Err(InnerError::FilterElementTooLong.into());
        }
        let numcells = 1 + padded_len!(datalen) / 8;

        let mut bytes: Vec<u8> = vec![0_u8; 8 + datalen];
        bytes[0] = FilterElementType::EXCLUDED_TAGS.0;
        #[allow(clippy::cast_possible_truncation)]
        {
            bytes[1] = numcells as u8;
        }
        let mut i = 8;
        for t in tags {
            let b = t.as_ref().as_bytes();
            let l = b.len();
            bytes[i..i + l].copy_from_slice(b);
            i += l;
        }
        Ok(OwnedFilterElement(bytes))
    }
}

impl Deref for OwnedFilterElement {
    type Target = FilterElement;

    fn deref(&self) -> &Self::Target {
        FilterElement::from_inner(&self.0)
    }
}

impl DerefMut for OwnedFilterElement {
    fn deref_mut(&mut self) -> &mut Self::Target {
        FilterElement::from_inner_mut(&mut self.0)
    }
}

impl AsRef<FilterElement> for OwnedFilterElement {
    fn as_ref(&self) -> &FilterElement {
        FilterElement::from_inner(&self.0)
    }
}

impl AsMut<FilterElement> for OwnedFilterElement {
    fn as_mut(&mut self) -> &mut FilterElement {
        FilterElement::from_inner_mut(&mut self.0)
    }
}

#[cfg(test)]
macro_rules! test_filter_element_type {
    ($new:expr, $typ:expr) => {{
        let value = $new;
        assert_eq!(value.get_type(), $typ);
    }};
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{OwnedRecord, RecordFlags, RecordParts, SecretKey};

    #[test]
    fn test_some_filter_elements() {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;

        let secret_key1 = SecretKey::generate(&mut csprng);
        let key1 = secret_key1.public();
        let secret_key2 = SecretKey::generate(&mut csprng);
        let key2 = secret_key2.public();
        let secret_key3 = SecretKey::generate(&mut csprng);
        // let key3 = secret_key3.public();

        let fe1_ak = OwnedFilterElement::new_author_keys(&[key1, key2]).unwrap();
        test_filter_element_type!(&fe1_ak, FilterElementType::AUTHOR_KEYS);

        let kind1 = Kind::MICROBLOG_ROOT;
        let kind2 = Kind::REPLY_COMMENT;
        let fe2_k = OwnedFilterElement::new_kinds(&[kind1, kind2]).unwrap();
        test_filter_element_type!(&fe2_k, FilterElementType::KINDS);

        let record = OwnedRecord::new(
            &secret_key1,
            &RecordParts {
                kind: Kind::MICROBLOG_ROOT,
                deterministic_key: None,
                timestamp: Timestamp::now().unwrap(),
                flags: RecordFlags::PRINTABLE,
                tags_bytes: b"",
                payload: b"Hello World!",
            },
        )
        .unwrap();
        assert_eq!(fe1_ak.matches(&record).unwrap(), true);
        assert_eq!(fe2_k.matches(&record).unwrap(), true);

        let record = OwnedRecord::new(
            &secret_key3,
            &RecordParts {
                kind: Kind::CHAT_MESSAGE,
                deterministic_key: None,
                timestamp: Timestamp::now().unwrap(),
                flags: RecordFlags::PRINTABLE,
                tags_bytes: b"",
                payload: b"Hello World!",
            },
        )
        .unwrap();
        assert_eq!(fe1_ak.matches(&record).unwrap(), false);
        assert_eq!(fe2_k.matches(&record).unwrap(), false);

        // TBD: This test could be far more complete
    }

    #[test]
    fn test_filter_element_iters() {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        use crate::OwnedTag;

        let secret_key1 = SecretKey::generate(&mut csprng);
        let key1 = secret_key1.public();
        let secret_key2 = SecretKey::generate(&mut csprng);
        let key2 = secret_key2.public();
        let secret_key3 = SecretKey::generate(&mut csprng);
        let key3 = secret_key3.public();

        // author_keys
        let fe = OwnedFilterElement::new_author_keys(&[key1, key2, key3]).unwrap();
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        let mut iter = fe.keys().unwrap();
        assert_eq!(iter.next(), Some(key1));
        assert_eq!(iter.next(), Some(key2));
        assert_eq!(iter.next(), Some(key3));
        assert_eq!(iter.next(), None);

        // signing_keys
        let fe = OwnedFilterElement::new_signing_keys(&[key1, key2, key3]).unwrap();
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        let mut iter = fe.keys().unwrap();
        assert_eq!(iter.next(), Some(key1));
        assert_eq!(iter.next(), Some(key2));
        assert_eq!(iter.next(), Some(key3));
        assert_eq!(iter.next(), None);

        // kinds
        let fe = OwnedFilterElement::new_kinds(&[Kind::KEY_SCHEDULE, Kind::BLOG_POST]).unwrap();
        assert!(fe.keys().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        let mut iter = fe.kinds().unwrap();
        assert_eq!(iter.next(), Some(Kind::KEY_SCHEDULE));
        assert_eq!(iter.next(), Some(Kind::BLOG_POST));
        assert_eq!(iter.next(), None);

        // timestamps
        let ts1 = Timestamp::from_nanoseconds(1_710_000_000_000_000_000).unwrap();
        let ts2 = Timestamp::now().unwrap();
        let fe = OwnedFilterElement::new_timestamps(&[ts1, ts2]).unwrap();
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        let mut iter = fe.timestamps().unwrap();
        assert_eq!(iter.next(), Some(ts1));
        assert_eq!(iter.next(), Some(ts2));
        assert_eq!(iter.next(), None);

        // includes tags
        let t1 = OwnedTag::new_notify_public_key(&key1);
        let t2 = OwnedTag::new_subkey(&key2);
        let fe = OwnedFilterElement::new_included_tags(&[&t1, &t2]).unwrap();
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        let mut iter = fe.tags().unwrap();
        assert_eq!(iter.next(), Some(&*t1));
        assert_eq!(iter.next(), Some(&*t2));
        assert_eq!(iter.next(), None);

        // since
        let ts = Timestamp::now().unwrap();
        let fe = OwnedFilterElement::new_since(ts);
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        assert_eq!(fe.since().unwrap(), Some(ts));

        // until
        let fe = OwnedFilterElement::new_until(ts);
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.ids().is_none());
        assert_eq!(fe.until().unwrap(), Some(ts));

        // Received since
        let fe = OwnedFilterElement::new_received_since(ts);
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        assert_eq!(fe.since().unwrap(), Some(ts));

        // Received until
        let fe = OwnedFilterElement::new_received_until(ts);
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.ids().is_none());
        assert_eq!(fe.until().unwrap(), Some(ts));

        // Exclude
        let id1 = Id::from_parts(&[0_u8; 40], ts1);
        let id2 = Id::from_parts(&[1_u8; 40], ts2);
        let fe = OwnedFilterElement::new_exclude(&[id1, id2]).unwrap();
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.tags().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        let mut iter = fe.ids().unwrap();
        assert_eq!(iter.next(), Some(id1.as_bytes()[..32].try_into().unwrap()));
        assert_eq!(iter.next(), Some(id2.as_bytes()[..32].try_into().unwrap()));
        assert_eq!(iter.next(), None);

        // excludes tags
        let fe = OwnedFilterElement::new_excluded_tags(&[&t1, &t2]).unwrap();
        assert!(fe.keys().is_none());
        assert!(fe.kinds().is_none());
        assert!(fe.timestamps().is_none());
        assert!(fe.since().unwrap().is_none());
        assert!(fe.until().unwrap().is_none());
        assert!(fe.ids().is_none());
        let mut iter = fe.tags().unwrap();
        assert_eq!(iter.next(), Some(&*t1));
        assert_eq!(iter.next(), Some(&*t2));
        assert_eq!(iter.next(), None);
    }
}
