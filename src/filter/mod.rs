mod filter_element;
pub use filter_element::*;

use crate::{Error, InnerError, Record};
use std::ops::{Deref, DerefMut};

/// A filter
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Filter([u8]);

impl Filter {
    // View a slice of bytes as a `Filter`
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Filter {
        unsafe { &*(std::ptr::from_ref::<[u8]>(s.as_ref()) as *const Filter) }
    }

    // View a mutable slice of bytes as a `Filter`
    fn from_inner_mut(inner: &mut [u8]) -> &mut Filter {
        // SAFETY: Filter is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Filter is safe.
        unsafe { &mut *(std::ptr::from_mut::<[u8]>(inner) as *mut Filter) }
    }

    /// Interpret a sequence of bytes as a `Filter`. Checks validity of the length.
    ///
    /// # Errors
    ///
    /// Errors if the input isn't long enough.
    ///
    /// # Safety
    ///
    /// Be sure the input is a valid Filter.
    #[allow(clippy::missing_panics_doc)]
    pub unsafe fn from_bytes(input: &[u8]) -> Result<&Filter, Error> {
        if input.len() < 8 {
            return Err(InnerError::EndOfInput.into());
        }
        let len = u16::from_le_bytes(input[0..2].try_into().unwrap()) as usize;
        if len % 8 != 0 {
            return Err(InnerError::InvalidLength.into());
        }
        if input.len() < len {
            return Err(InnerError::EndOfInput.into());
        }
        Ok(Self::from_inner(&input[0..len]))
    }

    /// Copy to an allocated owned data type
    #[must_use]
    pub fn to_owned(&self) -> OwnedFilter {
        OwnedFilter(self.0.to_owned())
    }

    /// As bytes (including the type and length bytes)
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Iterate over the `FilterElement`s
    #[must_use]
    pub fn elements(&self) -> FilterElementIter<'_> {
        FilterElementIter {
            bytes: self.as_bytes(),
            offset: 8,
        }
    }

    /// Does this filter match a given record?
    ///
    /// # Errors
    ///
    /// Throws an error if Self is `Kinds` and the internal length is wrong.
    /// Throws an error on any unknown `FilterElement`
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::too_many_lines)]
    pub fn matches(&self, record: &Record) -> Result<bool, Error> {
        for element in self.elements() {
            match element.matches(record) {
                Err(e) => {
                    if matches!(e.inner, InnerError::InvalidFilterElementForFunction) {
                        continue;
                    }

                    return Err(e);
                }
                Ok(false) => return Ok(false),
                Ok(true) => {}
            }
        }

        Ok(true)
    }

    /// Is the filter narrow?
    #[must_use]
    pub fn is_narrow(&self) -> bool {
        for element in self.elements() {
            if element.get_type().is_narrow() {
                return true;
            }
        }
        false
    }

    /// Get the `FilterElement` of the given type, if it exists
    #[must_use]
    pub fn get_element(&self, typ: FilterElementType) -> Option<&FilterElement> {
        self.elements().find(|&element| element.get_type() == typ)
    }
}

/// An iterator of the `FilterElement`s of a `Filter`
#[derive(Debug)]
pub struct FilterElementIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for FilterElementIter<'a> {
    type Item = &'a FilterElement;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offset;
        let full_len = self.bytes.len();
        if full_len < offset + 8 {
            None
        } else {
            let fe = unsafe {
                match FilterElement::from_bytes(&self.bytes[offset..]) {
                    Err(_) => return None,
                    Ok(fe) => fe,
                }
            };
            self.offset += fe.as_bytes().len();
            Some(fe)
        }
    }
}

/// An `OwnedFilter`
///
/// See also `Filter` for the borrowed variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedFilter(Vec<u8>);

impl OwnedFilter {
    /// Create a new `OwnedFilter` with the given `FilterElement`s
    ///
    /// # Errors
    ///
    /// Returns an `Err` if any `FilterElement` length is not a multiple of 8.
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(elements: &[&FilterElement]) -> Result<OwnedFilter, Error> {
        let len = 8 + elements.iter().map(|e| e.as_bytes().len()).sum::<usize>();
        let mut buffer = vec![0; len];
        buffer[0..2].copy_from_slice((len as u16).to_be_bytes().as_slice());
        let mut word = 1;
        for element in elements {
            let elen = element.as_bytes().len();
            buffer[word * 8..word * 8 + elen].copy_from_slice(element.as_bytes());
            if elen % 8 != 0 {
                return Err(InnerError::InvalidLength.into());
            }
            word += elen / 8;
        }
        Ok(OwnedFilter(buffer))
    }
}

impl Deref for OwnedFilter {
    type Target = Filter;

    fn deref(&self) -> &Self::Target {
        Filter::from_inner(&self.0)
    }
}

impl DerefMut for OwnedFilter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Filter::from_inner_mut(&mut self.0)
    }
}

impl AsRef<Filter> for OwnedFilter {
    fn as_ref(&self) -> &Filter {
        Filter::from_inner(&self.0)
    }
}

impl AsMut<Filter> for OwnedFilter {
    fn as_mut(&mut self) -> &mut Filter {
        Filter::from_inner_mut(&mut self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Kind, OwnedRecord, RecordFlags, RecordParts, SecretKey, Timestamp};

    #[test]
    fn test_filter() {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;

        let secret_key1 = SecretKey::generate(&mut csprng);
        let key1 = secret_key1.public();
        let secret_key2 = SecretKey::generate(&mut csprng);
        let key2 = secret_key2.public();

        let filter = OwnedFilter::new(&[
            &OwnedFilterElement::new_kinds(&[Kind::MICROBLOG_ROOT, Kind::REPLY_COMMENT]).unwrap(),
            &OwnedFilterElement::new_author_keys(&[key1, key2]).unwrap(),
        ])
        .unwrap();

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

        assert_eq!(filter.matches(&record).unwrap(), true);

        let record = OwnedRecord::new(
            &secret_key1,
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

        assert_eq!(filter.matches(&record).unwrap(), false);
    }
}
