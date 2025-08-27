use crate::{Error, InnerError};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A URL to a Mosaic server
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Url(String);

impl Url {
    /// Create from an `http::Uri` structure
    ///
    /// Silently discards any path and query in the input
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the URL is malformed, or if the scheme is not a mosaic
    /// scheme.
    pub fn from_http_uri(uri: http::Uri) -> Result<Url, Error> {
        let mut parts = uri.into_parts();
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
        if let Some(ref s) = parts.scheme {
            if s.as_str() != "wss" && s.as_str() != "https" {
                return Err(InnerError::BadScheme(s.as_str().to_owned()).into());
            }
        } else {
            return Err(InnerError::MissingScheme.into());
        }
        let uri = http::Uri::from_parts(parts)?;

        let s: String = format!("{uri}");
        Ok(Url(s))
    }
}

impl std::str::FromStr for Url {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri: http::Uri = s.parse()?;
        Self::from_http_uri(uri)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
