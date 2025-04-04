use crate::{Error, InnerError};
use http::uri::PathAndQuery;
use http::Uri;

const PATH_AND_QUERY: &str = "/";

pub(crate) fn clean_uri(uri: Uri) -> Result<Uri, Error> {
    let mut parts = uri.into_parts();
    parts.path_and_query = Some(PathAndQuery::from_static(PATH_AND_QUERY));
    if let Some(ref s) = parts.scheme {
        if s.as_str() != "wss" && s.as_str() != "https" {
            return Err(InnerError::BadScheme(s.as_str().to_owned()).into());
        }
    } else {
        return Err(InnerError::MissingScheme.into());
    }
    let uri = Uri::from_parts(parts)?;
    Ok(uri)
}
