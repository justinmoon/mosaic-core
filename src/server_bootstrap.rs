use crate::{Error, PublicKey, SecretKey};
use http::Uri;
use mainline::async_dht::AsyncDht;
use mainline::{Id, MutableItem};

pub const DHT_SERVER_SALT: &[u8] = b"msb24";

/// Bootstrap record for a server
#[derive(Debug, Clone)]
pub struct ServerBootstrap(Vec<Uri>, i64);

impl Default for ServerBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBootstrap {
    /// Create a new `ServerBootstrap` object
    #[must_use]
    pub fn new() -> ServerBootstrap {
        ServerBootstrap(vec![], 0)
    }

    /// Build a `ServerBootstrap` from a `Vec<Uri>` and a sequence number
    /// Extraneous `Uri` data will be stripped
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the any of the Uris have missing schemes or schemes that are not
    /// either `wss` or `https`
    pub fn from_vec_and_seq(mut v: Vec<Uri>, seq: i64) -> Result<ServerBootstrap, Error> {
        let mut output: Vec<Uri> = vec![];
        for uri in v.drain(..) {
            output.push(crate::uri::clean_uri(uri)?);
        }
        Ok(ServerBootstrap(output, seq))
    }

    /// View a `ServerBootstrap` as a `&[Uri]`
    #[must_use]
    pub fn inner(&self) -> &[Uri] {
        &self.0
    }

    /// Current sequence number (increases with each write)
    #[must_use]
    pub fn seq(&self) -> i64 {
        self.1
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Append a `Uri`
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the Uri is missing a scheme, or if the scheme is not
    /// either `wss` or `https`
    pub fn append_uri(&mut self, uri: Uri) -> Result<(), Error> {
        self.0.push(crate::uri::clean_uri(uri)?);
        Ok(())
    }

    /// Remove the `Uri` at the given index.
    /// If the index is beyond the end it will be a no-op.
    pub fn rm_index(&mut self, index: usize) {
        if index >= self.0.len() {
            return;
        }
        let _ = self.0.remove(index);
    }

    /// Encode a `ServerBootstrap` into a DHT value string
    #[must_use]
    pub fn to_dht_string(&self) -> String {
        let mut output: String = "S".to_string();
        for uri in &self.0 {
            output.push('\n');
            output.push_str(&format!("{uri}"));
            let _ = output.pop(); // trailing slash must be removed
        }
        output
    }

    /// Translate a DHT value string into a `ServerBootstrap`
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the string does not match the specification.
    pub fn from_dht_string_and_seq(s: &str, seq: i64) -> Result<ServerBootstrap, Error> {
        if !s.starts_with("S\n") || s.len() < 4 {
            return Err(Error::InvalidServerBootstrapString);
        }

        let mut output: Vec<Uri> = vec![];
        for part in s[2..].split('\n') {
            let uri = part.parse::<Uri>()?;
            let uri = crate::uri::clean_uri(uri)?;
            output.push(uri);
        }

        Ok(ServerBootstrap(output, seq))
    }

    /// Try to read a `ServerBootstrap` record for the given `PublicKey`
    /// using the supplied `Dht` state object
    ///
    /// # Errors
    ///
    /// Returns an error if the Dht was shutdown. If bad data is returned from the Dht, that is
    /// ignored; if all Dht nodes return bad data you will get `None`.
    pub async fn read_from_dht(
        pubkey: PublicKey,
        dht: &AsyncDht,
    ) -> Result<Option<ServerBootstrap>, Error> {
        let mutable_item = dht
            .get_mutable_most_recent(pubkey.as_bytes(), Some(DHT_SERVER_SALT))
            .await;

        if let Some(mi) = mutable_item {
            let s = std::str::from_utf8(mi.value().as_ref())?;
            let sb = ServerBootstrap::from_dht_string_and_seq(s, mi.seq())?;
            Ok(Some(sb))
        } else {
            Ok(None)
        }
    }

    /// Try to write a `ServerBootstrap` record for the given `PublicKey`
    /// using the supplied `Dht` state object.
    /// A Kademlia node Id is returned on success.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if it couldn't write to the Dht
    pub async fn write_to_dht(
        &mut self,
        secret_key: SecretKey,
        dht: &AsyncDht,
    ) -> Result<Id, Error> {
        let s = self.to_dht_string();

        let cas = if self.1 == 0 {
            // never written before
            None
        } else {
            Some(self.1)
        };
        self.1 += 1; // bump the sequence number

        let mutable_item = MutableItem::new(
            secret_key.to_signing_key(),
            s.as_bytes(),
            self.1,
            Some(DHT_SERVER_SALT),
        );

        let id = dht
            .put_mutable(mutable_item, cas)
            .await
            .map_err(|_| Error::DhtPutError)?;

        Ok(id)
    }
}

impl PartialEq for ServerBootstrap {
    fn eq(&self, other: &ServerBootstrap) -> bool {
        self.0 == other.0
    }
}

impl Eq for ServerBootstrap {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_server_bootstrap_serialization() {
        let s = "S\nwss://test.example\nhttps://192.168.99.99";
        let sbs = ServerBootstrap::from_dht_string_and_seq(s, 1).unwrap();
        let s2 = sbs.to_dht_string();
        assert_eq!(s, &s2);
    }

    #[tokio::test]
    async fn test_server_bootstrap_dht() {
        use crate::SecretKey;

        // Setup the DHT
        let dht = mainline::Dht::client().unwrap();
        let async_dht = dht.as_async();

        // Server key
        let secret_b64 = "7AgCGv/SF6EThqVuoxU4edrKzqrzqD9yd4e11eTkGIQ=";
        let secret_key = SecretKey::from_printable(secret_b64).unwrap();
        let public_key = secret_key.public();

        // Expected server bootstrap
        let s = "S\nwss://test.example\nhttps://192.168.99.99";
        let mut expected_server_bootstrap = ServerBootstrap::from_dht_string_and_seq(s, 3).unwrap();

        // Fetch ServerBootstrap for this server
        let maybe_fetched_server_bootstrap = ServerBootstrap::read_from_dht(public_key, &async_dht)
            .await
            .unwrap();

        if let Some(sbs) = maybe_fetched_server_bootstrap {
            assert_eq!(sbs, expected_server_bootstrap);
	    println!("Found expected server bootstrap, seq = {}", sbs.1);
        } else {
            // It has expired from the DHT
            // Let's write it
            let id = expected_server_bootstrap
                .write_to_dht(secret_key, &async_dht)
                .await
                .unwrap();
            println!("Stored new at {id}");
        }
    }
}
