use crate::{Error, PrivateKey, PublicKey};
use bitflags::bitflags;
use futures::StreamExt;
use mainline::async_dht::AsyncDht;
use mainline::{Bytes, Id, MutableItem};

pub const DHT_USER_SALT: &[u8] = b"mub24";

/// Server usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerUsage(u8);

bitflags! {
    /// Server Usages
    impl ServerUsage: u8 {
        const OUTBOX = 1<<0;
        const INBOX = 1<<1;
        const ENCRYPTION = 1<<2;
    }
}

impl ServerUsage {
    pub fn as_printable_byte(self) -> u8 {
        self.0 | 0b0011_0000
    }

    pub fn from_printable_byte(b: u8) -> ServerUsage {
        ServerUsage::from_bits(b & 0b111).unwrap()
    }
}

/// Bootstrap record for a user
#[derive(Debug, Clone)]
pub struct UserBootstrap(Vec<(ServerUsage, PublicKey)>, i64);

impl Default for UserBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

impl UserBootstrap {
    /// Create a new `UserBootstrap` object
    #[must_use]
    pub fn new() -> UserBootstrap {
        UserBootstrap(vec![], 1)
    }

    /// Build a `UserBootstrap` from a `Vec<(PublicKey, ServerUsage)>` and a sequence number
    /// Extraneous `Uri` data will be stripped
    #[must_use]
    pub fn from_vec_and_seq(v: Vec<(ServerUsage, PublicKey)>, seq: i64) -> UserBootstrap {
        UserBootstrap(v, seq)
    }

    /// View a `UserBootstrap` as a `&[Uri]`
    #[must_use]
    pub fn inner(&self) -> &[(ServerUsage, PublicKey)] {
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

    /// Append a usage and server
    pub fn append_server(&mut self, usage: ServerUsage, server_key: PublicKey) {
        self.0.push((usage, server_key));
    }

    /// Remove the server at the given index.
    /// If the index is beyond the end it will be a no-op.
    pub fn rm_index(&mut self, index: usize) {
        if index >= self.0.len() {
            return;
        }
        let _ = self.0.remove(index);
    }

    /// Encode a `UserBootstrap` into a DHT value string
    #[must_use]
    pub fn to_dht_string(&self) -> String {
        let mut output: String = "U".to_string();
        for (usage, server_key) in &self.0 {
            output.push('\n');
            output.push(usage.as_printable_byte() as char);
            output.push(' ');
            output.push_str(&format!("{server_key}"));
        }
        output
    }

    /// Translate a DHT value string into a `UserBootstrap`
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the string does not match the specification
    pub fn from_dht_string_and_seq(s: &str, seq: i64) -> Result<UserBootstrap, Error> {
        if !s.starts_with("U\n") || s.len() < 4 {
            return Err(Error::InvalidUserBootstrapString);
        }

        let mut output: Vec<(ServerUsage, PublicKey)> = vec![];
        for part in s[2..].split('\n') {
            let server_usage = ServerUsage::from_printable_byte(part.as_bytes()[0]);
            let public_key = PublicKey::from_printable(&part[2..])?;
            output.push((server_usage, public_key));
        }

        Ok(UserBootstrap(output, seq))
    }

    /// Try to read a `UserBootstrap` record for the given `PublicKey`
    /// using the supplied `Dht` state object
    ///
    /// # Errors
    ///
    /// Returns an error if the Dht was shutdown. If bad data is returned from the Dht, that is
    /// ignored; if all Dht nodes return bad data you will get `None`.
    pub async fn read_from_dht(
        pubkey: PublicKey,
        dht: &AsyncDht,
    ) -> Result<Option<UserBootstrap>, Error> {
        let mut recv_stream = dht
            .get_mutable(
                pubkey.as_bytes(),
                Some(Bytes::from_static(DHT_USER_SALT)),
                None,
            )
            .map_err(|_| Error::DhtWasShutdown)?;

        let mut output: Option<UserBootstrap> = None;
        while let Some(mutable) = recv_stream.next().await {
            // FIXME - do we have to check the signature ourselves?
            let Ok(s) = std::str::from_utf8(mutable.value().as_ref()) else {
                continue;
            };
            let Ok(ub) = UserBootstrap::from_dht_string_and_seq(s, *mutable.seq()) else {
                continue;
            };
            match output {
                None => output = Some(ub),
                Some(ref out) => {
                    if out.seq() < ub.seq() {
                        output = Some(ub);
                    }
                }
            }
        }

        Ok(output)
    }

    /// Try to write a `UserBootstrap` record for the given `PublicKey`
    /// using the supplied `Dht` state object.
    /// A Kademlia node Id is returned on success.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if it couldn't write to the Dht
    pub async fn write_to_dht(&self, private_key: PrivateKey, dht: &AsyncDht) -> Result<Id, Error> {
        let s = self.to_dht_string();
        let mutable_item = MutableItem::new(
            private_key.0,
            mainline::Bytes::from(s.into_bytes()),
            self.1,
            Some(Bytes::from_static(DHT_USER_SALT)),
        );

        let id = dht
            .put_mutable(mutable_item)
            .await
            .map_err(|_| Error::DhtPutError)?;

        Ok(id)
    }
}

impl PartialEq for UserBootstrap {
    fn eq(&self, other: &UserBootstrap) -> bool {
        self.0 == other.0
    }
}

impl Eq for UserBootstrap {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_user_bootstrap_serialization() {
        let s = "U\n3 7AgCGv/SF6EThqVuoxU4edrKzqrzqD9yd4e11eTkGIQ=\n1 vpYyesj/gbTHzY5X20fGrolobsTG4Ygim8X4DnfXxOU=";
        let ubs = UserBootstrap::from_dht_string_and_seq(s, 1).unwrap();
        let s2 = ubs.to_dht_string();
        assert_eq!(s, &s2);
    }

    #[tokio::test]
    async fn test_user_bootstrap_dht() {
        use crate::PrivateKey;

        // Setup the DHT
        let dht = mainline::Dht::client().unwrap();
        let async_dht = dht.as_async();

        // User key
        let private_b64 = "7AgCGv/SF6EThqVuoxU4edrKzqrzqD9yd4e11eTkGIQ=";
        let private_key = PrivateKey::from_printable(private_b64).unwrap();
        let public_key = private_key.public();

        // Expected user bootstrap
        let s = "U\n3 7AgCGv/SF6EThqVuoxU4edrKzqrzqD9yd4e11eTkGIQ=\n1 vpYyesj/gbTHzY5X20fGrolobsTG4Ygim8X4DnfXxOU=";
        let expected_user_bootstrap = UserBootstrap::from_dht_string_and_seq(s, 3).unwrap();

        // Fetch UserBootstrap from this server
        let maybe_fetched_user_bootstrap = UserBootstrap::read_from_dht(public_key, &async_dht)
            .await
            .unwrap();

        match maybe_fetched_user_bootstrap {
            Some(ubs) => assert_eq!(ubs, expected_user_bootstrap),
            None => {
                // It has expired from the DHT
                // Let's write it
                let id = expected_user_bootstrap
                    .write_to_dht(private_key, &async_dht)
                    .await
                    .unwrap();
                println!("Stored at {}", id);
            }
        }
    }
}
