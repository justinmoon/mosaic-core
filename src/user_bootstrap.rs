use crate::{Error, InnerError, PublicKey, SecretKey};
use bitflags::bitflags;
use mainline::async_dht::AsyncDht;
use mainline::{Id, MutableItem};

// note: this has been updated from "mub24" because printable pubkeys have changed.
pub(crate) const DHT_USER_SALT: &[u8] = b"mub25";

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
        UserBootstrap(vec![], 0)
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
        use std::fmt::Write;

        let mut output: String = "U".to_string();
        for (usage, server_key) in &self.0 {
            let _ = write!(
                output,
                "\n{} {server_key}",
                usage.as_printable_byte() as char
            );
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
            return Err(InnerError::InvalidUserBootstrapString.into());
        }

        // Must have a char index a position 2 (not inside a unicode multibyte)
        if !s.char_indices().any(|(i, _c)| i == 2) {
            return Err(InnerError::InvalidUserBootstrapString.into());
        }

        let mut output: Vec<(ServerUsage, PublicKey)> = vec![];
        #[allow(clippy::string_slice)]
        for part in s[2..].split('\n') {
            let server_usage = ServerUsage::from_printable_byte(part.as_bytes()[0]);
            #[allow(clippy::string_slice)]
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
        let mutable_item = dht
            .get_mutable_most_recent(pubkey.as_bytes(), Some(DHT_USER_SALT))
            .await;

        if let Some(mi) = mutable_item {
            let s = std::str::from_utf8(mi.value())?;
            let ub = UserBootstrap::from_dht_string_and_seq(s, mi.seq())?;
            Ok(Some(ub))
        } else {
            Ok(None)
        }
    }

    /// Try to write a `UserBootstrap` record for the given `PublicKey`
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
            Some(DHT_USER_SALT),
        );

        let id = dht
            .put_mutable(mutable_item, cas)
            .await
            .map_err(|_| InnerError::DhtPutError.into_err())?;

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
        let s = "U\n3 mopub0embq17gjmxub6m9mhrg4y33htppzoi6desbenjzzrbzzc4qm7bwo\n1 mopub01cqdc3i8j9pgdepwuxysqjus44eobwhijdnhg5wyopfng5rfmtyy";
        let ubs = UserBootstrap::from_dht_string_and_seq(s, 1).unwrap();
        let s2 = ubs.to_dht_string();
        assert_eq!(s, &s2);
    }

    #[tokio::test]
    #[ignore]
    async fn test_user_bootstrap_dht() {
        use crate::SecretKey;

        // Setup the DHT
        let dht = mainline::Dht::client().unwrap();
        let async_dht = dht.as_async();

        // User key
        // let secret_b64 = "7AgCGv/SF6EThqVuoxU4edrKzqrzqD9yd4e11eTkGIQ=";
        let printable = "mosec07oryrgz94em4nrhgwizkgfjax8pciuik6qwd6huzo647m38rdnny";
        let secret_key = SecretKey::from_printable(printable).unwrap();
        let public_key = secret_key.public();

        // Expected user bootstrap
        let s = "U\n3 mopub0embq17gjmxub6m9mhrg4y33htppzoi6desbenjzzrbzzc4qm7bwo\n1 mopub01cqdc3i8j9pgdepwuxysqjus44eobwhijdnhg5wyopfng5rfmtyy";
        let mut expected_user_bootstrap = UserBootstrap::from_dht_string_and_seq(s, 3).unwrap();

        // Fetch UserBootstrap from this server
        let maybe_fetched_user_bootstrap = UserBootstrap::read_from_dht(public_key, &async_dht)
            .await
            .unwrap();

        if let Some(ubs) = maybe_fetched_user_bootstrap {
            assert_eq!(ubs, expected_user_bootstrap);
            println!("Found expected user bootstrap, seq = {}", ubs.1);
        } else {
            // It has expired from the DHT
            // Let's write it
            let id = expected_user_bootstrap
                .write_to_dht(secret_key, &async_dht)
                .await
                .unwrap();
            println!("Stored new at {id}");
        }
    }
}
