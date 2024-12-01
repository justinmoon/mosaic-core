//! Mosaic core is a core library supporting the Mosaic protocol

#![warn(clippy::pedantic)]

pub use ed25519_dalek;
pub use mainline;
pub use rand;

mod crypto;

mod error;
pub use error::Error;

mod keys;
pub use keys::{PrivateKey, PublicKey};

mod record;
pub use record::Record;

mod server_bootstrap;
pub use server_bootstrap::ServerBootstrap;

mod timestamp;
pub use timestamp::Timestamp;

mod uri;

mod user_bootstrap;
pub use user_bootstrap::UserBootstrap;
