//! Mosaic core is a core library supporting the Mosaic protocol

#![warn(clippy::pedantic)]

pub use ed25519_dalek::SigningKey as DalekSigningKey;
pub use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
pub use mainline;
pub use rand;

mod address;
pub use address::Address;

mod crypto;

mod error;
pub use error::Error;

mod id;
pub use id::Id;

mod kind;
pub use kind::Kind;

mod keys;
pub use keys::{PublicKey, SecretKey};

mod record;
pub use record::Record;

mod record_flags;
pub use record_flags::RecordFlags;

mod reference;
pub use reference::Reference;

mod server_bootstrap;
pub use server_bootstrap::ServerBootstrap;

mod tag_type;
pub use tag_type::TagType;

mod timestamp;
pub use timestamp::Timestamp;

mod uri;

mod user_bootstrap;
pub use user_bootstrap::UserBootstrap;
