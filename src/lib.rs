//! Mosaic core is a core library supporting the
//! [Mosaic protocol](https://stevefarroll.github.io/mosaic-spec/)
//!
//! # Identity
//!
//! Users and Servers are known by their [`PublicKey`] proven by their
//! [`SecretKey`]. These are 32-byte packed data, and have to be unpacked
//! into their [`DalekVerifyingKey`] or [`DalekSigningKey`] respectively in
//! order to do cryptographic operations.
//!
//! # Bootstrap
//!
//! Server endpoints (URLs) are bootstrapped from Mainline DHT with
//! a [`ServerBootstrap`] record.
//!
//! The servers that a user uses are bootstrapped from Mainline DHT
//! with a [`UserBootstrap`] record.
//!
//! # Records
//!
//! [`Record`]s are of various [`Kind`]s and have [`Timestamp`]s and
//! [`RecordFlags`].
//!
//! [`Record`]s may have `Tags` (TBD) of varying [`TagType`]s.
//!
//! Every [`Record`] has an [`Id`] and an [`Address`] by which it can be
//! referred. In some contexts a [`Record`] may be referred to by either,
//! and so a [`Reference`] type can be used when it is unknown which kind
//! of reference is specified.
//!
//! # Protocol
//!
//! Protocol `Messages` (TBD) are sent between client and server over some
//! transport. Many client-initiated messages include a `Filter` (TBD)

#![warn(clippy::pedantic)]
#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    clippy::string_slice,
    unused_import_braces,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    unreachable_pub,
    missing_copy_implementations,
    missing_docs
)]

pub use ed25519_dalek::SigningKey as DalekSigningKey;
pub use ed25519_dalek::VerifyingKey as DalekVerifyingKey;
pub use mainline;
pub use rand;

mod address;
pub use address::Address;

mod crypto;

mod error;
pub use error::{Error, InnerError};

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

mod tags;
pub use tags::{Tag, TagType};

mod timestamp;
pub use timestamp::Timestamp;

mod uri;

mod user_bootstrap;
pub use user_bootstrap::UserBootstrap;
