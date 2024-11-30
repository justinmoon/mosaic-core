//! Mosaic core is a core library supporting the Mosaic protocol

#![warn(clippy::pedantic)]

mod error;
pub use error::Error;

mod keys;
pub use keys::{PrivateKey, PublicKey};

mod uri;
