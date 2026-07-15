//! Argus: See what your tokens are hiding.
//!
//! A JWT security analysis toolkit for auditing and educational use.
//! This crate exposes the core analysis engine; see the `argus` binary
//! for the CLI interface.

pub mod error;
pub mod token;

pub use error::TokenError;
pub use token::{DecodedToken, decode};

/// Returns the current Argus library version, sourced from Cargo.toml.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
