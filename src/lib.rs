//! Argus: See what your tokens are hiding.
//!
//! A JWT security analysis toolkit for auditing and educational use.
//! This crate exposes the core analysis engine; see the `argus` binary
//! for the CLI interface.

pub mod checks;
pub mod config;
pub mod error;
pub mod report;
pub mod scoring;
pub mod token;

pub use error::TokenError;
pub use token::{DecodedToken, decode};

pub use checks::{Check, Finding, Severity, run_all};

pub use scoring::{RiskScore, SeverityCounts, score};

pub use config::{Config, ConfigError};

pub use report::render::{Renderer, json::JsonRenderer, terminal::TerminalRenderer};
pub use report::{Report, RiskScoreSummary, TokenSummary};

/// Returns the current Argus library version, sourced from Cargo.toml.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
