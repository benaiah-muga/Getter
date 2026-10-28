//! Getter's coordinator-independent domain logic.
//!
//! This crate deliberately knows nothing about HTTP, SQLite, or Wasmtime. It
//! holds the rules that matter to correctness: configuration validation, state
//! transitions, resource-aware eligibility, result verification and
//! aggregation, secure token handling, and request-signature canonicalization.

#![deny(unsafe_code)]

pub mod auth;
pub mod config;
pub mod error;
pub mod init;
pub mod scheduler;
pub mod states;
pub mod validation;

pub use error::{ConfigError, InitError, ValidationError};
