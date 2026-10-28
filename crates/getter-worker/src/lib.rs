//! Getter worker: enrollment, polling, sandboxed execution, local limits, and a
//! loopback-only control API.
//!
//! A worker connects outbound to the coordinator. It owns all local resource
//! enforcement. The coordinator cannot raise the worker's concurrency, memory,
//! timeout, output, fuel, or download limits.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod client;
mod control;
mod error;
mod join;
mod service;
mod state;

pub use error::WorkerError;
pub use join::{identity_public_key, join, JoinOptions, JoinOutcome};
pub use service::{capabilities, run_worker};
pub use state::{ActiveTaskSnapshot, LocalStats, WorkerState};

/// The advertised ABI set for this worker build.
pub const SUPPORTED_ABIS: &[&str] = &[getter_protocol::WORKLOAD_ABI];
