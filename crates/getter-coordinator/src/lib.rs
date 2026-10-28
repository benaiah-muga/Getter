//! Getter coordinator service.

#![deny(unsafe_code)]

mod api;
mod discovery;
mod error;
mod server;

pub use discovery::discover as discover_coordinators;
pub use error::ApiError;
pub use server::{serve, spawn_coordinator, CoordinatorRuntime, ServeOptions};
