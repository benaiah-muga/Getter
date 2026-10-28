//! Worker errors with clear operator-facing messages and no secret leakage.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("worker is not configured: {0}")]
    Configuration(String),
    #[error("worker setup error: {0}")]
    Init(String),
    #[error("worker I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("coordinator request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordinator rejected the request ({status} {code}): {message}")]
    Api {
        status: u16,
        code: String,
        message: String,
    },
    #[error("coordinator returned an incompatible protocol version: {0}")]
    Protocol(String),
    #[error("coordinator response was malformed: {0}")]
    Response(String),
    #[error("coordinator CA could not be trusted: {0}")]
    Trust(String),
    #[error("pairing rejected: {0}")]
    Pairing(String),
    #[error("local worker limit refused the task: {0}")]
    LocalLimit(String),
    #[error("artifact download failed: {0}")]
    Artifact(String),
    #[error("runner failed: {0}")]
    Runner(String),
    #[error("worker state is unavailable: {0}")]
    State(String),
}

impl From<getter_core::InitError> for WorkerError {
    fn from(error: getter_core::InitError) -> Self {
        Self::Init(error.to_string())
    }
}

impl WorkerError {
    pub fn is_authorization_failure(&self) -> bool {
        matches!(self, Self::Api { status, .. } if *status == 401 || *status == 403)
    }
}
