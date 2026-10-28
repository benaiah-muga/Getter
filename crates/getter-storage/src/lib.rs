//! SQLite-backed coordinator state.
//!
//! All multi-row transitions (enrollment, claims, results, expiry, cancel) run
//! inside immediate transactions. The store is intentionally synchronous and
//! guarded by one mutex: SQLite is a local single-writer database and the
//! coordinator's requests are bounded. This keeps lease and result acceptance
//! decisions atomic instead of spreading them over async tasks.

#![deny(unsafe_code)]

mod jobs;
mod migrate;
mod models;
mod stats;
mod workers;

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, SecondsFormat, Utc};
use thiserror::Error;

pub use models::*;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("stored data is invalid: {0}")]
    InvalidData(String),
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("enrollment rejected: {0}")]
    Enrollment(String),
    #[error("storage lock is poisoned")]
    Poisoned,
}

impl StoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Database(_) => "database_error",
            Self::InvalidData(_) => "invalid_stored_data",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Forbidden(_) => "forbidden",
            Self::Enrollment(_) => "enrollment_rejected",
            Self::Poisoned => "storage_unavailable",
        }
    }
}

pub struct Store {
    connection: Mutex<rusqlite::Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                StoreError::InvalidData(format!("create database directory: {error}"))
            })?;
        }
        let connection = rusqlite::Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(rusqlite::Connection::open_in_memory()?)
    }

    fn from_connection(connection: rusqlite::Connection) -> Result<Self, StoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000)?;
        let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("memory") {
            // WAL is best-effort for in-memory databases.
            let _: String =
                connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        }
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.migrate()?;
        Ok(store)
    }

    fn connection(&self) -> Result<MutexGuard<'_, rusqlite::Connection>, StoreError> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn healthy(&self) -> bool {
        self.connection()
            .and_then(|connection| {
                connection
                    .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map_err(StoreError::from)
            })
            .map(|value| value == 1)
            .unwrap_or(false)
    }
}

pub fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|error| StoreError::InvalidData(format!("timestamp {value:?}: {error}")))
}

fn parse_optional_timestamp(value: Option<String>) -> Result<Option<DateTime<Utc>>, StoreError> {
    value.map(|value| parse_timestamp(&value)).transpose()
}

fn parse_job_state(value: &str) -> Result<getter_protocol::JobState, StoreError> {
    value
        .parse()
        .map_err(|error: String| StoreError::InvalidData(error))
}

fn parse_task_state(value: &str) -> Result<getter_protocol::TaskState, StoreError> {
    value
        .parse()
        .map_err(|error: String| StoreError::InvalidData(error))
}

fn verification_str(value: getter_protocol::VerificationPolicy) -> &'static str {
    match value {
        getter_protocol::VerificationPolicy::ExactSha256 => "exact_sha256",
        getter_protocol::VerificationPolicy::Trusted => "trusted",
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use getter_protocol::{
        JobManifest, TaskRequirements, TaskSpec, VerificationPolicy, WorkloadDescriptor,
        JOB_FORMAT, WORKLOAD_ABI,
    };
    use sha2::{Digest, Sha256};

    pub fn sha_hex(bytes: &[u8]) -> String {
        hex_encode(Sha256::digest(bytes).as_slice())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub fn manifest(output: &[u8], expected_hash: bool) -> JobManifest {
        let artifact = b"\0asm\x01\0\0\0";
        JobManifest {
            protocol: JOB_FORMAT.into(),
            name: "test job".into(),
            description: None,
            workload: WorkloadDescriptor {
                name: "test".into(),
                abi: WORKLOAD_ABI.into(),
                sha256: sha_hex(artifact),
            },
            tasks: vec![TaskSpec {
                id: "task-1".into(),
                input: "input".into(),
                requirements: None,
                expected_output_sha256: if expected_hash {
                    Some(sha_hex(output))
                } else {
                    None
                },
            }],
            requirements: TaskRequirements {
                timeout_secs: 10,
                ..TaskRequirements::default()
            },
            verification: if expected_hash {
                VerificationPolicy::ExactSha256
            } else {
                VerificationPolicy::Trusted
            },
            aggregation: getter_protocol::AggregationSpec::JsonSum {
                field: "value".into(),
            },
            expected_aggregate: None,
            max_attempts: 2,
            lease_seconds: 20,
        }
    }

    pub fn artifact() -> Vec<u8> {
        b"\0asm\x01\0\0\0".to_vec()
    }

    pub fn enrolled_store(
        now: DateTime<Utc>,
    ) -> (Store, String, getter_core::auth::WorkerSigningKey) {
        let store = Store::in_memory().expect("store");
        let token = "test-pairing-token";
        store
            .create_pairing_token("worker", &getter_core::auth::token_hash(token), now, 600)
            .expect("pair");
        let caps = getter_protocol::WorkerCapabilities {
            abi: vec![WORKLOAD_ABI.into()],
            os: "linux".into(),
            arch: "x86_64".into(),
            cpu_threads: 4,
            max_concurrency: 2,
            max_task_memory_bytes: 256 * 1024 * 1024,
            max_task_timeout_secs: 120,
            max_output_bytes: 1024 * 1024,
            max_fuel: 5_000_000_000,
            version: "test".into(),
        };
        let key = getter_core::auth::WorkerSigningKey::generate();
        let worker = store
            .enroll_worker(
                &getter_core::auth::token_hash(token),
                "worker",
                key.public_base64(),
                &caps,
                now,
            )
            .expect("enroll");
        (store, worker.id, key)
    }
}
