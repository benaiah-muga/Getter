//! Explicit, forward-only schema migrations.
//!
//! Migrations are applied in a single transaction and recorded by version. Any
//! failure rolls the version back rather than leaving a partially upgraded
//! database. Future migrations append to [`MIGRATIONS`].

#![deny(unsafe_code)]

use super::{Store, StoreError};

const MIGRATIONS: &[(i64, &str)] = &[(1, MIGRATION_V1), (2, MIGRATION_V2), (3, MIGRATION_V3)];

impl Store {
    pub fn migrate(&self) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );",
        )?;
        for (version, sql) in MIGRATIONS {
            let applied: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
                [version],
                |row| row.get(0),
            )?;
            if applied {
                continue;
            }
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            transaction.execute_batch(sql)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
                rusqlite::params![version, super::timestamp(chrono::Utc::now())],
            )?;
            transaction.commit()?;
        }
        Ok(())
    }
}

const MIGRATION_V1: &str = r#"
CREATE TABLE workers (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    capabilities_json TEXT NOT NULL,
    participation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT,
    revoked_at TEXT,
    uptime_secs INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE pairing_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    used_worker_id TEXT
);

CREATE TABLE artifacts (
    sha256 TEXT PRIMARY KEY NOT NULL,
    bytes BLOB NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    state TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    abi TEXT NOT NULL,
    verification_mode TEXT NOT NULL,
    lease_seconds INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    result_json TEXT,
    error TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (artifact_sha256) REFERENCES artifacts(sha256)
);

CREATE TABLE tasks (
    id TEXT PRIMARY KEY NOT NULL,
    job_id TEXT NOT NULL,
    task_key TEXT NOT NULL,
    seq INTEGER NOT NULL,
    input TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    requirements_json TEXT NOT NULL,
    cpu_slots INTEGER NOT NULL,
    memory_bytes INTEGER NOT NULL,
    timeout_secs INTEGER NOT NULL,
    output_bytes INTEGER NOT NULL,
    fuel INTEGER NOT NULL,
    expected_output_sha256 TEXT,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    assigned_worker_id TEXT,
    current_lease_id TEXT,
    output BLOB,
    output_sha256 TEXT,
    validation_status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    compute_ms INTEGER NOT NULL DEFAULT 0,
    fuel_used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    UNIQUE(job_id, task_key),
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_worker_id) REFERENCES workers(id)
);

CREATE TABLE leases (
    id TEXT PRIMARY KEY NOT NULL,
    task_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    output_sha256 TEXT,
    compute_ms INTEGER NOT NULL DEFAULT 0,
    fuel_used INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (worker_id) REFERENCES workers(id)
);

CREATE INDEX idx_jobs_state_created ON jobs(state, created_at);
CREATE INDEX idx_tasks_job_seq ON tasks(job_id, seq);
CREATE INDEX idx_tasks_state_seq ON tasks(state, seq);
CREATE INDEX idx_tasks_assigned_worker ON tasks(assigned_worker_id, state);
CREATE INDEX idx_leases_worker_state ON leases(worker_id, state);
CREATE INDEX idx_leases_task ON leases(task_id);
CREATE INDEX idx_leases_expiry ON leases(state, expires_at);
CREATE INDEX idx_pairing_expiry ON pairing_tokens(expires_at);
"#;

const MIGRATION_V2: &str = r#"
CREATE TABLE cancellation_notifications (
    lease_id TEXT PRIMARY KEY NOT NULL,
    worker_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acknowledged_at TEXT,
    FOREIGN KEY (worker_id) REFERENCES workers(id)
);
CREATE INDEX idx_cancel_notifications_pending
    ON cancellation_notifications(worker_id, acknowledged_at, created_at);
"#;

const MIGRATION_V3: &str = r#"
ALTER TABLE jobs ADD COLUMN workload_name TEXT NOT NULL DEFAULT '';
UPDATE jobs SET workload_name = COALESCE(
    json_extract(manifest_json, '$.workload.name'), ''
) WHERE workload_name = '';
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_recorded_and_idempotent() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("state.db");
        {
            let store = Store::open(&path).expect("open");
            assert_eq!(store.schema_version().expect("version"), 3);
        }
        let store = Store::open(&path).expect("reopen");
        store.migrate().expect("remigrate");
        assert_eq!(store.schema_version().expect("version"), 3);
        assert!(store.healthy());
    }

    #[test]
    fn fresh_in_memory_database_has_all_tables() {
        let store = Store::in_memory().expect("store");
        let connection = store.connection().expect("connection");
        for table in [
            "workers",
            "pairing_tokens",
            "jobs",
            "tasks",
            "leases",
            "artifacts",
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .expect("query");
            assert!(exists, "{table} missing");
        }
    }
}
