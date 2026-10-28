//! Worker enrollment, authentication material, heartbeats, and listings.

#![deny(unsafe_code)]

use chrono::{DateTime, Duration, Utc};
use getter_core::states::derived_worker_status;
use getter_protocol::{
    WorkerCapabilities, WorkerHeartbeat, WorkerParticipation, WorkerStatus, MAX_NAME_BYTES,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use super::models::*;
use super::{parse_optional_timestamp, parse_timestamp, timestamp, Store, StoreError};

impl Store {
    pub fn create_pairing_token(
        &self,
        name: &str,
        token_hash: &str,
        now: DateTime<Utc>,
        ttl_secs: u64,
    ) -> Result<WorkerPairingToken, StoreError> {
        if name.trim().is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(StoreError::Conflict("invalid pairing-token name".into()));
        }
        if !(60..=86_400).contains(&ttl_secs) {
            return Err(StoreError::Conflict(
                "pairing token lifetime must be between 60 and 86400 seconds".into(),
            ));
        }
        let id = Uuid::new_v4().to_string();
        let expires_at = now + Duration::seconds(ttl_secs as i64);
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO pairing_tokens(id, name, token_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, token_hash, timestamp(now), timestamp(expires_at)],
        )?;
        Ok(WorkerPairingToken {
            id,
            name: name.to_owned(),
            token_hash: token_hash.to_owned(),
            created_at: now,
            expires_at,
            used_at: None,
        })
    }

    /// Atomically consume a pairing token and create the worker identity. A
    /// token can enroll at most one worker.
    pub fn enroll_worker(
        &self,
        token_hash: &str,
        worker_name: &str,
        public_key_base64: &str,
        capabilities: &WorkerCapabilities,
        now: DateTime<Utc>,
    ) -> Result<StoredWorker, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let token = transaction
            .query_row(
                "SELECT id, name, expires_at, used_at FROM pairing_tokens WHERE token_hash = ?1",
                [token_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::Enrollment("invalid or expired pairing token".into()))?;
        let expires_at = parse_timestamp(&token.2)?;
        if token.3.is_some() || now > expires_at {
            return Err(StoreError::Enrollment(
                "invalid or expired pairing token".into(),
            ));
        }
        if token.1 != worker_name {
            return Err(StoreError::Enrollment(
                "pairing token is scoped to a different worker name".into(),
            ));
        }
        let worker_id = Uuid::new_v4().to_string();
        let capabilities_json = serde_json::to_string(capabilities)
            .map_err(|error| StoreError::InvalidData(error.to_string()))?;
        let insert = transaction.execute(
            "INSERT INTO workers(
                id, name, public_key, capabilities_json, participation, created_at, last_seen
             ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5)",
            params![
                worker_id,
                worker_name,
                public_key_base64,
                capabilities_json,
                timestamp(now)
            ],
        );
        if let Err(error) = insert {
            if matches!(
                error,
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::ConstraintViolation,
                        ..
                    },
                    _
                )
            ) {
                return Err(StoreError::Enrollment(
                    "worker name or public key is already registered".into(),
                ));
            }
            return Err(error.into());
        }
        let used = transaction.execute(
            "UPDATE pairing_tokens SET used_at = ?1, used_worker_id = ?2
             WHERE id = ?3 AND used_at IS NULL",
            params![timestamp(now), worker_id, token.0],
        )?;
        if used != 1 {
            return Err(StoreError::Enrollment(
                "invalid or expired pairing token".into(),
            ));
        }
        transaction.commit()?;

        Ok(StoredWorker {
            id: worker_id,
            name: worker_name.to_owned(),
            public_key_base64: public_key_base64.to_owned(),
            capabilities: capabilities.clone(),
            participation: WorkerParticipation::Active,
            created_at: now,
            last_seen: Some(now),
            revoked_at: None,
            uptime_secs: 0,
        })
    }

    pub fn worker_auth(&self, worker_id: &str) -> Result<WorkerAuth, StoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, public_key, revoked_at FROM workers WHERE id = ?1",
                [worker_id],
                |row| {
                    let revoked_at: Option<String> = row.get(2)?;
                    Ok(WorkerAuth {
                        id: row.get(0)?,
                        public_key_base64: row.get(1)?,
                        revoked: revoked_at.is_some(),
                    })
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound("worker"))
    }

    pub fn worker(&self, worker_id: &str) -> Result<StoredWorker, StoreError> {
        let connection = self.connection()?;
        load_worker(&connection, worker_id)
    }

    pub fn heartbeat(
        &self,
        worker_id: &str,
        heartbeat: &WorkerHeartbeat,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revoked: Option<String> = transaction
            .query_row(
                "SELECT revoked_at FROM workers WHERE id = ?1",
                [worker_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound("worker"))?;
        if revoked.is_some() {
            return Err(StoreError::Forbidden("worker has been revoked".into()));
        }
        let capabilities_json = serde_json::to_string(&heartbeat.capabilities)
            .map_err(|error| StoreError::InvalidData(error.to_string()))?;
        transaction.execute(
            "UPDATE workers SET participation = ?1, last_seen = ?2, uptime_secs = ?3,
                capabilities_json = ?4
             WHERE id = ?5",
            params![
                heartbeat.participation.as_str(),
                timestamp(now),
                heartbeat.uptime_secs,
                capabilities_json,
                worker_id
            ],
        )?;
        for lease_id in heartbeat.acknowledged_cancellations.iter().take(64) {
            if lease_id.is_empty() || lease_id.len() > 128 {
                continue;
            }
            transaction.execute(
                "UPDATE cancellation_notifications SET acknowledged_at = ?1
                 WHERE lease_id = ?2 AND worker_id = ?3 AND acknowledged_at IS NULL",
                params![timestamp(now), lease_id, worker_id],
            )?;
        }
        // Keep acknowledged notifications for a short audit/debug window, then
        // purge them so cancelled jobs cannot grow the database forever.
        let purge_cutoff = timestamp(now - Duration::days(7));
        transaction.execute(
            "DELETE FROM cancellation_notifications
             WHERE acknowledged_at IS NOT NULL AND acknowledged_at < ?1",
            [purge_cutoff],
        )?;
        let mut statement = transaction.prepare(
            "SELECT lease_id FROM cancellation_notifications
             WHERE worker_id = ?1 AND acknowledged_at IS NULL
             ORDER BY created_at ASC LIMIT 64",
        )?;
        let rows = statement.query_map([worker_id], |row| row.get::<_, String>(0))?;
        let mut leases = Vec::new();
        for row in rows {
            leases.push(row?);
        }
        drop(statement);
        transaction.commit()?;
        Ok(leases)
    }

    pub fn leave_worker(&self, worker_id: &str, now: DateTime<Utc>) -> Result<(), StoreError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE workers SET participation = 'offline', last_seen = ?1
             WHERE id = ?2 AND revoked_at IS NULL",
            params![timestamp(now), worker_id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound("worker"));
        }
        Ok(())
    }

    pub fn revoke_worker(&self, worker_id: &str, now: DateTime<Utc>) -> Result<(), StoreError> {
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE workers SET participation = 'offline', last_seen = ?1, revoked_at = ?1
             WHERE id = ?2 AND revoked_at IS NULL",
            params![timestamp(now), worker_id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound("worker"));
        }
        connection.execute(
            "UPDATE leases SET expires_at = ?1 WHERE worker_id = ?2 AND state = 'active'",
            params![timestamp(now), worker_id],
        )?;
        Ok(())
    }

    pub fn list_workers(
        &self,
        now: DateTime<Utc>,
        heartbeat_timeout_secs: u64,
    ) -> Result<Vec<WorkerSummaryRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT w.id, w.name, w.public_key, w.capabilities_json, w.participation,
                    w.created_at, w.last_seen, w.revoked_at, w.uptime_secs,
                    (SELECT COUNT(*) FROM leases l WHERE l.worker_id = w.id AND l.state = 'completed'),
                    (SELECT COUNT(*) FROM leases l WHERE l.worker_id = w.id AND l.state IN ('failed', 'expired', 'revoked')),
                    (SELECT COALESCE(SUM(l.compute_ms), 0) FROM leases l WHERE l.worker_id = w.id AND l.state = 'completed'),
                    (SELECT COUNT(*) FROM tasks t WHERE t.assigned_worker_id = w.id AND t.state IN ('assigned', 'running'))
             FROM workers w
             ORDER BY w.created_at ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
            ))
        })?;
        let mut workers = Vec::new();
        for row in rows {
            let (
                id,
                name,
                public_key,
                capabilities,
                participation,
                created_at,
                last_seen,
                revoked_at,
                uptime_secs,
                successful_tasks,
                failed_attempts,
                compute_ms,
                active_tasks,
            ) = row?;
            let capabilities: WorkerCapabilities = serde_json::from_str(&capabilities)
                .map_err(|error| StoreError::InvalidData(error.to_string()))?;
            let participation = parse_participation(&participation)?;
            let created_at = parse_timestamp(&created_at)?;
            let last_seen = parse_optional_timestamp(last_seen)?;
            let revoked_at = parse_optional_timestamp(revoked_at)?;
            let status = derived_worker_status(
                revoked_at.is_some(),
                participation,
                last_seen,
                now,
                heartbeat_timeout_secs,
            );
            workers.push(WorkerSummaryRecord {
                status,
                worker: StoredWorker {
                    id,
                    name,
                    public_key_base64: public_key,
                    capabilities,
                    participation,
                    created_at,
                    last_seen,
                    revoked_at,
                    uptime_secs: uptime_secs.max(0) as u64,
                },
                successful_tasks: successful_tasks.max(0) as u64,
                failed_attempts: failed_attempts.max(0) as u64,
                compute_ms: compute_ms.max(0) as u64,
                active_tasks: active_tasks.max(0) as u64,
            });
        }
        Ok(workers)
    }
}

pub(crate) fn load_worker(
    connection: &rusqlite::Connection,
    worker_id: &str,
) -> Result<StoredWorker, StoreError> {
    connection
        .query_row(
            "SELECT id, name, public_key, capabilities_json, participation, created_at,
                    last_seen, revoked_at, uptime_secs
             FROM workers WHERE id = ?1",
            [worker_id],
            |row| {
                let capabilities: String = row.get(3)?;
                let capabilities: WorkerCapabilities = serde_json::from_str(&capabilities)
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                Ok(StoredWorker {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key_base64: row.get(2)?,
                    capabilities,
                    participation: parse_participation(&row.get::<_, String>(4)?).map_err(
                        |error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        },
                    )?,
                    created_at: parse_timestamp(&row.get::<_, String>(5)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    last_seen: parse_optional_timestamp(row.get(6)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    revoked_at: parse_optional_timestamp(row.get(7)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    uptime_secs: row.get::<_, i64>(8)?.max(0) as u64,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::NotFound("worker"))
}

fn parse_participation(value: &str) -> Result<WorkerParticipation, StoreError> {
    match value {
        "active" => Ok(WorkerParticipation::Active),
        "paused" => Ok(WorkerParticipation::Paused),
        "draining" => Ok(WorkerParticipation::Draining),
        "offline" => Ok(WorkerParticipation::Offline),
        other => Err(StoreError::InvalidData(format!(
            "unknown worker participation {other:?}"
        ))),
    }
}

pub(crate) fn worker_status(
    worker: &StoredWorker,
    now: DateTime<Utc>,
    heartbeat_timeout_secs: u64,
) -> WorkerStatus {
    derived_worker_status(
        worker.revoked_at.is_some(),
        worker.participation,
        worker.last_seen,
        now,
        heartbeat_timeout_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use getter_protocol::WORKLOAD_ABI;

    fn caps() -> WorkerCapabilities {
        WorkerCapabilities {
            abi: vec![WORKLOAD_ABI.into()],
            os: "linux".into(),
            arch: "x86_64".into(),
            cpu_threads: 2,
            max_concurrency: 2,
            max_task_memory_bytes: 128 * 1024 * 1024,
            max_task_timeout_secs: 60,
            max_output_bytes: 1024 * 1024,
            max_fuel: 1_000_000_000,
            version: "test".into(),
        }
    }

    fn heartbeat(participation: WorkerParticipation) -> WorkerHeartbeat {
        WorkerHeartbeat {
            protocol: getter_protocol::PROTOCOL_VERSION.into(),
            participation,
            capabilities: caps(),
            running_tasks: 0,
            uptime_secs: 12,
            tasks_completed: 0,
            task_failures: 0,
            compute_ms: 0,
            acknowledged_cancellations: Vec::new(),
        }
    }

    #[test]
    fn pairing_token_is_single_use() {
        let store = Store::in_memory().expect("store");
        let now = Utc::now();
        let hash = getter_core::auth::token_hash("pair");
        store
            .create_pairing_token("worker-a", &hash, now, 900)
            .expect("create");
        store
            .enroll_worker(&hash, "worker-a", "public-key", &caps(), now)
            .expect("first enroll");
        assert!(store
            .enroll_worker(&hash, "worker-a", "another-key", &caps(), now)
            .is_err());
    }

    #[test]
    fn pairing_token_is_scoped_and_expires() {
        let store = Store::in_memory().expect("store");
        let now = Utc::now();
        let hash = getter_core::auth::token_hash("pair");
        store
            .create_pairing_token("worker-a", &hash, now, 60)
            .expect("create");
        assert!(store
            .enroll_worker(&hash, "worker-b", "key-b", &caps(), now)
            .is_err());
        assert!(store
            .enroll_worker(
                &hash,
                "worker-a",
                "key-a",
                &caps(),
                now + Duration::seconds(61)
            )
            .is_err());
    }

    #[test]
    fn revoked_worker_cannot_heartbeat() {
        let now = Utc::now();
        let (store, worker_id, _) = super::super::test_support::enrolled_store(now);
        store.revoke_worker(&worker_id, now).expect("revoke");
        assert!(store
            .heartbeat(&worker_id, &heartbeat(WorkerParticipation::Active), now)
            .is_err());
        let auth = store.worker_auth(&worker_id).expect("auth");
        assert!(auth.revoked);
    }

    #[test]
    fn heartbeat_updates_participation_and_uptime() {
        let now = Utc::now();
        let (store, worker_id, _) = super::super::test_support::enrolled_store(now);
        store
            .heartbeat(
                &worker_id,
                &heartbeat(WorkerParticipation::Paused),
                now + Duration::seconds(1),
            )
            .expect("heartbeat");
        let worker = store.worker(&worker_id).expect("worker");
        assert_eq!(worker.participation, WorkerParticipation::Paused);
        assert_eq!(worker.uptime_secs, 12);
        let listed = store
            .list_workers(now + Duration::seconds(2), 20)
            .expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].worker.id, worker_id);
    }
}
