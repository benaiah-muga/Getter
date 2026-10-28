//! Aggregate contribution and health statistics derived from accepted work.

#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use getter_protocol::{CoordinatorStatusResponse, WorkerStatus};

use super::models::*;
use super::workers::worker_status;
use super::{Store, StoreError};

impl Store {
    pub fn contribution(
        &self,
        now: DateTime<Utc>,
        heartbeat_timeout_secs: u64,
    ) -> Result<ContributionRecord, StoreError> {
        let workers = self.list_workers(now, heartbeat_timeout_secs)?;
        let connection = self.connection()?;
        let successful_tasks: i64 = connection.query_row(
            "SELECT COUNT(*) FROM tasks WHERE state = 'completed'",
            [],
            |row| row.get(0),
        )?;
        let failed_attempts: i64 = connection.query_row(
            "SELECT COUNT(*) FROM leases WHERE state IN ('failed', 'expired', 'revoked')",
            [],
            |row| row.get(0),
        )?;
        let verified_tasks: i64 = connection.query_row(
            "SELECT COUNT(*) FROM tasks WHERE validation_status = 'verified'",
            [],
            |row| row.get(0),
        )?;
        let completed_jobs: i64 = connection.query_row(
            "SELECT COUNT(*) FROM jobs WHERE state = 'completed'",
            [],
            |row| row.get(0),
        )?;
        let compute_ms: i64 = connection.query_row(
            "SELECT COALESCE(SUM(compute_ms), 0) FROM tasks WHERE state = 'completed'",
            [],
            |row| row.get(0),
        )?;
        drop(connection);
        let worker_contributions = workers
            .iter()
            .map(|summary| WorkerContributionRecord {
                worker_id: summary.worker.id.clone(),
                worker_name: summary.worker.name.clone(),
                status: summary.status,
                successful_tasks: summary.successful_tasks,
                failed_attempts: summary.failed_attempts,
                compute_ms: summary.compute_ms,
                last_seen: summary.worker.last_seen,
            })
            .collect::<Vec<_>>();
        Ok(ContributionRecord {
            summary: CoordinatorStats {
                total_workers: workers.len() as u64,
                online_workers: workers
                    .iter()
                    .filter(|summary| summary.status == WorkerStatus::Online)
                    .count() as u64,
                active_tasks: workers.iter().map(|summary| summary.active_tasks).sum(),
                successful_tasks: successful_tasks.max(0) as u64,
                failed_attempts: failed_attempts.max(0) as u64,
                verified_tasks: verified_tasks.max(0) as u64,
                completed_jobs: completed_jobs.max(0) as u64,
                compute_ms: compute_ms.max(0) as u64,
                total_uptime_secs: workers
                    .iter()
                    .map(|summary| summary.worker.uptime_secs)
                    .sum(),
            },
            workers: worker_contributions,
        })
    }

    pub fn status(
        &self,
        coordinator_name: &str,
        uptime_secs: u64,
        now: DateTime<Utc>,
        heartbeat_timeout_secs: u64,
    ) -> Result<CoordinatorStatusResponse, StoreError> {
        let jobs = self.job_progress_counts()?;
        let workers = self.list_workers(now, heartbeat_timeout_secs)?;
        let online_workers = workers
            .iter()
            .filter(|summary| summary.status == WorkerStatus::Online)
            .count() as u64;
        let active_tasks = workers.iter().map(|summary| summary.active_tasks).sum();
        Ok(CoordinatorStatusResponse {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: getter_protocol::PROTOCOL_VERSION.to_owned(),
            coordinator_name: coordinator_name.to_owned(),
            uptime_secs,
            online_workers,
            total_workers: workers.len() as u64,
            queued_jobs: jobs.queued,
            running_jobs: jobs.running,
            completed_jobs: jobs.completed,
            failed_jobs: jobs.failed,
            active_tasks,
            database_healthy: self.healthy(),
        })
    }

    pub fn mark_stale_workers_offline(
        &self,
        now: DateTime<Utc>,
        heartbeat_timeout_secs: u64,
    ) -> Result<usize, StoreError> {
        let cutoff = now
            - chrono::Duration::seconds(i64::try_from(heartbeat_timeout_secs).unwrap_or(i64::MAX));
        let connection = self.connection()?;
        // The freshness predicate is evaluated in the same UPDATE as the state
        // change, so a heartbeat racing this sweep cannot be overwritten.
        let changed = connection.execute(
            "UPDATE workers SET participation = 'offline'
             WHERE revoked_at IS NULL AND participation != 'offline'
               AND (last_seen IS NULL OR last_seen < ?1)",
            [super::timestamp(cutoff)],
        )?;
        Ok(changed)
    }

    pub fn worker_status_for(
        &self,
        worker: &StoredWorker,
        now: DateTime<Utc>,
        heartbeat_timeout_secs: u64,
    ) -> WorkerStatus {
        worker_status(worker, now, heartbeat_timeout_secs)
    }
}
