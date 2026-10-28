//! Job submission, claims, lease lifecycle, result acceptance, aggregation, and
//! recovery sweeps.

#![deny(unsafe_code)]

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use getter_core::auth::{constant_time_eq, lease_token, sha256_hex, token_hash};
use getter_core::scheduler::{select_tasks_for_worker, SchedulingTask, SchedulingWorker};
use getter_core::states::should_retry;
use getter_core::validation::{aggregate_outputs, verify_task_output, TaskOutput};
use getter_protocol::{
    JobManifest, JobResultRecord, JobState, TaskRequirements, TaskState, WorkerParticipation,
    WorkerStatus,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use super::models::*;
use super::workers::worker_status;
use super::{
    parse_job_state, parse_optional_timestamp, parse_task_state, parse_timestamp, timestamp,
    verification_str, Store, StoreError,
};

const ASSIGNMENT_SCAN_LIMIT: usize = 256;
const MAX_ASSIGNMENT_INPUT_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_ERROR_CHARS: usize = 500;

impl Store {
    pub fn create_job(
        &self,
        manifest: &JobManifest,
        artifact: &[u8],
        now: DateTime<Utc>,
    ) -> Result<StoredJob, StoreError> {
        let job_id = Uuid::new_v4().to_string();
        let manifest_json = serde_json::to_string(manifest)
            .map_err(|error| StoreError::InvalidData(error.to_string()))?;
        let description = manifest.description.clone();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO artifacts(sha256, bytes, size, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                manifest.workload.sha256,
                artifact,
                artifact.len() as i64,
                timestamp(now)
            ],
        )?;
        let existing_size: i64 = transaction.query_row(
            "SELECT size FROM artifacts WHERE sha256 = ?1",
            [&manifest.workload.sha256],
            |row| row.get(0),
        )?;
        if existing_size != artifact.len() as i64 {
            return Err(StoreError::Conflict(
                "artifact digest collides with a different stored size".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO jobs(
                id, name, description, state, manifest_json, artifact_sha256, abi,
                workload_name, verification_mode, lease_seconds, max_attempts,
                created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                job_id,
                manifest.name,
                description,
                manifest_json,
                manifest.workload.sha256,
                manifest.workload.abi,
                manifest.workload.name,
                verification_str(manifest.verification),
                manifest.lease_seconds,
                manifest.max_attempts,
                timestamp(now)
            ],
        )?;
        for (sequence, task) in manifest.tasks.iter().enumerate() {
            let requirements = task.requirements.as_ref().unwrap_or(&manifest.requirements);
            let requirements_json = serde_json::to_string(requirements)
                .map_err(|error| StoreError::InvalidData(error.to_string()))?;
            transaction.execute(
                "INSERT INTO tasks(
                    id, job_id, task_key, seq, input, input_sha256, requirements_json,
                    cpu_slots, memory_bytes, timeout_secs, output_bytes, fuel,
                    expected_output_sha256, state, max_attempts, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                           'queued', ?14, ?15, ?15)",
                params![
                    Uuid::new_v4().to_string(),
                    job_id,
                    task.id,
                    sequence as i64,
                    task.input,
                    sha256_hex(task.input.as_bytes()),
                    requirements_json,
                    requirements.cpu_slots,
                    requirements.memory_bytes as i64,
                    requirements.timeout_secs as i64,
                    requirements.output_bytes as i64,
                    requirements.fuel as i64,
                    task.expected_output_sha256,
                    manifest.max_attempts,
                    timestamp(now)
                ],
            )?;
        }
        transaction.commit()?;
        load_job(&connection, &job_id)
    }

    pub fn job(&self, job_id: &str) -> Result<StoredJob, StoreError> {
        let connection = self.connection()?;
        load_job(&connection, job_id)
    }

    pub fn job_detail(&self, job_id: &str) -> Result<StoredJobDetail, StoreError> {
        let connection = self.connection()?;
        let job = load_job(&connection, job_id)?;
        let tasks = load_tasks(&connection, job_id)?;
        Ok(StoredJobDetail { job, tasks })
    }

    pub fn job_progress(&self, job_id: &str) -> Result<JobProgressRecord, StoreError> {
        let connection = self.connection()?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE id = ?1)",
            [job_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NotFound("job"));
        }
        let mut statement = connection
            .prepare("SELECT state, COUNT(*) FROM tasks WHERE job_id = ?1 GROUP BY state")?;
        let rows = statement.query_map([job_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut progress = JobProgressRecord {
            total: 0,
            queued: 0,
            assigned: 0,
            running: 0,
            completed: 0,
            failed: 0,
            cancelled: 0,
        };
        for row in rows {
            let (state, count) = row?;
            let count = count.max(0) as u64;
            progress.total += count;
            match state.as_str() {
                "queued" => progress.queued = count,
                "assigned" => progress.assigned = count,
                "running" => progress.running = count,
                "completed" => progress.completed = count,
                "failed" => progress.failed = count,
                "cancelled" => progress.cancelled = count,
                other => {
                    return Err(StoreError::InvalidData(format!(
                        "unknown task state {other:?}"
                    )))
                }
            }
        }
        Ok(progress)
    }

    pub fn list_jobs(&self, limit: usize) -> Result<Vec<JobSummaryRecord>, StoreError> {
        let limit = limit.clamp(1, 1_000) as i64;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT j.id, j.name, j.state, j.workload_name, j.created_at, j.updated_at,
                    (SELECT COUNT(*) FROM tasks t WHERE t.job_id = j.id),
                    (SELECT COUNT(*) FROM tasks t WHERE t.job_id = j.id AND t.state = 'completed'),
                    (SELECT COUNT(*) FROM tasks t WHERE t.job_id = j.id AND t.state = 'failed'),
                    (SELECT COALESCE(SUM(t.compute_ms), 0) FROM tasks t WHERE t.job_id = j.id),
                    (SELECT COUNT(*) FROM tasks t WHERE t.job_id = j.id AND t.validation_status = 'verified')
             FROM jobs j
             ORDER BY j.created_at DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], |row| {
            let state: String = row.get(2)?;
            Ok(JobSummaryRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                state: parse_job_state(&state).map_err(sql_invalid)?,
                workload_name: row.get(3)?,
                created_at: parse_timestamp(&row.get::<_, String>(4)?).map_err(sql_invalid)?,
                updated_at: parse_timestamp(&row.get::<_, String>(5)?).map_err(sql_invalid)?,
                total_tasks: row.get::<_, i64>(6)?.max(0) as u64,
                completed_tasks: row.get::<_, i64>(7)?.max(0) as u64,
                failed_tasks: row.get::<_, i64>(8)?.max(0) as u64,
                compute_ms: row.get::<_, i64>(9)?.max(0) as u64,
                verified: row.get::<_, i64>(10)? > 0
                    && row.get::<_, i64>(7)? == row.get::<_, i64>(10)?,
            })
        })?;
        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    /// Claim queued tasks for one worker. Eligibility and free-slot accounting
    /// are both rechecked inside an immediate transaction.
    pub fn claim_assignments(
        &self,
        worker_id: &str,
        limit: usize,
        heartbeat_timeout_secs: u64,
        now: DateTime<Utc>,
    ) -> Result<Vec<LeaseAssignment>, StoreError> {
        let limit = limit.clamp(1, 32);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let worker = super::workers::load_worker(&transaction, worker_id)?;
        let status = worker_status(&worker, now, heartbeat_timeout_secs);
        if worker.revoked_at.is_some() {
            return Err(StoreError::Forbidden("worker has been revoked".into()));
        }
        if worker.participation != WorkerParticipation::Active {
            return Ok(Vec::new());
        }
        if status != WorkerStatus::Online {
            return Ok(Vec::new());
        }

        let active_slots: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(t.cpu_slots), 0)
             FROM tasks t JOIN leases l ON t.current_lease_id = l.id
             WHERE t.assigned_worker_id = ?1 AND t.state IN ('assigned', 'running')
               AND l.state = 'active'",
            [worker_id],
            |row| row.get(0),
        )?;
        let active_slots = active_slots.max(0) as u32;

        let candidates = load_claim_candidates(&transaction, &worker.capabilities)?;
        let scheduling_tasks: Vec<SchedulingTask> = candidates
            .iter()
            .map(|candidate| SchedulingTask {
                internal_id: candidate.task_id.clone(),
                abi: candidate.abi.clone(),
                requirements: candidate.requirements.clone(),
            })
            .collect();
        let worker_view = SchedulingWorker {
            participation: worker.participation,
            capabilities: &worker.capabilities,
            active_cpu_slots: active_slots,
        };
        let selected = select_tasks_for_worker(&scheduling_tasks, &worker_view, limit);
        if selected.is_empty() {
            transaction.commit()?;
            return Ok(Vec::new());
        }

        let selected: HashSet<String> = selected.into_iter().collect();
        let mut assignments = Vec::new();
        let mut batch_input_bytes = 0_usize;
        for candidate in candidates
            .iter()
            .filter(|candidate| selected.contains(&candidate.task_id))
        {
            // Fetch task inputs only after scheduling selected this assignment.
            // The eligibility scan must never materialize inputs for all
            // candidates under the store mutex.
            let (input, input_sha256): (String, String) = transaction.query_row(
                "SELECT input, input_sha256 FROM tasks WHERE id = ?1",
                [&candidate.task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if !assignments.is_empty()
                && batch_input_bytes.saturating_add(input.len()) > MAX_ASSIGNMENT_INPUT_BATCH_BYTES
            {
                break;
            }
            batch_input_bytes = batch_input_bytes.saturating_add(input.len());
            if candidate.attempts >= candidate.max_attempts {
                // Defensive: a queued task at its attempt ceiling is failed
                // rather than leased again.
                transaction.execute(
                    "UPDATE tasks SET state = 'failed', error = ?1, updated_at = ?2, finished_at = ?2
                     WHERE id = ?3 AND state = 'queued'",
                    params!["retry budget exhausted", timestamp(now), candidate.task_id],
                )?;
                continue;
            }
            let attempt = candidate.attempts + 1;
            let lease_id = Uuid::new_v4().to_string();
            let raw_token = lease_token();
            let expires_at = now + Duration::seconds(candidate.lease_seconds as i64);
            transaction.execute(
                "INSERT INTO leases(
                    id, task_id, job_id, worker_id, token_hash, attempt, state, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?8)",
                params![
                    lease_id,
                    candidate.task_id,
                    candidate.job_id,
                    worker_id,
                    token_hash(&raw_token),
                    attempt,
                    timestamp(now),
                    timestamp(expires_at)
                ],
            )?;
            let changed = transaction.execute(
                "UPDATE tasks SET state = 'assigned', attempts = ?1, assigned_worker_id = ?2,
                    current_lease_id = ?3, updated_at = ?4, error = NULL, started_at = NULL,
                    finished_at = NULL
                 WHERE id = ?5 AND state = 'queued'",
                params![
                    attempt,
                    worker_id,
                    lease_id,
                    timestamp(now),
                    candidate.task_id
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Conflict("task was claimed concurrently".into()));
            }
            transaction.execute(
                "UPDATE jobs SET state = 'running',
                    started_at = COALESCE(started_at, ?1), updated_at = ?1
                 WHERE id = ?2 AND state = 'queued'",
                params![timestamp(now), candidate.job_id],
            )?;
            assignments.push(LeaseAssignment {
                lease_id,
                lease_token: raw_token,
                job_id: candidate.job_id.clone(),
                job_name: candidate.job_name.clone(),
                task_id: candidate.task_id.clone(),
                task_key: candidate.task_key.clone(),
                attempt,
                max_attempts: candidate.max_attempts,
                lease_expires_at: expires_at,
                workload_name: candidate.workload_name.clone(),
                abi: candidate.abi.clone(),
                artifact_sha256: candidate.artifact_sha256.clone(),
                input,
                input_sha256,
                requirements: candidate.requirements.clone(),
            });
        }
        transaction.commit()?;
        Ok(assignments)
    }

    pub fn mark_started(
        &self,
        worker_id: &str,
        lease_id: &str,
        raw_token: &str,
        now: DateTime<Utc>,
    ) -> Result<StartAck, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = load_lease(&transaction, lease_id)?;
        if lease.worker_id != worker_id {
            return Err(StoreError::Forbidden(
                "lease belongs to another worker".into(),
            ));
        }
        if !constant_time_eq(&lease.token_hash, &token_hash(raw_token)) {
            return Err(StoreError::Forbidden("invalid lease token".into()));
        }
        if lease.state != "active" || lease.expires_at <= now {
            return Err(StoreError::Conflict("lease is no longer active".into()));
        }
        let task_state = parse_task_state(&lease.task_state)?;
        if !matches!(task_state, TaskState::Assigned | TaskState::Running) {
            return Err(StoreError::Conflict(format!(
                "task is {task_state}, not assigned or running"
            )));
        }
        if task_state == TaskState::Assigned {
            transaction.execute(
                "UPDATE tasks SET state = 'running', started_at = ?1, updated_at = ?1 WHERE id = ?2",
                params![timestamp(now), lease.task_id],
            )?;
            transaction.execute(
                "UPDATE leases SET started_at = COALESCE(started_at, ?1) WHERE id = ?2",
                params![timestamp(now), lease_id],
            )?;
        }
        transaction.execute(
            "UPDATE jobs SET state = 'running', started_at = COALESCE(started_at, ?1),
                updated_at = ?1 WHERE id = ?2 AND state = 'queued'",
            params![timestamp(now), lease.job_id],
        )?;
        let job_state: String = transaction.query_row(
            "SELECT state FROM jobs WHERE id = ?1",
            [&lease.job_id],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(StartAck {
            state: TaskState::Running,
            job_state: parse_job_state(&job_state)?,
        })
    }

    pub fn record_result(
        &self,
        submission: ResultSubmission,
        now: DateTime<Utc>,
    ) -> Result<ResultReceipt, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = load_lease(&transaction, &submission.lease_id)?;
        if lease.worker_id != submission.worker_id {
            return Err(StoreError::Forbidden(
                "lease belongs to another worker".into(),
            ));
        }
        if lease.task_id != submission.task_id {
            return Err(StoreError::Forbidden(
                "lease does not belong to this task".into(),
            ));
        }
        if !constant_time_eq(&lease.token_hash, &token_hash(&submission.lease_token)) {
            return Err(StoreError::Forbidden("invalid lease token".into()));
        }
        let task = load_task(&transaction, &lease.task_id)?;
        let job = load_job(&transaction, &lease.job_id)?;

        if let (Some(output), TaskState::Completed) = (&submission.output, task.state) {
            let digest = sha256_hex(output);
            if task.output_sha256.as_deref() == Some(digest.as_str())
                || task.output.as_deref() == Some(output.as_slice())
            {
                let message = "duplicate result accepted idempotently".to_owned();
                transaction.commit()?;
                return Ok(ResultReceipt {
                    accepted: true,
                    duplicate: true,
                    task_state: task.state,
                    job_state: job.state,
                    message,
                });
            }
        }
        if job.cancel_requested || job.state == JobState::Cancelled {
            let message = "job is cancelled".to_owned();
            transaction.commit()?;
            return Ok(ResultReceipt {
                accepted: false,
                duplicate: false,
                task_state: task.state,
                job_state: JobState::Cancelled,
                message,
            });
        }
        if lease.state != "active" || lease.expires_at <= now {
            let message = "lease expired or was revoked; result ignored".to_owned();
            let job_state = job.state;
            let task_state = task.state;
            transaction.commit()?;
            return Ok(ResultReceipt {
                accepted: false,
                duplicate: false,
                task_state,
                job_state,
                message,
            });
        }
        if !matches!(task.state, TaskState::Assigned | TaskState::Running) {
            return Err(StoreError::Conflict(format!(
                "task is {} and cannot accept a result",
                task.state
            )));
        }

        if let Some(reason) = submission.requeue {
            let reason = sanitize_error(&reason);
            transaction.execute(
                "UPDATE leases SET state = 'abandoned', finished_at = ?1, error = ?2
                 WHERE id = ?3 AND state = 'active'",
                params![timestamp(now), reason, lease.id],
            )?;
            let abandoned: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM leases WHERE task_id = ?1 AND state = 'abandoned'",
                [&task.id],
                |row| row.get(0),
            )?;
            let message = if abandoned > 32 {
                transaction.execute(
                    "UPDATE tasks SET state = 'failed', current_lease_id = NULL,
                        error = 'too many infrastructure interruptions', updated_at = ?1,
                        finished_at = ?1 WHERE id = ?2",
                    params![timestamp(now), task.id],
                )?;
                "requeue limit exceeded; task failed".to_owned()
            } else {
                transaction.execute(
                    "UPDATE tasks SET state = 'queued', current_lease_id = NULL,
                        attempts = MAX(attempts - 1, 0), error = ?1, updated_at = ?2,
                        started_at = NULL, finished_at = NULL
                     WHERE id = ?3 AND state IN ('assigned', 'running')",
                    params![reason, timestamp(now), task.id],
                )?;
                "task released to the queue without consuming a workload attempt".to_owned()
            };
            finalize_job(&transaction, &job.id, now)?;
            let task_state: String = transaction.query_row(
                "SELECT state FROM tasks WHERE id = ?1",
                [&task.id],
                |row| row.get(0),
            )?;
            let job_state: String = transaction.query_row(
                "SELECT state FROM jobs WHERE id = ?1",
                [&job.id],
                |row| row.get(0),
            )?;
            transaction.commit()?;
            return Ok(ResultReceipt {
                accepted: true,
                duplicate: false,
                task_state: parse_task_state(&task_state)?,
                job_state: parse_job_state(&job_state)?,
                message,
            });
        }

        let compute_ms = bounded_compute_ms(submission.compute_ms, &task.requirements);
        let fuel_used = bounded_fuel(submission.fuel_used, &task.requirements);
        let mut accepted = false;
        let message;
        if let Some(output) = submission.output {
            let verification = verify_task_output(
                &task.key,
                &output,
                &task.requirements,
                job.manifest.verification,
                task.expected_output_sha256.as_deref(),
            );
            match verification {
                Ok(validation) => {
                    let output_sha256 = sha256_hex(&output);
                    let validation_status = match validation {
                        getter_core::validation::VerificationResult::Verified => "verified",
                        getter_core::validation::VerificationResult::Unverified => "unverified",
                    };
                    transaction.execute(
                        "UPDATE tasks SET state = 'completed', output = ?1, output_sha256 = ?2,
                            validation_status = ?3, compute_ms = ?4, fuel_used = ?5,
                            current_lease_id = NULL, updated_at = ?6, finished_at = ?6, error = NULL
                         WHERE id = ?7 AND state IN ('assigned', 'running')",
                        params![
                            output,
                            output_sha256,
                            validation_status,
                            compute_ms as i64,
                            fuel_used as i64,
                            timestamp(now),
                            task.id
                        ],
                    )?;
                    transaction.execute(
                        "UPDATE leases SET state = 'completed', finished_at = ?1,
                            output_sha256 = ?2, compute_ms = ?3, fuel_used = ?4
                         WHERE id = ?5 AND state = 'active'",
                        params![
                            timestamp(now),
                            output_sha256,
                            compute_ms as i64,
                            fuel_used as i64,
                            lease.id
                        ],
                    )?;
                    accepted = true;
                    message = "result accepted".to_owned();
                }
                Err(error) => {
                    let error_text = format!("result rejected by verification policy: {error}");
                    message = error_text.clone();
                    apply_failure(
                        &transaction,
                        &task,
                        &lease,
                        &error_text,
                        true,
                        compute_ms,
                        fuel_used,
                        now,
                    )?;
                }
            }
        } else {
            let reason = sanitize_error(
                submission
                    .failure
                    .as_deref()
                    .unwrap_or("worker reported failure without detail"),
            );
            message = format!("failure recorded: {reason}");
            apply_failure(
                &transaction,
                &task,
                &lease,
                &reason,
                submission.retryable,
                compute_ms,
                fuel_used,
                now,
            )?;
        }

        finalize_job(&transaction, &job.id, now)?;
        let task_state: String =
            transaction.query_row("SELECT state FROM tasks WHERE id = ?1", [&task.id], |row| {
                row.get(0)
            })?;
        let job_state: String =
            transaction.query_row("SELECT state FROM jobs WHERE id = ?1", [&job.id], |row| {
                row.get(0)
            })?;
        transaction.commit()?;
        Ok(ResultReceipt {
            accepted,
            duplicate: false,
            task_state: parse_task_state(&task_state)?,
            job_state: parse_job_state(&job_state)?,
            message,
        })
    }

    pub fn expire_leases(&self, now: DateTime<Utc>) -> Result<ExpirySweep, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now_text = timestamp(now);
        let lease_ids: Vec<String> = {
            let mut statement = transaction
                .prepare("SELECT id FROM leases WHERE state = 'active' AND expires_at <= ?1")?;
            let rows = statement.query_map([&now_text], |row| row.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut expired = Vec::new();
        let mut jobs_touched = HashSet::new();
        for lease_id in lease_ids {
            let lease = load_lease(&transaction, &lease_id)?;
            let task = load_task(&transaction, &lease.task_id)?;
            let job = load_job(&transaction, &lease.job_id)?;
            transaction.execute(
                "UPDATE leases SET state = 'expired', finished_at = ?1, error = ?2
                 WHERE id = ?3 AND state = 'active'",
                params![timestamp(now), "lease expired before result", lease_id],
            )?;
            let next_state = if job.cancel_requested || job.state == JobState::Cancelled {
                TaskState::Cancelled
            } else if task.state.is_terminal() {
                task.state
            } else if should_retry(task.attempts, task.max_attempts, true) {
                TaskState::Queued
            } else {
                TaskState::Failed
            };
            if !task.state.is_terminal() {
                if next_state == TaskState::Queued {
                    transaction.execute(
                        "UPDATE tasks SET state = 'queued', current_lease_id = NULL,
                            updated_at = ?1, finished_at = NULL, started_at = NULL,
                            error = 'lease expired; task requeued'
                         WHERE id = ?2 AND state IN ('assigned', 'running')",
                        params![timestamp(now), task.id],
                    )?;
                } else if next_state == TaskState::Failed {
                    transaction.execute(
                        "UPDATE tasks SET state = 'failed', current_lease_id = NULL,
                            updated_at = ?1, finished_at = ?1,
                            error = 'lease expired after the final attempt'
                         WHERE id = ?2 AND state IN ('assigned', 'running')",
                        params![timestamp(now), task.id],
                    )?;
                } else if next_state == TaskState::Cancelled {
                    transaction.execute(
                        "UPDATE tasks SET state = 'cancelled', current_lease_id = NULL,
                            updated_at = ?1, finished_at = ?1, error = 'job cancelled'
                         WHERE id = ?2 AND state IN ('assigned', 'running')",
                        params![timestamp(now), task.id],
                    )?;
                }
            }
            jobs_touched.insert(job.id.clone());
            expired.push(ExpiredLease {
                lease_id,
                task_id: task.id,
                job_id: job.id,
                worker_id: lease.worker_id,
                next_task_state: next_state,
            });
        }
        for job_id in &jobs_touched {
            finalize_job(&transaction, job_id, now)?;
        }
        transaction.commit()?;
        Ok(ExpirySweep {
            expired_leases: expired,
            jobs_touched: jobs_touched.into_iter().collect(),
        })
    }

    pub fn cancel_job(&self, job_id: &str, now: DateTime<Utc>) -> Result<JobState, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = load_job(&transaction, job_id)?;
        if job.state == JobState::Cancelled {
            transaction.commit()?;
            return Ok(JobState::Cancelled);
        }
        if job.state.is_terminal() {
            return Err(StoreError::Conflict(format!(
                "job is already {}",
                job.state
            )));
        }
        transaction.execute(
            "INSERT OR IGNORE INTO cancellation_notifications(
                lease_id, worker_id, task_id, created_at
             )
             SELECT id, worker_id, task_id, ?1 FROM leases
             WHERE job_id = ?2 AND state = 'active'",
            params![timestamp(now), job_id],
        )?;
        transaction.execute(
            "UPDATE tasks SET state = 'cancelled', current_lease_id = NULL,
                updated_at = ?1, finished_at = ?1, error = 'job cancelled by administrator'
             WHERE job_id = ?2 AND state IN ('queued', 'assigned', 'running')",
            params![timestamp(now), job_id],
        )?;
        transaction.execute(
            "UPDATE leases SET state = 'revoked', finished_at = ?1, error = 'job cancelled'
             WHERE job_id = ?2 AND state = 'active'",
            params![timestamp(now), job_id],
        )?;
        transaction.execute(
            "UPDATE jobs SET state = 'cancelled', cancel_requested = 1,
                completed_at = ?1, updated_at = ?1, error = 'job cancelled by administrator'
             WHERE id = ?2",
            params![timestamp(now), job_id],
        )?;
        transaction.commit()?;
        Ok(JobState::Cancelled)
    }

    pub fn lease_artifact(
        &self,
        worker_id: &str,
        lease_id: &str,
        raw_token: &str,
        now: DateTime<Utc>,
    ) -> Result<ArtifactAccess, StoreError> {
        let connection = self.connection()?;
        let row: Option<(String, String, String, String, i64)> = connection
            .query_row(
                "SELECT l.token_hash, l.state, l.expires_at, j.artifact_sha256, j.cancel_requested
                 FROM leases l JOIN jobs j ON j.id = l.job_id
                 WHERE l.id = ?1 AND l.worker_id = ?2",
                params![lease_id, worker_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (token, state, expires_at, artifact_sha, cancel_requested) =
            row.ok_or(StoreError::NotFound("lease"))?;
        if !constant_time_eq(&token, &token_hash(raw_token)) {
            return Err(StoreError::Forbidden("invalid lease token".into()));
        }
        if state != "active" || parse_timestamp(&expires_at)? <= now {
            return Err(StoreError::Conflict("lease is no longer active".into()));
        }
        if cancel_requested != 0 {
            return Err(StoreError::Conflict("job is cancelled".into()));
        }
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT bytes FROM artifacts WHERE sha256 = ?1",
                [&artifact_sha],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound("artifact"))?;
        Ok(ArtifactAccess {
            bytes,
            sha256: artifact_sha,
        })
    }

    pub fn job_progress_counts(&self) -> Result<JobStateCounts, StoreError> {
        let connection = self.connection()?;
        let mut counts = JobStateCounts {
            queued: 0,
            running: 0,
            completed: 0,
            failed: 0,
            cancelled: 0,
        };
        let mut statement =
            connection.prepare("SELECT state, COUNT(*) FROM jobs GROUP BY state")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (state, count) = row?;
            let count = count.max(0) as u64;
            match state.as_str() {
                "queued" => counts.queued = count,
                "running" => counts.running = count,
                "completed" => counts.completed = count,
                "failed" => counts.failed = count,
                "cancelled" => counts.cancelled = count,
                other => {
                    return Err(StoreError::InvalidData(format!(
                        "unknown job state {other:?}"
                    )))
                }
            }
        }
        Ok(counts)
    }
}

struct ClaimCandidate {
    task_id: String,
    job_id: String,
    task_key: String,
    requirements: TaskRequirements,
    attempts: u32,
    max_attempts: u32,
    job_name: String,
    abi: String,
    artifact_sha256: String,
    workload_name: String,
    lease_seconds: u32,
}

fn load_claim_candidates(
    connection: &rusqlite::Connection,
    capabilities: &getter_protocol::WorkerCapabilities,
) -> Result<Vec<ClaimCandidate>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT t.id, t.job_id, t.task_key, t.requirements_json,
                t.attempts, t.max_attempts, j.name, j.abi, j.artifact_sha256,
                j.lease_seconds, j.workload_name
         FROM tasks t JOIN jobs j ON j.id = t.job_id
         WHERE t.state = 'queued' AND j.state IN ('queued', 'running')
           AND j.cancel_requested = 0
           AND t.cpu_slots <= ?1
           AND t.memory_bytes <= ?2
           AND t.timeout_secs <= ?3
           AND t.output_bytes <= ?4
           AND t.fuel <= ?5
         ORDER BY j.created_at, t.seq
         LIMIT ?6",
    )?;
    let rows = statement.query_map(
        rusqlite::params![
            capabilities.max_concurrency,
            capabilities.max_task_memory_bytes as i64,
            capabilities.max_task_timeout_secs as i64,
            capabilities.max_output_bytes as i64,
            capabilities.max_fuel as i64,
            ASSIGNMENT_SCAN_LIMIT as i64
        ],
        |row| {
            let requirements_json: String = row.get(3)?;
            let requirements: TaskRequirements =
                serde_json::from_str(&requirements_json).map_err(sql_invalid)?;
            Ok(ClaimCandidate {
                task_id: row.get(0)?,
                job_id: row.get(1)?,
                task_key: row.get(2)?,
                requirements,
                attempts: row.get::<_, i64>(4)?.max(0) as u32,
                max_attempts: row.get::<_, i64>(5)?.max(0) as u32,
                job_name: row.get(6)?,
                abi: row.get(7)?,
                artifact_sha256: row.get(8)?,
                lease_seconds: row.get::<_, i64>(9)?.max(0) as u32,
                workload_name: row.get(10)?,
            })
        },
    )?;
    let mut candidates = Vec::new();
    for row in rows {
        candidates.push(row?);
    }
    Ok(candidates)
}

struct StoredLease {
    id: String,
    task_id: String,
    job_id: String,
    worker_id: String,
    token_hash: String,
    state: String,
    expires_at: DateTime<Utc>,
    task_state: String,
}

fn load_lease(
    connection: &rusqlite::Connection,
    lease_id: &str,
) -> Result<StoredLease, StoreError> {
    connection
        .query_row(
            "SELECT l.id, l.task_id, l.job_id, l.worker_id, l.token_hash, l.state,
                    l.expires_at, t.state
             FROM leases l JOIN tasks t ON t.id = l.task_id WHERE l.id = ?1",
            [lease_id],
            |row| {
                Ok(StoredLease {
                    id: row.get(0)?,
                    task_id: row.get(1)?,
                    job_id: row.get(2)?,
                    worker_id: row.get(3)?,
                    token_hash: row.get(4)?,
                    state: row.get(5)?,
                    expires_at: parse_timestamp(&row.get::<_, String>(6)?).map_err(sql_invalid)?,
                    task_state: row.get(7)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::NotFound("lease"))
}

#[allow(clippy::too_many_arguments)]
fn apply_failure(
    transaction: &rusqlite::Transaction<'_>,
    task: &StoredTask,
    lease: &StoredLease,
    error: &str,
    retryable: bool,
    compute_ms: u64,
    fuel_used: u64,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let error = sanitize_error(error);
    transaction.execute(
        "UPDATE leases SET state = 'failed', finished_at = ?1, compute_ms = ?2,
            fuel_used = ?3, error = ?4 WHERE id = ?5 AND state = 'active'",
        params![
            timestamp(now),
            compute_ms as i64,
            fuel_used as i64,
            error,
            lease.id
        ],
    )?;
    let retry = should_retry(task.attempts, task.max_attempts, retryable);
    if retry {
        transaction.execute(
            "UPDATE tasks SET state = 'queued', current_lease_id = NULL, error = ?1,
                started_at = NULL, finished_at = NULL, updated_at = ?2
             WHERE id = ?3 AND state IN ('assigned', 'running')",
            params![error, timestamp(now), task.id],
        )?;
    } else {
        transaction.execute(
            "UPDATE tasks SET state = 'failed', current_lease_id = NULL, error = ?1,
                finished_at = ?2, updated_at = ?2, compute_ms = ?3, fuel_used = ?4
             WHERE id = ?5 AND state IN ('assigned', 'running')",
            params![
                error,
                timestamp(now),
                compute_ms as i64,
                fuel_used as i64,
                task.id
            ],
        )?;
    }
    Ok(())
}

/// Recompute terminal job state, validate aggregates, and persist the result.
fn finalize_job(
    transaction: &rusqlite::Transaction<'_>,
    job_id: &str,
    now: DateTime<Utc>,
) -> Result<JobState, StoreError> {
    let job = load_job(transaction, job_id)?;
    if job.state.is_terminal() {
        return Ok(job.state);
    }
    let mut statement = transaction.prepare(
        "SELECT COUNT(*), SUM(CASE WHEN state = 'completed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN state IN ('queued', 'assigned', 'running') THEN 1 ELSE 0 END)
         FROM tasks WHERE job_id = ?1",
    )?;
    let (total, completed, failed, active): (i64, i64, i64, i64) =
        statement.query_row([job_id], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            ))
        })?;
    drop(statement);
    if total == 0 || active > 0 {
        if job.state == JobState::Queued {
            transaction.execute(
                "UPDATE jobs SET state = 'running', updated_at = ?1 WHERE id = ?2",
                params![timestamp(now), job_id],
            )?;
        }
        return Ok(JobState::Running);
    }
    let next_state = if job.cancel_requested {
        JobState::Cancelled
    } else if failed > 0 || completed != total {
        JobState::Failed
    } else {
        JobState::Completed
    };
    let mut error_text = None;
    let mut result = None;
    if next_state == JobState::Completed {
        let tasks = load_tasks(transaction, job_id)?;
        let outputs: Vec<TaskOutput> = tasks
            .iter()
            .filter_map(|task| {
                task.output.as_ref().map(|bytes| TaskOutput {
                    task_key: task.key.clone(),
                    bytes: bytes.clone(),
                })
            })
            .collect();
        match aggregate_outputs(&job.manifest.aggregation, &outputs) {
            Ok(aggregate) => {
                let matches = job
                    .manifest
                    .expected_aggregate
                    .as_ref()
                    .map(|expected| expected == &aggregate);
                if matches == Some(false) {
                    error_text =
                        Some("aggregate result did not match expected_aggregate".to_owned());
                }
                let verified_tasks = tasks
                    .iter()
                    .filter(|task| task.validation_status == "verified")
                    .count() as u64;
                let compute_ms = tasks
                    .iter()
                    .fold(0_u64, |total, task| total.saturating_add(task.compute_ms));
                let record = JobResultRecord {
                    aggregate,
                    expected_aggregate: job.manifest.expected_aggregate.clone(),
                    aggregate_matches_expected: matches,
                    verified_tasks,
                    completed_tasks: total.max(0) as u64,
                    compute_ms,
                };
                result = Some(
                    serde_json::to_string(&record)
                        .map_err(|error| StoreError::InvalidData(error.to_string()))?,
                );
            }
            Err(error) => {
                error_text = Some(format!("aggregation failed: {error}"));
            }
        }
    }
    let final_state = if error_text.is_some() {
        JobState::Failed
    } else {
        next_state
    };
    transaction.execute(
        "UPDATE jobs SET state = ?1, result_json = ?2, error = ?3, updated_at = ?4,
            completed_at = ?4 WHERE id = ?5",
        params![
            final_state.as_str(),
            result,
            error_text,
            timestamp(now),
            job_id
        ],
    )?;
    Ok(final_state)
}

fn load_job(connection: &rusqlite::Connection, job_id: &str) -> Result<StoredJob, StoreError> {
    connection
        .query_row(
            "SELECT id, name, description, state, manifest_json, artifact_sha256, result_json,
                    error, cancel_requested, created_at, updated_at, started_at, completed_at
             FROM jobs WHERE id = ?1",
            [job_id],
            |row| {
                let manifest: String = row.get(4)?;
                let manifest: JobManifest = serde_json::from_str(&manifest).map_err(sql_invalid)?;
                let state: String = row.get(3)?;
                let result_json: Option<String> = row.get(6)?;
                let result = result_json
                    .map(|json| serde_json::from_str::<JobResultRecord>(&json))
                    .transpose()
                    .map_err(sql_invalid)?;
                Ok(StoredJob {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    state: parse_job_state(&state).map_err(sql_invalid)?,
                    manifest,
                    artifact_sha256: row.get(5)?,
                    result,
                    error: row.get(7)?,
                    cancel_requested: row.get::<_, i64>(8)? != 0,
                    created_at: parse_timestamp(&row.get::<_, String>(9)?).map_err(sql_invalid)?,
                    updated_at: parse_timestamp(&row.get::<_, String>(10)?).map_err(sql_invalid)?,
                    started_at: parse_optional_timestamp(row.get(11)?).map_err(sql_invalid)?,
                    completed_at: parse_optional_timestamp(row.get(12)?).map_err(sql_invalid)?,
                })
            },
        )
        .optional()?
        .ok_or(StoreError::NotFound("job"))
}

fn load_task(connection: &rusqlite::Connection, task_id: &str) -> Result<StoredTask, StoreError> {
    connection
        .query_row(
            "SELECT id, job_id, task_key, seq, state, input, input_sha256, requirements_json,
                    expected_output_sha256, attempts, max_attempts, assigned_worker_id,
                    current_lease_id, output, output_sha256, validation_status, error, compute_ms,
                    created_at, updated_at, started_at, finished_at
             FROM tasks WHERE id = ?1",
            [task_id],
            task_from_row,
        )
        .optional()?
        .ok_or(StoreError::NotFound("task"))
}

fn load_tasks(
    connection: &rusqlite::Connection,
    job_id: &str,
) -> Result<Vec<StoredTask>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT id, job_id, task_key, seq, state, input, input_sha256, requirements_json,
                expected_output_sha256, attempts, max_attempts, assigned_worker_id,
                current_lease_id, output, output_sha256, validation_status, error, compute_ms,
                created_at, updated_at, started_at, finished_at
         FROM tasks WHERE job_id = ?1 ORDER BY seq ASC",
    )?;
    let rows = statement.query_map([job_id], task_from_row)?;
    let mut tasks = Vec::new();
    for row in rows {
        tasks.push(row?);
    }
    Ok(tasks)
}

fn task_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredTask> {
    let state: String = row.get(4)?;
    let requirements: String = row.get(7)?;
    let requirements: TaskRequirements =
        serde_json::from_str(&requirements).map_err(sql_invalid)?;
    Ok(StoredTask {
        id: row.get(0)?,
        job_id: row.get(1)?,
        key: row.get(2)?,
        sequence: row.get(3)?,
        state: parse_task_state(&state).map_err(sql_invalid)?,
        input: row.get(5)?,
        input_sha256: row.get(6)?,
        requirements,
        expected_output_sha256: row.get(8)?,
        attempts: row.get::<_, i64>(9)?.max(0) as u32,
        max_attempts: row.get::<_, i64>(10)?.max(0) as u32,
        assigned_worker_id: row.get(11)?,
        current_lease_id: row.get(12)?,
        output: row.get(13)?,
        output_sha256: row.get(14)?,
        validation_status: row.get(15)?,
        error: row.get(16)?,
        compute_ms: row.get::<_, i64>(17)?.max(0) as u64,
        created_at: parse_timestamp(&row.get::<_, String>(18)?).map_err(sql_invalid)?,
        updated_at: parse_timestamp(&row.get::<_, String>(19)?).map_err(sql_invalid)?,
        started_at: parse_optional_timestamp(row.get(20)?).map_err(sql_invalid)?,
        finished_at: parse_optional_timestamp(row.get(21)?).map_err(sql_invalid)?,
    })
}

fn bounded_compute_ms(reported: u64, requirements: &TaskRequirements) -> u64 {
    requirements
        .timeout_secs
        .saturating_mul(1_000)
        .saturating_add(5_000)
        .min(reported)
}

fn bounded_fuel(reported: u64, requirements: &TaskRequirements) -> u64 {
    reported.min(requirements.fuel)
}

fn sanitize_error(message: &str) -> String {
    message
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(MAX_ERROR_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn sql_invalid(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{artifact, enrolled_store, manifest, sha_hex};
    use getter_protocol::AggregationSpec;
    use serde_json::Value;

    fn submit(store: &Store, now: DateTime<Utc>, output: &[u8]) -> StoredJob {
        let mut manifest = manifest(output, true);
        manifest.aggregation = AggregationSpec::JsonSum {
            field: "value".into(),
        };
        store.create_job(&manifest, &artifact(), now).expect("job")
    }

    fn claim(store: &Store, worker_id: &str, now: DateTime<Utc>) -> LeaseAssignment {
        store
            .claim_assignments(worker_id, 1, 20, now)
            .expect("claim")
            .into_iter()
            .next()
            .expect("assignment")
    }

    fn success(output: &[u8]) -> Value {
        serde_json::from_slice(output).expect("json output")
    }

    #[test]
    fn full_job_lifecycle_aggregates_and_marks_verified() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let output = br#"{"value":42}"#;
        let job = submit(&store, now, output);
        let assignment = claim(&store, &worker_id, now);
        store
            .mark_started(
                &worker_id,
                &assignment.lease_id,
                &assignment.lease_token,
                now + Duration::seconds(1),
            )
            .expect("start");
        let receipt = store
            .record_result(
                ResultSubmission {
                    worker_id: worker_id.clone(),
                    lease_id: assignment.lease_id.clone(),
                    task_id: assignment.task_id.clone(),
                    lease_token: assignment.lease_token.clone(),
                    output: Some(output.to_vec()),
                    failure: None,
                    retryable: false,
                    requeue: None,
                    compute_ms: 25,
                    fuel_used: 100,
                },
                now + Duration::seconds(2),
            )
            .expect("result");
        assert!(receipt.accepted);
        assert_eq!(receipt.job_state, JobState::Completed);
        let detail = store.job_detail(&job.id).expect("detail");
        assert_eq!(detail.job.state, JobState::Completed);
        let result = detail.job.result.expect("result");
        assert_eq!(result.aggregate, serde_json::json!({"total":"42"}));
        assert_eq!(result.verified_tasks, 1);
        assert_eq!(result.completed_tasks, 1);
        assert_eq!(detail.tasks[0].state, TaskState::Completed);
        assert_eq!(detail.tasks[0].validation_status, "verified");
        assert_eq!(success(output)["value"], 42);
    }

    #[test]
    fn duplicate_result_is_idempotent_and_stale_worker_is_rejected() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let output = br#"{"value":7}"#;
        let job = submit(&store, now, output);
        let assignment = claim(&store, &worker_id, now);
        let submission = || ResultSubmission {
            worker_id: worker_id.clone(),
            lease_id: assignment.lease_id.clone(),
            task_id: assignment.task_id.clone(),
            lease_token: assignment.lease_token.clone(),
            output: Some(output.to_vec()),
            failure: None,
            retryable: false,
            requeue: None,
            compute_ms: 5,
            fuel_used: 5,
        };
        let first = store
            .record_result(submission(), now + Duration::seconds(1))
            .expect("first");
        assert!(first.accepted && !first.duplicate);
        let second = store
            .record_result(submission(), now + Duration::seconds(2))
            .expect("second");
        assert!(second.accepted && second.duplicate);
        let detail = store.job_detail(&job.id).expect("detail");
        assert_eq!(detail.job.state, JobState::Completed);
        assert_eq!(detail.tasks[0].compute_ms, 5);
    }

    #[test]
    fn lease_expiry_requeues_then_exhausts_attempts() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let output = br#"{"value":1}"#;
        let job = submit(&store, now, output);
        let first = claim(&store, &worker_id, now);
        let sweep = store
            .expire_leases(now + Duration::seconds(21))
            .expect("expire");
        assert_eq!(sweep.expired_leases.len(), 1);
        assert_eq!(sweep.expired_leases[0].next_task_state, TaskState::Queued);
        let second = store
            .claim_assignments(&worker_id, 1, 3600, now + Duration::seconds(22))
            .expect("claim")
            .into_iter()
            .next()
            .expect("second assignment");
        assert_ne!(first.lease_id, second.lease_id);
        assert_eq!(second.attempt, 2);
        let _ = store
            .expire_leases(now + Duration::seconds(43))
            .expect("expire");
        let detail = store.job_detail(&job.id).expect("detail");
        assert_eq!(detail.tasks[0].state, TaskState::Failed);
        assert_eq!(detail.job.state, JobState::Failed);
    }

    #[test]
    fn infrastructure_requeue_does_not_consume_attempts() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let output = br#"{"value":6}"#;
        let job = submit(&store, now, output);
        let first = claim(&store, &worker_id, now);
        let receipt = store
            .record_result(
                ResultSubmission {
                    worker_id: worker_id.clone(),
                    lease_id: first.lease_id.clone(),
                    task_id: first.task_id.clone(),
                    lease_token: first.lease_token.clone(),
                    output: None,
                    failure: None,
                    retryable: false,
                    requeue: Some("worker paused".into()),
                    compute_ms: 0,
                    fuel_used: 0,
                },
                now + Duration::seconds(1),
            )
            .expect("requeue");
        assert!(receipt.accepted);
        assert_eq!(receipt.task_state, TaskState::Queued);
        let detail = store.job_detail(&job.id).expect("detail");
        assert_eq!(detail.tasks[0].attempts, 0);
        let second = claim(&store, &worker_id, now + Duration::seconds(2));
        assert_eq!(second.attempt, 1);
        let receipt = store
            .record_result(
                ResultSubmission {
                    worker_id,
                    lease_id: second.lease_id,
                    task_id: second.task_id,
                    lease_token: second.lease_token,
                    output: Some(output.to_vec()),
                    failure: None,
                    retryable: false,
                    requeue: None,
                    compute_ms: 2,
                    fuel_used: 2,
                },
                now + Duration::seconds(3),
            )
            .expect("result");
        assert!(receipt.accepted);
        assert_eq!(receipt.job_state, JobState::Completed);
    }

    #[test]
    fn late_result_after_expiry_is_not_accepted() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let output = br#"{"value":2}"#;
        let _job = submit(&store, now, output);
        let assignment = claim(&store, &worker_id, now);
        store
            .expire_leases(now + Duration::seconds(21))
            .expect("expire");
        let receipt = store
            .record_result(
                ResultSubmission {
                    worker_id,
                    lease_id: assignment.lease_id,
                    task_id: assignment.task_id,
                    lease_token: assignment.lease_token,
                    output: Some(output.to_vec()),
                    failure: None,
                    retryable: false,
                    requeue: None,
                    compute_ms: 1,
                    fuel_used: 1,
                },
                now + Duration::seconds(22),
            )
            .expect("late");
        assert!(!receipt.accepted);
        assert_eq!(receipt.task_state, TaskState::Queued);
    }

    #[test]
    fn invalid_output_hash_requeues_task() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let job = submit(&store, now, br#"{"value":3}"#);
        let assignment = claim(&store, &worker_id, now);
        let receipt = store
            .record_result(
                ResultSubmission {
                    worker_id,
                    lease_id: assignment.lease_id,
                    task_id: assignment.task_id,
                    lease_token: assignment.lease_token,
                    output: Some(br#"{"value":999}"#.to_vec()),
                    failure: None,
                    retryable: false,
                    requeue: None,
                    compute_ms: 1,
                    fuel_used: 1,
                },
                now + Duration::seconds(1),
            )
            .expect("result");
        assert!(!receipt.accepted);
        assert_eq!(receipt.task_state, TaskState::Queued);
        let detail = store.job_detail(&job.id).expect("detail");
        assert!(detail.tasks[0]
            .error
            .as_deref()
            .unwrap_or("")
            .contains("checksum"));
    }

    #[test]
    fn cancellation_revokes_lease_and_ignores_result() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let _job = submit(&store, now, br#"{"value":4}"#);
        let assignment = claim(&store, &worker_id, now);
        store.cancel_job(&assignment.job_id, now).expect("cancel");
        let mut heartbeat = getter_protocol::WorkerHeartbeat {
            protocol: getter_protocol::PROTOCOL_VERSION.into(),
            participation: getter_protocol::WorkerParticipation::Active,
            capabilities: getter_protocol::WorkerCapabilities {
                abi: vec![getter_protocol::WORKLOAD_ABI.into()],
                os: "linux".into(),
                arch: "x86_64".into(),
                cpu_threads: 2,
                max_concurrency: 2,
                max_task_memory_bytes: 128 * 1024 * 1024,
                max_task_timeout_secs: 60,
                max_output_bytes: 1024 * 1024,
                max_fuel: 1_000_000_000,
                version: "test".into(),
            },
            running_tasks: 1,
            uptime_secs: 1,
            tasks_completed: 0,
            task_failures: 0,
            compute_ms: 0,
            acknowledged_cancellations: Vec::new(),
        };
        let cancels = store
            .heartbeat(&worker_id, &heartbeat, now)
            .expect("heartbeat");
        assert_eq!(cancels, vec![assignment.lease_id.clone()]);
        heartbeat.acknowledged_cancellations = cancels;
        let cancels = store
            .heartbeat(&worker_id, &heartbeat, now + Duration::seconds(1))
            .expect("ack");
        assert!(cancels.is_empty());
        let receipt = store
            .record_result(
                ResultSubmission {
                    worker_id,
                    lease_id: assignment.lease_id,
                    task_id: assignment.task_id,
                    lease_token: assignment.lease_token,
                    output: Some(br#"{"value":4}"#.to_vec()),
                    failure: None,
                    retryable: false,
                    requeue: None,
                    compute_ms: 1,
                    fuel_used: 1,
                },
                now + Duration::seconds(1),
            )
            .expect("late");
        assert!(!receipt.accepted);
        assert_eq!(receipt.job_state, JobState::Cancelled);
        assert_eq!(
            store
                .cancel_job(&assignment.job_id, now)
                .expect("idempotent"),
            JobState::Cancelled
        );
    }

    #[test]
    fn artifact_download_requires_active_lease_and_correct_token() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let _job = submit(&store, now, br#"{"value":5}"#);
        let assignment = claim(&store, &worker_id, now);
        let artifact_access = store
            .lease_artifact(
                &worker_id,
                &assignment.lease_id,
                &assignment.lease_token,
                now,
            )
            .expect("artifact");
        assert_eq!(artifact_access.bytes, artifact());
        assert!(store
            .lease_artifact(&worker_id, &assignment.lease_id, "wrong", now)
            .is_err());
        assert!(store
            .lease_artifact(
                "other-worker",
                &assignment.lease_id,
                &assignment.lease_token,
                now
            )
            .is_err());
    }

    #[test]
    fn claim_respects_local_concurrency() {
        let now = Utc::now();
        let (store, worker_id, _) = enrolled_store(now);
        let output = br#"{"value":1}"#;
        let mut base = manifest(output, true);
        base.max_attempts = 3;
        base.tasks = (0..3)
            .map(|index| getter_protocol::TaskSpec {
                id: format!("task-{index}"),
                input: format!("{index}"),
                requirements: None,
                expected_output_sha256: Some(sha_hex(output)),
            })
            .collect();
        store.create_job(&base, &artifact(), now).expect("job");
        let assignments = store
            .claim_assignments(&worker_id, 10, 20, now)
            .expect("claim");
        // Worker advertises max_concurrency=2.
        assert_eq!(assignments.len(), 2);
        for assignment in &assignments {
            assert_eq!(assignment.workload_name, "test");
            assert!(!assignment.input.contains("expected_output_sha256"));
            assert!(assignment.input == "0" || assignment.input == "1" || assignment.input == "2");
        }
    }
}
