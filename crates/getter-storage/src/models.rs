//! Storage-facing domain records. These are intentionally separate from wire
//! DTOs: they contain lease secrets and raw outputs that are never serialized in
//! administrative responses.

#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use getter_protocol::{
    JobManifest, JobResultRecord, JobState, TaskRequirements, TaskState, VerificationPolicy,
    WorkerCapabilities, WorkerParticipation,
};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct StoredJob {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub state: JobState,
    pub manifest: JobManifest,
    pub artifact_sha256: String,
    pub result: Option<JobResultRecord>,
    pub error: Option<String>,
    pub cancel_requested: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct StoredTask {
    pub id: String,
    pub job_id: String,
    pub key: String,
    pub sequence: i64,
    pub state: TaskState,
    pub input: String,
    pub input_sha256: String,
    pub requirements: TaskRequirements,
    pub expected_output_sha256: Option<String>,
    pub attempts: u32,
    pub max_attempts: u32,
    pub assigned_worker_id: Option<String>,
    pub current_lease_id: Option<String>,
    pub output: Option<Vec<u8>>,
    pub output_sha256: Option<String>,
    pub validation_status: String,
    pub error: Option<String>,
    pub compute_ms: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct StoredJobDetail {
    pub job: StoredJob,
    pub tasks: Vec<StoredTask>,
}

#[derive(Debug, Clone)]
pub struct JobProgressRecord {
    pub total: u64,
    pub queued: u64,
    pub assigned: u64,
    pub running: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
}

impl JobProgressRecord {
    pub fn percent_complete(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            ((self.completed + self.failed + self.cancelled) as f64 / self.total as f64) * 100.0
        }
    }
}

#[derive(Debug, Clone)]
pub struct JobSummaryRecord {
    pub id: String,
    pub name: String,
    pub state: JobState,
    pub workload_name: String,
    pub total_tasks: u64,
    pub completed_tasks: u64,
    pub failed_tasks: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub compute_ms: u64,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct WorkerPairingToken {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct StoredWorker {
    pub id: String,
    pub name: String,
    pub public_key_base64: String,
    pub capabilities: WorkerCapabilities,
    pub participation: WorkerParticipation,
    pub created_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone)]
pub struct WorkerAuth {
    pub id: String,
    pub public_key_base64: String,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct WorkerSummaryRecord {
    pub worker: StoredWorker,
    pub status: getter_protocol::WorkerStatus,
    pub successful_tasks: u64,
    pub failed_attempts: u64,
    pub compute_ms: u64,
    pub active_tasks: u64,
}

#[derive(Debug, Clone)]
pub struct WorkerContributionRecord {
    pub worker_id: String,
    pub worker_name: String,
    pub status: getter_protocol::WorkerStatus,
    pub successful_tasks: u64,
    pub failed_attempts: u64,
    pub compute_ms: u64,
    pub last_seen: Option<DateTime<Utc>>,
}

/// A lease issued to a worker. `lease_token` is secret and must never be
/// persisted in plaintext or included in logs.
pub struct LeaseAssignment {
    pub lease_id: String,
    pub lease_token: String,
    pub job_id: String,
    pub job_name: String,
    pub task_id: String,
    pub task_key: String,
    pub attempt: u32,
    pub max_attempts: u32,
    pub lease_expires_at: DateTime<Utc>,
    pub workload_name: String,
    pub abi: String,
    pub artifact_sha256: String,
    pub input: String,
    pub input_sha256: String,
    pub requirements: TaskRequirements,
}

#[derive(Debug, Clone)]
pub struct StartAck {
    pub state: TaskState,
    pub job_state: JobState,
}

#[derive(Debug, Clone)]
pub struct ArtifactAccess {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub struct ResultSubmission {
    pub worker_id: String,
    pub lease_id: String,
    pub task_id: String,
    pub lease_token: String,
    pub output: Option<Vec<u8>>,
    pub failure: Option<String>,
    pub retryable: bool,
    pub requeue: Option<String>,
    pub compute_ms: u64,
    pub fuel_used: u64,
}

#[derive(Debug, Clone)]
pub struct ResultReceipt {
    pub accepted: bool,
    pub duplicate: bool,
    pub task_state: TaskState,
    pub job_state: JobState,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ExpirySweep {
    pub expired_leases: Vec<ExpiredLease>,
    pub jobs_touched: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExpiredLease {
    pub lease_id: String,
    pub task_id: String,
    pub job_id: String,
    pub worker_id: String,
    pub next_task_state: TaskState,
}

#[derive(Debug, Clone)]
pub struct JobStateCounts {
    pub queued: u64,
    pub running: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
}

#[derive(Debug, Clone)]
pub struct CoordinatorStats {
    pub total_workers: u64,
    pub online_workers: u64,
    pub active_tasks: u64,
    pub successful_tasks: u64,
    pub failed_attempts: u64,
    pub verified_tasks: u64,
    pub completed_jobs: u64,
    pub compute_ms: u64,
    pub total_uptime_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ContributionRecord {
    pub summary: CoordinatorStats,
    pub workers: Vec<WorkerContributionRecord>,
}

/// Internal result aggregate persisted in `jobs.result_json`.
#[derive(Debug, Clone)]
pub struct StoredJobResult {
    pub aggregate: Value,
    pub expected_aggregate: Option<Value>,
    pub aggregate_matches_expected: Option<bool>,
    pub verified_tasks: u64,
    pub completed_tasks: u64,
    pub compute_ms: u64,
}

pub fn verification_mode(manifest: &JobManifest) -> VerificationPolicy {
    manifest.verification
}
