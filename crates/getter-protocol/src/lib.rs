//! Stable, transport-neutral data formats for Getter.
//!
//! The protocol is versioned independently from the crate version. Breaking
//! changes to any type in this crate require a new [`PROTOCOL_VERSION`].
//! Unknown fields are rejected on inbound administrative and worker messages so
//! typos fail loudly; persisted manifests use the same schema.

#![deny(unsafe_code)]

pub mod discovery;
pub mod http;

pub use discovery::{
    DiscoveryAnnouncement, DiscoveryQuery, DEFAULT_DISCOVERY_PORT, DISCOVERY_MAGIC,
};
pub use http::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wire protocol version. Coordinators reject enrollment from other versions.
pub const PROTOCOL_VERSION: &str = "getter.protocol/v1";
/// Workload ABI implemented by this release.
pub const WORKLOAD_ABI: &str = "getter.abi.v1";
/// User-facing job file format accepted by the CLI.
pub const JOB_FORMAT: &str = "getter.job/v1";

pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_TASK_ID_BYTES: usize = 128;
pub const MAX_TASKS_PER_JOB: usize = 1_000;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TOTAL_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
pub const MAX_TASK_TIMEOUT_SECS: u64 = 3600;
pub const MAX_FUEL: u64 = 100_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

impl std::fmt::Display for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for JobState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("unknown job state {other:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Queued,
    Assigned,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TaskState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub const fn is_active(self) -> bool {
        matches!(self, Self::Assigned | Self::Running)
    }
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TaskState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "assigned" => Ok(Self::Assigned),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("unknown task state {other:?}")),
        }
    }
}

/// Resource and execution requirements shared by submission, scheduling, and
/// runtime enforcement. The worker always intersects these with local maxima;
/// a remote job cannot raise the owner's configured limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequirements {
    #[serde(default = "default_cpu_slots")]
    pub cpu_slots: u32,
    #[serde(default = "default_memory_bytes")]
    pub memory_bytes: u64,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_output_bytes")]
    pub output_bytes: u64,
    #[serde(default = "default_fuel")]
    pub fuel: u64,
}

impl Default for TaskRequirements {
    fn default() -> Self {
        Self {
            cpu_slots: default_cpu_slots(),
            memory_bytes: default_memory_bytes(),
            timeout_secs: default_timeout_secs(),
            output_bytes: default_output_bytes(),
            fuel: default_fuel(),
        }
    }
}

const fn default_cpu_slots() -> u32 {
    1
}

const fn default_memory_bytes() -> u64 {
    128 * 1024 * 1024
}

const fn default_timeout_secs() -> u64 {
    60
}

const fn default_output_bytes() -> u64 {
    1024 * 1024
}

const fn default_fuel() -> u64 {
    5_000_000_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    /// Stable, workload-author supplied task id, unique within the job.
    pub id: String,
    /// Opaque UTF-8 input passed to the workload ABI exactly as supplied.
    pub input: String,
    /// Optional per-task overrides. Missing values fall back to the job-level
    /// requirements rather than merging individual fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<TaskRequirements>,
    /// Trusted reference digest for exact-output validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_output_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDescriptor {
    pub name: String,
    pub abi: String,
    /// Lowercase hex SHA-256 of the submitted WASM bytes.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationPolicy {
    /// Every task must provide a matching `expected_output_sha256` reference.
    ExactSha256,
    /// Development escape hatch. Coordinators must opt in; no correctness claim
    /// is made and the UI labels these results unverified.
    Trusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AggregationSpec {
    None,
    JsonSum { field: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobManifest {
    pub protocol: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub workload: WorkloadDescriptor,
    pub tasks: Vec<TaskSpec>,
    pub requirements: TaskRequirements,
    pub verification: VerificationPolicy,
    pub aggregation: AggregationSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_aggregate: Option<Value>,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u32,
}

const fn default_max_attempts() -> u32 {
    3
}

const fn default_lease_seconds() -> u32 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSubmission {
    pub manifest: JobManifest,
    /// Standard base64 encoding of the WASM artifact.
    pub artifact_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCapabilities {
    pub abi: Vec<String>,
    pub os: String,
    pub arch: String,
    pub cpu_threads: u32,
    pub max_concurrency: u32,
    pub max_task_memory_bytes: u64,
    pub max_task_timeout_secs: u64,
    pub max_output_bytes: u64,
    pub max_fuel: u64,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerParticipation {
    Active,
    Paused,
    Draining,
    Offline,
}

impl WorkerParticipation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHeartbeat {
    pub protocol: String,
    pub participation: WorkerParticipation,
    pub capabilities: WorkerCapabilities,
    pub running_tasks: u32,
    pub uptime_secs: u64,
    pub tasks_completed: u64,
    pub task_failures: u64,
    pub compute_ms: u64,
    /// Cancellation notifications acknowledged since the previous heartbeat.
    #[serde(default)]
    pub acknowledged_cancellations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatResponse {
    pub protocol: String,
    pub coordinator_time: DateTime<Utc>,
    /// Active leases whose job was cancelled. Workers must abort these tasks.
    pub cancel_leases: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub protocol: String,
    pub pairing_token: String,
    pub worker_name: String,
    /// Standard base64 Ed25519 verifying key.
    pub public_key: String,
    pub capabilities: WorkerCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollResponse {
    pub protocol: String,
    pub worker_id: String,
    pub coordinator_name: String,
    pub coordinator_url: String,
    pub ca_fingerprint: Option<String>,
    pub server_time: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAssignment {
    pub protocol: String,
    pub lease_id: String,
    /// One-time lease secret. Never logged.
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
    pub artifact_url: String,
    pub input: String,
    pub input_sha256: String,
    pub requirements: TaskRequirements,
}

impl std::fmt::Debug for TaskAssignment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskAssignment")
            .field("lease_id", &self.lease_id)
            .field("job_id", &self.job_id)
            .field("task_id", &self.task_id)
            .field("task_key", &self.task_key)
            .field("attempt", &self.attempt)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("lease_token", &"<redacted>")
            .field("input", &format_args!("<{} bytes>", self.input.len()))
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentsResponse {
    pub protocol: String,
    pub assignments: Vec<TaskAssignment>,
    pub coordinator_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTokenRequest {
    pub lease_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartedResponse {
    pub accepted: bool,
    pub state: TaskState,
    pub coordinator_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskOutcome {
    Success {
        /// Standard base64 encoded output bytes.
        output_base64: String,
        /// Lowercase hex digest computed by the worker. The coordinator also
        /// recomputes it and signs acceptance on the bytes it actually received.
        output_sha256: String,
    },
    Failure {
        message: String,
        retryable: bool,
    },
    /// The worker could not execute for an infrastructure reason (local pause,
    /// shutdown, stale capability, or a cancelled sandbox). The coordinator
    /// requeues without consuming a workload retry, up to a bounded number of
    /// infrastructure interruptions.
    Requeue {
        reason: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResultRequest {
    pub protocol: String,
    pub lease_id: String,
    pub task_id: String,
    pub lease_token: String,
    pub outcome: TaskOutcome,
    pub compute_ms: u64,
    #[serde(default)]
    pub fuel_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultAck {
    pub accepted: bool,
    pub duplicate: bool,
    pub task_state: TaskState,
    pub job_state: JobState,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaveRequest {
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingTokenRequest {
    pub name: String,
    #[serde(default = "default_pairing_ttl")]
    pub ttl_secs: u64,
}

const fn default_pairing_ttl() -> u64 {
    900
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingTokenResponse {
    pub token: String,
    pub name: String,
    pub expires_at: DateTime<Utc>,
    pub coordinator_url: String,
    pub ca_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Online,
    Paused,
    Offline,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSummary {
    pub id: String,
    pub name: String,
    pub status: WorkerStatus,
    pub participation: WorkerParticipation,
    pub capabilities: WorkerCapabilities,
    pub created_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub successful_tasks: u64,
    pub failed_attempts: u64,
    pub compute_ms: u64,
    pub active_tasks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerListResponse {
    pub workers: Vec<WorkerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    pub id: String,
    pub key: String,
    pub state: TaskState,
    pub attempts: u32,
    pub max_attempts: u32,
    pub assigned_worker_id: Option<String>,
    pub assigned_worker_name: Option<String>,
    pub output_sha256: Option<String>,
    pub output_preview: Option<String>,
    pub error: Option<String>,
    pub validation_status: String,
    pub compute_ms: u64,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobProgress {
    pub total: u64,
    pub queued: u64,
    pub assigned: u64,
    pub running: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub percent_complete: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResultRecord {
    pub aggregate: Value,
    pub expected_aggregate: Option<Value>,
    pub aggregate_matches_expected: Option<bool>,
    pub verified_tasks: u64,
    pub completed_tasks: u64,
    pub compute_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub state: JobState,
    pub workload_name: String,
    pub artifact_sha256: String,
    pub verification_mode: VerificationPolicy,
    pub aggregation: AggregationSpec,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub cancel_requested: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDetailResponse {
    pub job: JobRecord,
    pub tasks: Vec<TaskRecord>,
    pub progress: JobProgress,
    pub result: Option<JobResultRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSummary {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobListResponse {
    pub jobs: Vec<JobSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelResponse {
    pub job_id: String,
    pub state: JobState,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionSummary {
    pub successful_tasks: u64,
    pub failed_attempts: u64,
    pub completed_jobs: u64,
    pub worker_count: u64,
    pub online_workers: u64,
    pub compute_ms: u64,
    pub verified_tasks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerContribution {
    pub worker_id: String,
    pub worker_name: String,
    pub status: WorkerStatus,
    pub successful_tasks: u64,
    pub failed_attempts: u64,
    pub compute_ms: u64,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionResponse {
    pub generated_at: DateTime<Utc>,
    pub coordinator_name: String,
    pub summary: ContributionSummary,
    pub workers: Vec<WorkerContribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorStatusResponse {
    pub version: String,
    pub protocol: String,
    pub coordinator_name: String,
    pub uptime_secs: u64,
    pub online_workers: u64,
    pub total_workers: u64,
    pub queued_jobs: u64,
    pub running_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub active_tasks: u64,
    pub database_healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}
