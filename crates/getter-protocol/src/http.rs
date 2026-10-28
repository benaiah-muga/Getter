//! HTTP path constants and authentication header names.
//!
//! Keeping these in the protocol crate prevents the coordinator, worker, and
//! doctor command from drifting apart.

#![deny(unsafe_code)]

pub const HEADER_WORKER_ID: &str = "x-getter-worker-id";
pub const HEADER_TIMESTAMP: &str = "x-getter-timestamp";
pub const HEADER_NONCE: &str = "x-getter-nonce";
pub const HEADER_SIGNATURE: &str = "x-getter-signature";
pub const HEADER_LEASE_TOKEN: &str = "x-getter-lease-token";
pub const HEADER_WORKER_VERSION: &str = "x-getter-worker-version";

pub const PATH_HEALTH: &str = "/healthz";
pub const PATH_READY: &str = "/readyz";
pub const PATH_CA: &str = "/v1/ca.pem";
pub const PATH_ENROLL: &str = "/v1/enroll";
pub const PATH_ADMIN_PAIRING: &str = "/v1/admin/pairing-tokens";
pub const PATH_ADMIN_WORKERS: &str = "/v1/admin/workers";
pub const PATH_ADMIN_JOBS: &str = "/v1/admin/jobs";
pub const PATH_ADMIN_STATUS: &str = "/v1/admin/status";
pub const PATH_ADMIN_CONTRIBUTION: &str = "/v1/admin/contribution";
pub const PATH_WORKER_HEARTBEAT: &str = "/v1/worker/heartbeat";
pub const PATH_WORKER_ASSIGNMENTS: &str = "/v1/worker/assignments";
pub const PATH_WORKER_RESULTS: &str = "/v1/worker/results";
pub const PATH_WORKER_LEAVE: &str = "/v1/worker/leave";

/// Maximum accepted HTTP request body across the coordinator API. The task
/// result and artifact paths have tighter endpoint-specific checks.
pub const MAX_HTTP_BODY_BYTES: usize = 48 * 1024 * 1024;

/// Worker request signatures are accepted only within this window.
pub const AUTH_CLOCK_SKEW_SECS: i64 = 90;
/// Nonces are remembered for this long to reject replay.
pub const AUTH_NONCE_TTL_SECS: u64 = 180;

/// Domain separator included in every worker request signature.
pub const WORKER_SIGNATURE_CONTEXT: &str = "getter-worker-request-v1";
