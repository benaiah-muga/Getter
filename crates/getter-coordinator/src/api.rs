//! HTTP handlers. Transport concerns stay here; domain decisions are delegated
//! to `getter-core` and `getter-storage`.

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use chrono::Utc;
use getter_core::auth::{normalize_sha256, pairing_token, sha256_hex, token_hash};
use getter_core::validation::{
    output_preview, validate_artifact, validate_manifest, validate_worker_capabilities,
    CoordinatorLimitsView,
};
use getter_protocol::{
    AssignmentsResponse, CancelResponse, ContributionResponse, CoordinatorStatusResponse,
    EnrollRequest, EnrollResponse, HealthResponse, HeartbeatResponse, JobDetailResponse,
    JobListResponse, JobProgress, JobRecord, JobSubmission, JobSummary, LeaseTokenRequest,
    LeaveRequest, PairingTokenRequest, PairingTokenResponse, ResultAck, StartedResponse,
    TaskAssignment, TaskOutcome, TaskRecord, TaskResultRequest, WorkerContribution,
    WorkerHeartbeat, WorkerListResponse, WorkerParticipation, WorkerSummary, PROTOCOL_VERSION,
};
use getter_storage::{
    JobProgressRecord, LeaseAssignment, StoredJob, StoredTask, WorkerSummaryRecord,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::server::{AppState, VerifiedWorker};

pub(crate) async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol: PROTOCOL_VERSION.into(),
    })
}

pub(crate) async fn ready(State(state): State<AppState>) -> Response {
    if state.store.healthy() {
        StatusCode::OK.into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                protocol: PROTOCOL_VERSION.into(),
            }),
        )
            .into_response()
    }
}

pub(crate) async fn ca_certificate(State(state): State<AppState>) -> Response {
    match &state.ca_pem {
        Some(pem) => {
            let mut response = Response::new(Body::from(pem.as_ref().clone()));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/x-pem-file"),
            );
            headers.insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            if let Some(fingerprint) = &state.ca_fingerprint {
                if let Ok(value) = header::HeaderValue::from_str(fingerprint) {
                    headers.insert("x-getter-ca-fingerprint", value);
                }
            }
            response
        }
        None => ApiError::not_found("TLS is not enabled on this coordinator").into_response(),
    }
}

pub(crate) async fn enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(
            "protocol_mismatch",
            format!("coordinator speaks {PROTOCOL_VERSION}"),
        ));
    }
    let name = request.worker_name.trim();
    if name.is_empty()
        || name.len() > getter_protocol::MAX_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "invalid_worker_name",
            "invalid worker name",
        ));
    }
    validate_worker_capabilities(&request.capabilities)?;
    let key_bytes = getter_core::init::public_key_bytes(&request.public_key).map_err(|_| {
        ApiError::bad_request(
            "invalid_public_key",
            "worker public key is not valid base64",
        )
    })?;
    if key_bytes.len() != 32 {
        return Err(ApiError::bad_request(
            "invalid_public_key",
            "worker public key must be 32 bytes",
        ));
    }
    let worker = state
        .store
        .enroll_worker(
            &token_hash(&request.pairing_token),
            name,
            &request.public_key,
            &request.capabilities,
            Utc::now(),
        )
        .map_err(|error| match error {
            getter_storage::StoreError::Enrollment(message) => {
                warn!(worker_name = %name, "enrollment rejected");
                ApiError::unauthorized(message)
            }
            other => ApiError::from(other),
        })?;
    info!(worker_id = %worker.id, worker_name = %worker.name, "worker enrolled");
    Ok(Json(EnrollResponse {
        protocol: PROTOCOL_VERSION.into(),
        worker_id: worker.id,
        coordinator_name: state.coordinator_name.to_string(),
        coordinator_url: state.config.public_url.clone(),
        ca_fingerprint: state.ca_fingerprint.clone(),
        server_time: Utc::now(),
    }))
}

pub(crate) async fn create_pairing_token(
    State(state): State<AppState>,
    Json(request): Json<PairingTokenRequest>,
) -> Result<Json<PairingTokenResponse>, ApiError> {
    let name = request.name.trim();
    if name.is_empty()
        || name.len() > getter_protocol::MAX_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "invalid_pairing_name",
            "invalid worker name",
        ));
    }
    let raw = pairing_token();
    let record =
        state
            .store
            .create_pairing_token(name, &token_hash(&raw), Utc::now(), request.ttl_secs)?;
    info!(worker_name = %name, expires_at = %record.expires_at, "pairing token created");
    Ok(Json(PairingTokenResponse {
        token: raw,
        name: record.name,
        expires_at: record.expires_at,
        coordinator_url: state.config.public_url.clone(),
        ca_fingerprint: state.ca_fingerprint.clone(),
    }))
}

pub(crate) async fn list_workers(
    State(state): State<AppState>,
) -> Result<Json<WorkerListResponse>, ApiError> {
    let workers = state
        .store
        .list_workers(Utc::now(), state.heartbeat_timeout_secs)?;
    Ok(Json(WorkerListResponse {
        workers: workers.into_iter().map(worker_summary).collect(),
    }))
}

fn worker_summary(summary: WorkerSummaryRecord) -> WorkerSummary {
    WorkerSummary {
        id: summary.worker.id,
        name: summary.worker.name,
        status: summary.status,
        participation: summary.worker.participation,
        capabilities: summary.worker.capabilities,
        created_at: summary.worker.created_at,
        last_seen: summary.worker.last_seen,
        successful_tasks: summary.successful_tasks,
        failed_attempts: summary.failed_attempts,
        compute_ms: summary.compute_ms,
        active_tasks: summary.active_tasks,
    }
}

pub(crate) async fn revoke_worker(
    State(state): State<AppState>,
    Path(worker_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.store.revoke_worker(&worker_id, Utc::now())?;
    info!(worker_id = %worker_id, "worker revoked");
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn submit_job(
    State(state): State<AppState>,
    Json(submission): Json<JobSubmission>,
) -> Result<Response, ApiError> {
    let limits = state.config.limits.clone();
    let view = CoordinatorLimitsView {
        max_tasks_per_job: limits.max_tasks_per_job,
        max_artifact_bytes: limits.max_artifact_bytes,
        max_total_input_bytes: limits.max_total_input_bytes,
        max_total_output_bytes: limits.max_total_output_bytes,
        max_result_bytes: limits.max_result_bytes,
        allow_trusted_verification: limits.allow_trusted_verification,
    };
    let mut manifest = submission.manifest;
    getter_core::validation::normalize_manifest(&mut manifest);
    validate_manifest(&manifest, view)?;
    let encoded_limit = limits
        .max_artifact_bytes
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(64);
    if submission.artifact_base64.len() > encoded_limit {
        return Err(ApiError::unprocessable(
            "artifact_too_large",
            "workload artifact exceeds the coordinator limit",
        ));
    }
    let artifact = base64::engine::general_purpose::STANDARD
        .decode(submission.artifact_base64.as_bytes())
        .map_err(|_| {
            ApiError::bad_request("invalid_artifact_encoding", "artifact is not valid base64")
        })?;
    validate_artifact(
        &artifact,
        &manifest.workload.sha256,
        limits.max_artifact_bytes,
    )?;
    let job = state.store.create_job(&manifest, &artifact, Utc::now())?;
    info!(
        job_id = %job.id,
        job_name = %job.name,
        tasks = manifest.tasks.len(),
        "job submitted"
    );
    let detail = state.store.job_detail(&job.id)?;
    let body = job_detail_response(&state, detail)?;
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

pub(crate) async fn list_jobs(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<JobListResponse>, ApiError> {
    let jobs = state.store.list_jobs(query.limit.unwrap_or(50))?;
    Ok(Json(JobListResponse {
        jobs: jobs
            .into_iter()
            .map(|job| JobSummary {
                id: job.id,
                name: job.name,
                state: job.state,
                workload_name: job.workload_name,
                total_tasks: job.total_tasks,
                completed_tasks: job.completed_tasks,
                failed_tasks: job.failed_tasks,
                created_at: job.created_at,
                updated_at: job.updated_at,
                compute_ms: job.compute_ms,
                verified: job.verified,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    pub(crate) limit: Option<usize>,
}

pub(crate) async fn inspect_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobDetailResponse>, ApiError> {
    let detail = state.store.job_detail(&job_id)?;
    Ok(Json(job_detail_response(&state, detail)?))
}

fn job_detail_response(
    state: &AppState,
    detail: getter_storage::StoredJobDetail,
) -> Result<JobDetailResponse, ApiError> {
    let progress = state.store.job_progress(&detail.job.id)?;
    let worker_names: HashMap<String, String> = state
        .store
        .list_workers(Utc::now(), state.heartbeat_timeout_secs)?
        .into_iter()
        .map(|summary| (summary.worker.id, summary.worker.name))
        .collect();
    let job = job_record(&detail.job);
    let tasks = detail
        .tasks
        .iter()
        .map(|task| task_record(task, &worker_names))
        .collect();
    Ok(JobDetailResponse {
        job,
        tasks,
        progress: progress_record(progress),
        result: detail.job.result.clone(),
    })
}

fn job_record(job: &StoredJob) -> JobRecord {
    JobRecord {
        id: job.id.clone(),
        name: job.name.clone(),
        description: job.description.clone(),
        state: job.state,
        workload_name: job.manifest.workload.name.clone(),
        artifact_sha256: job.artifact_sha256.clone(),
        verification_mode: job.manifest.verification,
        aggregation: job.manifest.aggregation.clone(),
        created_at: job.created_at,
        updated_at: job.updated_at,
        started_at: job.started_at,
        completed_at: job.completed_at,
        cancel_requested: job.cancel_requested,
        error: job.error.clone(),
    }
}

fn task_record(task: &StoredTask, worker_names: &HashMap<String, String>) -> TaskRecord {
    let preview = task
        .output
        .as_deref()
        .and_then(|bytes| output_preview(bytes, 2048));
    TaskRecord {
        id: task.id.clone(),
        key: task.key.clone(),
        state: task.state,
        attempts: task.attempts,
        max_attempts: task.max_attempts,
        assigned_worker_id: task.assigned_worker_id.clone(),
        assigned_worker_name: task
            .assigned_worker_id
            .as_ref()
            .and_then(|worker_id| worker_names.get(worker_id).cloned()),
        output_sha256: task.output_sha256.clone(),
        output_preview: preview,
        error: task.error.clone(),
        validation_status: task.validation_status.clone(),
        compute_ms: task.compute_ms,
        created_at: task.created_at,
        started_at: task.started_at,
        finished_at: task.finished_at,
    }
}

fn progress_record(progress: JobProgressRecord) -> JobProgress {
    JobProgress {
        total: progress.total,
        queued: progress.queued,
        assigned: progress.assigned,
        running: progress.running,
        completed: progress.completed,
        failed: progress.failed,
        cancelled: progress.cancelled,
        percent_complete: progress.percent_complete(),
    }
}

pub(crate) async fn cancel_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelResponse>, ApiError> {
    let state_value = state.store.cancel_job(&job_id, Utc::now())?;
    info!(job_id = %job_id, "job cancelled");
    Ok(Json(CancelResponse {
        job_id,
        state: state_value,
        message: "cancellation recorded; running workers are asked to stop".into(),
    }))
}

pub(crate) async fn status(
    State(state): State<AppState>,
) -> Result<Json<CoordinatorStatusResponse>, ApiError> {
    let status = state.store.status(
        &state.coordinator_name,
        state.started_at.elapsed().as_secs(),
        Utc::now(),
        state.heartbeat_timeout_secs,
    )?;
    Ok(Json(status))
}

pub(crate) async fn contribution(
    State(state): State<AppState>,
) -> Result<Json<ContributionResponse>, ApiError> {
    let record = state
        .store
        .contribution(Utc::now(), state.heartbeat_timeout_secs)?;
    let summary = record.summary;
    Ok(Json(ContributionResponse {
        generated_at: Utc::now(),
        coordinator_name: state.coordinator_name.to_string(),
        summary: getter_protocol::ContributionSummary {
            successful_tasks: summary.successful_tasks,
            failed_attempts: summary.failed_attempts,
            completed_jobs: summary.completed_jobs,
            worker_count: summary.total_workers,
            online_workers: summary.online_workers,
            compute_ms: summary.compute_ms,
            verified_tasks: summary.verified_tasks,
        },
        workers: record
            .workers
            .into_iter()
            .map(|worker| WorkerContribution {
                worker_id: worker.worker_id,
                worker_name: worker.worker_name,
                status: worker.status,
                successful_tasks: worker.successful_tasks,
                failed_attempts: worker.failed_attempts,
                compute_ms: worker.compute_ms,
                last_seen: worker.last_seen,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct AssignmentQuery {
    #[serde(default)]
    pub(crate) max: Option<usize>,
}

pub(crate) async fn assignments(
    State(state): State<AppState>,
    Extension(worker): Extension<VerifiedWorker>,
    Query(query): Query<AssignmentQuery>,
) -> Result<Json<AssignmentsResponse>, ApiError> {
    let limit = query.max.unwrap_or(1).clamp(1, 32);
    let assignments = state.store.claim_assignments(
        &worker.0,
        limit,
        state.heartbeat_timeout_secs,
        Utc::now(),
    )?;
    Ok(Json(AssignmentsResponse {
        protocol: PROTOCOL_VERSION.into(),
        assignments: assignments.into_iter().map(assignment).collect(),
        coordinator_time: Utc::now(),
    }))
}

fn assignment(assignment: LeaseAssignment) -> TaskAssignment {
    let artifact_url = format!("/v1/worker/leases/{}/artifact", assignment.lease_id);
    TaskAssignment {
        protocol: PROTOCOL_VERSION.into(),
        lease_id: assignment.lease_id,
        lease_token: assignment.lease_token,
        job_id: assignment.job_id,
        job_name: assignment.job_name,
        task_id: assignment.task_id,
        task_key: assignment.task_key,
        attempt: assignment.attempt,
        max_attempts: assignment.max_attempts,
        lease_expires_at: assignment.lease_expires_at,
        workload_name: assignment.workload_name,
        abi: assignment.abi,
        artifact_sha256: assignment.artifact_sha256,
        artifact_url,
        input: assignment.input,
        input_sha256: assignment.input_sha256,
        requirements: assignment.requirements,
    }
}

pub(crate) async fn heartbeat(
    State(state): State<AppState>,
    Extension(worker): Extension<VerifiedWorker>,
    Json(request): Json<WorkerHeartbeat>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(
            "protocol_mismatch",
            "heartbeat protocol mismatch",
        ));
    }
    if request.participation != WorkerParticipation::Offline {
        validate_worker_capabilities(&request.capabilities)?;
    }
    if request.acknowledged_cancellations.len() > 64
        || request
            .acknowledged_cancellations
            .iter()
            .any(|lease_id| lease_id.len() > 128 || lease_id.is_empty())
    {
        return Err(ApiError::bad_request(
            "invalid_cancellation_ack",
            "at most 64 cancellation acknowledgements of bounded length are accepted per heartbeat",
        ));
    }
    let cancel_leases = if request.participation == WorkerParticipation::Offline {
        state.store.leave_worker(&worker.0, Utc::now())?;
        Vec::new()
    } else {
        state.store.heartbeat(&worker.0, &request, Utc::now())?
    };
    Ok(Json(HeartbeatResponse {
        protocol: PROTOCOL_VERSION.into(),
        coordinator_time: Utc::now(),
        cancel_leases,
    }))
}

pub(crate) async fn mark_started(
    State(state): State<AppState>,
    Extension(worker): Extension<VerifiedWorker>,
    Path(lease_id): Path<String>,
    Json(request): Json<LeaseTokenRequest>,
) -> Result<Json<StartedResponse>, ApiError> {
    let ack = state
        .store
        .mark_started(&worker.0, &lease_id, &request.lease_token, Utc::now())?;
    Ok(Json(StartedResponse {
        accepted: true,
        state: ack.state,
        coordinator_time: Utc::now(),
    }))
}

pub(crate) async fn lease_artifact(
    State(state): State<AppState>,
    Extension(worker): Extension<VerifiedWorker>,
    Path(lease_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = headers
        .get(getter_protocol::HEADER_LEASE_TOKEN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing lease token header"))?;
    let artifact = state
        .store
        .lease_artifact(&worker.0, &lease_id, token, Utc::now())?;
    let mut response = Response::new(Body::from(artifact.bytes));
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/wasm"),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if let Ok(value) = header::HeaderValue::from_str(&artifact.sha256) {
        response_headers.insert("x-getter-artifact-sha256", value);
    }
    Ok(response)
}

pub(crate) async fn submit_result(
    State(state): State<AppState>,
    Extension(worker): Extension<VerifiedWorker>,
    Json(request): Json<TaskResultRequest>,
) -> Result<Json<ResultAck>, ApiError> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(
            "protocol_mismatch",
            "result protocol mismatch",
        ));
    }
    if request.lease_id.is_empty() || request.task_id.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_result",
            "lease and task ids are required",
        ));
    }
    let max = state.config.limits.max_result_bytes;
    let (output, failure, retryable, requeue) = match request.outcome {
        TaskOutcome::Success {
            output_base64,
            output_sha256,
        } => {
            if output_base64.len() > max.saturating_mul(4).saturating_div(3).saturating_add(64) {
                return Err(ApiError::unprocessable(
                    "result_too_large",
                    "result exceeds the coordinator's result limit",
                ));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(output_base64.as_bytes())
                .map_err(|_| {
                    ApiError::bad_request("invalid_result_encoding", "result is not valid base64")
                })?;
            if bytes.len() > max {
                return Err(ApiError::unprocessable(
                    "result_too_large",
                    "result exceeds the coordinator's result limit",
                ));
            }
            if sha256_hex(&bytes) != normalize_sha256(&output_sha256) {
                return Err(ApiError::unprocessable(
                    "invalid_output_hash",
                    "worker-declared output digest does not match the received bytes",
                ));
            }
            (Some(bytes), None, false, None)
        }
        TaskOutcome::Failure { message, retryable } => (None, Some(message), retryable, None),
        TaskOutcome::Requeue { reason } => (None, None, false, Some(reason)),
    };
    let receipt = state.store.record_result(
        getter_storage::ResultSubmission {
            worker_id: worker.0,
            lease_id: request.lease_id,
            task_id: request.task_id,
            lease_token: request.lease_token,
            output,
            failure,
            retryable,
            requeue,
            compute_ms: request.compute_ms,
            fuel_used: request.fuel_used,
        },
        Utc::now(),
    )?;
    Ok(Json(ResultAck {
        accepted: receipt.accepted,
        duplicate: receipt.duplicate,
        task_state: receipt.task_state,
        job_state: receipt.job_state,
        message: receipt.message,
    }))
}

pub(crate) async fn leave(
    State(state): State<AppState>,
    Extension(worker): Extension<VerifiedWorker>,
    Json(request): Json<LeaveRequest>,
) -> Result<StatusCode, ApiError> {
    if request.protocol != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(
            "protocol_mismatch",
            "leave protocol mismatch",
        ));
    }
    state.store.leave_worker(&worker.0, Utc::now())?;
    info!(worker_id = %worker.0, "worker disconnected gracefully");
    Ok(StatusCode::NO_CONTENT)
}
