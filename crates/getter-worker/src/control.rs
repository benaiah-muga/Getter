//! Loopback-only worker control API used by the CLI.
//!
//! The API is never bound to a non-loopback address (validated in
//! [`getter_core::config::WorkerConfig`]) and requires a per-worker random bearer
//! token stored with 0600 permissions. It has no LAN surface.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use getter_core::auth::constant_time_eq;
use serde::Serialize;
use tokio::net::TcpListener;

use crate::error::WorkerError;
use crate::state::{ActiveTaskSnapshot, WorkerState};

#[derive(Clone)]
struct ControlState {
    worker: Arc<WorkerState>,
    token: Arc<str>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    role: &'static str,
    worker_id: String,
    worker_name: String,
    coordinator_url: String,
    state: &'static str,
    manual_paused: bool,
    battery_paused: bool,
    battery_supported: bool,
    concurrency: u32,
    active_slots: u32,
    available_slots: u32,
    active_tasks: Vec<TaskView>,
    uptime_secs: u64,
    stats: crate::state::LocalStats,
    last_error: Option<String>,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct TaskView {
    lease_id: String,
    job_id: String,
    job_name: String,
    task_key: String,
    cpu_slots: u32,
    started_at: chrono::DateTime<chrono::Utc>,
}

impl From<ActiveTaskSnapshot> for TaskView {
    fn from(task: ActiveTaskSnapshot) -> Self {
        Self {
            lease_id: task.lease_id,
            job_id: task.job_id,
            job_name: task.job_name,
            task_key: task.task_key,
            cpu_slots: task.cpu_slots,
            started_at: task.started_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    ok: bool,
    state: &'static str,
    cancelled_tasks: usize,
    message: String,
}

pub async fn serve(
    listener: TcpListener,
    worker: Arc<WorkerState>,
    token: String,
) -> Result<(), WorkerError> {
    let state = ControlState {
        worker: Arc::clone(&worker),
        token: Arc::from(token),
    };
    let mut stop = worker.shutdown_receiver();
    let app = Router::new()
        .route("/status", get(status))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .route("/shutdown", post(shutdown))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while stop.changed().await.is_ok() {
                if *stop.borrow() {
                    break;
                }
            }
        })
        .await
        .map_err(|error| WorkerError::Runner(format!("control server: {error}")))
}

async fn require_token(
    State(state): State<ControlState>,
    request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match token {
        Some(token) if constant_time_eq(token, &state.token) => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "code": "unauthorized",
                "message": "a valid local control token is required"
            })),
        )
            .into_response(),
    }
}

async fn status(State(state): State<ControlState>) -> Json<StatusResponse> {
    let worker = &state.worker;
    Json(StatusResponse {
        role: "worker",
        worker_id: worker.worker_id.clone(),
        worker_name: worker.worker_name.clone(),
        coordinator_url: worker.coordinator_url.clone(),
        state: if worker.is_shutting_down() {
            "stopping"
        } else {
            worker.pause_description()
        },
        manual_paused: worker.manual_paused(),
        battery_paused: worker.battery_paused(),
        battery_supported: worker.battery_supported(),
        concurrency: worker.capabilities.max_concurrency,
        active_slots: worker.active_slots(),
        available_slots: worker.available_slots(),
        active_tasks: worker
            .active_tasks()
            .into_iter()
            .map(TaskView::from)
            .collect(),
        uptime_secs: worker.uptime_secs(),
        stats: worker.stats(),
        last_error: worker.last_error(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn pause(State(state): State<ControlState>) -> Response {
    match state.worker.set_manual_paused(true) {
        Ok(cancelled_tasks) => Json(ActionResponse {
            ok: true,
            state: "paused",
            cancelled_tasks,
            message: "new assignments stopped; running tasks are cancelled and will be retried"
                .into(),
        })
        .into_response(),
        Err(error) => control_error(error),
    }
}

async fn resume(State(state): State<ControlState>) -> Response {
    match state.worker.set_manual_paused(false) {
        Ok(_) => Json(ActionResponse {
            ok: true,
            state: if state.worker.is_paused() {
                "battery-paused"
            } else {
                "active"
            },
            cancelled_tasks: 0,
            message: "worker will poll for assignments when no pause policy is active".into(),
        })
        .into_response(),
        Err(error) => control_error(error),
    }
}

async fn shutdown(State(state): State<ControlState>) -> Response {
    state.worker.request_shutdown();
    Json(ActionResponse {
        ok: true,
        state: "stopping",
        cancelled_tasks: state.worker.active_count(),
        message: "worker is shutting down; running tasks are cancelled or allowed to finish by the supervisor timeout"
            .into(),
    })
    .into_response()
}

fn control_error(error: WorkerError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "code": "control_error",
            "message": error.to_string(),
        })),
    )
        .into_response()
}
