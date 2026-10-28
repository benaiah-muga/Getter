//! HTTP/TLS server bootstrap, middleware, and background maintenance.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use chrono::Utc;
use getter_core::auth::{
    constant_time_eq, verify_worker_signature, ReplayCheckError, WorkerReplayGuard,
};
use getter_core::config::{GetterConfig, Role};
use getter_core::init::{fingerprint_pem, read_admin_token};
use getter_protocol::{
    AUTH_CLOCK_SKEW_SECS, AUTH_NONCE_TTL_SECS, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
    HEADER_WORKER_ID,
};
use getter_storage::Store;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::api;
use crate::discovery;
use crate::error::ApiError;

#[derive(Clone)]
pub(crate) struct AppState {
    pub store: Arc<Store>,
    pub config: Arc<getter_core::config::CoordinatorConfig>,
    pub coordinator_name: Arc<str>,
    pub admin_token: Arc<str>,
    pub ca_pem: Option<Arc<Vec<u8>>>,
    pub ca_fingerprint: Option<String>,
    pub started_at: Instant,
    pub nonces: Arc<Mutex<WorkerReplayGuard>>,
    pub heartbeat_timeout_secs: u64,
}

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub home: PathBuf,
    pub config: GetterConfig,
}

#[derive(Clone)]
pub(crate) struct VerifiedWorker(pub String);

pub struct CoordinatorRuntime {
    pub local_addr: SocketAddr,
    pub shutdown: tokio::sync::watch::Sender<bool>,
    pub join: JoinHandle<anyhow::Result<()>>,
}

/// Run the coordinator until `shutdown` resolves. The caller owns process
/// supervision; `coordinator start` passes a Ctrl-C future.
pub async fn serve(
    options: ServeOptions,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    options
        .config
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid coordinator configuration: {error}"))?;
    if options.config.role != Role::Coordinator {
        anyhow::bail!("configuration role is not coordinator");
    }
    let config = options
        .config
        .coordinator
        .clone()
        .ok_or_else(|| anyhow::anyhow!("coordinator section is missing"))?;
    let admin_token = read_admin_token(&options.home)
        .map_err(|error| anyhow::anyhow!("could not read admin token: {error}"))?;
    let store = Arc::new(Store::open(&config.database_path)?);
    if let Some(tls) = &config.tls {
        ensure_private_key(&tls.private_key)?;
        std::fs::read(&tls.ca_cert)
            .map_err(|error| anyhow::anyhow!("TLS CA certificate: {error}"))?;
        std::fs::read(&tls.cert_chain)
            .map_err(|error| anyhow::anyhow!("TLS certificate chain: {error}"))?;
    }
    let ca_pem = match &config.tls {
        Some(tls) => Some(Arc::new(std::fs::read(&tls.ca_cert)?)),
        None => None,
    };
    let ca_fingerprint = ca_pem
        .as_deref()
        .map(|pem| fingerprint_pem(pem))
        .transpose()
        .map_err(|error| anyhow::anyhow!("could not fingerprint CA certificate: {error}"))?;
    let state = AppState {
        store: Arc::clone(&store),
        config: Arc::new(config.clone()),
        coordinator_name: Arc::from(options.config.name.as_str()),
        admin_token: Arc::from(admin_token.as_str()),
        ca_pem,
        ca_fingerprint: ca_fingerprint.clone(),
        started_at: Instant::now(),
        nonces: Arc::new(Mutex::new(WorkerReplayGuard::new(
            Duration::from_secs(AUTH_NONCE_TTL_SECS),
            262_144,
            100_000,
            Duration::from_secs(60),
            76_800,
        ))),
        heartbeat_timeout_secs: config.limits.heartbeat_timeout_secs,
    };
    let app = router(state);
    let bind = config.bind;

    let expiry_store = Arc::clone(&store);
    let expiry_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match expiry_store.expire_leases(Utc::now()) {
                Ok(sweep) if !sweep.expired_leases.is_empty() => {
                    for lease in &sweep.expired_leases {
                        warn!(
                            lease_id = %lease.lease_id,
                            task_id = %lease.task_id,
                            worker_id = %lease.worker_id,
                            next_state = %lease.next_task_state,
                            "lease expired; recovered task"
                        );
                    }
                }
                Ok(_) => {}
                Err(error) => warn!(error = %error, "lease expiry sweep failed"),
            }
        }
    });

    let stale_store = Arc::clone(&store);
    let heartbeat_timeout = config.limits.heartbeat_timeout_secs;
    let stale_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match stale_store.mark_stale_workers_offline(Utc::now(), heartbeat_timeout) {
                Ok(changed) if changed > 0 => {
                    info!(changed, "marked stale workers offline");
                }
                Ok(_) => {}
                Err(error) => warn!(error = %error, "stale-worker sweep failed"),
            }
        }
    });

    let discovery_task = if config.discovery.enabled {
        Some(discovery::spawn_announcer(
            config.discovery.clone(),
            options.config.name.clone(),
            config.public_url.clone(),
            ca_fingerprint,
        ))
    } else {
        None
    };

    let tls_paths = config.tls.clone();
    let mut shutdown = Box::pin(shutdown);
    let handle = axum_server::Handle::new();
    let graceful_handle = handle.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = &mut shutdown => {
                let _ = shutdown_tx.send(true);
                graceful_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            }
            result = shutdown_rx.changed() => {
                if result.is_ok() {
                    graceful_handle.graceful_shutdown(Some(Duration::from_secs(10)));
                }
            }
        }
    });

    info!(
        name = %options.config.name,
        bind = %bind,
        tls = tls_paths.is_some(),
        database = %config.database_path.display(),
        "starting Getter coordinator"
    );

    let result = match tls_paths {
        Some(tls) => {
            let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &tls.cert_chain,
                &tls.private_key,
            )
            .await
            .map_err(|error| anyhow::anyhow!("could not load TLS material: {error}"))?;
            axum_server::bind_rustls(bind, rustls)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
        None => {
            warn!(
                bind = %bind,
                "TLS is disabled; only loopback or explicitly permitted development bindings are allowed"
            );
            axum_server::bind(bind)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    };

    expiry_task.abort();
    stale_task.abort();
    if let Some(task) = discovery_task {
        task.abort();
    }
    result.map_err(|error| anyhow::anyhow!("coordinator server failed: {error}"))
}

fn ensure_private_key(path: &std::path::Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("TLS private key {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "TLS private key {} must be a regular file, not a symlink",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "TLS private key {} must not be readable by group or other users (chmod 600)",
                path.display()
            );
        }
    }
    Ok(())
}

/// Spawn the coordinator on a caller-selected port and return a handle useful
/// for integration tests and embedding. The task owns all server state.
pub async fn spawn_coordinator(options: ServeOptions) -> anyhow::Result<CoordinatorRuntime> {
    let config = options
        .config
        .coordinator
        .clone()
        .ok_or_else(|| anyhow::anyhow!("coordinator section missing"))?;
    let local_addr = config.bind;
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let join = tokio::spawn(async move {
        let mut receiver = shutdown_rx;
        serve(options, async move {
            while receiver.changed().await.is_ok() {
                if *receiver.borrow() {
                    break;
                }
            }
        })
        .await
    });
    // Give the listener a brief chance to bind before returning; tests also
    // probe /healthz, so a bind failure surfaces quickly.
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(CoordinatorRuntime {
        local_addr,
        shutdown,
        join,
    })
}

pub(crate) fn router(state: AppState) -> Router {
    let public = Router::new()
        .route(getter_protocol::PATH_HEALTH, get(api::health))
        .route(getter_protocol::PATH_READY, get(api::ready))
        .route(getter_protocol::PATH_CA, get(api::ca_certificate))
        .route(
            getter_protocol::PATH_ENROLL,
            post(api::enroll).layer(DefaultBodyLimit::max(64 * 1024)),
        );

    let admin_state = state.clone();
    let admin = Router::new()
        .route(
            getter_protocol::PATH_ADMIN_PAIRING,
            post(api::create_pairing_token),
        )
        .route(getter_protocol::PATH_ADMIN_WORKERS, get(api::list_workers))
        .route("/v1/admin/workers/{worker_id}", delete(api::revoke_worker))
        .route(
            getter_protocol::PATH_ADMIN_JOBS,
            get(api::list_jobs).post(api::submit_job),
        )
        .route("/v1/admin/jobs/{job_id}", get(api::inspect_job))
        .route("/v1/admin/jobs/{job_id}/cancel", post(api::cancel_job))
        .route(getter_protocol::PATH_ADMIN_STATUS, get(api::status))
        .route(
            getter_protocol::PATH_ADMIN_CONTRIBUTION,
            get(api::contribution),
        )
        .route_layer(middleware::from_fn_with_state(admin_state, require_admin));

    let worker_state = state.clone();
    let worker = Router::new()
        .route(
            getter_protocol::PATH_WORKER_ASSIGNMENTS,
            get(api::assignments),
        )
        .route(getter_protocol::PATH_WORKER_HEARTBEAT, post(api::heartbeat))
        .route(
            "/v1/worker/leases/{lease_id}/start",
            post(api::mark_started),
        )
        .route(
            "/v1/worker/leases/{lease_id}/artifact",
            get(api::lease_artifact),
        )
        .route(
            getter_protocol::PATH_WORKER_RESULTS,
            post(api::submit_result),
        )
        .route(getter_protocol::PATH_WORKER_LEAVE, post(api::leave))
        .route_layer(middleware::from_fn_with_state(worker_state, require_worker));

    let body_limit = state.config.limits.max_http_body_bytes;
    Router::new()
        .merge(public)
        .merge(admin)
        .merge(worker)
        .layer(middleware::from_fn(no_store))
        .layer(middleware::from_fn(log_requests))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response
}

async fn log_requests(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::debug!(
        %method,
        path = %path,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "coordinator request"
    );
    response
}

async fn require_admin(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match provided {
        Some(token) if constant_time_eq(token, &state.admin_token) => next.run(request).await,
        _ => ApiError::unauthorized("a valid coordinator admin token is required").into_response(),
    }
}

async fn require_worker(State(state): State<AppState>, request: Request, next: Next) -> Response {
    match authenticate_worker(&state, request).await {
        Ok(request) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

async fn authenticate_worker(state: &AppState, request: Request) -> Result<Request, ApiError> {
    let worker_id = header_string(&request, HEADER_WORKER_ID)?;
    let timestamp = header_string(&request, HEADER_TIMESTAMP)?;
    let nonce = header_string(&request, HEADER_NONCE)?;
    let signature = header_string(&request, HEADER_SIGNATURE)?;
    if worker_id.len() > 128 || nonce.len() < 8 || nonce.len() > 128 {
        return Err(ApiError::unauthorized(
            "malformed worker authentication headers",
        ));
    }
    let timestamp: i64 = timestamp
        .parse()
        .map_err(|_| ApiError::unauthorized("invalid worker request timestamp"))?;
    let now = Utc::now().timestamp();
    if now.abs_diff(timestamp) > AUTH_CLOCK_SKEW_SECS as u64 {
        return Err(ApiError::unauthorized(
            "worker request timestamp is outside the allowed clock window",
        ));
    }
    let auth = state
        .store
        .worker_auth(&worker_id)
        .map_err(|error| match error {
            getter_storage::StoreError::NotFound(_) => {
                ApiError::unauthorized("unknown worker identity")
            }
            other => ApiError::from(other),
        })?;
    if auth.revoked {
        return Err(ApiError::forbidden("worker has been revoked"));
    }
    let (parts, body) = request.into_parts();
    let max = state.config.limits.max_http_body_bytes;
    let bytes = to_bytes(body, max).await.map_err(|_| {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "request body exceeds coordinator limit",
        )
    })?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let message = getter_core::auth::worker_signature_message(
        &worker_id,
        parts.method.as_str(),
        path_and_query,
        timestamp,
        &nonce,
        &bytes,
    );
    verify_worker_signature(&auth.public_key_base64, &message, &signature)
        .map_err(ApiError::unauthorized)?;
    {
        let mut cache = state
            .nonces
            .lock()
            .map_err(|_| ApiError::internal("nonce cache", "poisoned"))?;
        match cache.check_and_insert(&worker_id, &nonce, Instant::now()) {
            Ok(()) => {}
            Err(ReplayCheckError::Replay) => {
                return Err(ApiError::unauthorized(
                    "worker request nonce was already used",
                ))
            }
            Err(ReplayCheckError::RateLimited) => {
                return Err(ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    "worker request rate limit exceeded; retry shortly",
                ))
            }
            Err(ReplayCheckError::Capacity) => {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "replay_guard_capacity",
                    "coordinator authentication capacity is temporarily exhausted",
                ))
            }
        }
    }
    tracing::trace!(worker_id = %worker_id, method = %parts.method, path = %path_and_query, "worker request authenticated");
    let mut request = Request::from_parts(parts, Body::from(bytes));
    request.extensions_mut().insert(VerifiedWorker(worker_id));
    Ok(request)
}

fn header_string(request: &Request, name: &str) -> Result<String, ApiError> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ApiError::unauthorized(format!("missing {name} header")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::Request;
    use chrono::Utc;
    use getter_core::auth::{self, WorkerSigningKey};
    use getter_protocol::{
        EnrollRequest, EnrollResponse, PairingTokenRequest, PairingTokenResponse,
        WorkerCapabilities, WorkerHeartbeat, WorkerParticipation, PROTOCOL_VERSION, WORKLOAD_ABI,
    };
    use getter_storage::Store;
    use tower::ServiceExt;

    fn coordinator_config() -> getter_core::config::CoordinatorConfig {
        getter_core::config::CoordinatorConfig {
            bind: "127.0.0.1:47810".parse().expect("bind"),
            public_url: "http://127.0.0.1:47810".into(),
            database_path: std::path::PathBuf::from("/tmp/getter-http-test.db"),
            tls: None,
            discovery: getter_core::config::DiscoveryConfig::default(),
            limits: getter_core::config::CoordinatorLimits::default(),
            allow_insecure_remote: false,
        }
    }

    fn capabilities() -> WorkerCapabilities {
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

    fn test_state() -> AppState {
        AppState {
            store: Arc::new(Store::in_memory().expect("store")),
            config: Arc::new(coordinator_config()),
            coordinator_name: Arc::from("test-coordinator"),
            admin_token: Arc::from("admin-secret"),
            ca_pem: None,
            ca_fingerprint: None,
            started_at: Instant::now(),
            nonces: Arc::new(Mutex::new(WorkerReplayGuard::new(
                Duration::from_secs(60),
                64,
                100,
                Duration::from_secs(60),
                100,
            ))),
            heartbeat_timeout_secs: 20,
        }
    }

    fn app(state: &AppState) -> Router {
        router(state.clone())
    }

    async fn response_body(response: Response) -> (StatusCode, Vec<u8>) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, bytes)
    }

    async fn admin_post<T: serde::Serialize>(
        state: &AppState,
        path: &str,
        body: &T,
    ) -> (StatusCode, Vec<u8>) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, "Bearer admin-secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).expect("json")))
            .expect("request");
        let response = app(state).oneshot(request).await.expect("response");
        response_body(response).await
    }

    fn worker_request(
        method: &str,
        path: &str,
        body: &[u8],
        worker_id: &str,
        key: &WorkerSigningKey,
    ) -> Request<Body> {
        let timestamp = Utc::now().timestamp();
        let nonce = auth::nonce();
        let message =
            auth::worker_signature_message(worker_id, method, path, timestamp, &nonce, body);
        let signature = key.sign(&message);
        Request::builder()
            .method(method)
            .uri(path)
            .header(HEADER_WORKER_ID, worker_id)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_vec()))
            .expect("request")
    }

    #[tokio::test]
    async fn health_is_public_and_admin_requires_bearer() {
        let state = test_state();
        let response = app(&state)
            .oneshot(
                Request::builder()
                    .uri(getter_protocol::PATH_HEALTH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let response = app(&state)
            .oneshot(
                Request::builder()
                    .uri(getter_protocol::PATH_ADMIN_STATUS)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app(&state)
            .oneshot(
                Request::builder()
                    .uri(getter_protocol::PATH_ADMIN_STATUS)
                    .header(header::AUTHORIZATION, "Bearer wrong")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app(&state)
            .oneshot(
                Request::builder()
                    .uri(getter_protocol::PATH_ADMIN_STATUS)
                    .header(header::AUTHORIZATION, "Bearer admin-secret")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn enrollment_is_one_time_and_worker_requests_are_signed_and_replay_safe() {
        let state = test_state();
        let (status, body) = admin_post(
            &state,
            getter_protocol::PATH_ADMIN_PAIRING,
            &PairingTokenRequest {
                name: "worker-a".into(),
                ttl_secs: 600,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let pairing: PairingTokenResponse = serde_json::from_slice(&body).expect("pairing json");
        let key = WorkerSigningKey::generate();
        let enrollment = EnrollRequest {
            protocol: PROTOCOL_VERSION.into(),
            pairing_token: pairing.token.clone(),
            worker_name: "worker-a".into(),
            public_key: key.public_base64().into(),
            capabilities: capabilities(),
        };
        let request = Request::builder()
            .method("POST")
            .uri(getter_protocol::PATH_ENROLL)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&enrollment).expect("json")))
            .expect("request");
        let response = app(&state).oneshot(request).await.expect("response");
        let (status, body) = response_body(response).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let enrolled: EnrollResponse = serde_json::from_slice(&body).expect("enroll json");
        assert_eq!(enrolled.coordinator_url, "http://127.0.0.1:47810");

        // A token cannot be used twice.
        let request = Request::builder()
            .method("POST")
            .uri(getter_protocol::PATH_ENROLL)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&enrollment).expect("json")))
            .expect("request");
        let response = app(&state).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Unsigned worker request rejected.
        let unsigned = Request::builder()
            .uri(getter_protocol::PATH_WORKER_ASSIGNMENTS)
            .body(Body::empty())
            .expect("request");
        let response = app(&state).oneshot(unsigned).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let heartbeat = WorkerHeartbeat {
            protocol: PROTOCOL_VERSION.into(),
            participation: WorkerParticipation::Active,
            capabilities: capabilities(),
            running_tasks: 0,
            uptime_secs: 1,
            tasks_completed: 0,
            task_failures: 0,
            compute_ms: 0,
            acknowledged_cancellations: Vec::new(),
        };
        let body = serde_json::to_vec(&heartbeat).expect("json");
        let path = getter_protocol::PATH_WORKER_HEARTBEAT;
        let request = worker_request("POST", path, &body, &enrolled.worker_id, &key);
        let replay_material = (
            request.headers().get(HEADER_NONCE).expect("nonce").clone(),
            request
                .headers()
                .get(HEADER_SIGNATURE)
                .expect("signature")
                .clone(),
            request
                .headers()
                .get(HEADER_TIMESTAMP)
                .expect("timestamp")
                .clone(),
        );
        let response = app(&state).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        // Same nonce/signature replayed is rejected.
        let replay = Request::builder()
            .method("POST")
            .uri(path)
            .header(HEADER_WORKER_ID, &enrolled.worker_id)
            .header(HEADER_NONCE, replay_material.0)
            .header(HEADER_SIGNATURE, replay_material.1)
            .header(HEADER_TIMESTAMP, replay_material.2)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .expect("request");
        let response = app(&state).oneshot(replay).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Tampered body with the original signature is rejected.
        let request = worker_request("POST", path, &body, &enrolled.worker_id, &key);
        let mut parts = request.into_parts();
        let tampered = br#"{"protocol":"getter.protocol/v1"}"#.to_vec();
        parts.1 = Body::from(tampered);
        let response = app(&state)
            .oneshot(Request::from_parts(parts.0, parts.1))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Revocation is enforced immediately.
        let revoke = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/admin/workers/{}", enrolled.worker_id))
            .header(header::AUTHORIZATION, "Bearer admin-secret")
            .body(Body::empty())
            .expect("request");
        let response = app(&state).oneshot(revoke).await.expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let request = worker_request(
            "GET",
            getter_protocol::PATH_WORKER_ASSIGNMENTS,
            b"",
            &enrolled.worker_id,
            &key,
        );
        let response = app(&state).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn oversized_cancellation_ack_lists_are_rejected_before_storage() {
        let state = test_state();
        let (status, body) = admin_post(
            &state,
            getter_protocol::PATH_ADMIN_PAIRING,
            &PairingTokenRequest {
                name: "worker-ack".into(),
                ttl_secs: 600,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let pairing: PairingTokenResponse = serde_json::from_slice(&body).expect("pairing");
        let key = WorkerSigningKey::generate();
        let enrollment = EnrollRequest {
            protocol: PROTOCOL_VERSION.into(),
            pairing_token: pairing.token,
            worker_name: "worker-ack".into(),
            public_key: key.public_base64().into(),
            capabilities: capabilities(),
        };
        let request = Request::builder()
            .method("POST")
            .uri(getter_protocol::PATH_ENROLL)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&enrollment).expect("json")))
            .expect("request");
        let response = app(&state).oneshot(request).await.expect("response");
        let (status, body) = response_body(response).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let enrolled: EnrollResponse = serde_json::from_slice(&body).expect("enroll");
        let heartbeat = WorkerHeartbeat {
            protocol: PROTOCOL_VERSION.into(),
            participation: WorkerParticipation::Active,
            capabilities: capabilities(),
            running_tasks: 0,
            uptime_secs: 1,
            tasks_completed: 0,
            task_failures: 0,
            compute_ms: 0,
            acknowledged_cancellations: (0..65).map(|index| format!("lease-{index}")).collect(),
        };
        let body = serde_json::to_vec(&heartbeat).expect("json");
        let request = worker_request(
            "POST",
            getter_protocol::PATH_WORKER_HEARTBEAT,
            &body,
            &enrolled.worker_id,
            &key,
        );
        let response = app(&state).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_job_routes_are_not_public() {
        let state = test_state();
        let response = app(&state)
            .oneshot(
                Request::builder()
                    .uri(getter_protocol::PATH_ADMIN_JOBS)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn pairing_token_is_not_returned_to_unauthenticated_admin_callers() {
        let state = test_state();
        let request = Request::builder()
            .method("POST")
            .uri(getter_protocol::PATH_ADMIN_PAIRING)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&PairingTokenRequest {
                    name: "w".into(),
                    ttl_secs: 600,
                })
                .expect("json"),
            ))
            .expect("request");
        let response = app(&state).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
