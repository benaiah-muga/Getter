//! Worker service loop: heartbeats, assignment polling, sandbox execution, and
//! local pause/battery policy.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use getter_core::config::{GetterConfig, Role, WorkerConfig};
use getter_core::init::{load_worker_identity, read_control_token};
use getter_protocol::{
    TaskAssignment, TaskOutcome, TaskRequirements, TaskResultRequest, WorkerCapabilities,
    PROTOCOL_VERSION, WORKLOAD_ABI,
};
use getter_runtime::{ExecutionRequest, RuntimeError, Sandbox, SandboxLimits};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::client::{encoded_output, WorkerClient};
use crate::state::WorkerState;

pub fn capabilities(config: &WorkerConfig) -> WorkerCapabilities {
    WorkerCapabilities {
        abi: crate::SUPPORTED_ABIS
            .iter()
            .map(|abi| (*abi).to_owned())
            .collect(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpu_threads: std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1) as u32,
        max_concurrency: config.concurrency,
        max_task_memory_bytes: config.max_task_memory_bytes,
        max_task_timeout_secs: config.max_task_timeout_secs,
        max_output_bytes: config.max_output_bytes,
        max_fuel: config.max_fuel,
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

/// Run the worker until the supplied shutdown future resolves or the local
/// control API requests shutdown. The worker always attempts a graceful leave.
pub async fn run_worker(
    home: PathBuf,
    config: GetterConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if config.role != Role::Worker {
        anyhow::bail!("configuration role is not worker");
    }
    config
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid worker configuration: {error}"))?;
    let worker_config = Arc::new(
        config
            .worker
            .clone()
            .ok_or_else(|| anyhow::anyhow!("worker section is missing"))?,
    );
    let identity = load_worker_identity(&home)
        .map_err(|error| anyhow::anyhow!("could not load worker identity: {error}"))?;
    let worker_id = identity
        .require_worker_id()
        .map_err(|error| anyhow::anyhow!("worker has not joined a coordinator: {error}"))?
        .to_owned();
    let signing_key = identity
        .signing_key()
        .map_err(|error| anyhow::anyhow!("invalid worker identity: {error}"))?;
    let control_token = read_control_token(&home)
        .map_err(|error| anyhow::anyhow!("could not read control token: {error}"))?;
    apply_niceness(worker_config.niceness);
    let caps = capabilities(&worker_config);
    let state = WorkerState::new(
        Arc::clone(&worker_config),
        worker_id.clone(),
        identity.worker_name.clone(),
        worker_config.coordinator_url.clone(),
        caps.clone(),
    );
    let client = Arc::new(WorkerClient::new(
        &worker_config.coordinator_url,
        worker_id,
        signing_key,
        worker_config.coordinator_ca.as_deref(),
        Duration::from_secs(worker_config.request_timeout_secs),
    )?);

    let sandbox = Arc::new(
        Sandbox::new(SandboxLimits {
            max_module_bytes: usize::try_from(worker_config.max_download_bytes)
                .unwrap_or(getter_protocol::MAX_ARTIFACT_BYTES)
                .min(getter_protocol::MAX_ARTIFACT_BYTES),
            max_input_bytes: getter_protocol::MAX_INPUT_BYTES,
            max_memory_bytes: worker_config.max_task_memory_bytes,
            max_output_bytes: worker_config.max_output_bytes,
            max_fuel: worker_config.max_fuel,
            max_timeout: Duration::from_secs(worker_config.max_task_timeout_secs),
        })
        .map_err(|error| anyhow::anyhow!("could not create execution sandbox: {error}"))?,
    );

    let control_listener = TcpListener::bind(worker_config.control_bind)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "could not bind worker control API at {}: {error}. If another worker uses this port, configure a different loopback control address.",
                worker_config.control_bind
            )
        })?;
    info!(
        worker_id = %state.worker_id,
        worker_name = %state.worker_name,
        coordinator = %worker_config.coordinator_url,
        control = %worker_config.control_bind,
        concurrency = worker_config.concurrency,
        "worker starting"
    );
    let control_state = Arc::clone(&state);
    let control_token_for_task = control_token.clone();
    let control_task = tokio::spawn(async move {
        if let Err(error) =
            crate::control::serve(control_listener, control_state, control_token_for_task).await
        {
            tracing::error!(error = %error, "worker control API stopped");
        }
    });

    let external_state = Arc::clone(&state);
    let external_shutdown = tokio::spawn(async move {
        shutdown.await;
        external_state.request_shutdown();
    });

    let heartbeat_state = Arc::clone(&state);
    let heartbeat_client = Arc::clone(&client);
    let heartbeat_task = tokio::spawn(async move {
        let mut stop = heartbeat_state.shutdown_receiver();
        let interval_secs = heartbeat_state.config.heartbeat_interval_secs.max(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = interval.tick() => {}
            }
            if heartbeat_state.is_shutting_down() {
                break;
            }
            let heartbeat = heartbeat_state.heartbeat();
            match heartbeat_client.heartbeat(&heartbeat).await {
                Ok(response) => {
                    heartbeat_state.clear_last_error();
                    heartbeat_state.mark_coordinator_synced();
                    heartbeat_state
                        .acknowledge_cancellation_delivery(&heartbeat.acknowledged_cancellations);
                    for lease_id in response.cancel_leases {
                        if heartbeat_state.cancel_lease(&lease_id) {
                            debug!(lease_id = %lease_id, "cancelled by coordinator");
                        }
                        heartbeat_state.queue_cancellation_ack(&lease_id);
                    }
                }
                Err(error) => {
                    if error.is_authorization_failure() {
                        warn!(error = %error, "coordinator rejected worker authentication; stopping");
                        heartbeat_state.set_last_error(error.to_string());
                        heartbeat_state.request_shutdown();
                        break;
                    }
                    warn!(error = %error, "heartbeat failed; will retry");
                    heartbeat_state.set_last_error(error.to_string());
                }
            }
        }
    });

    let battery_state = Arc::clone(&state);
    let pause_on_battery = worker_config.pause_on_battery;
    let battery_task = tokio::spawn(async move {
        let mut stop = battery_state.shutdown_receiver();
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = interval.tick() => {}
            }
            match battery_on_discharge() {
                Some(on_battery) => {
                    battery_state.set_battery_supported(true);
                    if pause_on_battery {
                        if let Err(error) = battery_state.set_battery_paused(on_battery) {
                            battery_state.set_last_error(error.to_string());
                        } else if on_battery {
                            info!("battery power detected; pausing worker participation");
                        } else if !battery_state.is_paused() {
                            info!("external power detected; worker may resume");
                        }
                    }
                }
                None => {
                    battery_state.set_battery_supported(false);
                }
            }
        }
    });

    let semaphore = Arc::new(Semaphore::new(worker_config.concurrency as usize));
    let mut joins: JoinSet<TaskReport> = JoinSet::new();
    let mut stop = state.shutdown_receiver();
    let poll_period = Duration::from_millis(worker_config.poll_interval_ms.max(100));
    let mut poll_interval = tokio::time::interval(poll_period);
    poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() { break; }
            }
            completed = joins.join_next(), if !joins.is_empty() => {
                match completed {
                    Some(Ok(report)) => {
                        state.finish_task(&report.lease_id);
                        match report.outcome {
                            ReportOutcome::Success => state.record_success(report.compute_ms),
                            ReportOutcome::Failure => state.record_failure(),
                            ReportOutcome::Neutral => {}
                        }
                        if let Some(message) = report.message {
                            debug!(lease_id = %report.lease_id, message = %message, "task finished");
                        }
                    }
                    Some(Err(error)) => {
                        warn!(error = %error, "task join failed");
                    }
                    None => {}
                }
            }
            _ = poll_interval.tick() => {
                if state.is_paused() || state.is_shutting_down() {
                    continue;
                }
                if !state.coordinator_synced() {
                    continue;
                }
                let free = semaphore.available_permits();
                if free == 0 {
                    continue;
                }
                match client.assignments(free).await {
                    Ok(response) => {
                        state.clear_last_error();
                        for assignment in response.assignments {
                            if assignment.protocol != PROTOCOL_VERSION {
                                state.set_last_error("coordinator returned a different protocol version");
                                continue;
                            }
                            let cancel = Arc::new(AtomicBool::new(
                                state.is_paused() || state.is_shutting_down(),
                            ));
                            if let Err(error) = state.register_task(&assignment, Arc::clone(&cancel)) {
                                state.set_last_error(error.to_string());
                                continue;
                            }
                            let task_state = Arc::clone(&state);
                            let task_client = Arc::clone(&client);
                            let task_sandbox = Arc::clone(&sandbox);
                            let task_semaphore = Arc::clone(&semaphore);
                            joins.spawn(async move {
                                run_assignment(
                                    task_state,
                                    task_client,
                                    task_sandbox,
                                    task_semaphore,
                                    assignment,
                                    cancel,
                                )
                                .await
                            });
                        }
                    }
                    Err(error) => {
                        if error.is_authorization_failure() {
                            warn!(error = %error, "coordinator rejected worker authentication; stopping");
                            state.set_last_error(error.to_string());
                            state.request_shutdown();
                        } else {
                            debug!(error = %error, "assignment poll failed; will retry");
                            state.set_last_error(error.to_string());
                        }
                    }
                }
            }
        }
    }

    // Stop acquiring work and interrupt running sandboxed tasks as promptly as
    // possible. Give result submission a bounded chance to finish.
    state.cancel_all();
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while !joins.is_empty() {
        match tokio::time::timeout_at(drain_deadline, joins.join_next()).await {
            Ok(Some(Ok(report))) => {
                state.finish_task(&report.lease_id);
                if matches!(report.outcome, ReportOutcome::Success) {
                    state.record_success(report.compute_ms);
                } else if matches!(report.outcome, ReportOutcome::Failure) {
                    state.record_failure();
                }
            }
            Ok(Some(Err(error))) => warn!(error = %error, "task join failed during shutdown"),
            Ok(None) => break,
            Err(_) => {
                warn!("worker shutdown timeout; aborting remaining local task futures");
                joins.abort_all();
                break;
            }
        }
    }
    heartbeat_task.abort();
    battery_task.abort();
    control_task.abort();
    external_shutdown.abort();
    match tokio::time::timeout(Duration::from_secs(3), client.leave()).await {
        Ok(Ok(())) => info!("coordinator acknowledged graceful worker disconnect"),
        Ok(Err(error)) => warn!(error = %error, "could not send graceful leave"),
        Err(_) => warn!("timed out sending graceful leave"),
    }
    info!("worker stopped");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportOutcome {
    Success,
    Failure,
    Neutral,
}

struct TaskReport {
    lease_id: String,
    outcome: ReportOutcome,
    compute_ms: u64,
    message: Option<String>,
}

async fn run_assignment(
    state: Arc<WorkerState>,
    client: Arc<WorkerClient>,
    sandbox: Arc<Sandbox>,
    semaphore: Arc<Semaphore>,
    assignment: TaskAssignment,
    cancel: Arc<AtomicBool>,
) -> TaskReport {
    let lease_id = assignment.lease_id.clone();
    // Validate local limits *before* acquiring semaphore permits. A malicious
    // or stale assignment can otherwise request more slots than the semaphore
    // owns and wait forever.
    if assignment.abi != WORKLOAD_ABI {
        return submit_failure(
            &state,
            &client,
            &assignment,
            0,
            format!("unsupported workload ABI {:?}", assignment.abi),
            false,
        )
        .await;
    }
    if assignment.input.len() > getter_protocol::MAX_INPUT_BYTES {
        return submit_failure(
            &state,
            &client,
            &assignment,
            0,
            "task input exceeds the local input limit".into(),
            false,
        )
        .await;
    }
    if let Err(reason) = local_limit_check(&state.config, &assignment.requirements) {
        return submit_requeue(&state, &client, &assignment, 0, reason).await;
    }
    if cancel.load(Ordering::Relaxed) || state.is_paused() || state.is_shutting_down() {
        return submit_requeue(
            &state,
            &client,
            &assignment,
            0,
            "worker paused or stopping before execution".into(),
        )
        .await;
    }
    let cpu_slots = assignment.requirements.cpu_slots.max(1);
    let _permit = match Arc::clone(&semaphore).try_acquire_many_owned(cpu_slots) {
        Ok(permit) => permit,
        Err(_) => {
            return submit_requeue(
                &state,
                &client,
                &assignment,
                0,
                "worker CPU capacity was not available".into(),
            )
            .await;
        }
    };

    let download_started = Instant::now();
    let artifact = match client
        .download_artifact(&assignment, state.config.max_download_bytes)
        .await
    {
        Ok(artifact) => artifact,
        Err(error) => {
            state.set_last_error(error.to_string());
            return submit_requeue(
                &state,
                &client,
                &assignment,
                download_started.elapsed().as_millis() as u64,
                format!("artifact download failed: {error}"),
            )
            .await;
        }
    };
    if cancel.load(Ordering::Relaxed) {
        return submit_requeue(
            &state,
            &client,
            &assignment,
            download_started.elapsed().as_millis() as u64,
            "worker cancelled before execution".into(),
        )
        .await;
    }
    let remaining = assignment
        .lease_expires_at
        .signed_duration_since(Utc::now())
        .num_seconds();
    let usable_seconds = remaining - i64::try_from(state.config.lease_safety_secs).unwrap_or(0);
    if usable_seconds <= 0 {
        return submit_requeue(
            &state,
            &client,
            &assignment,
            download_started.elapsed().as_millis() as u64,
            "insufficient lease time remaining to execute safely".into(),
        )
        .await;
    }
    let timeout_secs = assignment
        .requirements
        .timeout_secs
        .min(state.config.max_task_timeout_secs)
        .min(usable_seconds as u64)
        .max(1);
    match mark_started_with_retry(&client, &assignment).await {
        Ok(()) => {}
        Err(error) => {
            state.set_last_error(error.to_string());
            return task_report(
                lease_id,
                ReportOutcome::Neutral,
                download_started.elapsed().as_millis() as u64,
                Some(format!("could not mark task started: {error}")),
            );
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return submit_requeue(
            &state,
            &client,
            &assignment,
            0,
            "worker cancelled before execution".into(),
        )
        .await;
    }
    let request = ExecutionRequest {
        input: assignment.input.as_bytes().to_vec(),
        memory_bytes: assignment.requirements.memory_bytes,
        output_bytes: assignment.requirements.output_bytes,
        timeout: Duration::from_secs(timeout_secs),
        fuel: assignment.requirements.fuel,
        cancel: Arc::clone(&cancel),
    };
    let started = Instant::now();
    let artifact_for_task = artifact;
    let sandbox_for_task = Arc::clone(&sandbox);
    let execution =
        tokio::task::spawn_blocking(move || sandbox_for_task.execute(&artifact_for_task, &request))
            .await;
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    match execution {
        Ok(Ok(result)) => {
            let (output_base64, output_sha256) = encoded_output(&result.output);
            let request = TaskResultRequest {
                protocol: PROTOCOL_VERSION.into(),
                lease_id: assignment.lease_id.clone(),
                task_id: assignment.task_id.clone(),
                lease_token: assignment.lease_token.clone(),
                outcome: TaskOutcome::Success {
                    output_base64,
                    output_sha256,
                },
                compute_ms: result.elapsed_ms,
                fuel_used: result.fuel_used,
            };
            submit_result_with_retry(
                &state,
                &client,
                &assignment,
                request,
                ReportOutcome::Success,
                result.elapsed_ms,
            )
            .await
        }
        Ok(Err(RuntimeError::Cancelled)) => {
            submit_requeue(
                &state,
                &client,
                &assignment,
                elapsed_ms,
                "execution cancelled by local worker policy".into(),
            )
            .await
        }
        Ok(Err(error)) => {
            let (message, retryable) = classify_runtime_failure(&error);
            warn!(
                task = %assignment.task_key,
                job = %assignment.job_name,
                error = %message,
                "sandboxed task failed"
            );
            submit_failure(&state, &client, &assignment, elapsed_ms, message, retryable).await
        }
        Err(error) => {
            let message = format!("execution worker thread failed: {error}");
            state.set_last_error(message.clone());
            submit_failure(&state, &client, &assignment, elapsed_ms, message, true).await
        }
    }
}

async fn mark_started_with_retry(
    client: &WorkerClient,
    assignment: &TaskAssignment,
) -> Result<(), crate::WorkerError> {
    let mut last_error = None;
    for attempt in 0..3 {
        match client
            .mark_started_with_token(&assignment.lease_id, &assignment.lease_token)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                let retryable = !error.is_authorization_failure();
                last_error = Some(error);
                if !retryable {
                    break;
                }
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_secs((attempt as u64) + 1)).await;
                }
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| crate::WorkerError::Runner("task start acknowledgement failed".into())))
}

fn local_limit_check(config: &WorkerConfig, requirements: &TaskRequirements) -> Result<(), String> {
    if requirements.cpu_slots == 0 || requirements.cpu_slots > config.concurrency {
        return Err("task CPU requirement exceeds local concurrency".into());
    }
    if requirements.memory_bytes > config.max_task_memory_bytes {
        return Err("task memory requirement exceeds the worker's local maximum".into());
    }
    if requirements.timeout_secs > config.max_task_timeout_secs {
        return Err("task timeout exceeds the worker's local maximum".into());
    }
    if requirements.output_bytes > config.max_output_bytes {
        return Err("task output limit exceeds the worker's local maximum".into());
    }
    if requirements.fuel > config.max_fuel {
        return Err("task fuel limit exceeds the worker's local maximum".into());
    }
    Ok(())
}

fn classify_runtime_failure(error: &RuntimeError) -> (String, bool) {
    match error {
        RuntimeError::Cancelled => ("execution cancelled by local worker policy".into(), true),
        RuntimeError::Timeout => ("execution exceeded its wall-clock deadline".into(), true),
        RuntimeError::FuelExhausted => ("execution exhausted its fuel budget".into(), false),
        RuntimeError::MemoryLimit | RuntimeError::MemoryLimitRequested => {
            ("execution exceeded its memory limit".into(), false)
        }
        RuntimeError::OutputTooLarge { .. } | RuntimeError::OutputRequested => {
            ("execution produced more output than allowed".into(), false)
        }
        RuntimeError::InputTooLarge => ("task input exceeds the sandbox limit".into(), false),
        RuntimeError::ModuleTooLarge => ("workload artifact is too large".into(), false),
        RuntimeError::InvalidModule => {
            ("workload artifact is not a valid Wasm module".into(), false)
        }
        RuntimeError::ImportsForbidden(_) => (
            "workload imports host capabilities; getter.abi.v1 forbids imports".into(),
            false,
        ),
        RuntimeError::MissingExport(_) => {
            ("workload is missing a required ABI export".into(), false)
        }
        RuntimeError::InvalidOutputRegion { .. } => {
            ("workload returned an invalid output region".into(), false)
        }
        RuntimeError::Trap(message) => (format!("workload trapped: {message}"), false),
        RuntimeError::TimeoutRequested | RuntimeError::FuelRequested => {
            ("task limits exceed the worker sandbox".into(), false)
        }
        RuntimeError::Execution(message) => (format!("execution setup failed: {message}"), true),
    }
}

async fn submit_failure(
    state: &WorkerState,
    client: &WorkerClient,
    assignment: &TaskAssignment,
    compute_ms: u64,
    message: String,
    retryable: bool,
) -> TaskReport {
    let request = TaskResultRequest {
        protocol: PROTOCOL_VERSION.into(),
        lease_id: assignment.lease_id.clone(),
        task_id: assignment.task_id.clone(),
        lease_token: assignment.lease_token.clone(),
        outcome: TaskOutcome::Failure {
            message: message.chars().take(500).collect(),
            retryable,
        },
        compute_ms,
        fuel_used: 0,
    };
    submit_result_with_retry(
        state,
        client,
        assignment,
        request,
        ReportOutcome::Failure,
        compute_ms,
    )
    .await
}

async fn submit_requeue(
    state: &WorkerState,
    client: &WorkerClient,
    assignment: &TaskAssignment,
    compute_ms: u64,
    reason: String,
) -> TaskReport {
    let request = TaskResultRequest {
        protocol: PROTOCOL_VERSION.into(),
        lease_id: assignment.lease_id.clone(),
        task_id: assignment.task_id.clone(),
        lease_token: assignment.lease_token.clone(),
        outcome: TaskOutcome::Requeue {
            reason: reason.chars().take(500).collect(),
        },
        compute_ms,
        fuel_used: 0,
    };
    submit_result_with_retry(
        state,
        client,
        assignment,
        request,
        ReportOutcome::Neutral,
        compute_ms,
    )
    .await
}

async fn submit_result_with_retry(
    state: &WorkerState,
    client: &WorkerClient,
    assignment: &TaskAssignment,
    request: TaskResultRequest,
    accepted_outcome: ReportOutcome,
    compute_ms: u64,
) -> TaskReport {
    let mut last_error = None;
    for attempt in 0..3 {
        match client.submit_result(&request).await {
            Ok(ack) => {
                if ack.accepted {
                    if accepted_outcome == ReportOutcome::Success {
                        info!(
                            task = %assignment.task_key,
                            job = %assignment.job_name,
                            compute_ms,
                            "task completed"
                        );
                    }
                    return task_report(
                        assignment.lease_id.clone(),
                        accepted_outcome,
                        compute_ms,
                        Some(ack.message),
                    );
                }
                debug!(
                    task = %assignment.task_key,
                    message = %ack.message,
                    "result not accepted (stale lease or cancelled job)"
                );
                return task_report(
                    assignment.lease_id.clone(),
                    ReportOutcome::Neutral,
                    compute_ms,
                    Some(ack.message),
                );
            }
            Err(error) => {
                state.set_last_error(error.to_string());
                last_error = Some(error);
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_secs((attempt as u64) + 1)).await;
                }
            }
        }
    }
    let message = last_error
        .map(|error| format!("could not deliver result after retries: {error}"))
        .unwrap_or_else(|| "could not deliver result".into());
    warn!(task = %assignment.task_key, message = %message);
    task_report(
        assignment.lease_id.clone(),
        ReportOutcome::Neutral,
        compute_ms,
        Some(message),
    )
}

fn task_report(
    lease_id: String,
    outcome: ReportOutcome,
    compute_ms: u64,
    message: Option<String>,
) -> TaskReport {
    TaskReport {
        lease_id,
        outcome,
        compute_ms,
        message,
    }
}

fn apply_niceness(niceness: Option<i32>) {
    #[cfg(unix)]
    if let Some(niceness) = niceness {
        // SAFETY: setpriority with PRIO_PROCESS and process id 0 changes only
        // the calling process and has no pointer arguments. The return value is
        // checked; failure is non-fatal because resource priority is best
        // effort and already bounded by concurrency.
        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, niceness) };
        if result != 0 {
            warn!(
                niceness,
                error = %std::io::Error::last_os_error(),
                "could not set worker process niceness"
            );
        } else {
            info!(niceness, "worker process priority adjusted");
        }
    }
    #[cfg(not(unix))]
    if niceness.is_some() {
        debug!("process niceness is not supported on this platform");
    }
}

#[cfg(target_os = "linux")]
fn battery_on_discharge() -> Option<bool> {
    let entries = std::fs::read_dir("/sys/class/power_supply").ok()?;
    let mut found_battery = false;
    let mut discharging = false;
    for entry in entries.flatten() {
        let status_path = entry.path().join("status");
        let Ok(status) = std::fs::read_to_string(status_path) else {
            continue;
        };
        let kind_path = entry.path().join("type");
        let kind = std::fs::read_to_string(kind_path).unwrap_or_default();
        if kind.trim() != "Battery" {
            continue;
        }
        found_battery = true;
        if status.trim().eq_ignore_ascii_case("Discharging") {
            discharging = true;
        }
    }
    if found_battery {
        Some(discharging)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn battery_on_discharge() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_limits_reject_remote_overreach() {
        let config = WorkerConfig::default();
        let too_many_slots = TaskRequirements {
            cpu_slots: config.concurrency + 1,
            ..TaskRequirements::default()
        };
        assert!(local_limit_check(&config, &too_many_slots).is_err());
        let too_much_memory = TaskRequirements {
            memory_bytes: config.max_task_memory_bytes + 1,
            ..TaskRequirements::default()
        };
        assert!(local_limit_check(&config, &too_much_memory).is_err());
        let too_long = TaskRequirements {
            timeout_secs: config.max_task_timeout_secs + 1,
            ..TaskRequirements::default()
        };
        assert!(local_limit_check(&config, &too_long).is_err());
        let too_large = TaskRequirements {
            output_bytes: config.max_output_bytes + 1,
            ..TaskRequirements::default()
        };
        assert!(local_limit_check(&config, &too_large).is_err());
        let too_much_fuel = TaskRequirements {
            fuel: config.max_fuel + 1,
            ..TaskRequirements::default()
        };
        assert!(local_limit_check(&config, &too_much_fuel).is_err());
        assert!(local_limit_check(&config, &TaskRequirements::default()).is_ok());
    }
}
