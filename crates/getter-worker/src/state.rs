//! Shared, process-local worker state used by the assignment loop, heartbeat
//! loop, and loopback control API.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use chrono::{DateTime, Utc};
use getter_protocol::{
    TaskAssignment, WorkerCapabilities, WorkerHeartbeat, WorkerParticipation, PROTOCOL_VERSION,
};

use crate::error::WorkerError;

#[derive(Debug, Default)]
struct PauseFlags {
    manual: bool,
    battery: bool,
}

#[derive(Debug)]
pub struct ActiveTask {
    pub lease_id: String,
    pub job_id: String,
    pub job_name: String,
    pub task_key: String,
    pub cpu_slots: u32,
    pub started_at: DateTime<Utc>,
    pub cancel: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct ActiveTaskSnapshot {
    pub lease_id: String,
    pub job_id: String,
    pub job_name: String,
    pub task_key: String,
    pub cpu_slots: u32,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalStats {
    pub tasks_completed: u64,
    pub task_failures: u64,
    pub compute_ms: u64,
}

pub struct WorkerState {
    pub config: Arc<getter_core::config::WorkerConfig>,
    pub worker_id: String,
    pub worker_name: String,
    pub coordinator_url: String,
    pub capabilities: WorkerCapabilities,
    pub started: Instant,
    pub started_at: DateTime<Utc>,
    pause: Mutex<PauseFlags>,
    active: Mutex<BTreeMap<String, ActiveTask>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks_completed: AtomicU64,
    task_failures: AtomicU64,
    compute_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    battery_supported: AtomicBool,
    pending_cancellation_acks: Mutex<BTreeSet<String>>,
    coordinator_synced: AtomicBool,
}

impl WorkerState {
    pub fn new(
        config: Arc<getter_core::config::WorkerConfig>,
        worker_id: String,
        worker_name: String,
        coordinator_url: String,
        capabilities: WorkerCapabilities,
    ) -> Arc<Self> {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            config,
            worker_id,
            worker_name,
            coordinator_url,
            capabilities,
            started: Instant::now(),
            started_at: Utc::now(),
            pause: Mutex::new(PauseFlags::default()),
            active: Mutex::new(BTreeMap::new()),
            shutdown,
            tasks_completed: AtomicU64::new(0),
            task_failures: AtomicU64::new(0),
            compute_ms: AtomicU64::new(0),
            last_error: Mutex::new(None),
            battery_supported: AtomicBool::new(false),
            pending_cancellation_acks: Mutex::new(BTreeSet::new()),
            coordinator_synced: AtomicBool::new(false),
        })
    }

    pub fn shutdown_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    fn pause_guard(&self) -> Result<MutexGuard<'_, PauseFlags>, WorkerError> {
        self.pause
            .lock()
            .map_err(|_| WorkerError::State("pause lock poisoned".into()))
    }

    fn active_guard(&self) -> Result<MutexGuard<'_, BTreeMap<String, ActiveTask>>, WorkerError> {
        self.active
            .lock()
            .map_err(|_| WorkerError::State("active-task lock poisoned".into()))
    }

    pub fn is_paused(&self) -> bool {
        self.pause_guard()
            .map(|flags| flags.manual || flags.battery)
            .unwrap_or(true)
    }

    pub fn manual_paused(&self) -> bool {
        self.pause_guard().map(|flags| flags.manual).unwrap_or(true)
    }

    pub fn battery_paused(&self) -> bool {
        self.pause_guard()
            .map(|flags| flags.battery)
            .unwrap_or(true)
    }

    pub fn set_battery_supported(&self, supported: bool) {
        self.battery_supported.store(supported, Ordering::Relaxed);
    }

    pub fn battery_supported(&self) -> bool {
        self.battery_supported.load(Ordering::Relaxed)
    }

    /// Manual pause immediately cancels running tasks. The coordinator will
    /// requeue them after the failure result or lease expiry.
    pub fn set_manual_paused(&self, paused: bool) -> Result<usize, WorkerError> {
        let mut flags = self.pause_guard()?;
        let was_paused = flags.manual || flags.battery;
        flags.manual = paused;
        if paused && !was_paused {
            drop(flags);
            Ok(self.cancel_all())
        } else {
            Ok(0)
        }
    }

    pub fn set_battery_paused(&self, paused: bool) -> Result<usize, WorkerError> {
        let mut flags = self.pause_guard()?;
        let was_paused = flags.manual || flags.battery;
        flags.battery = paused;
        if paused && !was_paused {
            drop(flags);
            Ok(self.cancel_all())
        } else {
            Ok(0)
        }
    }

    pub fn register_task(
        &self,
        assignment: &TaskAssignment,
        cancel: Arc<AtomicBool>,
    ) -> Result<(), WorkerError> {
        let mut active = self.active_guard()?;
        if active.contains_key(&assignment.lease_id) {
            return Err(WorkerError::State(
                "lease is already active on this worker".into(),
            ));
        }
        active.insert(
            assignment.lease_id.clone(),
            ActiveTask {
                lease_id: assignment.lease_id.clone(),
                job_id: assignment.job_id.clone(),
                job_name: assignment.job_name.clone(),
                task_key: assignment.task_key.clone(),
                cpu_slots: assignment.requirements.cpu_slots,
                started_at: Utc::now(),
                cancel,
            },
        );
        Ok(())
    }

    pub fn finish_task(&self, lease_id: &str) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(lease_id);
        }
    }

    pub fn cancel_lease(&self, lease_id: &str) -> bool {
        self.active_guard()
            .ok()
            .and_then(|active| active.get(lease_id).map(|task| Arc::clone(&task.cancel)))
            .map(|cancel| {
                cancel.store(true, Ordering::Relaxed);
                true
            })
            .unwrap_or(false)
    }

    pub fn cancel_all(&self) -> usize {
        let Ok(active) = self.active_guard() else {
            return 0;
        };
        for task in active.values() {
            task.cancel.store(true, Ordering::Relaxed);
        }
        active.len()
    }

    /// True after the coordinator has accepted at least one heartbeat carrying
    /// the worker's current capabilities. Assignment polling waits for this so
    /// a restarted worker cannot be assigned under stale enrollment limits.
    pub fn coordinator_synced(&self) -> bool {
        self.coordinator_synced.load(Ordering::Relaxed)
    }

    pub fn mark_coordinator_synced(&self) {
        self.coordinator_synced.store(true, Ordering::Relaxed);
    }

    pub fn active_tasks(&self) -> Vec<ActiveTaskSnapshot> {
        self.active_guard()
            .map(|active| {
                active
                    .values()
                    .map(|task| ActiveTaskSnapshot {
                        lease_id: task.lease_id.clone(),
                        job_id: task.job_id.clone(),
                        job_name: task.job_name.clone(),
                        task_key: task.task_key.clone(),
                        cpu_slots: task.cpu_slots,
                        started_at: task.started_at,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn active_count(&self) -> usize {
        self.active_guard().map(|active| active.len()).unwrap_or(0)
    }

    pub fn active_slots(&self) -> u32 {
        self.active_guard()
            .map(|active| active.values().map(|task| task.cpu_slots).sum())
            .unwrap_or(0)
    }

    pub fn record_success(&self, compute_ms: u64) {
        self.tasks_completed.fetch_add(1, Ordering::Relaxed);
        self.compute_ms.fetch_add(compute_ms, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.task_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> LocalStats {
        LocalStats {
            tasks_completed: self.tasks_completed.load(Ordering::Relaxed),
            task_failures: self.task_failures.load(Ordering::Relaxed),
            compute_ms: self.compute_ms.load(Ordering::Relaxed),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn heartbeat(&self) -> WorkerHeartbeat {
        let paused = self.is_paused();
        let stats = self.stats();
        let acknowledged_cancellations = self
            .pending_cancellation_acks
            .lock()
            .map(|acks| acks.iter().take(64).cloned().collect())
            .unwrap_or_default();
        WorkerHeartbeat {
            protocol: PROTOCOL_VERSION.into(),
            participation: if paused {
                WorkerParticipation::Paused
            } else {
                WorkerParticipation::Active
            },
            capabilities: self.capabilities.clone(),
            running_tasks: self.active_count() as u32,
            uptime_secs: self.uptime_secs(),
            tasks_completed: stats.tasks_completed,
            task_failures: stats.task_failures,
            compute_ms: stats.compute_ms,
            acknowledged_cancellations,
        }
    }

    pub fn queue_cancellation_ack(&self, lease_id: &str) {
        if let Ok(mut acks) = self.pending_cancellation_acks.lock() {
            acks.insert(lease_id.to_owned());
        }
    }

    pub fn acknowledge_cancellation_delivery(&self, acknowledged: &[String]) {
        if let Ok(mut acks) = self.pending_cancellation_acks.lock() {
            for lease_id in acknowledged {
                acks.remove(lease_id);
            }
        }
    }

    pub fn set_last_error(&self, message: impl Into<String>) {
        if let Ok(mut error) = self.last_error.lock() {
            *error = Some(truncate(&message.into(), 500));
        }
    }

    pub fn clear_last_error(&self) {
        if let Ok(mut error) = self.last_error.lock() {
            *error = None;
        }
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|error| error.clone())
    }

    pub fn available_slots(&self) -> u32 {
        self.capabilities
            .max_concurrency
            .saturating_sub(self.active_slots())
    }

    pub fn pause_description(&self) -> &'static str {
        if self.battery_paused() {
            "battery"
        } else if self.manual_paused() {
            "manual"
        } else {
            "active"
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    let sanitized: String = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect();
    if sanitized.chars().count() <= max {
        sanitized
    } else {
        let mut result = sanitized.chars().take(max).collect::<String>();
        result.push('…');
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getter_protocol::TaskRequirements;

    fn state() -> Arc<WorkerState> {
        let config = getter_core::config::WorkerConfig {
            concurrency: 2,
            ..getter_core::config::WorkerConfig::default()
        };
        let capabilities = WorkerCapabilities {
            abi: vec![getter_protocol::WORKLOAD_ABI.into()],
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            cpu_threads: 2,
            max_concurrency: 2,
            max_task_memory_bytes: config.max_task_memory_bytes,
            max_task_timeout_secs: config.max_task_timeout_secs,
            max_output_bytes: config.max_output_bytes,
            max_fuel: config.max_fuel,
            version: "test".into(),
        };
        WorkerState::new(
            Arc::new(config),
            "worker-id".into(),
            "worker-name".into(),
            "http://127.0.0.1:47810".into(),
            capabilities,
        )
    }

    fn assignment(lease_id: &str) -> TaskAssignment {
        TaskAssignment {
            protocol: getter_protocol::PROTOCOL_VERSION.into(),
            lease_id: lease_id.into(),
            lease_token: "lease-secret".into(),
            job_id: "job".into(),
            job_name: "job".into(),
            task_id: "task".into(),
            task_key: "task-0".into(),
            attempt: 1,
            max_attempts: 3,
            lease_expires_at: Utc::now() + chrono::Duration::seconds(30),
            workload_name: "test".into(),
            abi: getter_protocol::WORKLOAD_ABI.into(),
            artifact_sha256: "a".repeat(64),
            artifact_url: "/artifact".into(),
            input: "input".into(),
            input_sha256: "b".repeat(64),
            requirements: TaskRequirements::default(),
        }
    }

    #[test]
    fn pause_cancels_running_tasks_and_heartbeat_reports_paused() {
        let state = state();
        assert!(!state.is_paused());
        let cancel = Arc::new(AtomicBool::new(false));
        state
            .register_task(&assignment("lease-1"), Arc::clone(&cancel))
            .expect("register");
        assert_eq!(state.active_slots(), 1);
        assert_eq!(state.available_slots(), 1);
        let cancelled = state.set_manual_paused(true).expect("pause");
        assert_eq!(cancelled, 1);
        assert!(cancel.load(Ordering::Relaxed));
        assert!(state.is_paused());
        assert_eq!(state.pause_description(), "manual");
        let heartbeat = state.heartbeat();
        assert_eq!(
            heartbeat.participation,
            getter_protocol::WorkerParticipation::Paused
        );
        assert_eq!(heartbeat.running_tasks, 1);
        state.set_manual_paused(false).expect("resume");
        assert!(!state.is_paused());
        state.finish_task("lease-1");
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn battery_pause_is_independent_from_manual_resume() {
        let state = state();
        state.set_battery_paused(true).expect("battery pause");
        assert!(state.is_paused());
        assert_eq!(state.pause_description(), "battery");
        state.set_manual_paused(false).expect("manual resume");
        assert!(state.is_paused());
        state.set_battery_paused(false).expect("ac power");
        assert!(!state.is_paused());
    }

    #[test]
    fn cancellation_acknowledgements_survive_until_delivered() {
        let state = state();
        state.queue_cancellation_ack("lease-a");
        state.queue_cancellation_ack("lease-b");
        let heartbeat = state.heartbeat();
        assert_eq!(heartbeat.acknowledged_cancellations.len(), 2);
        state.acknowledge_cancellation_delivery(&heartbeat.acknowledged_cancellations);
        assert!(state.heartbeat().acknowledged_cancellations.is_empty());
    }

    #[test]
    fn assignment_polling_waits_for_capability_sync() {
        let state = state();
        assert!(!state.coordinator_synced());
        state.mark_coordinator_synced();
        assert!(state.coordinator_synced());
    }

    #[test]
    fn stats_are_local_and_monotonic() {
        let state = state();
        state.record_success(12);
        state.record_success(8);
        state.record_failure();
        let stats = state.stats();
        assert_eq!(stats.tasks_completed, 2);
        assert_eq!(stats.compute_ms, 20);
        assert_eq!(stats.task_failures, 1);
    }
}
