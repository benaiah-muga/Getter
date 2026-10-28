//! State-transition guards and retry policy.

#![deny(unsafe_code)]

use chrono::{DateTime, Duration, Utc};
use getter_protocol::{JobState, TaskState, WorkerParticipation, WorkerStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    pub entity: &'static str,
    pub from: &'static str,
    pub to: &'static str,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid {} transition from {} to {}",
            self.entity, self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}

pub fn task_transition_allowed(from: TaskState, to: TaskState) -> bool {
    use TaskState::{Assigned, Cancelled, Completed, Failed, Queued, Running};
    matches!(
        (from, to),
        (Queued, Assigned)
            | (Queued, Cancelled)
            | (Assigned, Running)
            | (Assigned, Queued)
            | (Assigned, Cancelled)
            | (Assigned, Failed)
            | (Running, Completed)
            | (Running, Failed)
            | (Running, Queued)
            | (Running, Cancelled)
            | (Completed, Completed)
            | (Failed, Failed)
            | (Cancelled, Cancelled)
    )
}

pub fn check_task_transition(from: TaskState, to: TaskState) -> Result<(), TransitionError> {
    if task_transition_allowed(from, to) {
        Ok(())
    } else {
        Err(TransitionError {
            entity: "task",
            from: from.as_str(),
            to: to.as_str(),
        })
    }
}

pub fn job_transition_allowed(from: JobState, to: JobState) -> bool {
    use JobState::{Cancelled, Completed, Failed, Queued, Running};
    matches!(
        (from, to),
        (Queued, Running)
            | (Queued, Cancelled)
            | (Queued, Failed)
            | (Running, Completed)
            | (Running, Failed)
            | (Running, Cancelled)
            | (Completed, Completed)
            | (Failed, Failed)
            | (Cancelled, Cancelled)
    )
}

pub fn check_job_transition(from: JobState, to: JobState) -> Result<(), TransitionError> {
    if job_transition_allowed(from, to) {
        Ok(())
    } else {
        Err(TransitionError {
            entity: "job",
            from: from.as_str(),
            to: to.as_str(),
        })
    }
}

/// Number of lease-consuming attempts that have occurred. Retry is allowed when
/// the just-finished attempt is below the limit and the failure is retryable.
pub fn should_retry(attempts_used: u32, max_attempts: u32, retryable: bool) -> bool {
    retryable && attempts_used > 0 && attempts_used < max_attempts
}

/// Determine the user-visible status of a worker. Presence is inferred from
/// heartbeats rather than trusting a stale online row indefinitely.
pub fn derived_worker_status(
    revoked: bool,
    participation: WorkerParticipation,
    last_seen: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    heartbeat_timeout_secs: u64,
) -> WorkerStatus {
    if revoked {
        return WorkerStatus::Revoked;
    }
    let fresh = last_seen
        .map(|seen| {
            now.signed_duration_since(seen) <= Duration::seconds(heartbeat_timeout_secs as i64)
        })
        .unwrap_or(false);
    if !fresh {
        return WorkerStatus::Offline;
    }
    match participation {
        WorkerParticipation::Active | WorkerParticipation::Draining => WorkerStatus::Online,
        WorkerParticipation::Paused => WorkerStatus::Paused,
        WorkerParticipation::Offline => WorkerStatus::Offline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_terminal_states_do_not_reopen() {
        assert!(task_transition_allowed(
            TaskState::Queued,
            TaskState::Assigned
        ));
        assert!(task_transition_allowed(
            TaskState::Running,
            TaskState::Completed
        ));
        assert!(!task_transition_allowed(
            TaskState::Completed,
            TaskState::Queued
        ));
        assert!(!task_transition_allowed(
            TaskState::Cancelled,
            TaskState::Running
        ));
        assert!(check_task_transition(TaskState::Completed, TaskState::Running).is_err());
    }

    #[test]
    fn assigned_task_can_return_to_queue_after_lease_loss() {
        assert!(task_transition_allowed(
            TaskState::Assigned,
            TaskState::Queued
        ));
        assert!(task_transition_allowed(
            TaskState::Running,
            TaskState::Queued
        ));
    }

    #[test]
    fn job_completion_cannot_be_undone() {
        assert!(!job_transition_allowed(
            JobState::Completed,
            JobState::Running
        ));
        assert!(!job_transition_allowed(
            JobState::Cancelled,
            JobState::Completed
        ));
        assert!(job_transition_allowed(JobState::Running, JobState::Failed));
    }

    #[test]
    fn retry_is_bounded() {
        assert!(should_retry(1, 3, true));
        assert!(should_retry(2, 3, true));
        assert!(!should_retry(3, 3, true));
        assert!(!should_retry(1, 3, false));
        assert!(!should_retry(0, 3, true));
    }

    #[test]
    fn stale_heartbeat_is_offline() {
        let now = Utc::now();
        assert_eq!(
            derived_worker_status(
                false,
                WorkerParticipation::Active,
                Some(now - Duration::seconds(3)),
                now,
                20
            ),
            WorkerStatus::Online
        );
        assert_eq!(
            derived_worker_status(
                false,
                WorkerParticipation::Active,
                Some(now - Duration::seconds(30)),
                now,
                20
            ),
            WorkerStatus::Offline
        );
        assert_eq!(
            derived_worker_status(false, WorkerParticipation::Paused, Some(now), now, 20),
            WorkerStatus::Paused
        );
        assert_eq!(
            derived_worker_status(false, WorkerParticipation::Active, None, now, 20),
            WorkerStatus::Offline
        );
    }
}
