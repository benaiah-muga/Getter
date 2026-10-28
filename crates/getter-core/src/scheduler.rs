//! Deterministic scheduling rules.
//!
//! The coordinator is currently the only scheduler. Keeping the eligibility and
//! ordering logic pure makes it directly testable and gives future federated
//! schedulers a stable reference implementation.

#![deny(unsafe_code)]

use getter_protocol::{TaskRequirements, WorkerCapabilities, WorkerParticipation};

#[derive(Debug, Clone)]
pub struct SchedulingWorker<'a> {
    pub participation: WorkerParticipation,
    pub capabilities: &'a WorkerCapabilities,
    pub active_cpu_slots: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingTask {
    pub internal_id: String,
    pub abi: String,
    pub requirements: TaskRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligibility {
    NotActive,
    UnsupportedAbi,
    TooManyCpuSlots,
    NoFreeSlots,
    Memory,
    Timeout,
    Output,
    Fuel,
}

impl std::fmt::Display for Ineligibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotActive => "worker is not actively participating",
            Self::UnsupportedAbi => "worker does not support the workload ABI",
            Self::TooManyCpuSlots => "task requires more CPU slots than the worker allows",
            Self::NoFreeSlots => "worker has no free CPU slots",
            Self::Memory => "task memory requirement exceeds the worker's local limit",
            Self::Timeout => "task timeout exceeds the worker's local limit",
            Self::Output => "task output limit exceeds the worker's local limit",
            Self::Fuel => "task fuel limit exceeds the worker's local limit",
        })
    }
}

pub fn task_ineligibility(
    worker: &SchedulingWorker<'_>,
    task: &SchedulingTask,
) -> Option<Ineligibility> {
    let caps = worker.capabilities;
    if worker.participation != WorkerParticipation::Active {
        return Some(Ineligibility::NotActive);
    }
    if !caps.abi.iter().any(|abi| abi == &task.abi) {
        return Some(Ineligibility::UnsupportedAbi);
    }
    if task.requirements.cpu_slots == 0 || task.requirements.cpu_slots > caps.max_concurrency {
        return Some(Ineligibility::TooManyCpuSlots);
    }
    if worker
        .active_cpu_slots
        .saturating_add(task.requirements.cpu_slots)
        > caps.max_concurrency
    {
        return Some(Ineligibility::NoFreeSlots);
    }
    if task.requirements.memory_bytes > caps.max_task_memory_bytes {
        return Some(Ineligibility::Memory);
    }
    if task.requirements.timeout_secs > caps.max_task_timeout_secs {
        return Some(Ineligibility::Timeout);
    }
    if task.requirements.output_bytes > caps.max_output_bytes {
        return Some(Ineligibility::Output);
    }
    if task.requirements.fuel > caps.max_fuel {
        return Some(Ineligibility::Fuel);
    }
    None
}

/// Choose queued tasks for a worker without exceeding its advertised local
/// concurrency. Tasks are considered in queue order. A task that does not fit in
/// the remaining slots is skipped so smaller tasks can still make progress.
pub fn select_tasks_for_worker(
    tasks: &[SchedulingTask],
    worker: &SchedulingWorker<'_>,
    max_assignments: usize,
) -> Vec<String> {
    let mut remaining = worker
        .capabilities
        .max_concurrency
        .saturating_sub(worker.active_cpu_slots);
    let mut selected = Vec::new();
    for task in tasks {
        if selected.len() >= max_assignments {
            break;
        }
        if task.requirements.cpu_slots == 0 {
            continue;
        }
        let mut view = worker.clone();
        view.active_cpu_slots = worker
            .capabilities
            .max_concurrency
            .saturating_sub(remaining);
        if task_ineligibility(&view, task).is_none() {
            remaining = remaining.saturating_sub(task.requirements.cpu_slots);
            selected.push(task.internal_id.clone());
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use getter_protocol::WORKLOAD_ABI;

    fn caps(concurrency: u32) -> WorkerCapabilities {
        WorkerCapabilities {
            abi: vec![WORKLOAD_ABI.into()],
            os: "linux".into(),
            arch: "x86_64".into(),
            cpu_threads: concurrency,
            max_concurrency: concurrency,
            max_task_memory_bytes: 256 * 1024 * 1024,
            max_task_timeout_secs: 120,
            max_output_bytes: 1024 * 1024,
            max_fuel: 5_000_000_000,
            version: "test".into(),
        }
    }

    fn task(id: &str, slots: u32) -> SchedulingTask {
        SchedulingTask {
            internal_id: id.into(),
            abi: WORKLOAD_ABI.into(),
            requirements: TaskRequirements {
                cpu_slots: slots,
                ..TaskRequirements::default()
            },
        }
    }

    #[test]
    fn local_limits_win_over_remote_requirements() {
        let capabilities = caps(2);
        let worker = SchedulingWorker {
            participation: WorkerParticipation::Active,
            capabilities: &capabilities,
            active_cpu_slots: 0,
        };
        let mut oversized = task("a", 1);
        oversized.requirements.memory_bytes = 1024 * 1024 * 1024;
        assert_eq!(
            task_ineligibility(&worker, &oversized),
            Some(Ineligibility::Memory)
        );
        assert_eq!(
            task_ineligibility(&worker, &task("b", 3)),
            Some(Ineligibility::TooManyCpuSlots)
        );
    }

    #[test]
    fn paused_worker_gets_nothing() {
        let capabilities = caps(4);
        let worker = SchedulingWorker {
            participation: WorkerParticipation::Paused,
            capabilities: &capabilities,
            active_cpu_slots: 0,
        };
        let tasks = vec![task("a", 1), task("b", 1)];
        assert!(select_tasks_for_worker(&tasks, &worker, 10).is_empty());
    }

    #[test]
    fn selection_respects_slots_and_assignment_cap() {
        let capabilities = caps(3);
        let worker = SchedulingWorker {
            participation: WorkerParticipation::Active,
            capabilities: &capabilities,
            active_cpu_slots: 1,
        };
        let tasks = vec![task("a", 2), task("b", 1), task("c", 1)];
        assert_eq!(select_tasks_for_worker(&tasks, &worker, 10), vec!["a"]);
        assert_eq!(select_tasks_for_worker(&tasks, &worker, 10).len(), 1);

        let capabilities = caps(4);
        let worker = SchedulingWorker {
            participation: WorkerParticipation::Active,
            capabilities: &capabilities,
            active_cpu_slots: 0,
        };
        let tasks = vec![task("a", 2), task("b", 2), task("c", 2)];
        assert_eq!(select_tasks_for_worker(&tasks, &worker, 1), vec!["a"]);
        assert_eq!(select_tasks_for_worker(&tasks, &worker, 10), vec!["a", "b"]);
    }

    #[test]
    fn incompatible_abi_is_skipped_but_other_tasks_continue() {
        let capabilities = caps(2);
        let worker = SchedulingWorker {
            participation: WorkerParticipation::Active,
            capabilities: &capabilities,
            active_cpu_slots: 0,
        };
        let mut wrong = task("wrong", 1);
        wrong.abi = "other-abi".into();
        let tasks = vec![wrong, task("ok", 1)];
        assert_eq!(select_tasks_for_worker(&tasks, &worker, 10), vec!["ok"]);
    }
}
