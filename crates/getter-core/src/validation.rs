//! Submission, output, and aggregation validation.
//!
//! Validation is deliberately separate from persistence and transport. The
//! coordinator calls these functions before accepting any untrusted job or
//! result, and the same rules are exercised directly by unit tests.

#![deny(unsafe_code)]

use std::collections::HashSet;

use base64::Engine;
use getter_protocol::{
    AggregationSpec, JobManifest, TaskRequirements, TaskSpec, VerificationPolicy,
    WorkerCapabilities, JOB_FORMAT, MAX_FUEL, MAX_INPUT_BYTES, MAX_NAME_BYTES, MAX_OUTPUT_BYTES,
    MAX_TASKS_PER_JOB, MAX_TASK_ID_BYTES, MAX_TASK_TIMEOUT_SECS, WORKLOAD_ABI,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::{is_sha256_hex, normalize_sha256, sha256_hex};
use crate::error::ValidationError;

pub const LEASE_GRACE_SECS: u64 = 5;
pub const MAX_ATTEMPTS_CEILING: u32 = 10;
pub const MAX_AGGREGATE_JSON_BYTES: usize = 64 * 1024;
pub const MIN_MEMORY_BYTES: u64 = 1024 * 1024;
pub const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct CoordinatorLimitsView {
    pub max_tasks_per_job: usize,
    pub max_artifact_bytes: usize,
    pub max_total_input_bytes: usize,
    pub max_total_output_bytes: usize,
    pub max_result_bytes: usize,
    pub allow_trusted_verification: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// The output matched a trusted reference digest.
    Verified,
    /// The coordinator explicitly opted into accepting unverified results.
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskOutput {
    pub task_key: String,
    pub bytes: Vec<u8>,
}

pub fn validate_manifest(
    manifest: &JobManifest,
    limits: CoordinatorLimitsView,
) -> Result<(), ValidationError> {
    if manifest.protocol != JOB_FORMAT {
        return invalid(format!(
            "manifest protocol must be {JOB_FORMAT}, got {:?}",
            manifest.protocol
        ));
    }
    validate_text("job name", &manifest.name, MAX_NAME_BYTES, true)?;
    if let Some(description) = &manifest.description {
        if description.len() > 2048 {
            return invalid("description must be at most 2048 bytes");
        }
    }
    validate_text(
        "workload name",
        &manifest.workload.name,
        MAX_NAME_BYTES,
        true,
    )?;
    if manifest.workload.abi != WORKLOAD_ABI {
        return invalid(format!(
            "unsupported workload ABI {:?}; this release supports {WORKLOAD_ABI}",
            manifest.workload.abi
        ));
    }
    if !is_sha256_hex(&normalize_sha256(&manifest.workload.sha256)) {
        return invalid("workload.sha256 must be a 64-character hexadecimal SHA-256");
    }
    if manifest.tasks.is_empty() {
        return invalid("a job must contain at least one task");
    }
    if manifest.tasks.len() > limits.max_tasks_per_job.min(MAX_TASKS_PER_JOB) {
        return invalid(format!(
            "job contains {} tasks; the coordinator limit is {}",
            manifest.tasks.len(),
            limits.max_tasks_per_job.min(MAX_TASKS_PER_JOB)
        ));
    }
    if manifest.max_attempts == 0 || manifest.max_attempts > MAX_ATTEMPTS_CEILING {
        return invalid(format!(
            "max_attempts must be between 1 and {MAX_ATTEMPTS_CEILING}"
        ));
    }
    if manifest.lease_seconds < 10 || manifest.lease_seconds > 3600 {
        return invalid("lease_seconds must be between 10 and 3600");
    }
    validate_requirements("job", &manifest.requirements, manifest.lease_seconds)?;

    if manifest.verification == VerificationPolicy::Trusted && !limits.allow_trusted_verification {
        return invalid(
            "this coordinator does not accept unverified results; rerun `getter init` with \
             trusted verification enabled only for development or use exact_sha256",
        );
    }

    let mut ids = HashSet::new();
    let mut total_input = 0_usize;
    let mut total_output_limit = 0_u64;
    for task in &manifest.tasks {
        validate_text("task id", &task.id, MAX_TASK_ID_BYTES, false)?;
        if !task
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        {
            return invalid(format!(
                "task id {:?} contains unsupported characters (use ASCII letters, digits, '-', '_', '.', or ':')",
                task.id
            ));
        }
        if !ids.insert(task.id.as_str()) {
            return invalid(format!("duplicate task id {:?}", task.id));
        }
        if task.input.len() > MAX_INPUT_BYTES {
            return invalid(format!(
                "task {:?} input exceeds {MAX_INPUT_BYTES} bytes",
                task.id
            ));
        }
        total_input = total_input.saturating_add(task.input.len());
        if total_input > limits.max_total_input_bytes {
            return invalid(format!(
                "job inputs exceed the coordinator limit of {} bytes",
                limits.max_total_input_bytes
            ));
        }
        let requirements = task.requirements.as_ref().unwrap_or(&manifest.requirements);
        validate_requirements(
            &format!("task {:?}", task.id),
            requirements,
            manifest.lease_seconds,
        )?;
        total_output_limit = total_output_limit.saturating_add(requirements.output_bytes);
        if total_output_limit > limits.max_total_output_bytes as u64 {
            return invalid(format!(
                "declared task output limits exceed the coordinator total of {} bytes",
                limits.max_total_output_bytes
            ));
        }
        if requirements.timeout_secs.saturating_add(LEASE_GRACE_SECS)
            > u64::from(manifest.lease_seconds)
        {
            return invalid(format!(
                "task {:?} timeout {}s must be at least {LEASE_GRACE_SECS}s shorter than lease_seconds {}",
                task.id, requirements.timeout_secs, manifest.lease_seconds
            ));
        }
        match manifest.verification {
            VerificationPolicy::ExactSha256 => {
                let digest = task.expected_output_sha256.as_deref().ok_or_else(|| {
                    ValidationError::Invalid(format!(
                        "task {:?} is missing expected_output_sha256 required by exact_sha256 verification",
                        task.id
                    ))
                })?;
                if !is_sha256_hex(&normalize_sha256(digest)) {
                    return invalid(format!(
                        "task {:?} expected_output_sha256 is not a SHA-256 digest",
                        task.id
                    ));
                }
            }
            VerificationPolicy::Trusted => {
                if let Some(digest) = &task.expected_output_sha256 {
                    if !is_sha256_hex(&normalize_sha256(digest)) {
                        return invalid(format!(
                            "task {:?} expected_output_sha256 is not a SHA-256 digest",
                            task.id
                        ));
                    }
                }
            }
        }
    }
    match &manifest.aggregation {
        AggregationSpec::None => {}
        AggregationSpec::JsonSum { field } => {
            validate_text("aggregation field", field, 64, true)?;
            if !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return invalid(
                    "aggregation field must contain only ASCII letters, digits, or underscore",
                );
            }
        }
    }
    if let Some(expected) = &manifest.expected_aggregate {
        let encoded = serde_json::to_vec(expected).map_err(|error| {
            ValidationError::Invalid(format!("invalid expected aggregate: {error}"))
        })?;
        if encoded.len() > MAX_AGGREGATE_JSON_BYTES {
            return invalid(format!(
                "expected_aggregate must be at most {MAX_AGGREGATE_JSON_BYTES} bytes"
            ));
        }
    }
    if manifest.workload.sha256.len() != 64 {
        return invalid("workload.sha256 has the wrong length");
    }
    if limits.max_artifact_bytes == 0 || limits.max_result_bytes == 0 {
        return invalid("coordinator limits are invalid");
    }
    Ok(())
}

pub fn normalize_manifest(manifest: &mut JobManifest) {
    manifest.workload.sha256 = normalize_sha256(&manifest.workload.sha256);
    for task in &mut manifest.tasks {
        if let Some(hash) = task.expected_output_sha256.take() {
            task.expected_output_sha256 = Some(normalize_sha256(&hash));
        }
    }
}

pub fn validate_requirements(
    context: &str,
    requirements: &TaskRequirements,
    lease_seconds: u32,
) -> Result<(), ValidationError> {
    if requirements.cpu_slots == 0 || requirements.cpu_slots > 128 {
        return invalid(format!("{context} cpu_slots must be between 1 and 128"));
    }
    if !(MIN_MEMORY_BYTES..=MAX_MEMORY_BYTES).contains(&requirements.memory_bytes) {
        return invalid(format!(
            "{context} memory_bytes must be between {MIN_MEMORY_BYTES} and {MAX_MEMORY_BYTES}"
        ));
    }
    if requirements.timeout_secs == 0 || requirements.timeout_secs > MAX_TASK_TIMEOUT_SECS {
        return invalid(format!(
            "{context} timeout_secs must be between 1 and {MAX_TASK_TIMEOUT_SECS}"
        ));
    }
    if requirements.timeout_secs.saturating_add(LEASE_GRACE_SECS) > u64::from(lease_seconds) {
        return invalid(format!(
            "{context} timeout_secs plus the 5 second lease grace exceeds lease_seconds"
        ));
    }
    if requirements.output_bytes == 0 || requirements.output_bytes > MAX_OUTPUT_BYTES {
        return invalid(format!(
            "{context} output_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
        ));
    }
    if requirements.fuel == 0 || requirements.fuel > MAX_FUEL {
        return invalid(format!("{context} fuel must be between 1 and {MAX_FUEL}"));
    }
    Ok(())
}

pub fn validate_artifact(
    bytes: &[u8],
    expected_sha256: &str,
    max_bytes: usize,
) -> Result<(), ValidationError> {
    if bytes.is_empty() {
        return invalid("workload artifact is empty");
    }
    if bytes.len() > max_bytes {
        return invalid(format!(
            "workload artifact is {} bytes; the coordinator limit is {max_bytes}",
            bytes.len()
        ));
    }
    if !bytes.starts_with(b"\0asm") {
        return invalid("workload artifact is not a WebAssembly binary (missing magic)");
    }
    let actual = sha256_hex(bytes);
    if actual != normalize_sha256(expected_sha256) {
        return invalid(format!(
            "workload artifact SHA-256 mismatch: expected {}, computed {actual}",
            normalize_sha256(expected_sha256)
        ));
    }
    Ok(())
}

pub fn validate_worker_capabilities(
    capabilities: &WorkerCapabilities,
) -> Result<(), ValidationError> {
    validate_text(
        "worker version",
        &capabilities.version,
        MAX_NAME_BYTES,
        true,
    )?;
    validate_text("worker os", &capabilities.os, 32, true)?;
    validate_text("worker arch", &capabilities.arch, 32, true)?;
    if !capabilities.abi.iter().any(|abi| abi == WORKLOAD_ABI) {
        return invalid(format!("worker must advertise support for {WORKLOAD_ABI}"));
    }
    if capabilities.abi.len() > 8 {
        return invalid("worker advertised too many ABIs");
    }
    if capabilities.cpu_threads == 0 || capabilities.cpu_threads > 1024 {
        return invalid("worker cpu_threads is outside the permitted range");
    }
    if capabilities.max_concurrency == 0 || capabilities.max_concurrency > 128 {
        return invalid("worker max_concurrency must be between 1 and 128");
    }
    if capabilities.max_task_memory_bytes < MIN_MEMORY_BYTES {
        return invalid("worker max_task_memory_bytes is below 1 MiB");
    }
    if capabilities.max_task_timeout_secs == 0
        || capabilities.max_task_timeout_secs > MAX_TASK_TIMEOUT_SECS
    {
        return invalid("worker max_task_timeout_secs is outside the permitted range");
    }
    if capabilities.max_output_bytes == 0 || capabilities.max_output_bytes > MAX_OUTPUT_BYTES {
        return invalid("worker max_output_bytes is outside the permitted range");
    }
    if capabilities.max_fuel == 0 || capabilities.max_fuel > MAX_FUEL {
        return invalid("worker max_fuel is outside the permitted range");
    }
    Ok(())
}

/// Validate actual output bytes and the workload verification policy. The
/// worker's declared digest is deliberately not trusted for this check.
pub fn verify_task_output(
    task_id: &str,
    output: &[u8],
    requirements: &TaskRequirements,
    policy: VerificationPolicy,
    expected_output_sha256: Option<&str>,
) -> Result<VerificationResult, ValidationError> {
    if output.len() as u64 > requirements.output_bytes {
        return invalid(format!(
            "task {task_id:?} output is {} bytes, above its {} byte limit",
            output.len(),
            requirements.output_bytes
        ));
    }
    match (policy, expected_output_sha256) {
        (VerificationPolicy::ExactSha256, Some(expected)) => {
            let actual = sha256_hex(output);
            if actual != normalize_sha256(expected) {
                return invalid(format!(
                    "task {task_id:?} output failed the trusted reference checksum"
                ));
            }
            Ok(VerificationResult::Verified)
        }
        (VerificationPolicy::ExactSha256, None) => invalid(format!(
            "task {task_id:?} has no trusted reference checksum"
        )),
        (VerificationPolicy::Trusted, Some(expected)) => {
            let actual = sha256_hex(output);
            if actual != normalize_sha256(expected) {
                return invalid(format!(
                    "task {task_id:?} output failed its optional reference checksum"
                ));
            }
            Ok(VerificationResult::Verified)
        }
        (VerificationPolicy::Trusted, None) => Ok(VerificationResult::Unverified),
    }
}

pub fn declared_output_hash_matches(output: &[u8], declared_sha256: &str) -> bool {
    sha256_hex(output) == normalize_sha256(declared_sha256)
}

/// Deterministically aggregate completed task outputs. Only known aggregation
/// modes are executed; workload-provided code never runs in the coordinator.
pub fn aggregate_outputs(
    spec: &AggregationSpec,
    outputs: &[TaskOutput],
) -> Result<Value, ValidationError> {
    match spec {
        AggregationSpec::None => {
            let entries = outputs
                .iter()
                .map(|output| {
                    json!({
                        "task": output.task_key,
                        "sha256": sha256_hex(&output.bytes),
                        "bytes_base64": base64::engine::general_purpose::STANDARD.encode(&output.bytes),
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({ "outputs": entries }))
        }
        AggregationSpec::JsonSum { field } => {
            let mut total: u128 = 0;
            for output in outputs {
                let value: Value = serde_json::from_slice(&output.bytes).map_err(|error| {
                    ValidationError::Invalid(format!(
                        "task {:?} output is not valid JSON for json_sum: {error}",
                        output.task_key
                    ))
                })?;
                let object = value.as_object().ok_or_else(|| {
                    ValidationError::Invalid(format!(
                        "task {:?} output must be a JSON object for json_sum",
                        output.task_key
                    ))
                })?;
                let field_value = object.get(field).ok_or_else(|| {
                    ValidationError::Invalid(format!(
                        "task {:?} output is missing JSON field {field:?}",
                        output.task_key
                    ))
                })?;
                let numeric = match field_value {
                    Value::String(text) => text.parse::<u128>().map_err(|_| {
                        ValidationError::Invalid(format!(
                            "task {:?} field {field:?} must be an unsigned decimal integer",
                            output.task_key
                        ))
                    })?,
                    Value::Number(number) => number.as_u64().map(u128::from).ok_or_else(|| {
                        ValidationError::Invalid(format!(
                            "task {:?} field {field:?} must be a non-negative integer",
                            output.task_key
                        ))
                    })?,
                    _ => {
                        return invalid(format!(
                        "task {:?} field {field:?} must be an unsigned integer or decimal string",
                        output.task_key
                    ))
                    }
                };
                total = total
                    .checked_add(numeric)
                    .ok_or_else(|| ValidationError::Invalid("json_sum overflowed u128".into()))?;
            }
            Ok(json!({ "total": total.to_string() }))
        }
    }
}

pub fn expected_aggregate_matches(expected: &Value, actual: &Value) -> bool {
    expected == actual
}

pub fn output_preview(bytes: &[u8], max_bytes: usize) -> Option<String> {
    let truncated = &bytes[..bytes.len().min(max_bytes)];
    let text = std::str::from_utf8(truncated).ok()?;
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() && !matches!(character, '\n' | '\t') {
            safe.push('�');
        } else {
            safe.push(character);
        }
    }
    if bytes.len() > max_bytes {
        safe.push('…');
    }
    Some(safe)
}

fn validate_text(
    label: &str,
    value: &str,
    max_bytes: usize,
    reject_control: bool,
) -> Result<(), ValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return invalid(format!("{label} must not be empty"));
    }
    if trimmed.len() > max_bytes {
        return invalid(format!("{label} must be at most {max_bytes} bytes"));
    }
    if reject_control && value.chars().any(char::is_control) {
        return invalid(format!("{label} must not contain control characters"));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ValidationError> {
    Err(ValidationError::Invalid(message.into()))
}

/// Parsed view of a task's verification contract, used by storage and worker
/// result handling.
pub struct TaskVerificationContract<'a> {
    pub task_id: &'a str,
    pub policy: VerificationPolicy,
    pub expected_output_sha256: Option<&'a str>,
    pub requirements: &'a TaskRequirements,
}

impl<'a> From<(&'a TaskSpec, &'a JobManifest)> for TaskVerificationContract<'a> {
    fn from((task, manifest): (&'a TaskSpec, &'a JobManifest)) -> Self {
        Self {
            task_id: &task.id,
            policy: manifest.verification,
            expected_output_sha256: task.expected_output_sha256.as_deref(),
            requirements: task.requirements.as_ref().unwrap_or(&manifest.requirements),
        }
    }
}

/// Compute the digest of an artifact for display and comparison.
pub fn artifact_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use getter_protocol::{
        AggregationSpec, JobManifest, TaskRequirements, TaskSpec, VerificationPolicy,
        WorkloadDescriptor,
    };

    fn limits() -> CoordinatorLimitsView {
        CoordinatorLimitsView {
            max_tasks_per_job: 100,
            max_artifact_bytes: 1024 * 1024,
            max_total_input_bytes: 1024 * 1024,
            max_total_output_bytes: 64 * 1024 * 1024,
            max_result_bytes: 1024,
            allow_trusted_verification: false,
        }
    }

    fn manifest() -> JobManifest {
        let input = "hello";
        JobManifest {
            protocol: JOB_FORMAT.into(),
            name: "test job".into(),
            description: None,
            workload: WorkloadDescriptor {
                name: "sum".into(),
                abi: WORKLOAD_ABI.into(),
                sha256: "a".repeat(64),
            },
            tasks: vec![TaskSpec {
                id: "t-1".into(),
                input: input.into(),
                requirements: None,
                expected_output_sha256: Some(sha256_hex(b"output")),
            }],
            requirements: TaskRequirements {
                timeout_secs: 30,
                ..TaskRequirements::default()
            },
            verification: VerificationPolicy::ExactSha256,
            aggregation: AggregationSpec::None,
            expected_aggregate: None,
            max_attempts: 3,
            lease_seconds: 60,
        }
    }

    #[test]
    fn total_declared_output_limit_is_enforced() {
        let mut manifest = manifest();
        manifest.tasks = (0..65)
            .map(|index| TaskSpec {
                id: format!("t-{index}"),
                input: "x".into(),
                requirements: None,
                expected_output_sha256: Some(sha256_hex(b"out")),
            })
            .collect();
        // Default per-task output is 1 MiB; 65 tasks cross the 64 MiB aggregate
        // cap while remaining individually valid.
        let limits = CoordinatorLimitsView {
            max_total_output_bytes: 64 * 1024 * 1024,
            ..limits()
        };
        let error = validate_manifest(&manifest, limits).expect_err("aggregate cap");
        assert!(error.to_string().contains("declared task output limits"));
    }

    #[test]
    fn valid_manifest_passes() {
        validate_manifest(&manifest(), limits()).expect("valid");
    }

    #[test]
    fn trusted_verification_is_opt_in() {
        let mut manifest = manifest();
        manifest.verification = VerificationPolicy::Trusted;
        manifest.tasks[0].expected_output_sha256 = None;
        assert!(validate_manifest(&manifest, limits()).is_err());
        let mut permissive = limits();
        permissive.allow_trusted_verification = true;
        validate_manifest(&manifest, permissive).expect("opt in");
    }

    #[test]
    fn duplicate_and_malformed_task_ids_are_rejected() {
        let mut duplicate = manifest();
        duplicate.tasks.push(duplicate.tasks[0].clone());
        assert!(validate_manifest(&duplicate, limits()).is_err());

        let mut malformed = manifest();
        malformed.tasks[0].id = "bad/task".into();
        assert!(validate_manifest(&malformed, limits()).is_err());
    }

    #[test]
    fn oversized_input_and_unsafe_name_rejected() {
        let mut oversized = manifest();
        oversized.tasks[0].input = "x".repeat(MAX_INPUT_BYTES + 1);
        assert!(validate_manifest(&oversized, limits()).is_err());

        let mut unsafe_name = manifest();
        unsafe_name.name = "bad\nname".into();
        assert!(validate_manifest(&unsafe_name, limits()).is_err());
    }

    #[test]
    fn lease_must_outlive_timeout_with_grace() {
        let mut manifest = manifest();
        manifest.requirements.timeout_secs = 60;
        manifest.lease_seconds = 30;
        manifest.tasks[0].requirements = None;
        assert!(validate_manifest(&manifest, limits()).is_err());
    }

    #[test]
    fn artifact_integrity_and_magic_are_checked() {
        let artifact = b"\0asm\x01\0\0\0";
        validate_artifact(artifact, &sha256_hex(artifact), 1024).expect("artifact");
        assert!(validate_artifact(artifact, &"b".repeat(64), 1024).is_err());
        assert!(validate_artifact(b"not wasm", &sha256_hex(b"not wasm"), 1024).is_err());
    }

    #[test]
    fn output_checksum_validation_uses_real_bytes() {
        let requirements = TaskRequirements::default();
        let expected = sha256_hex(b"{\"value\":42}");
        assert_eq!(
            verify_task_output(
                "t",
                b"{\"value\":42}",
                &requirements,
                VerificationPolicy::ExactSha256,
                Some(&expected)
            )
            .expect("match"),
            VerificationResult::Verified
        );
        assert!(verify_task_output(
            "t",
            b"{\"value\":41}",
            &requirements,
            VerificationPolicy::ExactSha256,
            Some(&expected)
        )
        .is_err());
    }

    #[test]
    fn oversized_output_is_rejected_before_checksum() {
        let requirements = TaskRequirements {
            output_bytes: 4,
            ..TaskRequirements::default()
        };
        assert!(verify_task_output(
            "t",
            b"12345",
            &requirements,
            VerificationPolicy::Trusted,
            None
        )
        .is_err());
    }

    #[test]
    fn json_sum_handles_large_decimal_strings_and_overflow() {
        let outputs = vec![
            TaskOutput {
                task_key: "a".into(),
                bytes: br#"{"value":"100000000000000000000"}"#.to_vec(),
            },
            TaskOutput {
                task_key: "b".into(),
                bytes: br#"{"value":7}"#.to_vec(),
            },
        ];
        let aggregate = aggregate_outputs(
            &AggregationSpec::JsonSum {
                field: "value".into(),
            },
            &outputs,
        )
        .expect("sum");
        assert_eq!(aggregate, json!({"total": "100000000000000000007"}));

        let outputs = vec![
            TaskOutput {
                task_key: "a".into(),
                bytes: br#"{"value":"340282366920938463463374607431768211455"}"#.to_vec(),
            },
            TaskOutput {
                task_key: "b".into(),
                bytes: br#"{"value":1}"#.to_vec(),
            },
        ];
        assert!(aggregate_outputs(
            &AggregationSpec::JsonSum {
                field: "value".into()
            },
            &outputs
        )
        .is_err());
    }

    #[test]
    fn aggregation_rejects_malformed_outputs() {
        let outputs = vec![TaskOutput {
            task_key: "a".into(),
            bytes: b"not json".to_vec(),
        }];
        assert!(aggregate_outputs(
            &AggregationSpec::JsonSum {
                field: "value".into()
            },
            &outputs
        )
        .is_err());
    }

    #[test]
    fn none_aggregation_is_deterministic_and_includes_hashes() {
        let outputs = vec![
            TaskOutput {
                task_key: "a".into(),
                bytes: b"one".to_vec(),
            },
            TaskOutput {
                task_key: "b".into(),
                bytes: b"two".to_vec(),
            },
        ];
        let aggregate = aggregate_outputs(&AggregationSpec::None, &outputs).expect("none");
        assert_eq!(aggregate["outputs"][0]["task"], "a");
        assert_eq!(aggregate["outputs"][0]["sha256"], sha256_hex(b"one"));
    }

    #[test]
    fn previews_are_bounded_and_utf8_safe() {
        assert_eq!(output_preview(b"hello", 1024).as_deref(), Some("hello"));
        let preview = output_preview(b"abcdef", 3).expect("utf8");
        assert!(preview.starts_with("abc"));
        assert_eq!(output_preview(&[0xff, 0xfe], 10), None);
    }
}
