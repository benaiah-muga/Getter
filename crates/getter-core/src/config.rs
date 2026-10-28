//! Configuration schema, defaults, loading, and security checks.

#![deny(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use getter_protocol::{
    MAX_ARTIFACT_BYTES, MAX_HTTP_BODY_BYTES, MAX_NAME_BYTES, MAX_OUTPUT_BYTES, MAX_TASKS_PER_JOB,
    MAX_TASK_TIMEOUT_SECS, MAX_TOTAL_INPUT_BYTES, MAX_TOTAL_OUTPUT_BYTES,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::ConfigError;

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Coordinator,
    Worker,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Worker => "worker",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "coordinator" => Ok(Self::Coordinator),
            "worker" => Ok(Self::Worker),
            other => Err(format!(
                "unknown role {other:?}; expected coordinator or worker"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ca_cert: PathBuf,
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub port: u16,
    pub interval_secs: u64,
    /// Optional unicast target. Broadcast is used when this is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<SocketAddr>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: getter_protocol::DEFAULT_DISCOVERY_PORT,
            interval_secs: 5,
            target: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorLimits {
    pub max_tasks_per_job: usize,
    pub max_artifact_bytes: usize,
    pub max_total_input_bytes: usize,
    #[serde(default = "default_max_total_output_bytes")]
    pub max_total_output_bytes: usize,
    pub max_http_body_bytes: usize,
    pub max_result_bytes: usize,
    pub allow_trusted_verification: bool,
    pub heartbeat_timeout_secs: u64,
}

impl Default for CoordinatorLimits {
    fn default() -> Self {
        Self {
            max_tasks_per_job: MAX_TASKS_PER_JOB,
            max_artifact_bytes: MAX_ARTIFACT_BYTES,
            max_total_input_bytes: MAX_TOTAL_INPUT_BYTES,
            max_total_output_bytes: MAX_TOTAL_OUTPUT_BYTES,
            max_http_body_bytes: MAX_HTTP_BODY_BYTES,
            max_result_bytes: MAX_OUTPUT_BYTES as usize,
            allow_trusted_verification: false,
            heartbeat_timeout_secs: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorConfig {
    pub bind: SocketAddr,
    pub public_url: String,
    pub database_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
    pub discovery: DiscoveryConfig,
    pub limits: CoordinatorLimits,
    /// Never enable this for an untrusted network. It exists for isolated
    /// development and test environments only.
    #[serde(default)]
    pub allow_insecure_remote: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    pub coordinator_url: String,
    /// Local copy of the coordinator CA certificate. Required for HTTPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_ca: Option<PathBuf>,
    pub concurrency: u32,
    pub max_task_memory_bytes: u64,
    pub max_task_timeout_secs: u64,
    pub max_output_bytes: u64,
    pub max_fuel: u64,
    pub max_download_bytes: u64,
    pub poll_interval_ms: u64,
    pub heartbeat_interval_secs: u64,
    pub request_timeout_secs: u64,
    pub control_bind: SocketAddr,
    pub pause_on_battery: bool,
    /// Unix nice value applied at startup when supported. `None` leaves the
    /// process priority untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub niceness: Option<i32>,
    /// Abort a running task this many seconds before its lease expires if the
    /// coordinator has not extended it. No lease extension protocol exists in
    /// v0.1, so jobs must declare a lease longer than their execution timeout.
    pub lease_safety_secs: u64,
    #[serde(default)]
    pub allow_insecure_remote: bool,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(2) as u32;
        Self {
            coordinator_url: "http://127.0.0.1:47810".into(),
            coordinator_ca: None,
            concurrency: cpus.saturating_sub(1).clamp(1, 4),
            max_task_memory_bytes: 256 * 1024 * 1024,
            max_task_timeout_secs: 300,
            max_output_bytes: MAX_OUTPUT_BYTES,
            max_fuel: 5_000_000_000,
            max_download_bytes: MAX_ARTIFACT_BYTES as u64,
            poll_interval_ms: 750,
            heartbeat_interval_secs: 5,
            request_timeout_secs: 30,
            control_bind: "127.0.0.1:47811".parse().expect("static address"),
            pause_on_battery: true,
            niceness: Some(10),
            lease_safety_secs: 3,
            allow_insecure_remote: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetterConfig {
    pub version: u32,
    pub role: Role,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator: Option<CoordinatorConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<WorkerConfig>,
}

pub fn config_path(home: &Path) -> PathBuf {
    home.join("config.toml")
}

pub fn admin_token_path(home: &Path) -> PathBuf {
    home.join("secrets").join("admin-token")
}

pub fn control_token_path(home: &Path) -> PathBuf {
    home.join("secrets").join("control-token")
}

pub fn worker_identity_path(home: &Path) -> PathBuf {
    home.join("worker").join("identity.json")
}

impl GetterConfig {
    pub fn load(home: &Path) -> Result<Self, ConfigError> {
        let path = config_path(home);
        if !path.exists() {
            return Err(ConfigError::Missing(path));
        }
        let bytes = std::fs::read(&path)?;
        let config: Self = toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|_| ConfigError::Invalid("config.toml is not UTF-8".into()))?,
        )?;
        if config.version != CONFIG_VERSION {
            return Err(ConfigError::Version {
                found: config.version,
                expected: CONFIG_VERSION,
            });
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_name(&self.name)?;
        match self.role {
            Role::Coordinator => {
                let coordinator = self.coordinator.as_ref().ok_or_else(|| {
                    ConfigError::Invalid("role is coordinator but [coordinator] is missing".into())
                })?;
                if self.worker.is_some() {
                    return Err(ConfigError::Invalid(
                        "coordinator configuration must not contain a [worker] table".into(),
                    ));
                }
                coordinator.validate()
            }
            Role::Worker => {
                let worker = self.worker.as_ref().ok_or_else(|| {
                    ConfigError::Invalid("role is worker but [worker] is missing".into())
                })?;
                if self.coordinator.is_some() {
                    return Err(ConfigError::Invalid(
                        "worker configuration must not contain a [coordinator] table".into(),
                    ));
                }
                worker.validate()
            }
        }
    }

    pub fn coordinator(&self) -> Result<&CoordinatorConfig, ConfigError> {
        self.coordinator
            .as_ref()
            .ok_or_else(|| ConfigError::Invalid("not a coordinator configuration".into()))
    }

    pub fn worker(&self) -> Result<&WorkerConfig, ConfigError> {
        self.worker
            .as_ref()
            .ok_or_else(|| ConfigError::Invalid("not a worker configuration".into()))
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }
}

impl CoordinatorConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.public_url.len() > 512 {
            return Err(ConfigError::Invalid("public_url is too long".into()));
        }
        let url = Url::parse(&self.public_url)
            .map_err(|error| ConfigError::Invalid(format!("public_url is not a URL: {error}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::Invalid(
                "public_url must use http or https".into(),
            ));
        }
        if self.tls.is_some() && url.scheme() != "https" {
            return Err(ConfigError::Invalid(
                "public_url must use https when TLS is configured".into(),
            ));
        }
        if self.tls.is_none() && url.scheme() != "http" {
            return Err(ConfigError::Invalid(
                "public_url must use http when TLS is not configured".into(),
            ));
        }
        if self.bind.ip().is_unspecified() && self.public_url.contains("0.0.0.0") {
            return Err(ConfigError::Invalid(
                "public_url must name the reachable coordinator address, not 0.0.0.0".into(),
            ));
        }
        if !is_loopback_ip(self.bind.ip()) && self.tls.is_none() && !self.allow_insecure_remote {
            return Err(ConfigError::Invalid(
                "refusing to bind a non-loopback coordinator without TLS; configure TLS or set \
                 allow_insecure_remote=true only on an isolated development network"
                    .into(),
            ));
        }
        if let Some(tls) = &self.tls {
            if tls.ca_cert == tls.private_key || tls.cert_chain == tls.private_key {
                return Err(ConfigError::Invalid(
                    "TLS private key path must differ from certificate paths".into(),
                ));
            }
        }
        self.discovery.validate()?;
        self.limits.validate()
    }
}

impl DiscoveryConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "discovery port must be non-zero".into(),
            ));
        }
        if self.interval_secs < 1 || self.interval_secs > 300 {
            return Err(ConfigError::Invalid(
                "discovery interval_secs must be between 1 and 300".into(),
            ));
        }
        Ok(())
    }
}

const fn default_max_total_output_bytes() -> usize {
    MAX_TOTAL_OUTPUT_BYTES
}

impl CoordinatorLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_tasks_per_job == 0 || self.max_tasks_per_job > MAX_TASKS_PER_JOB {
            return Err(ConfigError::Invalid(format!(
                "max_tasks_per_job must be between 1 and {MAX_TASKS_PER_JOB}"
            )));
        }
        if self.max_artifact_bytes == 0 || self.max_artifact_bytes > MAX_ARTIFACT_BYTES {
            return Err(ConfigError::Invalid(format!(
                "max_artifact_bytes must be between 1 and {MAX_ARTIFACT_BYTES}"
            )));
        }
        if self.max_total_input_bytes == 0 || self.max_total_input_bytes > MAX_TOTAL_INPUT_BYTES {
            return Err(ConfigError::Invalid(format!(
                "max_total_input_bytes must be between 1 and {MAX_TOTAL_INPUT_BYTES}"
            )));
        }
        if self.max_result_bytes == 0 || self.max_result_bytes > MAX_OUTPUT_BYTES as usize {
            return Err(ConfigError::Invalid(format!(
                "max_result_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
            )));
        }
        if self.max_total_output_bytes < self.max_result_bytes
            || self.max_total_output_bytes > MAX_TOTAL_OUTPUT_BYTES
        {
            return Err(ConfigError::Invalid(format!(
                "max_total_output_bytes must be at least max_result_bytes and at most {MAX_TOTAL_OUTPUT_BYTES}"
            )));
        }
        let minimum_body = self
            .max_artifact_bytes
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(self.max_total_input_bytes)
            .saturating_add(1024 * 1024);
        if self.max_http_body_bytes < minimum_body || self.max_http_body_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid(format!(
                "max_http_body_bytes must be at least encoded artifact + total inputs + 1 MiB ({minimum_body}) and at most 67108864"
            )));
        }
        if self.heartbeat_timeout_secs < 5 || self.heartbeat_timeout_secs > 600 {
            return Err(ConfigError::Invalid(
                "heartbeat_timeout_secs must be between 5 and 600".into(),
            ));
        }
        Ok(())
    }
}

impl WorkerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let url = Url::parse(&self.coordinator_url).map_err(|error| {
            ConfigError::Invalid(format!("coordinator_url is not a URL: {error}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::Invalid(
                "coordinator_url must use http or https".into(),
            ));
        }
        let host_is_loopback = url.host_str().map(is_loopback_host).unwrap_or(false);
        if url.scheme() == "http" && !host_is_loopback && !self.allow_insecure_remote {
            return Err(ConfigError::Invalid(
                "refusing a plaintext coordinator URL for a non-loopback host; use https or set \
                 allow_insecure_remote=true only on an isolated development network"
                    .into(),
            ));
        }
        if url.scheme() == "https" && self.coordinator_ca.is_none() {
            return Err(ConfigError::Invalid(
                "coordinator_ca is required for an https coordinator URL".into(),
            ));
        }
        if self.concurrency == 0 || self.concurrency > 128 {
            return Err(ConfigError::Invalid(
                "concurrency must be between 1 and 128".into(),
            ));
        }
        if self.max_task_memory_bytes < 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "max_task_memory_bytes must be at least 1 MiB".into(),
            ));
        }
        if self.max_task_timeout_secs == 0 || self.max_task_timeout_secs > MAX_TASK_TIMEOUT_SECS {
            return Err(ConfigError::Invalid(format!(
                "max_task_timeout_secs must be between 1 and {MAX_TASK_TIMEOUT_SECS}"
            )));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_OUTPUT_BYTES {
            return Err(ConfigError::Invalid(format!(
                "max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
            )));
        }
        if self.max_fuel == 0 || self.max_fuel > getter_protocol::MAX_FUEL {
            return Err(ConfigError::Invalid(
                "max_fuel is outside the permitted range".into(),
            ));
        }
        if self.max_download_bytes == 0 || self.max_download_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "max_download_bytes must be between 1 and 67108864".into(),
            ));
        }
        if self.poll_interval_ms < 100 || self.poll_interval_ms > 60_000 {
            return Err(ConfigError::Invalid(
                "poll_interval_ms must be between 100 and 60000".into(),
            ));
        }
        if self.heartbeat_interval_secs < 1 || self.heartbeat_interval_secs > 300 {
            return Err(ConfigError::Invalid(
                "heartbeat_interval_secs must be between 1 and 300".into(),
            ));
        }
        if self.request_timeout_secs < 1 || self.request_timeout_secs > 300 {
            return Err(ConfigError::Invalid(
                "request_timeout_secs must be between 1 and 300".into(),
            ));
        }
        if !self.control_bind.ip().is_loopback() {
            return Err(ConfigError::Invalid(
                "worker control_bind must be a loopback address; the control API is never exposed \
                 to the network"
                    .into(),
            ));
        }
        if self.lease_safety_secs > 60 {
            return Err(ConfigError::Invalid(
                "lease_safety_secs must not exceed 60".into(),
            ));
        }
        if let Some(nice) = self.niceness {
            #[cfg(unix)]
            if !(-20..=19).contains(&nice) {
                return Err(ConfigError::Invalid(
                    "niceness must be between -20 and 19".into(),
                ));
            }
            #[cfg(not(unix))]
            let _ = nice;
        }
        Ok(())
    }

    pub fn coordinator_ca(&self) -> Option<&Path> {
        self.coordinator_ca.as_deref()
    }
}

pub fn validate_name(name: &str) -> Result<(), ConfigError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::Invalid("name must not be empty".into()));
    }
    if trimmed.len() > MAX_NAME_BYTES {
        return Err(ConfigError::Invalid(format!(
            "name must be at most {MAX_NAME_BYTES} bytes"
        )));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(ConfigError::Invalid(
            "name must not contain control characters".into(),
        ));
    }
    Ok(())
}

pub fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.is_loopback()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().map(is_loopback_ip).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker_config(url: &str) -> WorkerConfig {
        WorkerConfig {
            coordinator_url: url.into(),
            ..WorkerConfig::default()
        }
    }

    fn coordinator_config(bind: &str, public_url: &str) -> CoordinatorConfig {
        CoordinatorConfig {
            bind: bind.parse().expect("bind"),
            public_url: public_url.into(),
            database_path: PathBuf::from("/tmp/getter.db"),
            tls: None,
            discovery: DiscoveryConfig::default(),
            limits: CoordinatorLimits::default(),
            allow_insecure_remote: false,
        }
    }

    #[test]
    fn remote_plain_http_is_rejected_by_default() {
        assert!(worker_config("http://192.0.2.10:47810").validate().is_err());
        let mut config = worker_config("http://192.0.2.10:47810");
        config.allow_insecure_remote = true;
        assert!(config.validate().is_ok());
        assert!(worker_config("http://127.0.0.1:47810").validate().is_ok());
    }

    #[test]
    fn https_requires_trust_material() {
        assert!(worker_config("https://127.0.0.1:47810").validate().is_err());
        let mut config = worker_config("https://127.0.0.1:47810");
        config.coordinator_ca = Some(PathBuf::from("/tmp/ca.pem"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn control_api_cannot_bind_publicly() {
        let mut config = worker_config("http://127.0.0.1:47810");
        config.control_bind = "0.0.0.0:47811".parse().expect("address");
        assert!(config.validate().is_err());
    }

    #[test]
    fn coordinator_without_tls_cannot_bind_publicly() {
        let config = coordinator_config("0.0.0.0:47810", "http://192.0.2.2:47810");
        assert!(config.validate().is_err());
        let mut config = config;
        config.allow_insecure_remote = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_round_trips_and_rejects_unknown_fields() {
        let config = GetterConfig {
            version: CONFIG_VERSION,
            role: Role::Worker,
            name: "desk".into(),
            coordinator: None,
            worker: Some(worker_config("http://127.0.0.1:47810")),
        };
        let encoded = config.to_toml().expect("serialize");
        let decoded: GetterConfig = toml::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, config);

        let bad = format!("{encoded}\nmystery = true\n");
        assert!(toml::from_str::<GetterConfig>(&bad).is_err());
    }

    #[test]
    fn default_coordinator_limits_are_self_consistent() {
        let limits = CoordinatorLimits::default();
        assert!(limits.validate().is_ok());
        assert!(limits.max_http_body_bytes >= 40 * 1024 * 1024);
    }

    #[test]
    fn defaults_are_conservative() {
        let worker = WorkerConfig::default();
        assert!(worker.concurrency >= 1);
        assert_eq!(worker.max_task_memory_bytes, 256 * 1024 * 1024);
        assert!(worker.pause_on_battery);
        assert!(worker.validate().is_ok());

        let limits = CoordinatorLimits::default();
        assert!(!limits.allow_trusted_verification);
        assert_eq!(limits.heartbeat_timeout_secs, 20);
    }
}
