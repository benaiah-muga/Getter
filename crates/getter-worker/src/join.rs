//! Explicit worker enrollment, including out-of-band CA fingerprint pinning.

use std::path::{Path, PathBuf};

use getter_core::auth::constant_time_eq;
use getter_core::config::{config_path, GetterConfig};
use getter_core::init::{
    ensure_private_dir, fingerprint_pem, load_worker_identity, read_control_token, worker_ca_path,
    write_config, write_secret, write_worker_identity,
};
use getter_protocol::{EnrollRequest, PROTOCOL_VERSION};
use tracing::info;

use crate::client::{build_client_with_ca, fetch_ca_pem, WorkerClient};
use crate::error::WorkerError;

#[derive(Clone)]
pub struct JoinOptions {
    pub coordinator_url: String,
    pub pairing_token: String,
    pub ca_cert: Option<PathBuf>,
    pub ca_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JoinOutcome {
    pub worker_id: String,
    pub coordinator_name: String,
    pub ca_fingerprint: Option<String>,
}

/// Enroll this worker using a one-time pairing token.
///
/// For HTTPS coordinators the caller must either supply the coordinator CA
/// certificate or the fingerprint printed by `getter pair`. Fingerprint
/// bootstrap fetches the public CA over an unverified connection but refuses to
/// use it unless the DER fingerprint matches the out-of-band value. No pairing
/// token is sent over the unverified bootstrap connection.
pub async fn join(home: &Path, options: JoinOptions) -> Result<JoinOutcome, WorkerError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if options.pairing_token.trim().is_empty() {
        return Err(WorkerError::Pairing("pairing token is empty".into()));
    }
    let mut config =
        GetterConfig::load(home).map_err(|error| WorkerError::Configuration(error.to_string()))?;
    let mut worker = config
        .worker
        .clone()
        .ok_or_else(|| WorkerError::Configuration("not a worker configuration".into()))?;
    if config_path(home).exists() && worker.coordinator_url != options.coordinator_url {
        // Reconfiguration is explicit, but permit it as part of joining.
        worker.coordinator_ca = None;
    }
    let identity = load_worker_identity(home)
        .map_err(|error| WorkerError::Configuration(error.to_string()))?;
    let signing_key = identity
        .signing_key()
        .map_err(|error| WorkerError::Configuration(error.to_string()))?;

    let fingerprint = options
        .ca_fingerprint
        .as_deref()
        .map(normalize_fingerprint)
        .transpose()?;
    let https = options.coordinator_url.starts_with("https://");
    let saved_ca = worker_ca_path(home);
    ensure_private_dir(home)?;
    ensure_private_dir(&home.join("trust"))?;

    let ca_path = if https {
        let selected = if let Some(path) = &options.ca_cert {
            let pem = std::fs::read(path).map_err(|error| {
                WorkerError::Trust(format!("could not read CA certificate: {error}"))
            })?;
            let actual = fingerprint_pem(&pem)
                .map_err(|error| WorkerError::Trust(format!("invalid CA certificate: {error}")))?;
            let _der = getter_core::init::certificate_der_from_pem(&pem)
                .map_err(|error| WorkerError::Trust(error.to_string()))?;
            if let Some(expected) = &fingerprint {
                if !constant_time_eq(&actual, expected) {
                    return Err(WorkerError::Trust(
                        "supplied CA certificate does not match the expected fingerprint".into(),
                    ));
                }
            }
            write_secret(&saved_ca, &pem)?;
            actual
        } else if let Some(expected) = &fingerprint {
            let pem = fetch_ca_pem(
                &options.coordinator_url,
                std::time::Duration::from_secs(worker.request_timeout_secs),
            )
            .await?;
            let actual = fingerprint_pem(&pem)
                .map_err(|error| WorkerError::Trust(format!("invalid fetched CA: {error}")))?;
            if !constant_time_eq(&actual, expected) {
                return Err(WorkerError::Trust(
                    "fetched CA certificate does not match the pairing fingerprint".into(),
                ));
            }
            write_secret(&saved_ca, &pem)?;
            actual
        } else if worker
            .coordinator_ca
            .as_ref()
            .is_some_and(|path| path.exists())
        {
            let path = worker.coordinator_ca.clone().expect("checked");
            let pem = std::fs::read(&path)?;
            let actual = fingerprint_pem(&pem)
                .map_err(|error| WorkerError::Trust(format!("invalid CA certificate: {error}")))?;
            let _der = getter_core::init::certificate_der_from_pem(&pem)
                .map_err(|error| WorkerError::Trust(error.to_string()))?;
            if let Some(expected) = &fingerprint {
                if !constant_time_eq(&actual, expected) {
                    return Err(WorkerError::Trust(
                        "existing CA certificate does not match the expected fingerprint".into(),
                    ));
                }
            }
            actual
        } else {
            return Err(WorkerError::Trust(
                "HTTPS enrollment requires --ca-cert or --ca-fingerprint from the coordinator's pairing output"
                    .into(),
            ));
        };
        worker.coordinator_ca = Some(saved_ca.clone());
        Some((selected, saved_ca))
    } else {
        worker.coordinator_ca = None;
        None
    };

    let timeout = std::time::Duration::from_secs(worker.request_timeout_secs);
    worker.coordinator_url = options.coordinator_url.clone();
    worker
        .validate()
        .map_err(|error| WorkerError::Configuration(error.to_string()))?;
    let http = build_client_with_ca(ca_path.as_ref().map(|(_, path)| path.as_path()), timeout)?;
    let capabilities = crate::capabilities(&worker);
    let request = EnrollRequest {
        protocol: PROTOCOL_VERSION.into(),
        pairing_token: options.pairing_token,
        worker_name: identity.worker_name.clone(),
        public_key: signing_key.public_base64().to_owned(),
        capabilities,
    };
    let enrollment = WorkerClient::enroll(&http, &options.coordinator_url, &request).await?;
    if let Some((actual, _)) = &ca_path {
        if let Some(expected) = &fingerprint {
            if !constant_time_eq(actual, expected) {
                return Err(WorkerError::Trust(
                    "coordinator CA changed during enrollment".into(),
                ));
            }
        }
    }

    config.worker = Some(worker);
    write_config(home, &config)
        .map_err(|error| WorkerError::Configuration(format!("save config: {error}")))?;
    let mut identity = identity;
    identity.worker_id = Some(enrollment.worker_id.clone());
    write_worker_identity(home, &identity)
        .map_err(|error| WorkerError::Configuration(format!("save identity: {error}")))?;
    // Touch the control token file early so `worker start` fails clearly if the
    // home is incomplete.
    let _ = read_control_token(home).map_err(|error| WorkerError::Init(error.to_string()))?;
    info!(
        worker_id = %enrollment.worker_id,
        worker_name = %identity.worker_name,
        coordinator = %options.coordinator_url,
        "worker enrolled"
    );
    Ok(JoinOutcome {
        worker_id: enrollment.worker_id,
        coordinator_name: enrollment.coordinator_name,
        ca_fingerprint: enrollment.ca_fingerprint,
    })
}

fn normalize_fingerprint(value: &str) -> Result<String, WorkerError> {
    let value = value.trim().to_ascii_lowercase();
    let hex = value.strip_prefix("sha256:").unwrap_or(&value);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WorkerError::Trust(
            "CA fingerprint must be sha256:<64 hex characters>".into(),
        ));
    }
    Ok(format!("sha256:{hex}"))
}

/// Build an identity for diagnostics without exposing the private key.
pub fn identity_public_key(home: &Path) -> Result<String, WorkerError> {
    let identity = load_worker_identity(home)
        .map_err(|error| WorkerError::Configuration(error.to_string()))?;
    Ok(identity.public_key)
}
