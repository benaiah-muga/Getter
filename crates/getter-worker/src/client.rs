//! Signed coordinator client used by workers.

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use getter_core::auth::{nonce, sha256_hex, worker_signature_message, WorkerSigningKey};
use getter_protocol::{
    ApiErrorBody, AssignmentsResponse, EnrollRequest, EnrollResponse, HeartbeatResponse,
    LeaseTokenRequest, LeaveRequest, ResultAck, StartedResponse, TaskAssignment, TaskResultRequest,
    WorkerHeartbeat, HEADER_LEASE_TOKEN, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
    HEADER_WORKER_ID,
};
use reqwest::{Client, Method, Response, StatusCode};

use crate::error::WorkerError;

const JSON_BODY_LIMIT: usize = 32 * 1024 * 1024;
const ERROR_BODY_LIMIT: usize = 64 * 1024;

pub struct WorkerClient {
    http: Client,
    base_url: String,
    worker_id: String,
    signing_key: WorkerSigningKey,
    request_timeout: Duration,
}

impl WorkerClient {
    pub fn new(
        base_url: &str,
        worker_id: String,
        signing_key: WorkerSigningKey,
        ca_path: Option<&Path>,
        request_timeout: Duration,
    ) -> Result<Self, WorkerError> {
        let mut builder = Client::builder()
            .timeout(request_timeout)
            .user_agent(concat!("getter-worker/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = ca_path {
            let certificate = load_pinned_ca(path)?;
            builder = builder
                .add_root_certificate(certificate)
                .tls_built_in_root_certs(false);
        }
        let http = builder
            .build()
            .map_err(|error| WorkerError::Runner(format!("HTTP client: {error}")))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            worker_id,
            signing_key,
            request_timeout,
        })
    }

    pub fn http(&self) -> &Client {
        &self.http
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn signed_request(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        extra_headers: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Result<Response, WorkerError> {
        if !path.starts_with('/') {
            return Err(WorkerError::Runner("signed path must start with /".into()));
        }
        let timestamp = Utc::now().timestamp();
        let nonce = nonce();
        let message = worker_signature_message(
            &self.worker_id,
            method.as_str(),
            path,
            timestamp,
            &nonce,
            &body,
        );
        let signature = self.signing_key.sign(&message);
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .http
            .request(method, url)
            .header(HEADER_WORKER_ID, &self.worker_id)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_NONCE, nonce)
            .header(HEADER_SIGNATURE, signature);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        for (name, value) in extra_headers {
            request = request.header(*name, value);
        }
        let request = if body.is_empty() {
            request
        } else {
            request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
        };
        Ok(request.send().await?)
    }

    async fn signed_json<T: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        value: &T,
    ) -> Result<Response, WorkerError> {
        let body = serde_json::to_vec(value)
            .map_err(|error| WorkerError::Runner(format!("serialize request: {error}")))?;
        self.signed_request(method, path, body, &[], None).await
    }

    async fn decode_json<T: serde::de::DeserializeOwned>(
        &self,
        response: Response,
    ) -> Result<T, WorkerError> {
        let response = check_response(response).await?;
        let bytes = read_limited(response, JSON_BODY_LIMIT).await?;
        serde_json::from_slice(&bytes)
            .map_err(|error| WorkerError::Response(format!("invalid JSON response: {error}")))
    }

    pub async fn heartbeat(
        &self,
        heartbeat: &WorkerHeartbeat,
    ) -> Result<HeartbeatResponse, WorkerError> {
        let response = self
            .signed_json(
                Method::POST,
                getter_protocol::PATH_WORKER_HEARTBEAT,
                heartbeat,
            )
            .await?;
        let heartbeat: HeartbeatResponse = self.decode_json(response).await?;
        if heartbeat.protocol != getter_protocol::PROTOCOL_VERSION {
            return Err(WorkerError::Protocol(heartbeat.protocol));
        }
        Ok(heartbeat)
    }

    pub async fn assignments(&self, max: usize) -> Result<AssignmentsResponse, WorkerError> {
        let path = format!(
            "{}?max={}",
            getter_protocol::PATH_WORKER_ASSIGNMENTS,
            max.clamp(1, 32)
        );
        let response = self
            .signed_request(Method::GET, &path, Vec::new(), &[], None)
            .await?;
        let response: AssignmentsResponse = self.decode_json(response).await?;
        if response.protocol != getter_protocol::PROTOCOL_VERSION {
            return Err(WorkerError::Protocol(response.protocol));
        }
        Ok(response)
    }

    pub async fn mark_started_with_token(
        &self,
        lease_id: &str,
        lease_token: &str,
    ) -> Result<StartedResponse, WorkerError> {
        let path = format!("/v1/worker/leases/{lease_id}/start");
        let response = self
            .signed_json(
                Method::POST,
                &path,
                &LeaseTokenRequest {
                    lease_token: lease_token.to_owned(),
                },
            )
            .await?;
        self.decode_json(response).await
    }

    pub async fn download_artifact(
        &self,
        assignment: &TaskAssignment,
        max_bytes: u64,
    ) -> Result<Vec<u8>, WorkerError> {
        let response = self
            .signed_request(
                Method::GET,
                &assignment.artifact_url,
                Vec::new(),
                &[(HEADER_LEASE_TOKEN, assignment.lease_token.clone())],
                Some(self.request_timeout.saturating_mul(4)),
            )
            .await?;
        let response = check_response(response).await?;
        if let Some(length) = response.content_length() {
            if length > max_bytes {
                return Err(WorkerError::Artifact(format!(
                    "artifact is {length} bytes, above the local download limit of {max_bytes}"
                )));
            }
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if (bytes.len() + chunk.len()) as u64 > max_bytes {
                return Err(WorkerError::Artifact(
                    "artifact download exceeded the local size limit".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let digest = sha256_hex(&bytes);
        if digest != assignment.artifact_sha256 {
            return Err(WorkerError::Artifact(
                "artifact digest does not match the coordinator assignment".into(),
            ));
        }
        Ok(bytes)
    }

    pub async fn submit_result(
        &self,
        request: &TaskResultRequest,
    ) -> Result<ResultAck, WorkerError> {
        let response = self
            .signed_json(Method::POST, getter_protocol::PATH_WORKER_RESULTS, request)
            .await?;
        self.decode_json(response).await
    }

    pub async fn leave(&self) -> Result<(), WorkerError> {
        let response = self
            .signed_json(
                Method::POST,
                getter_protocol::PATH_WORKER_LEAVE,
                &LeaveRequest {
                    protocol: getter_protocol::PROTOCOL_VERSION.into(),
                },
            )
            .await?;
        check_response(response).await?;
        Ok(())
    }

    pub async fn enroll(
        http: &Client,
        base_url: &str,
        request: &EnrollRequest,
    ) -> Result<EnrollResponse, WorkerError> {
        let url = format!("{}/v1/enroll", base_url.trim_end_matches('/'));
        let response = http
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| WorkerError::Pairing(error.to_string()))?;
        let response = check_response(response).await?;
        let bytes = read_limited(response, JSON_BODY_LIMIT)
            .await
            .map_err(|error| WorkerError::Pairing(error.to_string()))?;
        let enrollment: EnrollResponse = serde_json::from_slice(&bytes).map_err(|error| {
            WorkerError::Pairing(format!("invalid enrollment response: {error}"))
        })?;
        if enrollment.protocol != getter_protocol::PROTOCOL_VERSION {
            return Err(WorkerError::Protocol(enrollment.protocol));
        }
        Ok(enrollment)
    }
}

/// Load exactly one CA certificate and construct a rustls trust anchor from
/// its DER bytes. Bundles are rejected so the out-of-band fingerprint pins the
/// entire trust store rather than only its first certificate.
pub fn load_pinned_ca(path: &Path) -> Result<reqwest::Certificate, WorkerError> {
    let pem = std::fs::read(path)?;
    let der = getter_core::init::certificate_der_from_pem(&pem)
        .map_err(|error| WorkerError::Trust(error.to_string()))?;
    reqwest::Certificate::from_der(&der)
        .map_err(|error| WorkerError::Trust(format!("invalid CA certificate: {error}")))
}

pub fn build_client_with_ca(
    ca_path: Option<&Path>,
    timeout: Duration,
) -> Result<Client, WorkerError> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .user_agent(concat!("getter-worker/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = ca_path {
        let certificate = load_pinned_ca(path)?;
        builder = builder
            .add_root_certificate(certificate)
            .tls_built_in_root_certs(false);
    }
    builder
        .build()
        .map_err(|error| WorkerError::Trust(format!("HTTP client: {error}")))
}

pub fn build_bootstrap_client(timeout: Duration) -> Result<Client, WorkerError> {
    Client::builder()
        .timeout(timeout)
        .user_agent(concat!("getter-bootstrap/", env!("CARGO_PKG_VERSION")))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|error| WorkerError::Trust(format!("bootstrap client: {error}")))
}

pub async fn fetch_ca_pem(base_url: &str, timeout: Duration) -> Result<Vec<u8>, WorkerError> {
    let client = build_bootstrap_client(timeout)?;
    let url = format!("{}/v1/ca.pem", base_url.trim_end_matches('/'));
    let response =
        client.get(url).send().await.map_err(|error| {
            WorkerError::Trust(format!("could not fetch CA certificate: {error}"))
        })?;
    if !response.status().is_success() {
        return Err(WorkerError::Trust(format!(
            "coordinator returned HTTP {} for its CA certificate",
            response.status()
        )));
    }
    let response = response;
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| WorkerError::Trust(format!("CA download failed: {error}")))?
    {
        if bytes.len() + chunk.len() > 64 * 1024 {
            return Err(WorkerError::Trust(
                "CA certificate response exceeded 64 KiB".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn check_response(response: Response) -> Result<Response, WorkerError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let bytes = read_limited(response, ERROR_BODY_LIMIT)
        .await
        .unwrap_or_default();
    let parsed = serde_json::from_slice::<ApiErrorBody>(&bytes).ok();
    Err(WorkerError::Api {
        status: status.as_u16(),
        code: parsed
            .as_ref()
            .map(|error| error.code.clone())
            .unwrap_or_else(|| status_name(status).into()),
        message: parsed.map(|error| error.message).unwrap_or_else(|| {
            String::from_utf8_lossy(&bytes)
                .trim()
                .chars()
                .take(500)
                .collect()
        }),
    })
}

fn status_name(status: StatusCode) -> &'static str {
    status.canonical_reason().unwrap_or("http_error")
}

async fn read_limited(mut response: Response, limit: usize) -> Result<Vec<u8>, WorkerError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            return Err(WorkerError::Response(format!(
                "coordinator response exceeded {limit} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Encode worker output for the result API. Kept in one place so the declared
/// digest always covers exactly the encoded bytes.
pub fn encoded_output(output: &[u8]) -> (String, String) {
    (
        base64::engine::general_purpose::STANDARD.encode(output),
        sha256_hex(output),
    )
}
