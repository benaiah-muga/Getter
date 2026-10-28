//! Authentication primitives shared by coordinator and worker.
//!
//! Workload results are authenticated with short-lived random lease secrets.
//! Worker API requests are signed with Ed25519, containing the worker id,
//! method, path and query, timestamp, nonce, and body digest. The coordinator
//! validates the clock window and a process-local nonce cache in addition to
//! the signature.

#![deny(unsafe_code)]

use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use getter_protocol::WORKER_SIGNATURE_CONTEXT;

pub const PAIRING_TOKEN_PREFIX: &str = "getter_pair_";
pub const LEASE_TOKEN_PREFIX: &str = "getter_lease_";

/// A signing key whose bytes are zeroized when dropped.
#[derive(Clone)]
pub struct WorkerSigningKey {
    inner: SigningKey,
    public_base64: String,
}

impl std::fmt::Debug for WorkerSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerSigningKey")
            .field("public_key", &self.public_base64)
            .finish_non_exhaustive()
    }
}

impl WorkerSigningKey {
    pub fn generate() -> Self {
        let inner = SigningKey::generate(&mut OsRng);
        let public_base64 = STANDARD.encode(inner.verifying_key().to_bytes());
        Self {
            inner,
            public_base64,
        }
    }

    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| "private key is not valid base64".to_owned())?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "private key must be exactly 32 bytes".to_owned())?;
        let inner = SigningKey::from_bytes(&bytes);
        let public_base64 = STANDARD.encode(inner.verifying_key().to_bytes());
        Ok(Self {
            inner,
            public_base64,
        })
    }

    pub fn private_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.inner.to_bytes()))
    }

    pub fn public_base64(&self) -> &str {
        &self.public_base64
    }

    pub fn sign(&self, message: &[u8]) -> String {
        STANDARD.encode(self.inner.sign(message).to_bytes())
    }
}

pub fn verify_worker_signature(
    public_key_base64: &str,
    message: &[u8],
    signature_base64: &str,
) -> Result<(), String> {
    let key_bytes = STANDARD
        .decode(public_key_base64)
        .map_err(|_| "stored public key is not valid base64".to_owned())?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "stored public key has the wrong length".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "stored public key is invalid".to_owned())?;
    let signature_bytes = STANDARD
        .decode(signature_base64)
        .map_err(|_| "signature is not valid base64".to_owned())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "signature has the wrong length".to_owned())?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| "signature verification failed".to_owned())
}

/// Canonical bytes covered by a worker request signature.
///
/// `path_and_query` must include a leading slash and the exact query string sent
/// on the wire. Body bytes are hashed before serialization is considered, so
/// semantically equivalent JSON with different bytes produces a different
/// signature (which is intentional).
pub fn worker_signature_message(
    worker_id: &str,
    method: &str,
    path_and_query: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = sha256_hex(body);
    format!(
        "{WORKER_SIGNATURE_CONTEXT}\n{worker_id}\n{}\n{path_and_query}\n{timestamp}\n{nonce}\n{body_hash}",
        method.to_ascii_uppercase()
    )
    .into_bytes()
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    // Slicing to the minimum length avoids leaking the length comparison timing
    // beyond the expected all-zero result for mismatched lengths.
    let mut equal = left.len() == right.len();
    let max = left.len().max(right.len());
    for index in 0..max {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        equal &= bool::from(a.ct_eq(&b));
    }
    equal
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn pairing_token() -> String {
    random_token(PAIRING_TOKEN_PREFIX)
}

pub fn lease_token() -> String {
    random_token(LEASE_TOKEN_PREFIX)
}

pub fn admin_token() -> String {
    random_token("getter_admin_")
}

pub fn control_token() -> String {
    random_token("getter_control_")
}

pub fn token_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

pub fn nonce() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn normalize_sha256(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Error returned when a worker request cannot be admitted to the replay guard.
/// Only [`ReplayCheckError::Replay`] indicates a signature replay; capacity and
/// rate-limit outcomes must be retried and must not de-authorize a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheckError {
    Replay,
    RateLimited,
    Capacity,
}

struct WorkerReplayState {
    nonces: std::collections::HashMap<String, Instant>,
    window_started: Instant,
    requests_in_window: u32,
    last_seen: Instant,
    last_nonce_prune: Instant,
}

/// Per-worker replay and request-rate guard.
///
/// A single worker cannot exhaust another worker's replay window. The guard is
/// process-local: signatures still expire after the short clock window, and the
/// coordinator's state transitions are idempotent and lease-bound, so a restart
/// does not turn replay into duplicated accepted results.
pub struct WorkerReplayGuard {
    workers: std::collections::HashMap<String, WorkerReplayState>,
    nonce_ttl: Duration,
    max_nonces_per_worker: usize,
    max_workers: usize,
    rate_window: Duration,
    max_requests_per_window: u32,
    last_prune: Instant,
}

impl WorkerReplayGuard {
    pub fn new(
        nonce_ttl: Duration,
        max_nonces_per_worker: usize,
        max_workers: usize,
        rate_window: Duration,
        max_requests_per_window: u32,
    ) -> Self {
        Self {
            workers: std::collections::HashMap::new(),
            nonce_ttl,
            max_nonces_per_worker,
            max_workers,
            rate_window,
            max_requests_per_window,
            last_prune: Instant::now(),
        }
    }

    pub fn check_and_insert(
        &mut self,
        worker_id: &str,
        nonce: &str,
        now: Instant,
    ) -> Result<(), ReplayCheckError> {
        if now.duration_since(self.last_prune) >= Duration::from_secs(30) {
            self.prune(now);
            self.last_prune = now;
        }
        if !self.workers.contains_key(worker_id) && self.workers.len() >= self.max_workers {
            return Err(ReplayCheckError::Capacity);
        }
        let ttl = self.nonce_ttl;
        let max_nonces = self.max_nonces_per_worker;
        let window = self.rate_window;
        let max_requests = self.max_requests_per_window;
        let state = self
            .workers
            .entry(worker_id.to_owned())
            .or_insert_with(|| WorkerReplayState {
                nonces: std::collections::HashMap::new(),
                window_started: now,
                requests_in_window: 0,
                last_seen: now,
                last_nonce_prune: now,
            });
        state.last_seen = now;
        if now.duration_since(state.window_started) >= window {
            state.window_started = now;
            state.requests_in_window = 0;
        }
        state.requests_in_window = state.requests_in_window.saturating_add(1);
        if state.requests_in_window > max_requests {
            return Err(ReplayCheckError::RateLimited);
        }
        if now.duration_since(state.last_nonce_prune) >= Duration::from_secs(1) {
            state
                .nonces
                .retain(|_, inserted| now.duration_since(*inserted) < ttl);
            state.last_nonce_prune = now;
        }
        if state.nonces.contains_key(nonce) {
            return Err(ReplayCheckError::Replay);
        }
        if state.nonces.len() >= max_nonces {
            return Err(ReplayCheckError::Capacity);
        }
        state.nonces.insert(nonce.to_owned(), now);
        Ok(())
    }

    fn prune(&mut self, now: Instant) {
        let retain = self.nonce_ttl.saturating_mul(2);
        self.workers
            .retain(|_, state| now.duration_since(state.last_seen) < retain);
    }

    #[cfg(test)]
    fn workers_len(&self) -> usize {
        self.workers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_round_trip_and_tamper_detection() {
        let key = WorkerSigningKey::generate();
        let message = worker_signature_message(
            "worker-1",
            "POST",
            "/v1/worker/results?x=1",
            1_700_000_000,
            "nonce",
            br#"{"hello":"world"}"#,
        );
        let signature = key.sign(&message);
        verify_worker_signature(key.public_base64(), &message, &signature).expect("valid");

        let mut tampered = message.clone();
        let last = tampered.last_mut().expect("nonempty");
        *last ^= 1;
        assert!(verify_worker_signature(key.public_base64(), &tampered, &signature).is_err());
    }

    #[test]
    fn canonical_message_binds_every_component() {
        let base = worker_signature_message("w", "GET", "/v1/a", 10, "n", b"");
        assert_ne!(
            base,
            worker_signature_message("other", "GET", "/v1/a", 10, "n", b"")
        );
        assert_ne!(
            base,
            worker_signature_message("w", "POST", "/v1/a", 10, "n", b"")
        );
        assert_ne!(
            base,
            worker_signature_message("w", "GET", "/v1/a?q=1", 10, "n", b"")
        );
        assert_ne!(
            base,
            worker_signature_message("w", "GET", "/v1/a", 11, "n", b"")
        );
        assert_ne!(
            base,
            worker_signature_message("w", "GET", "/v1/a", 10, "other", b"")
        );
        assert_ne!(
            base,
            worker_signature_message("w", "GET", "/v1/a", 10, "n", b"x")
        );
    }

    #[test]
    fn replay_guard_is_per_worker_and_expires_nonces() {
        let mut guard =
            WorkerReplayGuard::new(Duration::from_secs(2), 10, 10, Duration::from_secs(60), 100);
        let now = Instant::now();
        assert_eq!(guard.check_and_insert("worker-a", "abc", now), Ok(()));
        assert_eq!(
            guard.check_and_insert("worker-a", "abc", now),
            Err(ReplayCheckError::Replay)
        );
        // Another worker's nonce namespace is independent.
        assert_eq!(guard.check_and_insert("worker-b", "abc", now), Ok(()));
        assert_eq!(
            guard.check_and_insert("worker-a", "abc", now + Duration::from_secs(3)),
            Ok(())
        );
    }

    #[test]
    fn one_worker_cannot_fill_the_global_guard_or_rate_limit_others() {
        let mut guard =
            WorkerReplayGuard::new(Duration::from_secs(60), 8, 100, Duration::from_secs(60), 5);
        let now = Instant::now();
        for index in 0..5 {
            assert_eq!(
                guard.check_and_insert("noisy", &format!("n-{index}"), now),
                Ok(())
            );
        }
        assert_eq!(
            guard.check_and_insert("noisy", "n-over", now),
            Err(ReplayCheckError::RateLimited)
        );
        // A different worker still authenticates successfully.
        assert_eq!(guard.check_and_insert("quiet", "q1", now), Ok(()));
        assert_eq!(guard.workers_len(), 2);
    }

    #[test]
    fn constants_are_reported() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("secret", "secreu"));
        assert!(!constant_time_eq("short", "longer"));
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"z".repeat(64)));
        assert!(pairing_token().starts_with(PAIRING_TOKEN_PREFIX));
        assert!(lease_token().starts_with(LEASE_TOKEN_PREFIX));
    }
}
