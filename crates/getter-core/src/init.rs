//! First-run setup and secure local state material.
//!
//! Generated private keys and tokens are written with owner-only permissions on
//! Unix. TLS uses a freshly generated local CA; the CA private key is discarded
//! after issuing the server certificate, so compromising the coordinator host
//! later cannot mint new trusted certificates from a stored CA key.

#![deny(unsafe_code)]

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use base64::Engine;
use getter_protocol::PROTOCOL_VERSION;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{admin_token, control_token, WorkerSigningKey};
use crate::config::{
    admin_token_path, config_path, control_token_path, validate_name, worker_identity_path,
    CoordinatorConfig, CoordinatorLimits, DiscoveryConfig, GetterConfig, Role, TlsConfig,
    WorkerConfig, CONFIG_VERSION,
};
use crate::error::{ConfigError, InitError};

pub const IDENTITY_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct CoordinatorInitOptions {
    pub home: PathBuf,
    pub name: String,
    pub bind: SocketAddr,
    pub public_url: Option<String>,
    pub tls: bool,
    pub discovery: bool,
    /// Additional DNS names to include in the server certificate SAN list.
    pub hostnames: Vec<String>,
    pub force: bool,
}

pub struct CoordinatorInitResult {
    pub config: GetterConfig,
    pub admin_token: String,
    pub ca_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WorkerInitOptions {
    pub home: PathBuf,
    pub name: String,
    pub coordinator_url: String,
    pub coordinator_ca: Option<PathBuf>,
    pub control_bind: Option<SocketAddr>,
    pub force: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    pub version: u32,
    pub worker_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Standard base64 Ed25519 private key. This file is never uploaded.
    pub private_key: String,
    /// Standard base64 public key sent at enrollment.
    pub public_key: String,
}

impl WorkerIdentity {
    pub fn signing_key(&self) -> Result<WorkerSigningKey, InitError> {
        let key = WorkerSigningKey::from_base64(&self.private_key).map_err(InitError::Identity)?;
        if key.public_base64() != self.public_key {
            return Err(InitError::Identity(
                "public key does not match the private key".into(),
            ));
        }
        Ok(key)
    }

    pub fn require_worker_id(&self) -> Result<&str, InitError> {
        self.worker_id
            .as_deref()
            .ok_or_else(|| InitError::Identity("worker has not joined a coordinator yet".into()))
    }
}

pub fn generate_coordinator_config(
    options: &CoordinatorInitOptions,
) -> Result<CoordinatorInitResult, InitError> {
    let home = &options.home;
    guard_init_home(home)?;
    let existing_config = config_path(home);
    if existing_config.exists() && !options.force {
        return Err(ConfigError::AlreadyExists(existing_config).into());
    }
    validate_name(&options.name).map_err(InitError::Config)?;

    ensure_private_dir(home)?;
    ensure_private_dir(&home.join("secrets"))?;
    ensure_private_dir(&home.join("data"))?;

    let admin = admin_token();
    write_secret(admin_token_path(home).as_path(), admin.as_bytes())?;

    let public_url = match &options.public_url {
        Some(url) => url.clone(),
        None => derive_public_url(options.bind, options.tls),
    };

    let (tls, ca_fingerprint) = if options.tls {
        ensure_private_dir(&home.join("tls"))?;
        let generated = generate_tls_material(home, options.bind, &options.hostnames)?;
        (
            Some(TlsConfig {
                ca_cert: generated.ca_path,
                cert_chain: generated.cert_path,
                private_key: generated.key_path,
            }),
            Some(generated.fingerprint),
        )
    } else {
        (None, None)
    };

    let config = GetterConfig {
        version: CONFIG_VERSION,
        role: Role::Coordinator,
        name: options.name.clone(),
        coordinator: Some(CoordinatorConfig {
            bind: options.bind,
            public_url,
            database_path: home.join("data").join("getter.db"),
            tls,
            discovery: DiscoveryConfig {
                enabled: options.discovery,
                ..DiscoveryConfig::default()
            },
            limits: CoordinatorLimits::default(),
            allow_insecure_remote: false,
        }),
        worker: None,
    };
    config.validate().map_err(InitError::Config)?;
    write_config(home, &config)?;
    Ok(CoordinatorInitResult {
        config,
        admin_token: admin,
        ca_fingerprint,
    })
}

pub fn generate_worker_identity(options: &WorkerInitOptions) -> Result<GetterConfig, InitError> {
    let home = &options.home;
    guard_init_home(home)?;
    let existing_config = config_path(home);
    let identity_file = worker_identity_path(home);
    if (existing_config.exists() || identity_file.exists()) && !options.force {
        return Err(ConfigError::AlreadyExists(existing_config).into());
    }
    validate_name(&options.name).map_err(InitError::Config)?;

    ensure_private_dir(home)?;
    ensure_private_dir(&home.join("secrets"))?;
    ensure_private_dir(&home.join("worker"))?;
    ensure_private_dir(&home.join("trust"))?;

    let signing_key = WorkerSigningKey::generate();
    let identity = WorkerIdentity {
        version: IDENTITY_VERSION,
        worker_name: options.name.clone(),
        worker_id: None,
        private_key: signing_key.private_base64().to_string(),
        public_key: signing_key.public_base64().to_owned(),
    };
    write_worker_identity(home, &identity)?;

    let control = control_token();
    write_secret(control_token_path(home).as_path(), control.as_bytes())?;

    let mut worker = WorkerConfig {
        coordinator_url: options.coordinator_url.clone(),
        ..WorkerConfig::default()
    };
    if let Some(control_bind) = options.control_bind {
        worker.control_bind = control_bind;
    }
    if let Some(ca_source) = &options.coordinator_ca {
        let destination = worker_ca_path(home);
        let bytes = std::fs::read(ca_source).map_err(|source| InitError::Io {
            path: ca_source.clone(),
            source,
        })?;
        // Validate and fingerprint while copying.
        fingerprint_pem(&bytes)?;
        write_secret(&destination, &bytes)?;
        worker.coordinator_ca = Some(destination);
    }
    let config = GetterConfig {
        version: CONFIG_VERSION,
        role: Role::Worker,
        name: options.name.clone(),
        coordinator: None,
        worker: Some(worker),
    };
    config.validate().map_err(InitError::Config)?;
    write_config(home, &config)?;
    Ok(config)
}

pub fn worker_ca_path(home: &Path) -> PathBuf {
    home.join("trust").join("coordinator-ca.pem")
}

#[derive(Debug)]
struct GeneratedTls {
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    fingerprint: String,
}

fn generate_tls_material(
    home: &Path,
    bind: SocketAddr,
    extra_hostnames: &[String],
) -> Result<GeneratedTls, InitError> {
    let mut sans: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if !bind.ip().is_unspecified() {
        sans.push(bind.ip().to_string());
    } else if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            sans.push(interface.ip().to_string());
        }
    }
    for hostname in extra_hostnames {
        let trimmed = hostname.trim();
        if !trimmed.is_empty() {
            sans.push(trimmed.to_owned());
        }
    }
    sans.sort();
    sans.dedup();

    let ca_key = KeyPair::generate().map_err(|error| InitError::Tls(error.to_string()))?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| InitError::Tls(error.to_string()))?;
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "Getter Local CA");
    ca_name.push(DnType::OrganizationName, "Getter");
    ca_params.distinguished_name = ca_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|error| InitError::Tls(error.to_string()))?;

    let server_key = KeyPair::generate().map_err(|error| InitError::Tls(error.to_string()))?;
    let mut server_params =
        CertificateParams::new(sans).map_err(|error| InitError::Tls(error.to_string()))?;
    let mut server_name = DistinguishedName::new();
    server_name.push(DnType::CommonName, "Getter Coordinator");
    server_name.push(DnType::OrganizationName, "Getter");
    server_params.distinguished_name = server_name;
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(|error| InitError::Tls(error.to_string()))?;

    let ca_path = home.join("tls").join("ca.pem");
    let cert_path = home.join("tls").join("server.pem");
    let key_path = home.join("tls").join("server-key.pem");
    write_secret(&ca_path, ca_cert.pem().as_bytes())?;
    write_secret(&cert_path, server_cert.pem().as_bytes())?;
    write_secret(&key_path, server_key.serialize_pem().as_bytes())?;

    Ok(GeneratedTls {
        ca_path,
        cert_path,
        key_path,
        fingerprint: certificate_fingerprint(ca_cert.der()),
    })
}

pub fn certificate_fingerprint(der: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(der)))
}

/// Parse exactly one certificate from a PEM trust file.
///
/// Bundles are rejected: a fingerprint check that authenticates only the first
/// certificate while the TLS client trusts every certificate in the bundle is
/// not a pin. Getter therefore stores and consumes exactly one coordinator CA.
pub fn certificate_der_from_pem(pem: &[u8]) -> Result<Vec<u8>, InitError> {
    let mut reader = std::io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| InitError::Tls(format!("CA certificate is not valid PEM: {error}")))?;
    if certs.len() != 1 {
        return Err(InitError::Tls(format!(
            "CA trust file must contain exactly one certificate, found {}",
            certs.len()
        )));
    }
    Ok(certs[0].as_ref().to_vec())
}

pub fn fingerprint_pem(pem: &[u8]) -> Result<String, InitError> {
    let der = certificate_der_from_pem(pem)?;
    Ok(certificate_fingerprint(&der))
}

pub fn load_worker_identity(home: &Path) -> Result<WorkerIdentity, InitError> {
    let path = worker_identity_path(home);
    let metadata = std::fs::symlink_metadata(&path).map_err(|source| InitError::Io {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InitError::Identity(format!(
            "{} must be a regular file, not a symlink",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(InitError::Identity(format!(
                "{} must not be readable by group or other users (chmod 600)",
                path.display()
            )));
        }
    }
    let bytes = read_regular(&path)?;
    let identity: WorkerIdentity = serde_json::from_slice(&bytes)
        .map_err(|error| InitError::Identity(format!("identity JSON is invalid: {error}")))?;
    if identity.version != IDENTITY_VERSION {
        return Err(InitError::Identity(format!(
            "unsupported identity version {}",
            identity.version
        )));
    }
    // Verifies that the embedded private and public keys agree.
    identity.signing_key()?;
    Ok(identity)
}

pub fn write_worker_identity(home: &Path, identity: &WorkerIdentity) -> Result<(), InitError> {
    let bytes = serde_json::to_vec_pretty(identity)
        .map_err(|error| InitError::Identity(error.to_string()))?;
    write_secret(&worker_identity_path(home), &bytes)?;
    Ok(())
}

pub fn read_admin_token(home: &Path) -> Result<String, InitError> {
    read_secret_string(&admin_token_path(home))
}

pub fn read_control_token(home: &Path) -> Result<String, InitError> {
    read_secret_string(&control_token_path(home))
}

pub fn write_config(home: &Path, config: &GetterConfig) -> Result<(), InitError> {
    config.validate().map_err(InitError::Config)?;
    let encoded = config.to_toml().map_err(InitError::Config)?;
    write_secret(&config_path(home), encoded.as_bytes())?;
    Ok(())
}

fn guard_init_home(home: &Path) -> Result<(), InitError> {
    if home.parent().is_none() {
        return Err(InitError::Refused(
            "refusing to initialize Getter at a filesystem root".into(),
        ));
    }
    if home.exists() && !config_path(home).exists() {
        let mut entries = std::fs::read_dir(home).map_err(|source| InitError::Io {
            path: home.to_path_buf(),
            source,
        })?;
        if entries.next().is_some() {
            return Err(InitError::Refused(format!(
                "refusing to initialize Getter in non-empty directory {}",
                home.display()
            )));
        }
    }
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> Result<(), InitError> {
    std::fs::create_dir_all(path).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| InitError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
}

/// Write a file with owner-only permissions, replacing it atomically.
pub fn write_secret(path: &Path, contents: &[u8]) -> Result<(), InitError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| InitError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|source| InitError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.write_all(contents).map_err(|source| InitError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| InitError::Io {
            path: temporary.clone(),
            source,
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| InitError::Io {
                path: temporary.clone(),
                source,
            },
        )?;
    }
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(first_error) => {
            // Windows does not replace an existing destination via rename.
            if path.exists() {
                std::fs::remove_file(path).map_err(|source| InitError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
                std::fs::rename(&temporary, path).map_err(|source| InitError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            } else {
                let _ = std::fs::remove_file(&temporary);
                Err(InitError::Io {
                    path: path.to_path_buf(),
                    source: first_error,
                })
            }
        }
    }
}

fn read_regular(path: &Path) -> Result<Vec<u8>, InitError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InitError::Identity(format!(
            "{} must be a regular file, not a symlink",
            path.display()
        )));
    }
    std::fs::read(path).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_secret_string(path: &Path) -> Result<String, InitError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| InitError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InitError::Identity(format!(
            "{} must be a regular file, not a symlink",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(InitError::Identity(format!(
                "{} must not be readable by group or other users (chmod 600)",
                path.display()
            )));
        }
    }
    let bytes = read_regular(path)?;
    let value = String::from_utf8(bytes)
        .map_err(|_| InitError::Identity(format!("{} is not UTF-8", path.display())))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(InitError::Identity(format!("{} is empty", path.display())));
    }
    Ok(value)
}

fn derive_public_url(bind: SocketAddr, tls: bool) -> String {
    let scheme = if tls { "https" } else { "http" };
    let host = if bind.ip().is_loopback() {
        bind.ip()
    } else if bind.ip().is_unspecified() {
        discover_primary_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    } else {
        bind.ip()
    };
    let addr = SocketAddr::new(host, bind.port());
    format!("{scheme}://{addr}")
}

fn discover_primary_ip() -> Option<IpAddr> {
    let interfaces = if_addrs::get_if_addrs().ok()?;
    let mut fallback = None;
    for interface in interfaces {
        if interface.ip().is_loopback() {
            continue;
        }
        if interface.ip().is_ipv4() {
            return Some(interface.ip());
        }
        if fallback.is_none() {
            fallback = Some(interface.ip());
        }
    }
    fallback
}

/// Bootstrap version metadata. Kept here so setup errors can mention the
/// protocol the generated state will speak.
pub fn protocol_version() -> &'static str {
    PROTOCOL_VERSION
}

/// Decode a base64 public key for diagnostics without keeping it secret.
pub fn public_key_bytes(encoded: &str) -> Result<Vec<u8>, InitError> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| InitError::Identity("public key is not valid base64".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinator_options(home: &Path) -> CoordinatorInitOptions {
        CoordinatorInitOptions {
            home: home.to_path_buf(),
            name: "test-coordinator".into(),
            bind: "127.0.0.1:0".parse().expect("bind"),
            public_url: Some("https://127.0.0.1:47810".into()),
            tls: true,
            discovery: false,
            hostnames: vec!["getter.test".into()],
            force: false,
        }
    }

    #[test]
    fn coordinator_setup_creates_secure_state_and_valid_tls() {
        let directory = tempfile::tempdir().expect("tempdir");
        let result = generate_coordinator_config(&coordinator_options(directory.path()))
            .expect("coordinator init");
        assert!(config_path(directory.path()).exists());
        assert!(result
            .ca_fingerprint
            .expect("fingerprint")
            .starts_with("sha256:"));
        let ca = std::fs::read(directory.path().join("tls/ca.pem")).expect("ca");
        assert!(fingerprint_pem(&ca)
            .expect("fingerprint")
            .starts_with("sha256:"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(directory.path().join("tls/server-key.pem"))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        let loaded = GetterConfig::load(directory.path()).expect("load config");
        assert_eq!(loaded.role, Role::Coordinator);
    }

    #[test]
    fn worker_identity_detects_key_mismatch() {
        let directory = tempfile::tempdir().expect("tempdir");
        generate_worker_identity(&WorkerInitOptions {
            home: directory.path().to_path_buf(),
            name: "test-worker".into(),
            coordinator_url: "http://127.0.0.1:47810".into(),
            coordinator_ca: None,
            control_bind: None,
            force: false,
        })
        .expect("worker init");
        let mut identity = load_worker_identity(directory.path()).expect("identity");
        identity.public_key = WorkerSigningKey::generate().public_base64().to_owned();
        write_worker_identity(directory.path(), &identity).expect("write");
        assert!(load_worker_identity(directory.path()).is_err());
    }

    #[test]
    fn multi_certificate_ca_bundles_are_rejected() {
        let ca_key = rcgen::KeyPair::generate().expect("key");
        let mut first_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        first_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let first = first_params.self_signed(&ca_key).expect("first cert");
        let other_key = rcgen::KeyPair::generate().expect("key");
        let mut second_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        second_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let second = second_params.self_signed(&other_key).expect("second cert");
        let bundle = format!("{}{}", first.pem(), second.pem());
        assert!(certificate_der_from_pem(bundle.as_bytes()).is_err());
        assert!(fingerprint_pem(bundle.as_bytes()).is_err());
    }

    #[test]
    fn existing_configuration_requires_force() {
        let directory = tempfile::tempdir().expect("tempdir");
        let options = coordinator_options(directory.path());
        generate_coordinator_config(&options).expect("first");
        assert!(generate_coordinator_config(&options).is_err());
    }
}
