use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration not found at {0}; run `getter init` first")]
    Missing(std::path::PathBuf),
    #[error("configuration is unreadable: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("configuration is invalid: {0}")]
    Invalid(String),
    #[error("configuration serialization failed: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("unsupported configuration version {found}; this build supports version {expected}")]
    Version { found: u32, expected: u32 },
    #[error("configuration already exists at {0} (use --force to replace it)")]
    AlreadyExists(std::path::PathBuf),
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("could not create {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS material generation failed: {0}")]
    Tls(String),
    #[error("refusing to create configuration: {0}")]
    Refused(String),
    #[error("identity file is invalid: {0}")]
    Identity(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("{0}")]
    Invalid(String),
}
