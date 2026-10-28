//! The `getter` command-line interface.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use base64::Engine;
use clap::{Args, Parser, Subcommand, ValueEnum};
use getter_core::config::{
    admin_token_path, config_path, control_token_path, worker_identity_path, GetterConfig, Role,
};
use getter_core::init::{
    ensure_private_dir, fingerprint_pem, generate_coordinator_config, generate_worker_identity,
    read_admin_token, read_control_token, write_config, CoordinatorInitOptions, WorkerInitOptions,
};
use getter_protocol::{
    ContributionResponse, CoordinatorStatusResponse, JobDetailResponse, JobListResponse,
    PairingTokenRequest, PairingTokenResponse, WorkerListResponse, WorkerStatus, JOB_FORMAT,
    MAX_ARTIFACT_BYTES,
};
use getter_worker::{join, run_worker, JoinOptions};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

const EXAMPLES: &str = "\
Examples:
  getter init --role coordinator --name home-coordinator
  getter coordinator start
  getter pair --name laptop --ttl-secs 600
  getter init --role worker --name laptop --home ~/.getter-laptop
  getter worker join --coordinator https://192.168.1.10:47810 --token <token> --ca-fingerprint <sha256:...>
  getter worker start --home ~/.getter-laptop
  getter jobs submit --file examples/sum-squares/job.json --watch

Run `getter <command> --help` for command-specific examples and defaults.";

#[derive(Debug, Parser)]
#[command(
    name = "getter",
    version,
    about = "Turn idle CPUs into a verifiable distributed compute network",
    long_about = "Getter is a local-first distributed computing engine. A coordinator schedules \
                  independently executable WASM tasks; enrolled workers enforce their own CPU, \
                  memory, time, fuel, output, and download-size limits.",
    after_help = EXAMPLES
)]
struct Cli {
    /// Local state directory (defaults to $GETTER_HOME or ~/.getter).
    #[arg(long, global = true, env = "GETTER_HOME", value_name = "DIR")]
    home: Option<PathBuf>,
    /// Emit machine-readable JSON instead of a human table.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a coordinator or worker identity and configuration.
    Init(InitArgs),
    /// Run the coordinator service.
    Coordinator(CoordinatorArgs),
    /// Run and control the local worker, or enroll it.
    Worker(WorkerArgs),
    /// Create a short-lived worker pairing token (requires a running coordinator).
    Pair(PairArgs),
    /// Show the local role, service reachability, limits, and active tasks.
    Status,
    /// List authorized workers and their availability.
    Workers,
    /// Submit, inspect, list, or cancel jobs.
    Jobs(JobsArgs),
    /// Show honest local-network contribution statistics.
    Contribute,
    /// Diagnose configuration, permissions, TLS, networking, and runtime issues.
    Doctor,
    /// Inspect or update supported configuration values.
    Config(ConfigArgs),
    /// Discover Getter coordinators on the local network (unauthenticated).
    Discover(DiscoverArgs),
    /// Remove local Getter state for this home. Service-manager cleanup is manual.
    Uninstall(UninstallArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, value_enum)]
    role: InitRole,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    bind: Option<SocketAddr>,
    /// Bind all interfaces, use TLS, derive the public URL, and enable discovery.
    #[arg(long)]
    lan: bool,
    /// Disable TLS. Only permitted for loopback development unless config is edited.
    #[arg(long)]
    no_tls: bool,
    #[arg(long)]
    public_url: Option<String>,
    /// Enable UDP discovery advertisements (automatic with --lan).
    #[arg(long)]
    discovery: bool,
    /// Additional DNS name for the coordinator TLS certificate.
    #[arg(long = "hostname")]
    hostnames: Vec<String>,
    /// Coordinator URL for a worker, defaulting to loopback development.
    #[arg(long)]
    coordinator_url: Option<String>,
    /// Coordinator CA certificate to copy into worker trust state.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Loopback address for the worker control API.
    #[arg(long)]
    control_bind: Option<SocketAddr>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InitRole {
    Coordinator,
    Worker,
}

#[derive(Debug, Args)]
struct CoordinatorArgs {
    #[command(subcommand)]
    command: CoordinatorCommand,
}

#[derive(Debug, Subcommand)]
enum CoordinatorCommand {
    /// Start the coordinator HTTP(S) service in the foreground.
    Start,
}

#[derive(Debug, Args)]
struct WorkerArgs {
    #[command(subcommand)]
    command: WorkerCommand,
}

#[derive(Debug, Subcommand)]
enum WorkerCommand {
    /// Enroll this worker with a coordinator using a short-lived pairing token.
    Join(JoinArgs),
    /// Start the worker in the foreground.
    Start,
    /// Stop taking new work and cancel running local tasks (they are retried).
    Pause,
    /// Resume taking work when no battery policy requires a pause.
    Resume,
    /// Ask the local worker to shut down gracefully.
    Stop,
    /// Show the local worker control API status.
    Status,
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("token_source")
        .required(true)
        .multiple(false)
        .args(["token", "token_file"])
))]
struct JoinArgs {
    /// Coordinator base URL, for example https://192.168.1.10:47810.
    #[arg(long)]
    coordinator: String,
    /// Pairing token value. Prefer --token-file to keep it out of shell history.
    #[arg(long, conflicts_with = "token_file")]
    token: Option<String>,
    /// Read the one-time pairing token from a file (mode 0600 recommended).
    #[arg(long, conflicts_with = "token")]
    token_file: Option<PathBuf>,
    /// Copy and pin this coordinator CA certificate instead of fetching by fingerprint.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Out-of-band CA fingerprint printed by `getter pair`.
    #[arg(long)]
    ca_fingerprint: Option<String>,
}

#[derive(Debug, Args)]
struct PairArgs {
    #[arg(long)]
    name: String,
    #[arg(long, default_value_t = 900)]
    ttl_secs: u64,
    /// Write a copy of the coordinator CA certificate for transfer to a worker.
    #[arg(long)]
    write_ca: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct JobsArgs {
    #[command(subcommand)]
    command: JobsCommand,
}

#[derive(Debug, Subcommand)]
enum JobsCommand {
    /// Submit a getter.job/v1 file and base64-encode its referenced Wasm artifact.
    Submit {
        #[arg(long)]
        file: PathBuf,
        /// Poll until the job reaches a terminal state and show the result.
        #[arg(long)]
        watch: bool,
    },
    /// List recent jobs.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Inspect a job and all task states.
    Inspect {
        job_id: String,
        /// Poll until terminal, printing progress updates.
        #[arg(long)]
        watch: bool,
    },
    /// Request cancellation of a queued or running job.
    Cancel { job_id: String },
}

#[derive(Debug, Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the parsed configuration with secret paths (never secrets).
    Show,
    /// Set a supported dotted configuration key. Restart to apply service changes.
    Set { key: String, value: String },
    /// Print the config file path.
    Path,
}

#[derive(Debug, Args)]
struct DiscoverArgs {
    #[arg(long, default_value_t = getter_protocol::DEFAULT_DISCOVERY_PORT)]
    port: u16,
    #[arg(long, default_value_t = 3)]
    seconds: u64,
}

#[derive(Debug, Args)]
struct UninstallArgs {
    /// Confirm removal of local configuration, identities, keys, and database.
    #[arg(long)]
    yes: bool,
}

#[derive(Clone)]
struct AdminClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl AdminClient {
    async fn for_config(home: &Path, config: &GetterConfig) -> anyhow::Result<Self> {
        let coordinator = config
            .coordinator
            .as_ref()
            .context("this home is not a coordinator configuration")?;
        let token = read_admin_token(home)
            .map_err(|error| anyhow::anyhow!("could not read admin token: {error}"))?;
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("getter-cli/", env!("CARGO_PKG_VERSION")));
        if let Some(tls) = &coordinator.tls {
            let pem = std::fs::read(&tls.ca_cert)
                .with_context(|| format!("read CA certificate {}", tls.ca_cert.display()))?;
            let der = getter_core::init::certificate_der_from_pem(&pem).map_err(|error| {
                anyhow::anyhow!("coordinator CA certificate is invalid: {error}")
            })?;
            let certificate = reqwest::Certificate::from_der(&der)
                .context("coordinator CA certificate is invalid DER")?;
            builder = builder
                .add_root_certificate(certificate)
                .tls_built_in_root_certs(false);
        }
        let http = builder.build().context("build admin HTTP client")?;
        Ok(Self {
            http,
            base_url: coordinator.public_url.trim_end_matches('/').to_owned(),
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let response = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("request GET {path}"))?;
        parse_response(response).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        let response = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("request POST {path}"))?;
        parse_response(response).await
    }
}

async fn parse_response<T: DeserializeOwned>(response: reqwest::Response) -> anyhow::Result<T> {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("read coordinator response")?;
    if !status.is_success() {
        return Err(api_error(status, &bytes));
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("coordinator returned malformed JSON (HTTP {status})"))
}

fn api_error(status: reqwest::StatusCode, bytes: &[u8]) -> anyhow::Error {
    match serde_json::from_slice::<getter_protocol::ApiErrorBody>(bytes) {
        Ok(error) => anyhow::anyhow!("{}: {} (HTTP {status})", error.code, error.message),
        Err(_) => anyhow::anyhow!(
            "coordinator request failed (HTTP {status}): {}",
            String::from_utf8_lossy(bytes)
                .trim()
                .chars()
                .take(300)
                .collect::<String>()
        ),
    }
}

struct ControlClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl ControlClient {
    fn for_config(home: &Path, config: &GetterConfig) -> anyhow::Result<Self> {
        let worker = config
            .worker
            .as_ref()
            .context("this home is not a worker configuration")?;
        let token = read_control_token(home)
            .map_err(|error| anyhow::anyhow!("could not read control token: {error}"))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("getter-cli/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base_url: format!("http://{}", worker.control_bind),
            token,
        })
    }

    async fn get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("local worker is not running or the control API is unreachable")?;
        parse_response(response).await
    }

    async fn post(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("local worker is not running or the control API is unreachable")?;
        parse_response(response).await
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let home = resolve_home(cli.home)?;
    match cli.command {
        Command::Init(args) => init(&home, args, cli.json).await,
        Command::Coordinator(args) => coordinator(home, args).await,
        Command::Worker(args) => worker(home, args, cli.json).await,
        Command::Pair(args) => pair(&home, args, cli.json).await,
        Command::Status => status(&home, cli.json).await,
        Command::Workers => workers(&home, cli.json).await,
        Command::Jobs(args) => jobs(&home, args, cli.json).await,
        Command::Contribute => contribute(&home, cli.json).await,
        Command::Doctor => {
            if cli.json {
                bail!("`--json` is not supported by doctor; use its human-readable diagnostics");
            }
            doctor(&home).await
        }
        Command::Config(args) => config_command(&home, args, cli.json),
        Command::Discover(args) => discover(args, cli.json).await,
        Command::Uninstall(args) => {
            if cli.json {
                bail!("`--json` is not supported by uninstall");
            }
            uninstall(&home, args).await
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(error) => {
                    tracing::error!(error = %error, "could not listen for SIGTERM");
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %error, "could not listen for Ctrl-C");
        }
    }
}

fn resolve_home(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(home) = explicit {
        return Ok(home);
    }
    if let Some(home) = std::env::var_os("GETTER_HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        return Ok(PathBuf::from(home).join(".getter"));
    }
    bail!("could not determine a home directory; pass --home or set GETTER_HOME")
}

async fn init(home: &Path, args: InitArgs, json: bool) -> anyhow::Result<()> {
    if home.parent().is_none() {
        bail!("refusing to initialize Getter at a filesystem root");
    }
    if home.exists() && !config_path(home).exists() {
        let non_empty = std::fs::read_dir(home)
            .with_context(|| format!("read init directory {}", home.display()))?
            .next()
            .is_some();
        if non_empty {
            bail!(
                "refusing to initialize Getter in non-empty directory {}; choose a new or empty directory",
                home.display()
            );
        }
    }
    match args.role {
        InitRole::Coordinator => {
            let bind = args.bind.unwrap_or_else(|| {
                if args.lan {
                    SocketAddr::from(([0, 0, 0, 0], 47810))
                } else {
                    SocketAddr::from(([127, 0, 0, 1], 47810))
                }
            });
            let name = args.name.unwrap_or_else(|| "getter-coordinator".into());
            let result = generate_coordinator_config(&CoordinatorInitOptions {
                home: home.to_path_buf(),
                name,
                bind,
                public_url: args.public_url,
                tls: !args.no_tls,
                discovery: args.discovery || args.lan,
                hostnames: args.hostnames,
                force: args.force,
            })?;
            let coordinator = result
                .config
                .coordinator
                .as_ref()
                .context("created coordinator config is missing")?;
            let summary = serde_json::json!({
                "ok": true,
                "role": "coordinator",
                "home": home,
                "name": result.config.name,
                "public_url": coordinator.public_url,
                "bind": coordinator.bind,
                "tls": coordinator.tls.is_some(),
                "discovery": coordinator.discovery.enabled,
                "ca_fingerprint": result.ca_fingerprint,
                "admin_token_path": admin_token_path(home),
                "config_path": config_path(home),
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("Getter coordinator initialized");
                println!("  home:          {}", home.display());
                println!("  name:          {}", result.config.name);
                println!("  public URL:    {}", coordinator.public_url);
                println!("  bind:          {}", coordinator.bind);
                println!(
                    "  TLS:           {}",
                    if coordinator.tls.is_some() {
                        "enabled (local CA)"
                    } else {
                        "disabled"
                    }
                );
                if let Some(fingerprint) = &result.ca_fingerprint {
                    println!("  CA fingerprint: {fingerprint}");
                }
                println!(
                    "  admin token:   {} (0600, never printed)",
                    admin_token_path(home).display()
                );
                println!();
                println!("Next:");
                println!("  1. getter coordinator start --home {}", home.display());
                println!(
                    "  2. getter pair --name <worker-name> --home {}",
                    home.display()
                );
                println!("  3. install Getter on another machine and run `getter worker join`.");
            }
        }
        InitRole::Worker => {
            ensure_private_dir(home)?;
            let name = args.name.unwrap_or_else(|| "getter-worker".into());
            let config = generate_worker_identity(&WorkerInitOptions {
                home: home.to_path_buf(),
                name: name.clone(),
                coordinator_url: args
                    .coordinator_url
                    .unwrap_or_else(|| "http://127.0.0.1:47810".into()),
                coordinator_ca: args.ca_cert,
                control_bind: args.control_bind,
                force: args.force,
            })?;
            let worker = config.worker.as_ref().context("worker config missing")?;
            let summary = serde_json::json!({
                "ok": true,
                "role": "worker",
                "home": home,
                "name": name,
                "coordinator_url": worker.coordinator_url,
                "control_bind": worker.control_bind,
                "concurrency": worker.concurrency,
                "max_task_memory_bytes": worker.max_task_memory_bytes,
                "config_path": config_path(home),
                "identity_path": worker_identity_path(home),
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("Getter worker initialized");
                println!("  home:            {}", home.display());
                println!("  name:            {name}");
                println!("  coordinator URL: {}", worker.coordinator_url);
                println!("  control API:     http://{}", worker.control_bind);
                println!("  concurrency:     {}", worker.concurrency);
                println!(
                    "  memory per task: {} MiB",
                    worker.max_task_memory_bytes / (1024 * 1024)
                );
                println!();
                println!("Next:");
                println!("  getter worker join --coordinator <url> --token <pairing-token> \\");
                println!(
                    "    --ca-fingerprint <sha256:...> --home {}",
                    home.display()
                );
                println!("  getter worker start --home {}", home.display());
            }
        }
    }
    Ok(())
}

async fn coordinator(home: PathBuf, args: CoordinatorArgs) -> anyhow::Result<()> {
    match args.command {
        CoordinatorCommand::Start => {
            let config = GetterConfig::load(&home)?;
            if config.role != Role::Coordinator {
                bail!("this home is configured as a worker, not a coordinator");
            }
            getter_coordinator::serve(getter_coordinator::ServeOptions { home, config }, async {
                if let Err(error) = tokio::signal::ctrl_c().await {
                    tracing::error!(error = %error, "could not listen for Ctrl-C");
                }
            })
            .await
        }
    }
}

async fn worker(home: PathBuf, args: WorkerArgs, json: bool) -> anyhow::Result<()> {
    match args.command {
        WorkerCommand::Join(args) => {
            let pairing_token = match (args.token, args.token_file) {
                (Some(token), None) => token.trim().to_owned(),
                (None, Some(path)) => std::fs::read_to_string(&path)
                    .with_context(|| format!("read pairing token file {}", path.display()))?
                    .trim()
                    .to_owned(),
                _ => bail!("provide exactly one of --token or --token-file"),
            };
            if pairing_token.is_empty() {
                bail!("pairing token is empty");
            }
            let outcome = join(
                &home,
                JoinOptions {
                    coordinator_url: args.coordinator.clone(),
                    pairing_token,
                    ca_cert: args.ca_cert,
                    ca_fingerprint: args.ca_fingerprint,
                },
            )
            .await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "worker_id": outcome.worker_id,
                        "coordinator_name": outcome.coordinator_name,
                        "coordinator_url": args.coordinator,
                        "ca_fingerprint": outcome.ca_fingerprint,
                    }))?
                );
            } else {
                println!("Worker enrolled and authorized");
                println!("  worker id:        {}", outcome.worker_id);
                println!(
                    "  coordinator:      {} ({})",
                    args.coordinator, outcome.coordinator_name
                );
                if let Some(fingerprint) = outcome.ca_fingerprint {
                    println!("  CA fingerprint:   {fingerprint}");
                }
                println!("Next: getter worker start --home {}", home.display());
            }
            Ok(())
        }
        WorkerCommand::Start => {
            let config = GetterConfig::load(&home)?;
            if config.role != Role::Worker {
                bail!("this home is configured as a coordinator, not a worker");
            }
            run_worker(home, config, shutdown_signal()).await
        }
        WorkerCommand::Pause
        | WorkerCommand::Resume
        | WorkerCommand::Stop
        | WorkerCommand::Status => {
            let config = GetterConfig::load(&home)?;
            let client = ControlClient::for_config(&home, &config)?;
            let (path, action) = match &args.command {
                WorkerCommand::Pause => ("/pause", "pause"),
                WorkerCommand::Resume => ("/resume", "resume"),
                WorkerCommand::Stop => ("/shutdown", "stop"),
                WorkerCommand::Status => ("/status", "status"),
                _ => unreachable!(),
            };
            let value = if path == "/status" {
                client.get(path).await?
            } else {
                client.post(path).await?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                print_worker_status_or_action(&value, action);
            }
            Ok(())
        }
    }
}

fn print_worker_status_or_action(value: &serde_json::Value, action: &str) {
    if action == "status" {
        println!("Local worker");
        println!(
            "  id:          {}",
            value["worker_id"].as_str().unwrap_or("?")
        );
        println!(
            "  name:        {}",
            value["worker_name"].as_str().unwrap_or("?")
        );
        println!("  state:       {}", value["state"].as_str().unwrap_or("?"));
        println!(
            "  coordinator: {}",
            value["coordinator_url"].as_str().unwrap_or("?")
        );
        println!(
            "  slots:       {}/{} active",
            value["active_slots"].as_u64().unwrap_or(0),
            value["concurrency"].as_u64().unwrap_or(0)
        );
        println!(
            "  uptime:      {}s",
            value["uptime_secs"].as_u64().unwrap_or(0)
        );
        println!(
            "  completed:   {} tasks, {} ms compute",
            value["stats"]["tasks_completed"].as_u64().unwrap_or(0),
            value["stats"]["compute_ms"].as_u64().unwrap_or(0)
        );
        if let Some(tasks) = value["active_tasks"].as_array() {
            if tasks.is_empty() {
                println!("  active:      (none)");
            } else {
                println!("  active:");
                for task in tasks {
                    println!(
                        "    {} / {} [{}]",
                        task["job_name"].as_str().unwrap_or("?"),
                        task["task_key"].as_str().unwrap_or("?"),
                        task["lease_id"].as_str().unwrap_or("?")
                    );
                }
            }
        }
        if let Some(error) = value["last_error"].as_str() {
            println!("  last error:  {error}");
        }
    } else {
        println!(
            "worker {}: {} ({} cancelled)",
            action,
            value["state"].as_str().unwrap_or("unknown"),
            value["cancelled_tasks"].as_u64().unwrap_or(0)
        );
        if let Some(message) = value["message"].as_str() {
            println!("  {message}");
        }
    }
}

async fn pair(home: &Path, args: PairArgs, json: bool) -> anyhow::Result<()> {
    let config = GetterConfig::load(home)?;
    let admin = AdminClient::for_config(home, &config).await?;
    let response: PairingTokenResponse = admin
        .post(
            getter_protocol::PATH_ADMIN_PAIRING,
            &PairingTokenRequest {
                name: args.name.clone(),
                ttl_secs: args.ttl_secs,
            },
        )
        .await?;
    let coordinator = config
        .coordinator
        .as_ref()
        .context("missing coordinator config")?;
    if let Some(target) = args.write_ca {
        let tls = coordinator
            .tls
            .as_ref()
            .context("coordinator has no TLS CA certificate")?;
        let pem = std::fs::read(&tls.ca_cert)?;
        std::fs::write(&target, pem)
            .with_context(|| format!("write CA certificate to {}", target.display()))?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("Pairing token created for worker {:?}", response.name);
        println!("  token:          {}", response.token);
        println!("  coordinator:    {}", response.coordinator_url);
        if let Some(fingerprint) = &response.ca_fingerprint {
            println!("  CA fingerprint: {fingerprint}");
        }
        println!("  expires at:     {}", response.expires_at.to_rfc3339());
        println!();
        println!("This token is a secret and is shown only once. On the worker machine run:");
        println!("  getter init --role worker --name {}", response.name);
        println!("  getter worker join \\");
        println!("    --coordinator {} \\", response.coordinator_url);
        println!("    --token {} \\", response.token);
        if let Some(fingerprint) = &response.ca_fingerprint {
            println!("    --ca-fingerprint {fingerprint}");
        }
    }
    Ok(())
}

async fn status(home: &Path, json: bool) -> anyhow::Result<()> {
    let config = GetterConfig::load(home)?;
    match config.role {
        Role::Coordinator => {
            let admin = AdminClient::for_config(home, &config).await?;
            let status: CoordinatorStatusResponse =
                admin.get(getter_protocol::PATH_ADMIN_STATUS).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("Getter coordinator {}", status.coordinator_name);
                println!(
                    "  status:        {}",
                    if status.database_healthy {
                        "ready"
                    } else {
                        "degraded"
                    }
                );
                println!(
                    "  endpoints:     {}",
                    config.coordinator.as_ref().context("config")?.public_url
                );
                println!("  uptime:        {}s", status.uptime_secs);
                println!(
                    "  workers:       {} online / {} authorized",
                    status.online_workers, status.total_workers
                );
                println!("  active tasks:  {}", status.active_tasks);
                println!(
                    "  jobs:          {} running, {} queued, {} completed, {} failed",
                    status.running_jobs,
                    status.queued_jobs,
                    status.completed_jobs,
                    status.failed_jobs
                );
                println!("  version:       {} ({})", status.version, status.protocol);
            }
        }
        Role::Worker => {
            let client = ControlClient::for_config(home, &config)?;
            let value = client.get("/status").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                print_worker_status_or_action(&value, "status");
            }
        }
    }
    Ok(())
}

async fn workers(home: &Path, json: bool) -> anyhow::Result<()> {
    let config = GetterConfig::load(home)?;
    let admin = AdminClient::for_config(home, &config).await?;
    let response: WorkerListResponse = admin.get(getter_protocol::PATH_ADMIN_WORKERS).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    if response.workers.is_empty() {
        println!("No workers have been enrolled. Create a pairing token with `getter pair`.");
        return Ok(());
    }
    println!(
        "{:<36}  {:<20}  {:<9}  {:>5}  {:>9}  {:>12}  LAST SEEN",
        "ID", "NAME", "STATUS", "ACT", "DONE", "COMPUTE"
    );
    for worker in response.workers {
        println!(
            "{:<36}  {:<20}  {:<9}  {:>5}  {:>9}  {:>10}ms  {}",
            worker.id,
            truncate(&safe_display(&worker.name), 20),
            worker_status_label(worker.status),
            worker.active_tasks,
            worker.successful_tasks,
            worker.compute_ms,
            worker
                .last_seen
                .map(|time| time.to_rfc3339())
                .unwrap_or_else(|| "never".into())
        );
    }
    Ok(())
}

fn worker_status_label(status: WorkerStatus) -> &'static str {
    match status {
        WorkerStatus::Online => "online",
        WorkerStatus::Paused => "paused",
        WorkerStatus::Offline => "offline",
        WorkerStatus::Revoked => "revoked",
    }
}

async fn jobs(home: &Path, args: JobsArgs, json: bool) -> anyhow::Result<()> {
    let config = GetterConfig::load(home)?;
    let admin = AdminClient::for_config(home, &config).await?;
    match args.command {
        JobsCommand::Submit { file, watch } => {
            let job = submit_file(&admin, &file).await?;
            if json && !watch {
                println!("{}", serde_json::to_string_pretty(&job)?);
            } else {
                print_job_detail(&job);
            }
            if watch {
                watch_job(&admin, &job.job.id, json).await?;
            }
            Ok(())
        }
        JobsCommand::List { limit } => {
            let response: JobListResponse = admin
                .get(&format!(
                    "{}?limit={}",
                    getter_protocol::PATH_ADMIN_JOBS,
                    limit
                ))
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }
            if response.jobs.is_empty() {
                println!("No jobs yet. Submit one with `getter jobs submit --file <job.json>`.");
                return Ok(());
            }
            println!(
                "{:<36}  {:<10}  {:>9}  {:<8}  {:<20}  NAME",
                "ID", "STATE", "PROGRESS", "VERIFIED", "WORKLOAD"
            );
            for job in response.jobs {
                println!(
                    "{:<36}  {:<10}  {:>4}/{:<4}  {:<8}  {:<20}  {}",
                    job.id,
                    job.state,
                    job.completed_tasks,
                    job.total_tasks,
                    if job.verified { "yes" } else { "no" },
                    truncate(&job.workload_name, 20),
                    job.name
                );
            }
            Ok(())
        }
        JobsCommand::Inspect { job_id, watch } => {
            let detail: JobDetailResponse = admin.get(&format!("/v1/admin/jobs/{job_id}")).await?;
            if json && !watch {
                println!("{}", serde_json::to_string_pretty(&detail)?);
            } else {
                print_job_detail(&detail);
            }
            if watch {
                watch_job(&admin, &job_id, json).await?;
            }
            Ok(())
        }
        JobsCommand::Cancel { job_id } => {
            let response: getter_protocol::CancelResponse = admin
                .post(
                    &format!("/v1/admin/jobs/{job_id}/cancel"),
                    &serde_json::json!({}),
                )
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!("{}: {}", response.job_id, response.message);
            }
            Ok(())
        }
    }
}

async fn submit_file(admin: &AdminClient, file: &Path) -> anyhow::Result<JobDetailResponse> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("read job file {}", file.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parse job file {}", file.display()))?;
    let artifact_path = value
        .get_mut("workload")
        .and_then(|workload| workload.as_object_mut())
        .and_then(|workload| workload.remove("artifact"))
        .and_then(|artifact| artifact.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("job file workload.artifact must name a .wasm file"))?;
    let manifest: getter_protocol::JobManifest = serde_json::from_value(value)
        .with_context(|| format!("job file {} does not match getter.job/v1", file.display()))?;
    if manifest.protocol != JOB_FORMAT {
        bail!(
            "job protocol must be {JOB_FORMAT}, got {:?}",
            manifest.protocol
        );
    }
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    let artifact_path = if Path::new(&artifact_path).is_absolute() {
        PathBuf::from(&artifact_path)
    } else {
        base.join(&artifact_path)
    };
    let metadata = std::fs::metadata(&artifact_path)
        .with_context(|| format!("workload artifact not found: {}", artifact_path.display()))?;
    if metadata.len() > MAX_ARTIFACT_BYTES as u64 {
        bail!("workload artifact exceeds {} bytes", MAX_ARTIFACT_BYTES);
    }
    let artifact = std::fs::read(&artifact_path)
        .with_context(|| format!("read workload artifact {}", artifact_path.display()))?;
    let actual = hex::encode(Sha256::digest(&artifact));
    if actual != manifest.workload.sha256.to_ascii_lowercase() {
        bail!(
            "workload artifact SHA-256 mismatch: manifest says {}, file is {actual}. \
             Rebuild the artifact or regenerate the job with examples/sum-squares/generate_job.py.",
            manifest.workload.sha256
        );
    }
    eprintln!(
        "submitting {} task(s), artifact {} bytes, sha256 {}",
        manifest.tasks.len(),
        artifact.len(),
        actual
    );
    let submission = getter_protocol::JobSubmission {
        manifest,
        artifact_base64: base64::engine::general_purpose::STANDARD.encode(artifact),
    };
    let detail: JobDetailResponse = admin
        .post(getter_protocol::PATH_ADMIN_JOBS, &submission)
        .await?;
    Ok(detail)
}

async fn watch_job(admin: &AdminClient, job_id: &str, json: bool) -> anyhow::Result<()> {
    let mut last_signature = String::new();
    loop {
        let detail: JobDetailResponse = admin.get(&format!("/v1/admin/jobs/{job_id}")).await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&detail)?);
        } else {
            let signature = format!(
                "{}:{}/{}/{}/{}/{}",
                detail.job.state,
                detail.progress.completed,
                detail.progress.running,
                detail.progress.assigned,
                detail.progress.failed,
                detail.tasks.iter().map(|task| task.attempts).sum::<u32>()
            );
            if signature != last_signature {
                println!(
                    "{}  {} {:.1}%  completed={} running={} assigned={} queued={} failed={} workers={}",
                    detail.job.state,
                    job_id,
                    detail.progress.percent_complete,
                    detail.progress.completed,
                    detail.progress.running,
                    detail.progress.assigned,
                    detail.progress.queued,
                    detail.progress.failed,
                    detail
                        .tasks
                        .iter()
                        .filter_map(|task| task.assigned_worker_name.clone())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                );
                last_signature = signature;
            }
        }
        if detail.job.state.is_terminal() {
            if !json {
                println!();
                print_job_detail(&detail);
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}

fn print_job_detail(detail: &JobDetailResponse) {
    println!(
        "job {}  {}  [{}]  {:.1}%",
        detail.job.id, detail.job.name, detail.job.state, detail.progress.percent_complete
    );
    println!(
        "  workload:   {}  ({})",
        detail.job.workload_name, detail.job.artifact_sha256
    );
    println!(
        "  tasks:      {} completed, {} failed, {} running, {} assigned, {} queued",
        detail.progress.completed,
        detail.progress.failed,
        detail.progress.running,
        detail.progress.assigned,
        detail.progress.queued
    );
    println!(
        "  verification: {:?}  ·  aggregation: {:?}",
        detail.job.verification_mode, detail.job.aggregation
    );
    if let Some(error) = &detail.job.error {
        println!("  error:      {error}");
    }
    println!();
    println!(
        "{:<16}  {:<10}  {:>7}  {:<22}  {:>10}  VALIDATION",
        "TASK", "STATE", "ATTEMPT", "WORKER", "COMPUTE"
    );
    for task in &detail.tasks {
        println!(
            "{:<16}  {:<10}  {:>3}/{:<3}  {:<22}  {:>7}ms  {}",
            task.key,
            task.state,
            task.attempts,
            task.max_attempts,
            truncate(task.assigned_worker_name.as_deref().unwrap_or("-"), 22),
            task.compute_ms,
            task.validation_status
        );
    }
    if let Some(result) = &detail.result {
        println!();
        println!("  aggregate:  {}", result.aggregate);
        println!(
            "  verified:   {}/{} tasks; expected aggregate match: {}",
            result.verified_tasks,
            result.completed_tasks,
            result
                .aggregate_matches_expected
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".into())
        );
    }
}

async fn contribute(home: &Path, json: bool) -> anyhow::Result<()> {
    let config = GetterConfig::load(home)?;
    let admin = AdminClient::for_config(home, &config).await?;
    let response: ContributionResponse =
        admin.get(getter_protocol::PATH_ADMIN_CONTRIBUTION).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    println!("Contribution on {}", response.coordinator_name);
    println!(
        "  workers:           {} authorized, {} online",
        response.summary.worker_count, response.summary.online_workers
    );
    println!("  tasks completed:   {}", response.summary.successful_tasks);
    println!("  verified tasks:    {}", response.summary.verified_tasks);
    println!("  failed attempts:   {}", response.summary.failed_attempts);
    println!("  jobs completed:    {}", response.summary.completed_jobs);
    println!(
        "  compute time:      {:.2}s recorded by workers",
        response.summary.compute_ms as f64 / 1000.0
    );
    if response.workers.is_empty() {
        println!("\nNo enrolled workers yet.");
    } else {
        println!();
        println!(
            "{:<20}  {:<9}  {:>8}  {:>8}  {:>12}",
            "WORKER", "STATUS", "DONE", "FAILED", "COMPUTE"
        );
        for worker in response.workers {
            println!(
                "{:<20}  {:<9}  {:>8}  {:>8}  {:>10}ms",
                truncate(&safe_display(&worker.worker_name), 20),
                worker_status_label(worker.status),
                worker.successful_tasks,
                worker.failed_attempts,
                worker.compute_ms
            );
        }
    }
    println!(
        "\nFigures are accepted work recorded by this coordinator, not theoretical CPU capacity."
    );
    Ok(())
}

async fn discover(args: DiscoverArgs, json: bool) -> anyhow::Result<()> {
    let announcements = getter_coordinator::discover_coordinators(
        args.port,
        Duration::from_secs(args.seconds.clamp(1, 30)),
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&announcements)?);
        return Ok(());
    }
    if announcements.is_empty() {
        println!(
            "No coordinators answered discovery on UDP port {}. This is normal on networks that \
             block broadcast. Use the coordinator URL printed by `getter pair` instead.",
            args.port
        );
        return Ok(());
    }
    for announcement in announcements {
        println!(
            "{}  {}  protocol={}  ca={}  version={}",
            safe_display(&announcement.coordinator_name),
            safe_display(&announcement.coordinator_url),
            safe_display(&announcement.protocol),
            safe_display(announcement.ca_fingerprint.as_deref().unwrap_or("none")),
            safe_display(&announcement.version)
        );
    }
    println!("\nDiscovery does not authorize a worker. Enrollment still requires a pairing token.");
    Ok(())
}

async fn doctor(home: &Path) -> anyhow::Result<()> {
    let mut failures = 0_usize;
    let mut warnings = 0_usize;
    println!("Getter doctor for {}", home.display());
    let config_path = config_path(home);
    if !config_path.is_file() {
        println!("[fail] configuration not found: {}", config_path.display());
        println!("       Run `getter init --role coordinator|worker`.");
        bail!("configuration is missing");
    }
    println!("[ok]   configuration file: {}", config_path.display());
    let config = GetterConfig::load(home).context("load configuration")?;
    println!(
        "[ok]   configuration parses and validates; role={}",
        config.role
    );
    match config.role {
        Role::Coordinator => {
            let coordinator = config.coordinator.as_ref().context("coordinator config")?;
            if coordinator.tls.is_some() {
                let tls = coordinator.tls.as_ref().context("TLS config")?;
                for (label, path) in [
                    ("CA", &tls.ca_cert),
                    ("certificate chain", &tls.cert_chain),
                    ("private key", &tls.private_key),
                ] {
                    if path.is_file() {
                        println!("[ok]   TLS {label}: {}", path.display());
                    } else {
                        println!("[fail] TLS {label} missing: {}", path.display());
                        failures += 1;
                    }
                }
                if check_private_file(&tls.private_key, true).is_ok() {
                    println!("[ok]   TLS private key has private permissions");
                } else {
                    println!("[fail] TLS private key is missing or accessible to group/other");
                    failures += 1;
                }
                match std::fs::read(&tls.ca_cert)
                    .map_err(|error| error.to_string())
                    .and_then(|pem| fingerprint_pem(&pem).map_err(|error| error.to_string()))
                {
                    Ok(fingerprint) => println!("[ok]   CA fingerprint: {fingerprint}"),
                    Err(error) => {
                        println!("[fail] CA certificate unusable: {error}");
                        failures += 1;
                    }
                }
                if coordinator.public_url.starts_with("https://") {
                    println!("[ok]   public URL uses HTTPS");
                } else {
                    println!("[fail] TLS is configured but public_url is not HTTPS");
                    failures += 1;
                }
            } else {
                let loopback = coordinator.bind.ip().is_loopback();
                if loopback {
                    println!("[warn] TLS is disabled on a loopback-only coordinator");
                    warnings += 1;
                } else {
                    println!("[fail] TLS is disabled on a non-loopback coordinator");
                    failures += 1;
                }
            }
            if check_private_file(&admin_token_path(home), true).is_err() {
                println!("[fail] admin token missing or too permissive (expected 0600)");
                failures += 1;
            } else {
                println!("[ok]   admin token exists with private permissions");
            }
            if coordinator
                .database_path
                .parent()
                .map(Path::is_dir)
                .unwrap_or(false)
            {
                println!(
                    "[ok]   database directory: {}",
                    coordinator.database_path.display()
                );
            } else {
                println!(
                    "[warn] database parent directory does not exist yet: {}",
                    coordinator.database_path.display()
                );
                warnings += 1;
            }
            match reachable_health(&config).await {
                Ok(version) => println!("[ok]   coordinator health endpoint reachable ({version})"),
                Err(error) => {
                    println!(
                        "[warn] coordinator is not reachable at {}: {error}",
                        coordinator.public_url
                    );
                    println!(
                        "       Start it with `getter coordinator start` if this is unexpected."
                    );
                    warnings += 1;
                }
            }
            match AdminClient::for_config(home, &config).await {
                Ok(admin) => match admin
                    .get::<CoordinatorStatusResponse>(getter_protocol::PATH_ADMIN_STATUS)
                    .await
                {
                    Ok(status) => {
                        println!(
                            "[ok]   authenticated admin API reachable; {} workers online, database healthy={}",
                            status.online_workers, status.database_healthy
                        );
                        if !status.database_healthy {
                            failures += 1;
                        }
                    }
                    Err(error) => {
                        println!("[fail] authenticated admin API failed: {error}");
                        failures += 1;
                    }
                },
                Err(error) => {
                    println!("[fail] admin client could not be constructed: {error}");
                    failures += 1;
                }
            }
        }
        Role::Worker => {
            let worker = config.worker.as_ref().context("worker config")?;
            if check_private_file(&worker_identity_path(home), true).is_err() {
                println!("[fail] worker identity missing or too permissive (expected 0600)");
                failures += 1;
            } else {
                println!("[ok]   worker identity exists with private permissions");
            }
            if check_private_file(&control_token_path(home), true).is_err() {
                println!("[fail] control token missing or too permissive (expected 0600)");
                failures += 1;
            } else {
                println!("[ok]   control token exists with private permissions");
            }
            if let Some(ca) = &worker.coordinator_ca {
                if ca.is_file() {
                    let fingerprint = std::fs::read(ca)
                        .map_err(|error| error.to_string())
                        .and_then(|pem| fingerprint_pem(&pem).map_err(|error| error.to_string()));
                    match fingerprint {
                        Ok(fingerprint) => println!("[ok]   pinned coordinator CA: {fingerprint}"),
                        Err(error) => {
                            println!("[fail] coordinator CA unusable: {error}");
                            failures += 1;
                        }
                    }
                } else {
                    println!("[fail] coordinator CA missing: {}", ca.display());
                    failures += 1;
                }
            }
            match reachable_health(&config).await {
                Ok(version) => println!(
                    "[ok]   coordinator {} is reachable (health {version})",
                    worker.coordinator_url
                ),
                Err(error) => {
                    println!(
                        "[warn] coordinator {} is not reachable: {error}",
                        worker.coordinator_url
                    );
                    warnings += 1;
                }
            }
            match ControlClient::for_config(home, &config) {
                Ok(control) => match control.get("/status").await {
                    Ok(status) => println!(
                        "[ok]   local worker control API reachable; state={} active={}",
                        status["state"].as_str().unwrap_or("?"),
                        status["active_tasks"].as_array().map(Vec::len).unwrap_or(0)
                    ),
                    Err(error) => {
                        println!("[warn] local worker control API not reachable: {error}");
                        warnings += 1;
                    }
                },
                Err(error) => {
                    println!("[fail] control client unavailable: {error}");
                    failures += 1;
                }
            }
        }
    }
    println!();
    println!("Summary: {failures} failure(s), {warnings} warning(s)");
    if failures > 0 {
        bail!("doctor found {failures} blocking problem(s)");
    }
    Ok(())
}

async fn reachable_health(config: &GetterConfig) -> anyhow::Result<String> {
    let (url, ca_path) = match config.role {
        Role::Coordinator => {
            let coordinator = config.coordinator.as_ref().context("coordinator config")?;
            (
                coordinator.public_url.clone(),
                coordinator.tls.as_ref().map(|tls| tls.ca_cert.clone()),
            )
        }
        Role::Worker => {
            let worker = config.worker.as_ref().context("worker config")?;
            (
                worker.coordinator_url.clone(),
                worker.coordinator_ca.clone(),
            )
        }
    };
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent(concat!("getter-doctor/", env!("CARGO_PKG_VERSION")));
    if let Some(ca_path) = ca_path {
        let pem = std::fs::read(&ca_path)
            .with_context(|| format!("read CA certificate {}", ca_path.display()))?;
        let der = getter_core::init::certificate_der_from_pem(&pem)
            .map_err(|error| anyhow::anyhow!("CA certificate is invalid: {error}"))?;
        let certificate = reqwest::Certificate::from_der(&der)?;
        builder = builder
            .add_root_certificate(certificate)
            .tls_built_in_root_certs(false);
    }
    let client = builder.build()?;
    let response = client
        .get(format!("{}/healthz", url.trim_end_matches('/')))
        .send()
        .await?;
    let status = response.status();
    let value: serde_json::Value = response.json().await?;
    if !status.is_success() {
        bail!("health endpoint returned HTTP {status}");
    }
    Ok(value["version"].as_str().unwrap_or("unknown").to_owned())
}

fn config_command(home: &Path, args: ConfigArgs, json: bool) -> anyhow::Result<()> {
    match args.command {
        ConfigCommand::Show => {
            let config = GetterConfig::load(home)?;
            let encoded = config.to_toml()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"config": config}))?
                );
            } else {
                println!("# {}", config_path(home).display());
                print!("{encoded}");
            }
            Ok(())
        }
        ConfigCommand::Path => {
            println!("{}", config_path(home).display());
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            let mut config = GetterConfig::load(home)?;
            set_config_value(&mut config, &key, &value)?;
            config.validate()?;
            write_config(home, &config)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true, "changed": key, "restart_required": true
                    }))?
                );
            } else {
                println!("set {key} = {value}");
                println!("Restart the affected service for runtime settings to take effect.");
            }
            Ok(())
        }
    }
}

fn set_config_value(config: &mut GetterConfig, key: &str, value: &str) -> anyhow::Result<()> {
    let parse_u32 = || {
        value
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("{key} expects an integer"))
    };
    let parse_u64 = || {
        value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{key} expects an integer"))
    };
    let parse_bool = || {
        value
            .parse::<bool>()
            .map_err(|_| anyhow::anyhow!("{key} expects true or false"))
    };
    match config.role {
        Role::Worker => {
            let worker = config.worker.as_mut().context("worker config")?;
            match key {
                "worker.concurrency" => worker.concurrency = parse_u32()?,
                "worker.max_task_memory_bytes" => worker.max_task_memory_bytes = parse_u64()?,
                "worker.max_task_timeout_secs" => worker.max_task_timeout_secs = parse_u64()?,
                "worker.max_output_bytes" => worker.max_output_bytes = parse_u64()?,
                "worker.max_fuel" => worker.max_fuel = parse_u64()?,
                "worker.poll_interval_ms" => worker.poll_interval_ms = parse_u64()?,
                "worker.heartbeat_interval_secs" => worker.heartbeat_interval_secs = parse_u64()?,
                "worker.pause_on_battery" => worker.pause_on_battery = parse_bool()?,
                "worker.control_bind" => {
                    worker.control_bind = value.parse().context("control_bind expects IP:port")?
                }
                "worker.niceness" => {
                    worker.niceness = if value == "none" {
                        None
                    } else {
                        Some(
                            value
                                .parse()
                                .context("niceness expects an integer or none")?,
                        )
                    }
                }
                "worker.max_download_bytes" => worker.max_download_bytes = parse_u64()?,
                "worker.coordinator_url" => worker.coordinator_url = value.to_owned(),
                other => bail!("unsupported worker config key {other:?}"),
            }
        }
        Role::Coordinator => {
            let coordinator = config.coordinator.as_mut().context("coordinator config")?;
            match key {
                "coordinator.bind" => {
                    coordinator.bind = value.parse().context("coordinator.bind expects IP:port")?
                }
                "coordinator.public_url" => coordinator.public_url = value.to_owned(),
                "coordinator.discovery.enabled" => coordinator.discovery.enabled = parse_bool()?,
                "coordinator.discovery.interval_secs" => {
                    coordinator.discovery.interval_secs = parse_u64()?
                }
                "coordinator.limits.heartbeat_timeout_secs" => {
                    coordinator.limits.heartbeat_timeout_secs = parse_u64()?
                }
                "coordinator.limits.max_tasks_per_job" => {
                    coordinator.limits.max_tasks_per_job = value
                        .parse()
                        .context("max_tasks_per_job expects an integer")?
                }
                "coordinator.limits.max_artifact_bytes" => {
                    coordinator.limits.max_artifact_bytes = value
                        .parse()
                        .context("max_artifact_bytes expects an integer")?
                }
                "coordinator.limits.max_total_output_bytes" => {
                    coordinator.limits.max_total_output_bytes = value
                        .parse()
                        .context("max_total_output_bytes expects an integer")?
                }
                "coordinator.limits.allow_trusted_verification" => {
                    coordinator.limits.allow_trusted_verification = parse_bool()?
                }
                other => bail!("unsupported coordinator config key {other:?}"),
            }
        }
    }
    Ok(())
}

fn check_private_file(path: &Path, required: bool) -> anyhow::Result<()> {
    if !path.is_file() {
        if required {
            bail!("missing file {}", path.display());
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is readable by group/other (mode {:o})",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}

async fn uninstall(home: &Path, args: UninstallArgs) -> anyhow::Result<()> {
    if !args.yes {
        bail!(
            "refusing to remove {} without --yes; this deletes configuration, identities, keys, and local job state",
            home.display()
        );
    }
    let canonical =
        std::fs::canonicalize(home).with_context(|| format!("resolve home {}", home.display()))?;
    if canonical.parent().is_none() {
        bail!("refusing to remove filesystem root");
    }
    let config = GetterConfig::load(&canonical)?;
    if config.role == Role::Worker {
        if let Ok(control) = ControlClient::for_config(&canonical, &config) {
            let _ = control.post("/shutdown").await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let config_file = canonical.join("config.toml");
    if !config_file.is_file() {
        bail!("refusing to remove directory without a Getter config file");
    }
    std::fs::remove_dir_all(&canonical)
        .with_context(|| format!("remove Getter home {}", canonical.display()))?;
    println!("Removed Getter local state at {}", canonical.display());
    println!("If you installed Getter as a systemd/launchd service, remove that unit manually:");
    println!("  systemctl --user disable --now getter.service  # Linux");
    println!("  launchctl bootout gui/$(id -u) <label>        # macOS");
    Ok(())
}

fn safe_display(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        let mut shortened = value
            .chars()
            .take(max.saturating_sub(1))
            .collect::<String>();
        shortened.push('…');
        shortened
    }
}
