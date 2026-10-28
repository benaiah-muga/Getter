# Limitations

Getter `0.1.0` is alpha software. This page is the canonical list of things it
does not do, does only partially, or has not verified. If another document seems
to promise otherwise, this page and [Security](security.md) win.

## Release and assurance status

- **No signed release exists.** There are no published binaries, checksums,
  signatures, SBOMs, or crates.io packages for `0.1.0`. Build from source.
- **No external third-party audit.** An independent pre-release security review
  was completed and critical/high findings were addressed, but there is no
  external audit report, certification, penetration-test report, or bug-bounty
  coverage.
- **No CI run result is claimed.** `.github/workflows/ci.yml` and
  `.github/workflows/release.yml` are checked in, but this snapshot does not
  claim that a particular CI run passed or that a release workflow ran. A local
  `cargo audit` reports zero known vulnerabilities and one unmaintained-crate
  warning (`rustls-pemfile`); CI treats actual vulnerabilities as blocking.
- **No physical-LAN verification.** The LAN procedure is documented but has not
  been verified on separate physical machines in this environment.
- **The kill/restart E2E harness has only been verified on the development
  host.** `scripts/e2e-local.sh` automates the flow and passed locally, but no
  GitHub Actions run is claimed for this snapshot and physical-LAN failure
  recovery is not verified. See [Testing](testing.md).
- The project is developed primarily on Linux. macOS and Windows
  builds are not verified. Unix permission checks and battery pausing are
  platform-specific.

## Execution semantics

- **At least once, not exactly once.** A task can run again after a crash,
  timeout, pause, cancellation, network failure, or coordinator restart. A
  workload with side effects outside its returned bytes must be idempotent or
  accept duplicates.
- **No coordinator high availability.** One coordinator owns one SQLite
  database. There is no replication, failover, or multi-writer mode. Corrupt or
  lost local state can lose jobs.
- **No federation and no P2P.** Workers do not talk to each other. Artifacts come
  from the coordinator under a lease. The lease-authorized endpoint is an
  extension point, not a peer protocol.
- **No job-level retry.** A failed or cancelled job is terminal. You can submit
  it again as a new job.
- **No exactly-once result side effects.** Result acceptance is idempotent for
  the same completed output, but workload-side effects can repeat.
- **No resource reservation.** The scheduler considers currently active slots
  and advertised capabilities. It does not reserve memory/CPU across assignments
  or guarantee that a queued job can ever be scheduled.
- **No preemption by priority.** There is no priority queue or fair share beyond
  queue order and eligibility. Admin cancellation is the only preemption.
- **No lease extension.** Jobs must declare `lease_seconds` at least five seconds
  longer than any task timeout. Workers stop before lease expiry.

## Security and verification

- **Wasm sandboxing is not a proof.** It is defense in depth against untrusted
  guest code, subject to Wasmtime and host correctness. Keep the worker current.
- **Checksums are not general computation honesty.** `exact_sha256` validates
  against a job author's reference digest. It cannot detect a bad reference, and
  there is no independent replication or fraud proof. `trusted` mode is
  explicitly unverified.
- **Compilation of a newly seen module is outside fuel and guest timeout
  bounds.** The worker compiles a new module before starting the guest deadline
  (compiled modules may be cached per process). A large or complex module can
  consume worker CPU within the module-size and concurrency limits.
- **Replay protection is process-local.** The per-worker replay/rate guard
  resets on coordinator restart. The signed-request clock window is ±90 seconds;
  the current guard allows 76,800 requests per 60 seconds per worker, 262,144
  nonces per worker, and up to 100,000 tracked workers, but those limits are not
  configurable.
- **No TLS client certificates.** Worker identity is an application-level
  Ed25519 signature. The private key is a bearer credential on the worker host.
- **The loopback control API uses a bearer token, not server authentication.**
  Any process running as the same OS user can read the control token and
  pause/resume/stop the worker. Loopback prevents LAN access, not same-user
  access.
- **SQLite work is synchronous under one process mutex.** Requests that touch
  the store serialize; a slow disk or a burst of shared-state operations can
  increase latency and reduce concurrency.
- **Per-task memory limits aggregate across concurrency.** A worker with
  concurrency N and a per-task ceiling M can commit roughly N×M of guest linear
  memory plus host overhead. There is no worker-wide memory admission or cgroup
  limit.
- **Enrollment and claim responses are not idempotent at the transport layer.**
  A lost enrollment response consumes the pairing token and requires operator
  recovery; a lost assignment response leaves the lease active until expiry,
  delaying task recovery.
- **No at-rest encryption.** SQLite stores job inputs, outputs, and metadata in
  plaintext. File permissions protect the home from other local users, not from
  root or a compromised host.
- **No remote attestation.** The coordinator cannot cryptographically prove what
  binary or hardware a worker is running.
- **No per-job worker authorization.** Any enrolled, active worker that fits the
  requirements can claim a queued task.
- **No admin/public rate limiting.** A per-worker signed-request guard throttles
  worker traffic (76,800 requests per 60 s, 262,144 nonces per worker) and bounds
  replay state, but unauthenticated admin/public attempts and connection floods
  are not rate-limited. `429`/`503` from this guard are transient, not
  deauthorization.
- **No online CA rotation or key-management tooling.** Replacing the CA means
  reinitializing and re-enrolling workers; treat it as a planned outage. A CA
  trust file must contain exactly one certificate; multi-cert bundles are
  rejected.
- **No audit log or tamper-evident event log.** `tracing` output goes to stderr
  and whatever captures it. Logs are not signed or write-once.
- **No secret scanning or dependency-deny policy in CI.** CI runs
  `cargo audit`; `cargo-deny`/`deny.toml` is not configured, and secret scanning
  is not configured.
- **No confidentiality from the coordinator or assigned worker.** They see inputs
  and outputs by design.
- **Discovery is unauthenticated.** It is informational and grants no trust. An
  attacker can announce a fake coordinator; pairing and fingerprint verification
  are still required.
- **Not hardened for hostile multi-tenant admin use.** The admin token is
  all-powerful. Treat operators and the coordinator host as trusted.

## Platform and resource controls

- **Battery pausing is Linux-only.** It reads
  `/sys/class/power_supply/*/{type,status}` and checks every 30 seconds when
  available. Linux systems without readable battery entries report unsupported.
  Other platforms never battery-pause.
- **Idle-user detection is not implemented.** A worker does not pause because a
  user is active.
- **No bandwidth shaping.** `max_download_bytes` and the artifact limit cap
  download size; they do not limit throughput or network utilization.
- **Niceness is best-effort.** On Unix the worker calls `setpriority` at startup
  with the configured nice value (default 10); failure is logged and does not
  stop the worker. Windows has no equivalent here.
- **No CPU affinity, cgroups, or hard memory quota.** Memory is a Wasm linear
  memory limit, not an OS-level RSS guarantee. Compilation and host overhead are
  outside the per-task memory limit.
- **No GPU, accelerator, or native binary support.** Only `wasm32` guest code
  implementing `getter.abi.v1`.
- **No WASI or host imports.** This is intentional: the sandbox has zero
  imports. Workloads needing files, clocks, randomness, or network must obtain
  them through input bytes and return everything else as output. (Randomness and
  wall-clock time are not provided by the host.)
- **No `getter_free`.** The SDK leaks input/output allocations; hosts use a fresh
  instance per task or discard the instance after reading output.
- **Output limit is 1 MiB per task** and the default aggregate declared-output
  ceiling is 64 MiB per job. A job can't raise a worker's local limits.
- **Artifact ceiling is 16 MiB** in the protocol/runtime. The coordinator config
  cannot raise it above that in `0.1.0`.
- **No streaming results.** Results are submitted after execution completes; a
  long task holds a slot and lease for its duration.
- **No task progress or partial output.** Only terminal success/failure is
  reported.

## Networking and operations

- **Loopback quick start is the intended primary topology.** LAN operation is a
  documented, unverified-on-physical-hardware procedure.
- **TLS is required by default for remote binds.** Plaintext remote operation
  needs an explicit `allow_insecure_remote = true` config edit and is only for an
  isolated lab.
- **The public URL must be reachable.** `pair` and admin CLI commands use
  `coordinator.public_url`; a wrong address or NAT makes them fail even if the
  process is listening.
- **The TLS certificate has no automatic renewal.** It is generated locally at
  `init`; there is no ACME or rotation daemon.
- **No service-manager integration.** `getter uninstall` removes local state but
  does not disable or remove systemd/launchd units. Unit examples are documented,
  not installed.
- **No built-in log rotation, metrics endpoint, or tracing export.** Use
  stderr capture, systemd/journald, or your own collector; do not expose
  `RUST_LOG=trace` in production.
- **No database compaction or retention policy.** Long-running coordinators
  accumulate artifacts/jobs until you manage the home directory; there is no
  garbage collection command.
- **No coordinator authentication of job submitters beyond one admin token.**
  Multi-user role separation is not implemented.
- **No remote worker administration.** Worker lifecycle commands use the local
  loopback control API. There is no admin endpoint to pause a remote worker.
- **No Unicode normalization guarantees for names.** Names are validated for
  length/control characters, not normalized; use ASCII names for portability.
- **The quick start uses TLS on loopback.** Browsers and tools may warn about a
  private CA; use the CLI or `--cacert` rather than disabling verification.

## Compatibility

- Wire format `getter.protocol/v1`, job format `getter.job/v1`, and ABI
  `getter.abi.v1` are fixed identifiers. Breaking changes require a new
  identifier; do not assume undocumented fields will be ignored (unknown fields
  are rejected).
- Rust `1.97.0` and the checked-in `Cargo.lock` are the supported build inputs.
  Dependency updates can change Wasmtime behavior; read release notes.
- The checked-in Wasm artifact is not promised bit-for-bit reproducible across
  arbitrary toolchains, linkers, or profiles. Regenerate `job.json` if a rebuild
  changes its SHA-256.
- SQLite migrations are forward-only. Downgrading a binary may leave a schema it
  cannot read. Back up before upgrades.

## Future work

See the "Future work" section of [Security](security.md). These are directions,
not commitments: durable replay protection, compile-time limits, independent
result replication, remote attestation, rate limits, per-job authorization,
client certificates, CA rotation, at-rest encryption, release-key signing, and
an external third-party audit.
