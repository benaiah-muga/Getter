# Changelog

All notable changes to Getter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
after 1.0. Before 1.0, minor releases may make incompatible changes; protocol,
job-format, and workload-ABI version identifiers are versioned separately.

## [Unreleased]

### Added

- Coordinator service with authenticated HTTP(S) APIs, SQLite persistence,
  leased task scheduling, lease expiry recovery, cancellation, and optional UDP
  discovery.
- Worker service with outbound-only coordinator communication, a loopback-only
  bearer-token control API, signed requests using Ed25519 identity keys,
  configurable niceness, battery-discharge pausing on Linux, and per-worker
  resource ceilings.
- Capability-free Wasmtime 43 execution sandbox with fuel metering, wall-clock
  cancellation, memory/table/instance limits, output bounds, module size limits,
  and a strict no-imports rule.
- `getter.abi.v1` workload ABI, authoring SDK (`getter-workload-sdk`), the
  `getter_workload!` macro, and the deterministic `sum-squares` reference
  workload.
- Trusted per-task SHA-256 verification, deterministic `json_sum` aggregation,
  optional expected-aggregate comparison, and at-least-once retry/lease
  semantics with duplicate-result acknowledgement.
- Persistent cancellation notifications and explicit infrastructure requeues, so
  local pause/shutdown/no-capacity interruptions do not consume a workload
  attempt (bounded to 32 abandoned leases per task).
- `getter` CLI covering initialization, pairing, coordinator and worker
  lifecycle, local status, job submission and inspection, contribution
  statistics, diagnostics, configuration editing, discovery, and uninstall.
- TLS enabled by default with a locally generated CA, CA-fingerprint pinning for
  workers, loopback-only worker control, one-time expiring pairing tokens, and
  owner-only local state on Unix.
- `sum-squares` example with 12 tasks over 12,000,000 values, checked-in Wasm
  artifact (`sha256:73bd35d33ba5047a32416f5049905df38ca5e008eef67333ca05a00775aa13e1`),
  trusted per-task hashes, and expected aggregate
  `575999928000002000000`.
- Architecture, protocol, workload, configuration, local-network, security,
  operations, CLI, testing, release, and limitations documentation.

### Security

- Administrative API bearer authentication with constant-time comparison.
- Ed25519 request signatures bound to worker ID, method, path and query,
  timestamp, nonce, and body digest.
- TLS server authentication with a pinned local CA; plaintext remote
  coordinator bindings and URLs are refused unless explicitly overridden for
  isolated development.
- One-time, name-scoped pairing tokens with hashed storage and bounded TTLs.
- Short-lived lease tokens hashed at rest; lease authorization for artifact
  retrieval.
- Per-worker replay guard with a bounded request-rate ceiling and a bounded
  nonce cache (process-local).
- Bounded HTTP bodies, job counts, inputs, outputs, artifact sizes, and isolated
  loopback worker control.

### Known limitations

- The project is alpha software. No signed release or published binary exists
  yet. An independent pre-release security review completed and critical/high
  findings were addressed, but no external third-party audit report is claimed.
- Execution is at least once, not exactly once; workloads with external side
  effects must tolerate re-execution.
- Wasm sandboxing is defense in depth, not a formal proof.
- Checksums provide integrity and reference correctness, not general
  computation honesty.
- Compilation of a newly seen Wasm module is outside fuel and guest wall-clock
  bounds; compiled modules may be cached per worker process.
- The worker-request replay/rate guard is process-local and resets on coordinator
  restart.
- LAN discovery is unauthenticated and grants no trust.
- Battery pausing is Linux-only; idle-user detection and bandwidth shaping are
  not implemented.
- CI and the multi-process kill/restart E2E workflow exist, but no run result is
  claimed in this snapshot; see [Testing](docs/testing.md).
- Physical separate-machine LAN deployment is a documented procedure that has
  not been verified on physical hardware in this environment.

[Unreleased]: https://github.com/benaiah-muga/Getter/commits/main
