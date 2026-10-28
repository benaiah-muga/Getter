# Getter documentation

Getter is a local-first distributed computing engine for independently
executable Wasm tasks. A coordinator validates and schedules jobs; enrolled
workers execute tasks inside a capability-free sandbox and enforce their own
resource limits.

> **Status:** alpha, version `0.1.0`. No signed release and no external
> third-party audit. An independent pre-release security review was completed
> and critical/high findings were addressed. See [Limitations](limitations.md),
> [Security](../SECURITY.md), and the [threat model](threat-model.md).

## Start here

| Document | What it covers |
| --- | --- |
| [README](../README.md) | Mission, features, installation, quick start, two-worker example, project layout |
| [Architecture](architecture.md) | Crate boundaries, control/compute planes, scheduling, leases, storage, failure model |
| [Protocol](protocol.md) | HTTP endpoints, worker signatures, state machines, idempotency, status codes |
| [Workloads](workloads.md) | `getter.abi.v1`, `getter_workload!`, job authoring, trusted hashes, limits, validation |
| [Configuration](configuration.md) | Actual TOML fields, defaults, ranges, file locations, `getter config set` keys |
| [CLI reference](cli.md) | Every command and flag from the current `getter --help` output |
| [Local network](local-network.md) | TLS pinning, explicit addresses, firewall, offline operation, systemd, multiple workers |
| [Security](security.md) | Policy, guarantees, explicit caveats, mitigations, non-guarantees |
| [Threat model](threat-model.md) | Detailed trust boundaries, attackers, abuse cases, residual risk |
| [Operations](operations.md) | Deployment, systemd examples, logs, health checks, backups, upgrades, revocation, troubleshooting |
| [Testing](testing.md) | Test commands, CI requirements, local E2E harness, what is verified and what is not |
| [Release process](release.md) | Build, checksums, signing expectations, versioning, release checklist |
| [Limitations](limitations.md) | Honest list of missing or unverified behavior in `0.1.0` |
| [Contributing](../CONTRIBUTING.md) | Toolchain, gates, code and documentation expectations |
| [Security policy](../SECURITY.md) | Private reporting, supported versions, scope |
| [Changelog](../CHANGELOG.md) | Unreleased changes and known limitations |

## Conventions

- Product and binary: **Getter**, `getter`.
- Wire protocol: `getter.protocol/v1`.
- Job file format: `getter.job/v1`.
- Workload ABI: `getter.abi.v1`.
- Default coordinator address: `127.0.0.1:47810`.
- Default worker control address: `127.0.0.1:47811`.
- Optional discovery: UDP `47812`.
- License: Apache-2.0.
- Local state: one `--home` per role/identity, defaulting to `$GETTER_HOME` or
  `~/.getter`.

Commands in these documents were checked against the CLI in this repository.
Statements about physical LAN operation, CI results, release artifacts, and
external audit results are explicitly marked when unverified.
