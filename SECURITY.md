# Security Policy

Getter is alpha software (`0.1.0`). An independent pre-release security review of
the authentication, sandbox, lease, replay, and resource enforcement design was
completed; critical/high findings were addressed. This is not an external
third-party audit, and no audit report or certification is claimed. See the
[threat model](docs/threat-model.md) for the detailed analysis.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public issue
with exploit details, secrets, or a working proof of concept.

Preferred channel:

<https://github.com/benaiah-muga/Getter/security/advisories/new>

If GitHub private vulnerability reporting is unavailable, contact a maintainer
through their GitHub profile to arrange a private channel before sending
details.

Please include, where possible:

- affected version or commit (`getter --version`, plus the commit if known);
- the component (coordinator, worker, runtime, CLI, storage, protocol, SDK, or
  example);
- configuration and deployment shape (loopback, LAN, TLS on/off, number of
  workers);
- impact and prerequisites;
- reproduction steps or a minimal proof of concept;
- whether the issue is already public and any disclosure deadline.

We aim to acknowledge reports within five business days, agree on a remediation
and disclosure plan, and publish coordinated details after a fix is available.
These are targets for a volunteer project, not a contractual SLA. Please give us
a reasonable opportunity to fix the issue before public disclosure; 90 days is a
practical default for non-actively-exploited issues.

There is no bug bounty program.

## Supported versions

| Version | Support |
| --- | --- |
| `0.1.x` (alpha, unreleased) | Best-effort fixes on the current development line |
| Older snapshots and forks | Not supported |

No signed release or long-term-support branch exists yet. Security fixes land on
the main development line; backports will be announced if a supported release
ever branches. Check the repository releases and
[CHANGELOG](CHANGELOG.md) for status.

## Scope

In scope:

- authentication or authorization bypass in the admin, enrollment, worker, or
  local control APIs;
- sandbox escape, host capability access, or incorrect enforcement of memory,
  fuel, wall-clock, output, input, or module limits;
- TLS certificate-validation or CA-pinning bypass in `pair`, `join`, CLI
  clients, or the worker;
- replay, forgery, or cross-worker use of worker signatures, pairing tokens, or
  lease tokens;
- path traversal, symlink attacks, unsafe file permissions, or secret disclosure
  in local state handling;
- denial of service that bypasses documented limits using unauthenticated or
  low-privilege input;
- integrity failures in artifact/input/output handling or aggregation;
- supply-chain issues in this repository's direct dependencies that are
  reachable through Getter's use of them;
- vulnerabilities in the workload SDK or example that could break the documented
  host/guest contract.

Out of scope or by design:

- an operator or administrator with the admin token submitting arbitrary Wasm,
  reading coordinator state, or exhausting resources within configured limits;
- a compromised coordinator host, root access, physical access, or a malicious
  local OS user who can read that user's `0600` secrets;
- a worker seeing the inputs and outputs of tasks assigned to it (it must, in
  order to compute them);
- denial of service by someone who already holds the admin token or can kill the
  process;
- the absence of exactly-once execution, general Byzantine-result honesty,
  bandwidth shaping, idle-user detection, P2P transfer, coordinator high
  availability, or federation (see [Limitations](docs/limitations.md));
- social engineering and third-party services;
- upstream vulnerabilities that Getter does not expose or misuse; report those
  upstream as well.

## Security model in brief

Getter separates the control plane from the compute plane:

- The **coordinator** is trusted. It validates jobs, stores SQLite state, issues
  leases, verifies outputs against trusted reference hashes, aggregates results,
  and authenticates workers and administrators.
- An **administrator** is trusted. The admin bearer token protects job
  submission, pairing-token creation, inspection, cancellation, status, and
  contribution endpoints. The token is stored under `<home>/secrets/admin-token`
  with mode `0600` and is never printed by the CLI.
- A **worker** is semi-trusted. It is enrolled with a one-time pairing token,
  proves possession of an Ed25519 key on every coordinator request, and enforces
  its own resource ceilings. It runs untrusted Wasm and reports results.
- A **workload** is untrusted guest code. `getter.abi.v1` permits no imports, no
  WASI, no filesystem, no network, no environment, and no arguments. The host
  only copies input bytes into guest memory and bounded output bytes back.
- A **task output** is accepted only after the coordinator recomputes its SHA-256
  and checks the job's verification policy. Worker-declared hashes are not
  trusted for acceptance. `trusted` verification mode is an explicit,
  coordinator-opt-in development escape hatch and marks results unverified.

Transport security is TLS with a locally generated CA. Workers pin either the CA
certificate or its SHA-256 fingerprint. Worker API requests are additionally
signed. TLS provides server authentication; workers do **not** present client
certificates, so worker identity is established at the application layer.

## Explicit limitations and non-guarantees

These are security-relevant and must not be papered over:

1. **Wasm sandboxing is not a proof.** Wasmtime is a large, memory-unsafe
   codebase. Getter configures a capability-free store with limits, but a
   Wasmtime bug, a CPU errata, or an embedding mistake could break isolation.
   The sandbox is defense in depth. Keep the worker build and Wasmtime current.
2. **Checksums are integrity and reference correctness, not general computation
   honesty.** `exact_sha256` proves that a task's bytes match the digest supplied
   in the job manifest. If the job author supplies a wrong or malicious digest,
   the check validates the wrong result. There is no independent replication,
   fraud proof, or remote attestation. `trusted` mode makes no correctness claim
   at all.
3. **Compilation of a newly seen module is outside fuel and guest timeout
   bounds.** The worker compiles and validates a module before starting the guest
   wall-clock deadline; compiled modules may be cached per process. A large or
   pathological new module can consume worker CPU within the module-size and
   concurrency limits. Do not treat fuel or the guest timeout as a bound on
   total worker CPU for the first execution of an artifact.
4. **Replay protection is process-local.** Signed worker requests are checked
   against an in-memory, per-worker replay guard with a 180-second nonce TTL and
   a 90-second clock window. The guard also applies a per-worker request-rate
   ceiling and bounded capacity, but it resets on coordinator restart. A captured
   signed request could be replayed within the clock window if the attacker can
   also reach the coordinator and the request is still useful.
5. **LAN discovery is unauthenticated.** Discovery datagrams carry no secret and
   grant no authority. Anyone on the LAN can announce a coordinator name, URL,
   and fingerprint. `getter discover` is informational; it never auto-enrolls a
   worker. Always verify the coordinator address and CA fingerprint through a
   separate trusted channel.
6. **Physical-LAN deployment is untested here.** The LAN procedure is documented
   but has not been verified on separate physical machines in this environment.
   Treat it as an unverified procedure, test in your own isolated lab, and use
   the fingerprint check.
7. **No external audit report exists.** The independent pre-release review found
   and addressed critical/high issues, but it is not a substitute for an external
   third-party audit or certification.
8. **No TLS client certificates.** Possession of a worker's private key is the
   worker identity. Protect `<home>/worker/identity.json` and all `0600` files.
9. **Local state is not encrypted at rest.** SQLite contains job manifests,
   inputs, outputs, hashes, and worker metadata. Protect the home directory and
   backups accordingly.
10. **No admin/public rate limiting and no per-job worker ACL.** A per-worker
    signed-request guard throttles and bounds replay state, but unauthenticated
    admin attempts, public enrollment attempts, and connection floods are not
    rate-limited. Any enrolled worker can claim eligible queued tasks. Put the
    service behind a firewall and monitor it.
11. **The loopback bearer token is not server authentication.** Any process
    running as the same OS user can read the worker control token and stop or
    pause that worker. Loopback binding prevents LAN access, not local
    same-user access.
12. **Enrollment and claim responses are not idempotent at the transport
    layer.** If the coordinator commits an enrollment but the response is lost,
    the one-time token is consumed and a retry is rejected; if a claim response
    is lost, the lease remains active until expiry and the task is requeued.
    Operators must recover by issuing a new pairing token or waiting for lease
    expiry.
13. **SQLite work is synchronous behind one process mutex, and per-task memory
    limits do not cap the sum across concurrent tasks.** A worker with
    concurrency N may commit up to N times its per-task memory ceiling plus host
    overhead; the coordinator serializes database writes.

## Hardening guidance

- Keep TLS enabled. Never set `allow_insecure_remote = true` outside an isolated
  lab network. A CA trust file must contain exactly one certificate; multi-cert
  bundles are rejected rather than silently trusting the first certificate.
- Restrict the coordinator TCP port to intended worker/admin networks. Keep
  admin operations on loopback or a trusted management network where possible.
- Verify the CA fingerprint printed by `getter pair` out of band; do not trust a
  fingerprint obtained only from unauthenticated discovery.
- Prefer `--token-file` over `--token` so pairing tokens do not enter shell
  history or process listings. Delete the file after enrollment. The public
  enrollment endpoint is independently capped at 64 KiB of JSON.
- Treat `401`/`403` as authentication failures and `429`/`503` as transient
  throttling/capacity; do not de-authorize a worker for the latter.
- Keep homes, configs, identities, tokens, TLS keys, and database backups at
  `0700`/`0600`. On Unix, Getter creates and checks these permissions, but it
  cannot protect them from the same user or root.
- Use NTP or another trusted clock source. Worker signatures allow only ±90
  seconds of clock skew.
- Run the worker as a dedicated, unprivileged user. Its niceness and battery
  policy do not require root.
- Bound worker concurrency and per-task memory/output/fuel/timeout below host
  capacity; leave headroom for compilation and the OS.
- Treat workload source as code you are choosing to execute inside the sandbox.
  Supply-chain review of a workload is still your responsibility.
- Back up coordinator state before upgrades; migrations are forward-only.
- Watch upstream Wasmtime and Rust security advisories and rebuild promptly.

## Future work

The following are planned directions, not current guarantees:

- durable/distributed replay protection;
- compile-time limits or precompilation with bounded resources;
- independent output replication or randomized re-execution for stronger result
  honesty;
- remote attestation or signed worker measurements;
- configurable rate limits and per-job authorization;
- TLS client certificates or attested worker channels;
- online CA rotation and key-management tooling;
- at-rest encryption options for local state;
- an independent third-party audit and a signed release process.

See [the threat model](docs/threat-model.md),
[security overview](docs/security.md), [limitations](docs/limitations.md), and
[local network deployment](docs/local-network.md) for details.
