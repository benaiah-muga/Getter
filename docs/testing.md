# Testing

Getter's tests are ordinary Cargo tests plus a multi-process local harness. This
page records the commands, what they cover, and what is **not** verified.

## Status

- Unit and integration tests live in the Rust crates and the example; their
  coverage is summarized below. This revision does not claim a final test result
  in this environment.
- The command-line interface and configuration are covered by tests and the E2E
  harness.
- `.github/workflows/ci.yml` and `.github/workflows/release.yml` are checked in.
  A green workflow run for the exact commit is the evidence that matters; this
  snapshot does not claim one.
- `scripts/e2e-local.sh` implements the full kill/restart recovery sequence and
  is invoked by the CI `e2e` job. Its recovery phase is still being finalized in
  this delivery, so no passing `GETTER_E2E_PASS` run is claimed here.
- Physical separate-machine LAN operation is **not tested** here.
- An independent pre-release security review was completed and critical/high
  findings were addressed; this is not an external third-party audit report.

## Fast local gates

From the repository root, with the pinned toolchain and locked dependencies:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

Focused runs:

```sh
cargo test -p getter-protocol
cargo test -p getter-core
cargo test -p getter-storage
cargo test -p getter-runtime
cargo test -p getter-coordinator
cargo test -p getter-worker
cargo test -p getter-workload-sdk
cargo test --manifest-path examples/sum-squares/Cargo.toml
```

Useful additions when the tools are installed:

```sh
cargo audit --deny warnings   # if cargo-audit is installed
cargo deny check              # if configured; no deny.toml is checked in
```

## What the tests cover

| Area | Representative coverage |
| --- | --- |
| Protocol | Wire-type round trips, unknown-field rejection, discovery compatibility, HTTP constants |
| Config | Defaults, validation, plaintext-remote refusal, loopback control enforcement, TLS requirements, unknown fields |
| Auth | Ed25519 sign/verify, signature canonicalization, tamper detection, nonce replay/expiry, constant-time comparison, token prefixes |
| Runtime | Capability-free execution, import rejection, missing exports, fuel/wall-clock/memory/output bounds, invalid regions, cancellation, artifact limits |
| Storage | Migrations, schema version, enrollment token single-use/name/expiry, revocation, heartbeats, claims, retries, infrastructure requeues, duplicate results, stale results, lease expiry, cancellation, aggregation |
| Scheduler/states | Local limits override remote requests, paused workers get no tasks, slot accounting, guard transitions, retry ceilings |
| Validation | Manifest limits, duplicate IDs, unsafe names, required trusted hashes, artifact digest/magic, output verification, `json_sum` overflow, previews |
| Coordinator | Router/admin/worker auth, public endpoints, job submission/inspection/cancel, status, contribution, body limits |
| Worker | Client signing/retries, pause/battery flags, state accounting, join/trust failure paths |
| SDK/example | Output packing, allocation, zero-length input, null-pointer guard, exact bytes, checked overflow, reference hashes |
| CLI | Init/pair/join/config/status behavior where covered by crate and integration tests |
| E2E | Separate processes over TLS, two workers, real workload, unauthorized enrollment, pause/kill/restart recovery, CLI verification |

Tests do not prove absence of vulnerabilities, Wasmtime correctness, or behavior
on untested platforms. See [Security](security.md) for the threat model.

## The two-worker manual workflow

The README quick start is the manual two-worker workflow. For a reproducible
run, use separate homes and distinct loopback control ports:

```sh
GETTER=./target/release/getter
$GETTER --home ./.getter-coord init --role coordinator --name home-coordinator --bind 127.0.0.1:47810
$GETTER --home ./.getter-coord coordinator start
```

In other terminals, pair each worker, initialize it, join with the printed token
and CA fingerprint, and start it. Worker 1 uses `47811`; worker 2 uses `47821`.
Then submit the reference job and assert the result:

```sh
$GETTER --home ./.getter-coord jobs submit --file examples/sum-squares/job.json --watch
$GETTER --home ./.getter-coord jobs inspect <job-id> --json
$GETTER --home ./.getter-coord contribute
```

Expected on success: `completed` job, 12/12 tasks `verified`, aggregate
`{"total":"575999928000002000000"}`, and two distinct worker names in task rows.
The checked-in artifact is
`sha256:73bd35d33ba5047a32416f5049905df38ca5e008eef67333ca05a00775aa13e1`.

## Full local harness

```sh
bash scripts/e2e-local.sh
```

Prerequisites: bash, Python 3, and a built binary. The script:

1. Reuses `$GETTER_BIN` if set; otherwise uses `target/release/getter` or builds
   it with `cargo build --locked -p getter-cli --release`.
2. Allocates free loopback ports for the coordinator and two workers and creates
   a temporary root with separate homes.
3. Initializes a TLS coordinator and starts `getter coordinator start`.
4. Uses `getter pair --json` for `e2e-w1` and `e2e-w2`, initializes each worker
   with a distinct control port, writes each token to a `0600` file, and runs
   `getter worker join --token-file ... --ca-fingerprint ...`.
5. Verifies an invalid pairing token is rejected for a rogue home.
6. Starts both workers and waits for two `online` workers.
7. Submits the checked-in `examples/sum-squares/job.json`, waits for completion,
   and asserts 12 completed/verified tasks, zero failures, the expected
   aggregate, and task assignment across two distinct workers.
8. Pauses worker 2, generates a 4-task/80,000,000-value recovery job with
   `--timeout-secs 25 --lease-seconds 30`, waits for worker 1 to show an active
   task, freezes and SIGKILLs worker 1.
9. SIGKILLs the coordinator, restarts it, and checks that the in-flight recovery
   job still exists and is running or completed.
10. Resumes worker 2, waits for lease expiry/retry/completion, and asserts 4/4
    verified tasks, a matching aggregate, at least one task with attempts ≥ 2,
    and all recovery work assigned to worker 2.
11. Runs `workers`, `contribute`, `doctor`, and `status`, checks the killed
    worker is shown offline and contribution statistics are non-zero.
12. Prints `GETTER_E2E_PASS jobs=2 workers=2 retried_tasks=1
    coordinator_restarts=1 verification=exact_sha256` on success.

The script uses loopback TLS only. It does not configure a physical LAN, does
not run a security audit, and does not prove Wasm sandbox correctness. The
recovery phase is still being finalized; treat the script as the intended
harness and record its actual output rather than assuming a pass.

Environment options:

- `GETTER_BIN=/path/to/getter` — reuse a specific build.
- `KEEP_E2E_STATE=1` — retain the temporary homes and logs (the script prints
  the path). Useful for diagnosing a failure.
- `TMPDIR=/path` — choose where the temporary root is created.

The harness is intentionally destructive only inside its temporary directory.
It uses real processes, real TLS, real SQLite, and the real Wasm artifact.

## Example artifact checks

```sh
sha256sum examples/sum-squares/sum_squares.wasm
# 73bd35d33ba5047a32416f5049905df38ca5e008eef67333ca05a00775aa13e1
```

Rebuild and regenerate — do not hand-edit the hash:

```sh
./scripts/build-example.sh
python3 examples/sum-squares/generate_job.py
sha256sum examples/sum-squares/sum_squares.wasm
```

The generator validates WebAssembly 1.0 magic, zero imports, required exports,
the artifact digest, partition coverage, per-task u128 sums computed with the
independent closed-form identity (the guest still iterates), and the aggregate.
Its `--timeout-secs` and `--lease-seconds` options exist for recovery/longer
jobs and must satisfy `lease >= timeout + 5`.

## CI requirements

The checked-in `.github/workflows/ci.yml` has four jobs:

- **quality:** `cargo fmt --all -- --check`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`,
  `cargo test --locked --workspace --all-targets`, example Wasm build,
  independent job generation, and expected aggregate assertion.
- **e2e:** release binary build and `GETTER_BIN=... bash scripts/e2e-local.sh`.
- **dependency-audit:** `cargo audit --deny warnings`.
- **docs:** `node scripts/gates/docs.mjs`.

On a Linux runner the example steps are:

```sh
rustup target add wasm32-unknown-unknown
./scripts/build-example.sh
python3 examples/sum-squares/generate_job.py --out /tmp/getter-example-job.json
cargo test --manifest-path examples/sum-squares/Cargo.toml
```

`cargo audit --deny warnings` is part of the checked-in CI `dependency-audit`
job. `cargo deny` is not configured (`deny.toml` is absent). Run the audit
locally before a release:

```sh
cargo audit --deny warnings
```

The CI `docs` job runs `node scripts/gates/docs.mjs`, which checks required
files (including this repository's `docs/threat-model.md`), the banner hash,
documentation links, and workflow commands. A workflow existing is not a claim
that it passed; link the actual run for the commit being released.

## Not tested or not claimed

- Physical LAN firewalling, Wi-Fi, subnets, VPNs, NAT, and multiple physical
  machines.
- macOS and Windows runtime behavior, permissions, battery policy, and service
  management.
- Long-running soak tests, memory-leak profiling, and database growth under
  sustained production load.
- Fuzzing, Miri, property-based testing, formal verification, or adversarial
  testing of Wasmtime itself.
- Bandwidth shaping, idle-user detection, and large worker fleets.
- Upgrade/downgrade compatibility beyond the forward-only migration tests.
- External third-party audit report, penetration test, or signed-release
  verification. (The independent pre-release review is not an external audit.)
- Online CA rotation, backup/restore automation, and disaster recovery drills.
