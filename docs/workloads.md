# Workloads and jobs

Getter executes deterministic WebAssembly modules that implement
`getter.abi.v1`. A module is guest code with **no imports**: no WASI, no
filesystem, no network, no environment, no arguments, and no host functions.
The host supplies raw input bytes and reads a bounded output byte range.

## The ABI in one page

A workload is a Rust `cdylib` compiled for `wasm32-unknown-unknown`.

| Requirement | Value |
| --- | --- |
| ABI identifier | `getter.abi.v1` |
| Required exports | `memory`, `getter_alloc(u32) -> u32`, `getter_execute(u32, u32) -> u64` |
| Imports | **None** |
| Input | Raw bytes; the host calls `getter_alloc(len)`, writes exactly `len` bytes, then calls `getter_execute(ptr, len)` |
| Output | `u64` packing `(output_pointer as u64) << 32 | output_length` |
| Deallocation | None; the guest leaks input/output. The host uses a fresh instance per task or discards the instance |
| Empty input | Valid; `len == 0` |
| Empty output | Valid; length zero means the host reads nothing, regardless of pointer |
| Panic/trap | Recorded as a failed attempt |

The guest must not retain or mutate the input slice after
`getter_execute` returns. The host must allocate input through `getter_alloc`,
write only within the requested length, and not call `getter_execute` concurrently
on the same instance. Getter's worker follows those rules and executes one task
per instance.

```text
getter_alloc(len) ──► pointer
host writes len bytes at pointer
getter_execute(pointer, len) ──► (output_ptr << 32) | output_len
host reads output_len bytes at output_ptr (bounded by the task output limit)
drop instance
```

## Authoring with the SDK

Create a standalone guest crate:

```toml
[package]
name = "my-workload"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
getter-workload-sdk = { path = "../../crates/getter-workload-sdk" }

[workspace]
```

`[workspace]` keeps the guest out of the engine workspace. Replace the path with
a published package if one exists in the future; this repository does not
publish crates in `0.1.0`.

```rust
use getter_workload_sdk::getter_workload;

fn handler(input: &[u8]) -> Vec<u8> {
    format!("saw {} bytes", input.len()).into_bytes()
}

getter_workload!(handler);
```

The macro exports two functions around a free function with the exact type
`fn(&[u8]) -> Vec<u8>`; the module also exports its linear memory:

- `getter_alloc(u32) -> u32` allocates a writable input buffer and returns its
  Wasm32 address. It allocates at least one byte even for length zero so the
  pointer is non-null. The allocation is intentionally leaked.
- `getter_execute(u32, u32) -> u64` reconstructs the input slice, calls the
  handler, leaks the output `Vec`, and packs the output pointer/length.
- `memory` is the module's exported linear memory (the ABI requires the export).

The handler must be visible in the same module as the macro invocation. It must
not retain the input slice after returning. Returning a `Vec<u8>` is expected;
the Rust standard library's allocation/formatting code is compiled into the
guest and does not create host imports.

### Safety contract

The ABI boundary is raw FFI and cannot be checked by Rust across the host/guest
boundary. The SDK contains the only required `unsafe` code:

- `getter_alloc` leaks a writable allocation.
- `getter_execute` reconstructs a slice from a host-supplied pointer/length and
  leaks the output.
- A null pointer with a non-zero length panics before any dereference.

Every `unsafe` block has a `SAFETY:` comment. Workload authors should use the
SDK rather than hand-writing exports unless they fully understand the contract.
The host is responsible for the pointer/length it passes; a malicious/buggy host
can cause undefined guest behavior, but the host is trusted in Getter's model.

## Build the artifact

From the repository root:

```sh
./scripts/build-example.sh
```

The script runs from the repository root so the pinned toolchain applies, uses a
stable workspace-local target directory, requires the
`wasm32-unknown-unknown` target, copies the release artifact to
`examples/sum-squares/sum_squares.wasm`, and prints its SHA-256. It inherits
`CARGO_HOME` and does not hardcode one.

Equivalent direct build:

```sh
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/sum-squares/Cargo.toml \
  --target wasm32-unknown-unknown --release
```

The repository artifact is 23,828 bytes:

```text
sha256 73bd35d33ba5047a32416f5049905df38ca5e008eef67333ca05a00775aa13e1
```

A rebuild may change the bytes across toolchain/linker/profile changes. If the
hash changes, regenerate the job; do not edit hashes by hand.

## The job file (`getter.job/v1`)

A job file is JSON with `deny_unknown_fields`. The checked-in example:

```json
{
  "protocol": "getter.job/v1",
  "name": "sum-of-squares",
  "description": "Partitioned sum of squares over [0, 12000000).",
  "workload": {
    "name": "sum-of-squares",
    "abi": "getter.abi.v1",
    "sha256": "73bd35d33ba5047a32416f5049905df38ca5e008eef67333ca05a00775aa13e1",
    "artifact": "sum_squares.wasm"
  },
  "tasks": [
    {
      "id": "task-000",
      "input": "0:1000000",
      "expected_output_sha256": "0a1e85ea7627d4b4176620760ab048abca42cccb58ed22593b9eac8b4ef1b851"
    }
  ],
  "requirements": {
    "cpu_slots": 1,
    "memory_bytes": 67108864,
    "timeout_secs": 10,
    "output_bytes": 1048576,
    "fuel": 5000000000
  },
  "verification": { "mode": "exact_sha256" },
  "aggregation": { "mode": "json_sum", "field": "value" },
  "expected_aggregate": { "total": "575999928000002000000" },
  "max_attempts": 3,
  "lease_seconds": 20
}
```

The real file has 12 tasks.

### Fields

| Field | Meaning |
| --- | --- |
| `protocol` | Must be `getter.job/v1` |
| `name` | Non-empty job name, at most 128 bytes, no control characters |
| `description` | Optional, at most 2,048 bytes |
| `workload.name` | Display/workload name, at most 128 bytes |
| `workload.abi` | Must be `getter.abi.v1` |
| `workload.sha256` | Lowercase/uppercase accepted, normalized to lowercase; 64 hex chars; must match the uploaded artifact |
| `workload.artifact` | **CLI-only** path to the `.wasm`, relative to the job file (or absolute). Removed before the manifest is sent to the coordinator |
| `tasks` | 1–1,000 tasks, unique IDs (ASCII letters/digits/`-_.:`), max 128 bytes each |
| `tasks[].input` | Opaque UTF-8 string, passed to the ABI as its UTF-8 bytes; max 1 MiB per task |
| `tasks[].requirements` | Optional full override of the job-level requirements; fields are not merged |
| `tasks[].expected_output_sha256` | Required for `exact_sha256`; optional for `trusted`; normalized lower-case |
| `requirements` | `cpu_slots`, `memory_bytes`, `timeout_secs`, `output_bytes`, `fuel`; defaults shown below |
| `verification.mode` | `exact_sha256` (default in examples) or `trusted` |
| `aggregation.mode` | `none` or `json_sum` with `field` |
| `expected_aggregate` | Optional exact JSON value; at most 64 KiB encoded |
| `max_attempts` | 1–10; default 3 |
| `lease_seconds` | 10–3,600; default 90; must be at least every task timeout + 5 s |

The `requirements` object itself is required at the job level; individual
fields inside it are defaulted when omitted. Defaults:

| Field | Default |
| --- | --- |
| `cpu_slots` | 1 |
| `memory_bytes` | 128 MiB |
| `timeout_secs` | 60 |
| `output_bytes` | 1 MiB |
| `fuel` | 5,000,000,000 |

The job-level requirements are validated, then each task's optional
`requirements` object is validated as a complete replacement. If a per-task
override omits a field, that field takes the `TaskRequirements` default, not the
job-level value. The scheduler
compares requirements with worker capabilities; the worker intersects them with
its configured maxima and rejects anything larger. A remote job cannot raise a
worker's limits.

## Verification policy

### `exact_sha256`

Every task must have `expected_output_sha256`. On result submission the
coordinator:

1. rejects output larger than the task's `output_bytes`;
2. computes SHA-256 over the exact received bytes;
3. compares it to the normalized trusted value;
4. marks the task `verified` on a match, or rejects the result as a failure on a
   mismatch.

The worker's declared `output_sha256` is checked against the received bytes by
the API, but acceptance uses the coordinator's own digest. A failed verification
is retryable under the task's `max_attempts`; after exhaustion the task fails.
Infrastructure requeues (pause, shutdown, local cancellation, unavailable CPU,
download failure, or insufficient lease time) do **not** consume a workload
attempt; they are separately bounded to 32 abandoned leases per task.

### `trusted`

`trusted` accepts output without a required reference hash and marks it
`unverified`. The coordinator must explicitly opt in:

```sh
getter --home ~/.getter config set coordinator.limits.allow_trusted_verification true
# restart the coordinator
```

Without that opt-in, an `exact_sha256` job with a missing hash or a `trusted` job
is rejected at submission. `trusted` is a development escape hatch, not a
correctness claim. If a task in `trusted` mode has a hash, an optional checksum is
still enforced.

### Aggregation

- `none`: the job result contains task keys, SHA-256 digests, and base64 output
  bytes. Useful when output is not numeric.
- `json_sum`: each output must be a JSON object with the configured `field`;
  the value must be an unsigned integer (JSON number fitting `u64`) or an
  unsigned decimal string fitting `u128`. Summing uses checked `u128` and fails
  on overflow. The result is `{"total":"<decimal>"}`.

`expected_aggregate`, if present, is compared exactly to the computed aggregate.
A mismatch fails the job with `aggregate result did not match
expected_aggregate`, even if every task completed.

## Generate the reference job

From the repository root:

```sh
python3 examples/sum-squares/generate_job.py
```

This writes `examples/sum-squares/job.json` with 12 deterministic partitions
covering `[0, 12000000)`, a trusted SHA-256 per task, the artifact digest, the
artifact path relative to the job file, and the expected total
`575999928000002000000`.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--tasks N` | 12 | Number of contiguous partitions |
| `--values N` | 12000000 | Process `[0, N)` |
| `--artifact PATH` | `<example>/sum_squares.wasm` | Wasm artifact to validate/hash |
| `--out PATH` | `<example>/job.json` | Output job path |
| `--expected-sha256 HEX` | none | Fail unless the artifact has this digest |
| `--timeout-secs N` | 10 | Per-task timeout |
| `--lease-seconds N` | 20 | Task lease; must be at least timeout + 5 |

The generator uses the independent closed-form identity
`sum(i² for i in [start,end))` for trusted totals, while the Rust guest still
iterates over every value. Both methods must produce the same canonical bytes;
the checked-in hashes are unchanged by this optimization. The generator also
partitions deterministically, checks per-task and aggregate `u128` overflow,
validates Wasm 1.0 magic, zero imports, and required exports, hashes the
artifact, and rejects `--expected-sha256` mismatches. When the artifact changes,
regenerate the job.

The recovery E2E harness generates a longer job directly into a temporary
directory, for example:

```sh
python3 examples/sum-squares/generate_job.py --tasks 4 --values 80000000 \
  --timeout-secs 25 --lease-seconds 30 \
  --artifact examples/sum-squares/sum_squares.wasm \
  --out /tmp/recovery-job.json
```

## The sum-squares reference workload

`examples/sum-squares/src/lib.rs` parses `start:end` (end exclusive, `u128`),
walks the range one integer at a time, accumulates checked squares, and returns
exactly:

```text
{"value":"<decimal>"}
```

No whitespace and no trailing newline. For `10:12` the output is exactly
`{"value":"221"}`. The checked `u128` arithmetic means a range whose mathematical
sum would overflow traps instead of wrapping. The default range is far below
that limit.

Host-mode tests exercise parsing, the iterative sum, checked overflow, and exact
output bytes:

```sh
cargo test --manifest-path examples/sum-squares/Cargo.toml
```

They do not execute the Wasm artifact; the E2E harness and a real worker do.

## Job authoring checklist

- [ ] The artifact is a WebAssembly 1.0 module with `memory`, `getter_alloc`, and
      `getter_execute`, and **zero imports**.
- [ ] `workload.abi` is exactly `getter.abi.v1`.
- [ ] `workload.sha256` matches the artifact; `workload.artifact` is the correct
      path relative to the job file.
- [ ] Partitions are contiguous, non-overlapping, and cover the intended input.
- [ ] Trusted output hashes are computed over the exact bytes the guest returns.
- [ ] `timeout_secs + 5 <= lease_seconds`; `max_attempts` is appropriate for
      retry cost.
- [ ] Every task fits within the target workers' memory/output/fuel/timeout and
      total output ceiling.
- [ ] Aggregation field/shape matches the outputs; expected aggregate is exact.
- [ ] The workload is deterministic and safe to re-execute (at-least-once).
- [ ] The job name/description do not contain secrets.
- [ ] For `trusted` mode, you have explicitly accepted that results are
      unverified and the coordinator allows it.

## Failure modes

| Symptom | Meaning |
| --- | --- |
| `workload artifact SHA-256 mismatch` | Manifest digest and file disagree; rebuild/regenerate |
| `unsupported workload ABI` | `workload.abi` is not `getter.abi.v1` |
| `imports host capabilities` | The module imports anything; remove the dependency/WASI target |
| `missing required export` | The macro was not used or the module is not a `cdylib` |
| `execution exceeded its wall-clock deadline` | Guest exceeded timeout; increase timeout/lease appropriately or optimize |
| `execution exhausted its fuel budget` | Increase fuel within local maxima or optimize |
| `execution exceeded its memory limit` | Raise memory requirement/worker limit or reduce allocation |
| `workload produced ... above ... limit` | Raise output_bytes/worker max or reduce output |
| `result rejected by verification policy` | Output does not match the trusted hash (or required hash is missing) |
| `aggregate result did not match expected_aggregate` | Partition/reference sum error |
| `json_sum overflowed u128` | Input/reference too large for the aggregator |
| Task stuck `queued` | No active worker fits the requirements/ABI or slots are saturated |

The sandbox is defense in depth, not a formal proof. Module compilation happens
before the guest timeout and is only bounded by module size and worker
concurrency. Checksums prove integrity against a trusted reference, not general
honesty. See [Security](security.md) and [Limitations](limitations.md).
