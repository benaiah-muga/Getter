# sum-squares example workload

`sum-squares` is the deterministic reference workload for Getter. It is a
standalone Rust `cdylib` for `wasm32-unknown-unknown` that implements
`getter.abi.v1` using the [Getter workload SDK](../../crates/getter-workload-sdk/README.md).
It deliberately has no dependencies other than the SDK; the small JSON output is
formatted by hand, with no serde.

## What it computes

Each task input is exactly `start:end` in ASCII decimal, with `end` exclusive
and both endpoints fitting in `u128`. The guest parses the two endpoints, then
walks the range one integer at a time and accumulates checked `u128` squares. It
does **not** use a closed-form shortcut.

The output is exactly:

```text
{"value":"<u128-decimal>"}
```

There is no whitespace and no trailing newline. For example, `10:12` produces
`{"value":"221"}`. The output bytes are deterministic, so a job can verify each
task with `exact_sha256`.

The generator partitions `[0, values)` into contiguous ranges that cover the
whole interval exactly once. With the defaults there are 12 tasks of 1,000,000
values each. The guest uses checked arithmetic: if a chosen range's mathematical
sum of squares does not fit in `u128`, the workload traps instead of wrapping.
The default range is far below that limit.

## Build the artifact

From the repository root:

```sh
./scripts/build-example.sh
```

The script uses the Cargo home from the environment (it does not hardcode one),
runs from the repository root so `rust-toolchain.toml` applies, builds the
`wasm32-unknown-unknown` release artifact, copies it to
`examples/sum-squares/sum_squares.wasm`, and prints its SHA-256. It requires the
`wasm32-unknown-unknown` target:

```sh
rustup target add wasm32-unknown-unknown
```

The equivalent direct build is:

```sh
cargo build --manifest-path examples/sum-squares/Cargo.toml \
  --target wasm32-unknown-unknown --release
```

The repository artifact is `sum_squares.wasm`, 22,651 bytes:

```text
sha256 853269c113a222f5229bd5ce245ebe668d1c2978dc047554d8748e9e2246930e
```

The checked-in `.wasm` is the built artifact of the source in this directory;
the source is provided and the build script rebuilds it. Binary output is not
promised to be bit-for-bit reproducible across arbitrary toolchain, linker, or
profile changes, so regenerate `job.json` whenever a rebuild changes the
artifact hash.

## Generate the job

From the repository root:

```sh
python3 examples/sum-squares/generate_job.py
```

This writes `examples/sum-squares/job.json` with:

- 12 deterministic partitions (`task-000` through `task-011`) covering exactly
  `[0, 12000000)`,
- the expected SHA-256 of the exact canonical output bytes for every task,
- the artifact SHA-256 and the artifact path relative to `job.json`, and
- the aggregate total `575999928000002000000`.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--tasks N` | `12` | Number of contiguous partitions |
| `--values N` | `12000000` | Process `[0, N)` |
| `--artifact PATH` | `<example>/sum_squares.wasm` | Wasm artifact to validate and hash |
| `--out PATH` | `<example>/job.json` | Job JSON destination |
| `--expected-sha256 HEX` | none | Fail unless the artifact has this SHA-256 |
| `--timeout-secs N` | `10` | Per-task execution timeout |
| `--lease-seconds N` | `20` | Task lease; must be at least timeout + 5 |

The generator computes the trusted task totals with an independent closed-form
sum-of-squares identity while the Rust guest still iterates over every value.
The two methods must produce the same canonical bytes, so the checked-in hashes
are unchanged. It validates that the artifact is a WebAssembly 1.0 module with
no imports and the required `memory`, `getter_alloc`, and `getter_execute`
exports, computes the artifact SHA-256, and checks `--expected-sha256` when it is
supplied. It refuses to write a job when
the artifact is missing, imports anything, lacks an export, fails the optional
digest check, or a task's reference total or the aggregate would exceed the
guest's `u128`. It also rejects `--lease-seconds` below `--timeout-secs + 5`.
Task IDs are zero-padded (`task-000`), and `workload.artifact` is emitted
relative to the job file.

The generated `job.json` in this directory is the output of the default
invocation. A task's `expected_output_sha256` can be independently reproduced
from its `input` with any SHA-256 implementation over the canonical bytes above;
the generator's `--values`/`--tasks` arguments change the partitioning and
therefore the hashes.

## Tests

Host-mode unit tests exercise parsing, the iterating sum, checked-overflow
behavior, and exact output bytes:

```sh
cargo test --manifest-path examples/sum-squares/Cargo.toml
```

The guest source compiles for the host as well as for Wasm, which is what makes
these tests possible. The unit tests do not execute the Wasm artifact; use the
generator and a Getter runtime for end-to-end verification.
