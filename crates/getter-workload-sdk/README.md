# getter-workload-sdk

Authoring SDK for deterministic Getter workloads. It implements the guest side
of `getter.abi.v1` with no third-party dependencies and no host capability
bindings: a workload is pure guest code that runs inside Getter's sandbox, and
the coordinator/worker enforce memory, time, fuel, input, and output limits.

The SDK provides:

- [`getter_workload!`](src/lib.rs), a macro that exports the required ABI
  functions around a `fn(&[u8]) -> Vec<u8>` handler.
- `pack_output` / `unpack_output` for the ABI's packed `u64` result.
- `allocate_input` / `alloc_input` for the input buffer that the host writes
  before execution.
- An `input_slice` helper for reading the host-provided input pointer.

## ABI v1

A workload is a `cdylib` compiled for `wasm32-unknown-unknown`. Every module
must satisfy all of the following:

| Requirement | Value |
| --- | --- |
| ABI identifier | `getter.abi.v1` |
| Exports | `memory`, `getter_alloc(u32) -> u32`, `getter_execute(u32, u32) -> u64` |
| Imports | None |
| Input | Raw task input bytes (the example workload uses UTF-8 `start:end`) |
| Output | Opaque bytes |

The host calls `getter_alloc(input_len)`, writes exactly `input_len` bytes at
the returned address, and calls `getter_execute(input_ptr, input_len)`.
`getter_execute` returns one `u64`:

```text
                       high 32 bits              low 32 bits
result = (output_pointer as u64) << 32 | (output_length as u64)
```

The host reads `output_length` bytes starting at `output_pointer`. Output may be
empty; a zero length means no bytes should be read regardless of the pointer.
Input may also be empty, in which case a zero-length call such as
`getter_execute(0, 0)` is valid.

There is intentionally no `getter_free`. The SDK leaks both the input
allocation and the output allocation so that memory remains valid until the
host has read the result and dropped the module instance. Hosts should use a
fresh instance per task (or discard the instance after each execution) rather
than execute many tasks in one growing instance.

Hosts must allocate input through `getter_alloc`; writing beyond the requested
length is undefined behavior in the guest. The SDK traps on a null input
pointer with a non-zero length. A guest panic (including a malformed task
input) becomes a Wasm trap; the worker treats a trap as a failed attempt.

### Safety

The FFI boundary cannot be checked by Rust on either side. This crate contains
the only `unsafe` code needed by an author:

- `getter_alloc` hands the host a leaked, writable allocation.
- `getter_execute` reconstructs the input slice from a host-supplied pointer
  and length, then leaks the handler's output `Vec`.
- Every `unsafe` block has a `// SAFETY:` comment stating the host obligation
  it relies on.

The crate is compiled as a normal host `rlib` for tests too. Host pointers do
not fit in the ABI's `u32`, so the ABI exports are only meaningful in a Wasm
guest; the host tests exercise the pointer/length helpers without truncating
real pointers.

## Usage

Add the path (or published crate, when available) to a standalone guest
package:

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

Write the handler and expand the macro:

```rust
use getter_workload_sdk::getter_workload;

fn handler(input: &[u8]) -> Vec<u8> {
    format!("saw {} bytes", input.len()).into_bytes()
}

getter_workload!(handler);
```

Build the artifact:

```sh
cargo build --manifest-path my-workload/Cargo.toml \
  --target wasm32-unknown-unknown --release
```

The Wasm file is under
`my-workload/target/wasm32-unknown-unknown/release/my_workload.wasm`. A job's
`workload.sha256` must be the SHA-256 of that file, and `workload.artifact` is a
path relative to the job JSON file.

The macro accepts a path to a free function. The function must be visible in
the same module as the macro invocation and must have the signature
`fn(&[u8]) -> Vec<u8>`. It must not retain the input slice after returning.
Returning a `Vec` allocated through `std` is expected; the module has no
imports because the standard library's allocation and formatting code is
compiled into the guest.

## Example

[`examples/sum-squares`](../../examples/sum-squares/README.md) is the complete
reference workload: it parses `start:end`, iterates over every value in the
range, sums the squares using checked `u128` arithmetic, and returns exactly
`{"value":"<decimal>"}`. Its generator produces trusted per-task hashes and an
expected aggregate total, and its build script emits the checked-in
`sum_squares.wasm`.

## Tests

From the repository root:

```sh
cargo test -p getter-workload-sdk
```

The host unit tests cover output packing and unpacking, the allocation helper
(including the zero-length case), zero-length input handling, the null-pointer
guard, and raw byte-slice construction. Wasm artifacts are verified separately
by their build/generation tooling; no Wasm execution is claimed by these tests.
