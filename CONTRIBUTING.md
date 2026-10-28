# Contributing to Getter

Thanks for helping build Getter. This project is alpha software; clear bug
reports, documentation fixes, tests, and focused implementation changes are all
welcome.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report security issues privately as described in [SECURITY.md](SECURITY.md), not
in a public issue.

## Before you start

- Check existing issues and pull requests to avoid duplicate work.
- Open an issue or discussion before a large change, a protocol change, a
  storage migration, or a new dependency. Those changes need design agreement
  and compatibility review.
- Do not include secrets, real pairing tokens, worker private keys, or
  production job data in issues, logs, tests, or commits.

## Toolchain and prerequisites

The repository pins Rust `1.97.0` in [`rust-toolchain.toml`](rust-toolchain.toml)
and checks in [`Cargo.lock`](Cargo.lock). Use both.

```sh
rustup show active-toolchain   # should report 1.97.0
rustup target add wasm32-unknown-unknown
```

Additional tools:

- Python 3.10+ for `examples/sum-squares/generate_job.py` and
  `scripts/e2e-local.sh`.
- A C toolchain for the bundled SQLite build (`rusqlite`/`libsqlite3-sys`).
- Bash for the example build and end-to-end scripts. The project is developed
  primarily on Linux; macOS and Windows builds are not verified in this
  environment.

## Build and test

From the repository root:

```sh
cargo build --locked --workspace
cargo test --locked --workspace --all-targets
```

Useful focused commands:

```sh
cargo test -p getter-core
cargo test -p getter-storage
cargo test -p getter-runtime
cargo test -p getter-coordinator
cargo test -p getter-worker
cargo test -p getter-protocol
cargo test -p getter-workload-sdk
cargo test --manifest-path examples/sum-squares/Cargo.toml
```

### Required formatting and lint gates

These are the CI gates. Run them before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

`cargo fmt --all` applies formatting. Clippy warnings are treated as errors in
CI. Do not add blanket `#[allow]` attributes to silence a warning without a
comment explaining why the lint is wrong or unavoidable.

`.github/workflows/ci.yml` runs these quality gates, the two-worker recovery E2E,
`cargo audit`, and `node scripts/gates/docs.mjs` (required docs,
banner hash, links, and workflow checks). Do not claim a change passed CI unless
the workflow actually ran.

### Dependency and license checks

CI installs `cargo-audit` and runs `cargo audit`. Locally:

```sh
cargo audit
```

`cargo-deny` is not configured (`deny.toml` is absent). New dependencies need
justification, a license compatible with Apache-2.0, and a review of their
default features. Keep `Cargo.lock` updated deliberately and commit it.

### End-to-end local demonstration

The full local harness is:

```sh
bash scripts/e2e-local.sh
```

It reuses `GETTER_BIN` if set, otherwise builds `target/release/getter` with
`--locked`. It uses loopback TLS only, creates a temporary home under
`$TMPDIR`, and exercises two workers, the real `sum-squares` job, an
unauthenticated enrollment rejection, worker pause/kill, coordinator restart,
lease expiry/retry, and CLI status/contribution/doctor checks. Set
`KEEP_E2E_STATE=1` to retain temporary homes and logs. The same script is run by
the CI `e2e` job; this revision does not claim a CI run result. See
[Testing](docs/testing.md) for what the script covers and what remains
unverified.

The example alone can be checked without the full harness:

```sh
./scripts/build-example.sh
python3 examples/sum-squares/generate_job.py
cargo test --manifest-path examples/sum-squares/Cargo.toml
```

`./scripts/build-example.sh` overwrites the checked-in artifact. Commit the
artifact and regenerate `job.json` together when the artifact hash changes.

## Code expectations

- Keep crate boundaries meaningful. `getter-protocol` is transport-neutral,
  `getter-core` owns domain/auth/validation logic, `getter-storage` owns SQLite,
  `getter-runtime` owns Wasmtime, and `getter-coordinator`/`getter-worker` stay
  transport/runtime adapters.
- Do not move security decisions into transport handlers when they belong in
  validation, storage, or state-transition code.
- All wire types live in `getter-protocol` and reject unknown fields. A breaking
  wire change requires a new `PROTOCOL_VERSION`. A job-format or ABI change
  requires a new identifier, not a silent reinterpretation.
- Storage migrations are append-only. Add a new numbered migration; never edit
  an applied migration. State transitions must go through the storage
  transaction that enforces them.
- No new host capabilities in the workload sandbox. `getter.abi.v1` has zero
  imports; adding WASI or host functions is a design change and a new ABI.
- Validate all untrusted sizes and hashes before allocating or executing. Prefer
  explicit limits and checked arithmetic over implicit assumptions.
- Keep secrets out of `Debug`, logs, errors, and CLI output. Lease tokens,
  private keys, and control/admin tokens must never be logged. Pairing tokens are
  printed once by design.
- Every `unsafe` block needs a `// SAFETY:` comment explaining its invariants.
  The workspace denies `unsafe_code` outside the workload SDK's narrow ABI
  exception.
- Avoid `unwrap()`/`expect()` in request, storage, and runtime paths except for
  truly static invariants. The workspace clippy configuration denies
  `unwrap_used`, `dbg_macro`, and `todo`.
- Add regression tests for behavior changes. Security-sensitive behavior needs a
  test that would fail if the check were removed.

## Documentation expectations

- Keep [README](README.md), [configuration](docs/configuration.md),
  [protocol](docs/protocol.md), [workloads](docs/workloads.md), and
  [security](docs/security.md) in sync with code.
- Use relative links that resolve from a fresh clone. Do not invent commands,
  flags, endpoints, fields, or CI status.
- Document limitations and unverified procedures honestly. Distinguish "tested
  here" from "intended" and "not verified".
- When changing the CLI, update [CLI reference](docs/cli.md) from the actual
  `getter --help` output.
- When changing config fields, update [configuration](docs/configuration.md) and
  the `getter config set` allow-list. Fields are parsed with
  `deny_unknown_fields`; a stale example will fail at startup.
- Add a changelog entry for user-visible changes under `[Unreleased]`.

## Pull requests

A good pull request:

- has a focused title and a short motivation;
- explains the security and compatibility impact;
- includes tests and documentation updates;
- lists commands run and their results;
- calls out anything not verified or intentionally deferred;
- does not mix unrelated refactors with a behavior change;
- does not modify generated artifacts without the source/build step that
  produced them.

Use the pull request template. Maintainers may ask for a design issue before
reviewing a large diff, and may decline changes that add host capabilities,
break protocol compatibility, or weaken documented security properties.

## License

By contributing, you agree that your contribution is licensed under the Apache
License, Version 2.0, as described in [LICENSE](LICENSE). There is no separate
CLA configured. Preserve copyright and license notices in files you modify.
