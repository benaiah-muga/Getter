# Release process

This page documents the release process that is checked in **and** the parts
that are still expectations. **No signed release, published binary, or verified
release artifact exists for `0.1.0`.** An independent pre-release security review
was completed and critical/high findings were addressed; that is not an external
audit. Nothing here claims that a release was produced, that CI is green, or that
an external audit took place.

## Versioning

- Crate and product version: `0.1.0` in the workspace.
- Wire protocol: `getter.protocol/v1`.
- Job format: `getter.job/v1`.
- Workload ABI: `getter.abi.v1`.
- Before 1.0, minor versions may make incompatible changes. Once 1.0 is reached,
  the project intends to follow Semantic Versioning for the product while
  versioning the protocol, job format, and ABI independently.
- `0.1.0` is the first public definition of `getter.protocol/v1`; there are no
  previously deployed v1 peers. After the first release, a breaking protocol
  change requires a new protocol identifier and coordinated
  coordinator/worker/CLI updates. A new job shape requires a new job-format
  identifier. A new guest contract requires a new ABI identifier and SDK/runtime
  support; do not redefine `getter.abi.v1`.
- Storage migrations are forward-only. The current schema version is 3. A
  release that changes the schema must document the upgrade path and test
  migration from the previous supported schema.

## Build inputs

- Rust `1.97.0` via [`rust-toolchain.toml`](../rust-toolchain.toml), with
  `rustfmt`, `clippy`, and `wasm32-unknown-unknown`.
- Checked-in [`Cargo.lock`](../Cargo.lock); use `--locked`.
- The `sum-squares` artifact is checked in at
  `examples/sum-squares/sum_squares.wasm`; a rebuild must regenerate
  `job.json` if the hash changes.
- Python 3 for job generation and the release workflow's reference check.

## CI and release workflows

The repository now contains:

- `.github/workflows/ci.yml` — on pushes to `main`, pull requests, and manual
  dispatch:
  - **quality:** format check, locked clippy with warnings denied, locked
    workspace tests with all targets, example Wasm build, independent generated
    job assertion, and expected aggregate check;
  - **e2e:** release binary build and `scripts/e2e-local.sh` with two workers,
    pause/kill/restart recovery, and validation;
  - **dependency-audit:** `cargo audit`;
  - **docs:** `node scripts/gates/docs.mjs` (required paths, banner hash, docs
    content, links, workflows).
- `.github/workflows/release.yml` — on a `v*` tag or manual dispatch:
  - re-runs format, clippy, tests, and the example generation/assertion;
  - builds `target/release/getter`;
  - packages `getter-<version>-x86_64-unknown-linux-gnu.tar.gz` containing the
    binary, README, LICENSE, NOTICE, CHANGELOG, and checked-in example Wasm;
  - writes a SHA-256 sidecar;
  - creates a GitHub build-provenance attestation and uploads the workflow
    artifact;
  - creates or updates a GitHub release with the tarball and checksum.

The existence of these workflows is not evidence that they passed for a given
commit. A release must link the actual green run for the tagged commit.

## Pre-release gates

Run and record locally as well:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo build --locked --release -p getter-cli

rustup target add wasm32-unknown-unknown
./scripts/build-example.sh
python3 examples/sum-squares/generate_job.py --out /tmp/getter-example-job.json
cargo test --manifest-path examples/sum-squares/Cargo.toml

cargo audit
node scripts/gates/docs.mjs
GETTER_BIN="$PWD/target/release/getter" bash scripts/e2e-local.sh
```

Attach the exact commands, commit, environment, and observed output. Do not use
this checklist to imply that tests, CI, or a review that did not run were
successful. The E2E harness remains the full recovery demonstration, but this
snapshot makes no claim about a passing run.

## Binary build

```sh
cargo build --locked --release -p getter-cli
./target/release/getter --version
```

The binary is `target/release/getter`; the version is `0.1.0`. It embeds the
workspace version, protocol version, and Wasmtime/runtime build. Builds are
currently specific to the host target and toolchain; no cross-compiled matrix or
reproducible-build guarantee exists. The release profile uses thin LTO, 16 codegen
units, no debug info, and stripped symbols (see the workspace `Cargo.toml`). Do
not claim that independent builds produce identical bytes; add and verify a
reproducible-build process before claiming that property.

## Checksums

The release workflow generates a SHA-256 sidecar next to the tarball, and the
manual equivalent is:

```sh
cd dist
sha256sum getter-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  > getter-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

When a release exists, publish the checksum with the artifact and independently
in the release notes. A checksum from the same compromised host is not
independent evidence.

## Signing and attestation expectations

Current checked-in behavior:

- The release workflow requests GitHub Actions `id-token: write` and
  `attestations: write`, and uses `actions/attest-build-provenance@v2` for
  build provenance on the tarball. This is a signed statement about the build,
  not a Getter release-key signature and not an external audit.
- **No GPG/SSH release key, key fingerprint, transparency-log entry, or detached
  artifact signature exists.**

The intended future process, once a release key is established:

1. Build on a clean, patched machine from a protected commit/tag.
2. Verify the lockfile and toolchain; produce the binary, tarball, and checksum.
3. Sign the checksum (or a manifest containing every artifact and checksum) with
   a release key, for example `gpg --detach-sign` or `cosign sign-blob`.
4. Publish the detached signature and the public key/fingerprint alongside the
   artifact.
5. Record the key fingerprint and verification commands in the release notes.
6. Have a second maintainer reproduce the build/checksum where feasible.

Future verification shape (not currently usable because no verified release exists):

```sh
sha256sum -c getter-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
gh attestation verify getter-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo benaiah-muga/Getter
# After a release key exists and is published:
gpg --verify getter-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sig \
  getter-0.1.0-x86_64-unknown-linux-gnu.tar.gz
gpg --fingerprint <published-release-key-fingerprint>
```

Do not treat a GitHub attestation, a checksum, or an unsigned tarball as a
complete authenticity/trust guarantee for a production deployment. Verify the
repository, tag, workflow run, attestation, and (when available) detached
signature through independent channels.

## Release checklist

- [ ] Version, protocol/job/ABI identifiers, schema version, and changelog agree.
- [ ] `Cargo.lock` is committed and `--locked` builds pass.
- [ ] `ci.yml` quality, e2e, audit, and docs jobs are green for the exact commit.
- [ ] Format, locked clippy, locked all-target tests, example build/generation/
      tests pass locally.
- [ ] Dependency/license review and `cargo audit` are current.
- [ ] E2E harness result is attached, including commit, environment, and output.
- [ ] Independent pre-release security review status is stated; unresolved
      findings are disclosed or fixed. This is not an external audit.
- [ ] Documentation links resolve; commands match `getter --help`; config defaults
      match the code (including `max_total_output_bytes` and 48 MiB HTTP default).
- [ ] No secrets or private homes are included in the source or artifacts.
- [ ] Checksums are generated and verified.
- [ ] The release workflow produced a provenance attestation.
- [ ] A release key signs the checksum (only once a key exists); otherwise the
      release is explicitly labeled unsigned.
- [ ] Release notes list limitations, known issues, upgrade/migration steps, and
      the supported platform/target.
- [ ] The tag and published artifacts point at the reviewed commit.
- [ ] CI/release workflow logs are linked and actually green.

Until every applicable item is true, call the result a development snapshot, not
a signed release.

## Publishing

No crates.io publication is configured. If publishing `getter-workload-sdk` or
other crates later, package only intended files, verify `cargo package` contents
and license metadata, publish in dependency order, and keep path dependencies
out of published manifests. A published SDK does not imply a published engine.

## After release

- Keep the release notes, checksums, and attestation links available.
- Monitor upstream Rust/Wasmtime advisories and the repository's security
  channel.
- If a vulnerability is found, follow [SECURITY.md](../SECURITY.md), publish a
  coordinated advisory with affected versions and mitigations, and sign updated
  artifacts when a release key exists.
- Do not silently replace an artifact under the same version. Publish a new
  version and explain the revocation.
