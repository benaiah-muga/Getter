#!/bin/sh
# Build the sum-squares example for wasm32-unknown-unknown and update the
# checked-in artifact next to its source. CARGO_HOME is inherited from the
# environment; this script does not pin a machine-specific Cargo home.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
manifest="$repo_root/examples/sum-squares/Cargo.toml"
artifact="$repo_root/examples/sum-squares/sum_squares.wasm"
built="$repo_root/examples/sum-squares/target/wasm32-unknown-unknown/release/sum_squares.wasm"
cargo_bin=${CARGO:-cargo}

if ! command -v "$cargo_bin" >/dev/null 2>&1; then
    printf 'error: cargo not found; set CARGO to the cargo binary\n' >&2
    exit 1
fi

# Force a workspace-local target directory so the artifact path is stable even
# when the caller has CARGO_TARGET_DIR set. It is covered by the root .gitignore.
CARGO_TARGET_DIR="$repo_root/examples/sum-squares/target"
export CARGO_TARGET_DIR

# Run from the repository root so rust-toolchain.toml selects the pinned
# toolchain even when the script is invoked from another directory.
cd "$repo_root"
"$cargo_bin" build --manifest-path "$manifest" --target wasm32-unknown-unknown --release

if [ ! -f "$built" ]; then
    printf 'error: expected Wasm artifact not found at %s\n' "$built" >&2
    exit 1
fi

cp "$built" "$artifact"
chmod 644 "$artifact"

if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$artifact" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$artifact" | awk '{print $1}')
elif command -v openssl >/dev/null 2>&1; then
    digest=$(openssl dgst -sha256 "$artifact" | awk '{print $NF}')
else
    printf 'error: no SHA-256 tool found (tried sha256sum, shasum, openssl)\n' >&2
    exit 1
fi

printf 'artifact: %s\n' "$artifact"
printf 'sha256: %s\n' "$digest"
