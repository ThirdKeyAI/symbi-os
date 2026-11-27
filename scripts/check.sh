#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
source scripts/tool-versions.sh

export PATH="$PWD/.tools/bin:$PATH"
export CEDAR_BIN="${CEDAR_BIN:-cedar}"
export CARGO_BUILD_JOBS=1
export RUST_TEST_THREADS=1
export RAYON_NUM_THREADS=1

require_version() {
  local expected="$1"
  shift
  local actual
  actual="$("$@")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'Expected %s, got %s. Run bash scripts/bootstrap-tools.sh.\n' "$expected" "$actual" >&2
    exit 1
  fi
}

require_version "cedar-policy-cli $SYMBI_CEDAR_VERSION" "$CEDAR_BIN" --version
require_version "cargo-deny $SYMBI_DENY_VERSION" cargo deny --version
require_version "cargo-vet $SYMBI_VET_VERSION" cargo vet --version

bash -n scripts/bootstrap-tools.sh scripts/check.sh scripts/tool-versions.sh

bash scripts/check-image.sh

# Always build and lint the workspace with its MSRV, even if stable is newer.
cargo +"$SYMBI_RUST_VERSION" fmt --all -- --check
cargo +"$SYMBI_RUST_VERSION" clippy --workspace --all-targets --locked -- -D warnings
cargo +"$SYMBI_RUST_VERSION" test --workspace --locked
cargo +"$SYMBI_RUST_VERSION" doc --workspace --no-deps --locked
cargo +"$SYMBI_RUST_VERSION" deny --locked check
cargo +"$SYMBI_RUST_VERSION" vet --locked
