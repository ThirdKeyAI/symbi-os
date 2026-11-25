#!/usr/bin/env bash
# Build-time setup only. Never install this script or its tools in the OS image.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
source scripts/tool-versions.sh

# Install one tool at a time with one compiler job and no optimization/debug
# metadata. These checkers are not shipped binaries; minimize local resources.
export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_DEV_INCREMENTAL=false
export RAYON_NUM_THREADS=1
export RUSTUP_CONCURRENT_DOWNLOADS=1

command -v rustup >/dev/null
rustup toolchain install "$SYMBI_RUST_VERSION" --profile minimal --component rustfmt --component clippy --no-self-update
rustup toolchain install "$SYMBI_TOOL_RUST_VERSION" --profile minimal --no-self-update

tools_root="$PWD/.tools"
install_tool() {
  local package="$1" version="$2" binary="$3"
  local installed="$tools_root/bin/$binary"
  if [[ -x "$installed" ]] && [[ "$("$installed" --version)" == "$package $version" ]]; then
    printf 'Reusing %s %s\n' "$package" "$version"
    return
  fi
  cargo +"$SYMBI_TOOL_RUST_VERSION" install --debug --jobs 1 --locked \
    --root "$tools_root" --version "$version" "$package"
}

install_tool cargo-deny "$SYMBI_DENY_VERSION" cargo-deny
install_tool cargo-vet "$SYMBI_VET_VERSION" cargo-vet
install_tool cedar-policy-cli "$SYMBI_CEDAR_VERSION" cedar
