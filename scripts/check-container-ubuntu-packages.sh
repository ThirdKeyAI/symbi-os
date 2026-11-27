#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo 'Usage: check-container-ubuntu-packages.sh [check|consume|build|materialize]' >&2
  exit 2
fi

mode=${1:-check}
root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
cd "$root"
exec env PYTHONDONTWRITEBYTECODE=1 python3 \
  -m image.container.ubuntu_fixture_inputs --root "$root" "$mode"
