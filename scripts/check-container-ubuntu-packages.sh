#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )) || [[ ${1:-check} != check ]]; then
  echo 'Usage: check-container-ubuntu-packages.sh [check]' >&2
  exit 2
fi

root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
cd "$root"
exec env PYTHONDONTWRITEBYTECODE=1 python3 \
  -m image.container.ubuntu_fixture_inputs --root "$root" check
