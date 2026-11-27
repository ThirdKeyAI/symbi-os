#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
sha256sum --check --strict image/vendor/SHA256SUMS
bash -n image/harden-image.sh image/overlay/usr/libexec/* image/overlay/etc/profile.d/*
python3 -m unittest discover -s image/tests -v
