#!/usr/bin/env bash
set -euo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted \
  && "${SYMBI_REQUESTED_QUALIFICATION:-}" == containers ]] || {
  echo 'Container input preflight requires the disposable hosted container gate.' >&2
  exit 1
}
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || {
  echo 'Container input preflight requires the exact OS source commit.' >&2
  exit 1
}
[[ "${GITHUB_REPOSITORY:-}" == ThirdKeyAI/symbi-os \
  && "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ \
  && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'Container input preflight requires exact hosted run identity.' >&2
  exit 1
}

root=$(git rev-parse --show-toplevel)
cd "$root"
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import os
from pathlib import Path

from image.boot.inputs import require_desktop_image
from image.qualification.container_hosted import run_container_preflight
from image.toolchain.reuse import unique_json

root = Path.cwd().resolve()
lock = unique_json((root / "image/desktop-images.lock.json").read_bytes())
pins = unique_json((root / "image/base-images.json").read_bytes())
require_desktop_image(lock, pins, "generic")
result = run_container_preflight(
    root, os.environ["GITHUB_SHA"], lock["images"]["generic"]["tested_commit"])
if (result.get("passed") is not True
        or result.get("fedora_runtime_ready") is not True
        or result.get("native_fixture_image_ready") is not True
        or result.get("qualified") is not False
        or result.get("os_qualified") is not False
        or result.get("release_qualified") is not False):
    blockers = result.get("blockers")
    detail = ",".join(blockers) if isinstance(blockers, list) else "invalid-preflight-result"
    raise SystemExit("Container native inputs are not ready: " + detail)
print("Authenticated container inputs are ready for the bounded image transfer")
PY
