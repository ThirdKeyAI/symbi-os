#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Kitty bundle inspection requires disposable GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/kitty-bundle-evidence"
mkdir -p "$evidence"
unit="symbi-kitty-bundle-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --uid="$(id -u)" --gid="$(id -g)" \
  --property=MemoryMax=512M --property=MemorySwapMax=0 --property=CPUQuota=100% \
  --property=TasksMax=32 --property=Nice=10 --property=RuntimeMaxSec=15min \
  --property=TimeoutStopSec=15 --property=KillMode=control-group \
  --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
  --property=PrivateTmp=yes --property=ProtectSystem=strict \
  --property="ReadWritePaths=$root/.cache" --property=UMask=0077 \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  python3 -m image.kitty.bundle 2>&1 | tee "$evidence/hosted-inspection.log"
status=${PIPESTATUS[0]}
set -e
exit "$status"
