#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Hyprland runtime packaging requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/hyprland-runtime-evidence"
mkdir -p "$evidence"
unit="symbi-hypr-runtime-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=35min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  HOME=/root USER=root GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_SHA=$GITHUB_SHA" PYTHONDONTWRITEBYTECODE=1 \
  python3 image/hyprland/hosted_runtime.py 2>&1 | tee "$evidence/hosted-runtime.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R "$(id -u):$(id -g)" "$evidence"
exit "$status"
