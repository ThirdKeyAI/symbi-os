#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Fedora base inventory requires a GitHub-hosted runner.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/fedora-base-evidence"
mkdir -p "$evidence"
unit="symbi-fedora-base-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=2G --property=MemorySwapMax=0 --property=CPUQuota=100% \
  --property=TasksMax=256 --property=Nice=10 --property=Delegate=yes --property=DelegateSubgroup=supervisor \
  --property=RuntimeMaxSec=30min --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  HOME=/root USER=root GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_SHA=$GITHUB_SHA" python3 image/hyprland/inventory.py \
  2>&1 | tee "$evidence/hosted-inventory.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R "$(id -u):$(id -g)" "$evidence"
exit "$status"
