#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Package discovery requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/fedora-package-evidence"
mkdir -p "$evidence"
unit="symbi-fedora-packages-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=3G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=45min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  PYTHONDONTWRITEBYTECODE=1 python3 image/hyprland/package_inventory.py \
  2>&1 | tee "$evidence/hosted-discovery.log"
status=${PIPESTATUS[0]}
set -e
load_state=$(sudo systemctl show "$unit" --property=LoadState --value)
if [[ "$load_state" == not-found ]]; then
  printf 'LoadState=not-found\nObservation=unit collected; use cgroup-final.json\n' > "$evidence/systemd-result.txt"
else
  sudo systemctl show "$unit" --property=LoadState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUUsageNSec,RuntimeMaxUSec > "$evidence/systemd-result.txt"
fi
exit "$status"
