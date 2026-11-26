#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Portal consent compilation requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/portal-consent-evidence"
mkdir -p "$evidence"
unit="symbi-portal-consent-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=8G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=50min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.portal.hosted_consent \
  2>&1 | tee "$evidence/hosted-build.log"
status=${PIPESTATUS[0]}
set -e
load_state=$(sudo systemctl show "$unit" --property=LoadState --value)
if [[ "$load_state" == not-found ]]; then
  printf 'LoadState=not-found\nObservation=unit collected; use result.json cgroup_final\n' > "$evidence/systemd-result.txt"
else
  sudo systemctl show "$unit" --property=LoadState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUUsageNSec,RuntimeMaxUSec | tee "$evidence/systemd-result.txt"
fi
sudo chown -R "$(id -u):$(id -g)" "$evidence"
if [[ -d "$root/.cache/portal-consent-payload" ]]; then
  sudo chown -R "$(id -u):$(id -g)" "$root/.cache/portal-consent-payload"
fi
exit "$status"
