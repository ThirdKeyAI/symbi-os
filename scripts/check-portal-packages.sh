#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Portal package discovery requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/portal-package-evidence"
mkdir -p "$evidence"
unit="symbi-portal-rpms-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=3G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=45min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.portal.hosted_discover \
  2>&1 | tee "$evidence/hosted-discovery.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R "$(id -u):$(id -g)" "$evidence"
exit "$status"
