#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Container fixture execution requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
mkdir -p "$root/.cache/container-fixture-evidence"
unit="symbi-container-fixtures-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=110min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME" "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" \
  "GITHUB_SHA=$GITHUB_SHA" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
  "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" "GITHUB_REF_NAME=$GITHUB_REF_NAME" \
  "FIXTURE_USER=$(id -un)" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
  PYTHONDONTWRITEBYTECODE=1 python3 image/container/hosted/check.py \
  2>&1 | tee "$root/.cache/container-fixture-evidence/hosted-fixtures.log"
status=${PIPESTATUS[0]}
set -e
load_state=$(sudo systemctl show "$unit" --property=LoadState --value)
if [[ "$load_state" == not-found ]]; then
  printf 'LoadState=not-found\nObservation=unit collected; use cgroup-final.json\n' > "$root/.cache/container-fixture-evidence/systemd-result.txt"
else
  sudo systemctl show "$unit" --property=LoadState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUUsageNSec,RuntimeMaxUSec > "$root/.cache/container-fixture-evidence/systemd-result.txt"
fi
# Only reviewed public output is retained. The private fixture directory holds
# synthetic signing keys and is deliberately outside this copy and artifact.
if [[ -d "$root/.cache/container-fixture-work/public" ]]; then
  python3 image/container/hosted/inputs.py "$root/.cache/container-fixture-work/public" "$root/.cache/container-fixture-evidence/public"
fi
exit "$status"
