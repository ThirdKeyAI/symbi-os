#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Media closure production requires disposable GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/media-closure-evidence"
output="$root/.cache/media-closure-output"
mkdir -p "$evidence"
unit="symbi-media-closure-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=3G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=95min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.desktop_packages.media_closure_hosted \
  2>&1 | tee "$evidence/hosted-producer.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R --no-dereference "$(id -u):$(id -g)" "$evidence"
if [[ -d "$output" ]]; then
  sudo chown -R --no-dereference "$(id -u):$(id -g)" "$output"
fi
exit "$status"
