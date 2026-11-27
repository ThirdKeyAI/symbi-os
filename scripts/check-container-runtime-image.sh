#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Container-runtime image assembly requires a disposable GitHub-hosted runner.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/container-runtime-image-evidence"
mkdir -p "$evidence"
case "${1:-}" in
  prepare)
    unit="symbi-container-image-prep-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    options=(--uid="$(id -u)" --gid="$(id -g)" --property=MemoryMax=1G \
      --property=CPUQuota=100% --property=TasksMax=64 --property=RuntimeMaxSec=30min)
    module=image.container.runtime_image_prepare
    ;;
  build)
    unit="symbi-container-image-build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    options=(--property=MemoryMax=4G --property=CPUQuota=200% --property=TasksMax=256 \
      --property=RuntimeMaxSec=60min --property=Delegate=yes --property=DelegateSubgroup=supervisor)
    module=image.container.runtime_image_build
    ;;
  *) echo 'Select prepare or build.' >&2; exit 2 ;;
esac
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  "${options[@]}" --property=MemorySwapMax=0 --property=Nice=10 --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "HOME=${HOME}" "USER=${USER}" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_SHA=${GITHUB_SHA}" "GITHUB_RUN_ID=${GITHUB_RUN_ID}" \
  "GITHUB_RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT}" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m "$module" 2>&1 | tee "$evidence/hosted-$1.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R "$(id -u):$(id -g)" "$evidence"
if [[ -d "$root/.cache/container-runtime-image-output" ]]; then
  sudo chown -R "$(id -u):$(id -g)" "$root/.cache/container-runtime-image-output"
fi
# shellcheck disable=SC2024
sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
  --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode \
  --property=ExecMainStatus > "$evidence/$1-systemd-result.txt" || true
exit "$status"
