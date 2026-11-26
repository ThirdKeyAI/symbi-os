#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Atomic image preflight requires a disposable GitHub-hosted runner.' >&2; exit 1;
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic || "${SYMBI_IMAGE_VARIANT:-}" == nvidia ]] || exit 2
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/atomic-image-evidence"
mkdir -p "$evidence"
case "${1:-}" in
  prepare)
    options=(--uid="$(id -u)" --gid="$(id -g)" --property=MemoryMax=1G --property=CPUQuota=100% --property=TasksMax=64 --property=RuntimeMaxSec=15min)
    ;;
  inspect)
    options=(--property=MemoryMax=4G --property=CPUQuota=200% --property=TasksMax=256 --property=RuntimeMaxSec=40min --property=Delegate=yes --property=DelegateSubgroup=supervisor)
    ;;
  *) echo 'Select prepare or inspect.' >&2; exit 2 ;;
esac
unit="symbi-atomic-$1-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  "${options[@]}" --property=MemorySwapMax=0 --property=Nice=10 --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  "SYMBI_IMAGE_VARIANT=$SYMBI_IMAGE_VARIANT" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m image.boot.hosted "$1" 2>&1 | tee "$evidence/hosted-$1.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R "$(id -u):$(id -g)" "$evidence"
# shellcheck disable=SC2024
sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
  --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode --property=ExecMainStatus \
  > "$evidence/$1-systemd-result.txt" || true
exit "$status"
