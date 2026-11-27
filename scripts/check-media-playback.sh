#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Media playback qualification requires disposable hosted CI.' >&2
  exit 1
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic || "${SYMBI_IMAGE_VARIANT:-}" == nvidia ]] || exit 2
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/media-playback-evidence"
mkdir -p "$evidence"
unit="symbi-media-playback-${SYMBI_IMAGE_VARIANT}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=3G --property=MemorySwapMax=0 --property=CPUQuota=100% \
  --property=TasksMax=128 --property=Nice=10 --property=RuntimeMaxSec=50min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  HOME=/root GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_SHA=$GITHUB_SHA" "SYMBI_IMAGE_VARIANT=$SYMBI_IMAGE_VARIANT" \
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.desktop_packages.media_hosted \
  2>&1 | tee "$evidence/hosted.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R --no-dereference "$(id -u):$(id -g)" "$evidence"
# shellcheck disable=SC2024
sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
  --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode --property=ExecMainStatus \
  > "$evidence/systemd-result.txt" || true
exit "$status"
