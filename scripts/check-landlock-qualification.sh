#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Landlock qualification requires a disposable GitHub-hosted runner.' >&2; exit 1;
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic && "${SYMBI_QUALIFICATION:-}" == landlock ]] || exit 2
root=$(git rev-parse --show-toplevel)
atomic_evidence="$root/.cache/atomic-disk-evidence"
qualification_evidence="$root/.cache/landlock-qualification-evidence"
mkdir -p "$atomic_evidence"
unit="symbi-landlock-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=RuntimeMaxSec=145min --property=Nice=10 \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  SYMBI_IMAGE_VARIANT=generic SYMBI_QUALIFICATION=landlock PYTHONDONTWRITEBYTECODE=1 \
  python3 -m image.atomic.hosted 2>&1 | tee "$atomic_evidence/hosted.log"
status=${PIPESTATUS[0]}
set -e
sudo chown -R "$(id -u):$(id -g)" "$atomic_evidence" "$qualification_evidence" 2>/dev/null || true
# shellcheck disable=SC2024
sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
  --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode --property=ExecMainStatus \
  > "$atomic_evidence/systemd-result.txt" || true
exit "$status"
