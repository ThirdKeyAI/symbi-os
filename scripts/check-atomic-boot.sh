#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Atomic installation and boot require a disposable GitHub-hosted runner.' >&2; exit 1;
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic && "${SYMBI_QUALIFICATION:-}" == update ]] || exit 2
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/atomic-disk-evidence"
evidence_dirs=(
  "$root/.cache/atomic-image-evidence"
  "$root/.cache/atomic-disk-evidence"
  "$root/.cache/atomic-update-evidence"
)
cache="$root/.cache"
if [[ -L "$cache" || ( -e "$cache" && ! -d "$cache" ) ]]; then
  echo 'Atomic cache root is not a direct directory.' >&2
  exit 3
fi
mkdir -p "$cache"
for path in "${evidence_dirs[@]}"; do
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ -L "$path" || ! -d "$path" ]]; then
      echo "Refusing unsafe Atomic evidence path before use: $path" >&2
      exit 3
    fi
    if ! unsafe=$(sudo find -P "$path" -xdev ! -type d ! \( -type f -links 1 \) \
      -print -quit); then
      echo "Could not inspect Atomic evidence path before use: $path" >&2
      exit 3
    fi
    if [[ -n "$unsafe" ]]; then
      echo "Refusing linked or special Atomic evidence content before use: $path" >&2
      exit 3
    fi
  fi
done
mkdir -p "$evidence"
unit="symbi-atomic-disk-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=RuntimeMaxSec=110min --property=Nice=10 \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  SYMBI_IMAGE_VARIANT=generic SYMBI_QUALIFICATION=update PYTHONDONTWRITEBYTECODE=1 \
  python3 -m image.atomic.hosted 2>&1 | tee "$evidence/hosted.log"
status=${PIPESTATUS[0]}
set -e
ownership_status=0
if [[ -L "$root/.cache" || ! -d "$root/.cache" ]]; then
  echo 'Atomic cache root is not a direct directory.' >&2
  ownership_status=3
else
  for path in "${evidence_dirs[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
      if [[ -L "$path" || ! -d "$path" ]]; then
        echo "Refusing unsafe Atomic evidence path: $path" >&2
        ownership_status=3
      elif [[ -n "$(sudo find -P "$path" -xdev ! -type d ! \( -type f -links 1 \) -print -quit)" ]]; then
        echo "Refusing linked or special Atomic evidence content: $path" >&2
        ownership_status=3
      elif ! sudo find -P "$path" -xdev \( -type d -o \( -type f -links 1 \) \) \
        -exec chown --no-dereference "$(id -u):$(id -g)" -- {} +; then
        ownership_status=4
      fi
    fi
  done
fi
if (( ownership_status == 0 )); then
  # shellcheck disable=SC2024
  sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
    --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode --property=ExecMainStatus \
    > "$evidence/systemd-result.txt" || true
else
  sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
    --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode --property=ExecMainStatus \
    >&2 || true
fi
(( status == 0 )) || exit "$status"
exit "$ownership_status"
