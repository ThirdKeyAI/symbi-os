#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Interactive appliance production requires a disposable GitHub-hosted runner.' >&2
  exit 1
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic && "${SYMBI_QUALIFICATION:-}" == appliance ]] || exit 2
root=$(git rev-parse --show-toplevel)
cache="$root/.cache"
paths=(
  "$cache/atomic-disk-evidence"
  "$cache/interactive-appliance-evidence"
  "$cache/interactive-appliance-stage"
  "$cache/interactive-appliance-artifact"
)
if [[ -L $cache || ( -e $cache && ! -d $cache ) ]]; then
  echo 'Appliance cache root is not a direct directory.' >&2
  exit 3
fi
mkdir -p "$cache"
for path in "${paths[@]}"; do
  if [[ -e $path || -L $path ]]; then
    echo "Appliance output path must be new: $path" >&2
    exit 3
  fi
done
unit="symbi-appliance-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=5G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=RuntimeMaxSec=115min --property=Nice=10 \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  SYMBI_IMAGE_VARIANT=generic SYMBI_QUALIFICATION=appliance PYTHONDONTWRITEBYTECODE=1 \
  python3 -m image.atomic.hosted
status=$?
set -e
ownership_status=0
for path in "$cache/atomic-disk-evidence" "$cache/interactive-appliance-evidence" \
            "$cache/interactive-appliance-artifact"; do
  if [[ -e $path || -L $path ]]; then
    if [[ -L $path || ! -d $path ]] || \
       [[ -n "$(sudo find -P "$path" -xdev ! -type d ! \( -type f -links 1 \) -print -quit)" ]]; then
      echo "Refusing unsafe appliance output: $path" >&2
      ownership_status=3
    elif ! sudo find -P "$path" -xdev \( -type d -o \( -type f -links 1 \) \) \
      -exec chown --no-dereference "$(id -u):$(id -g)" -- {} +; then
      ownership_status=4
    fi
  fi
done
if (( status != 0 || ownership_status != 0 )) && \
   [[ -e $cache/interactive-appliance-evidence || -L $cache/interactive-appliance-evidence ]]; then
  sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH="$root" \
    GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    /usr/bin/python3 -m image.appliance.hosted --sanitize-failure || true
  if [[ -d $cache/interactive-appliance-evidence && ! -L $cache/interactive-appliance-evidence ]] && \
     [[ -z "$(sudo find -P "$cache/interactive-appliance-evidence" -xdev ! -type d ! \( -type f -links 1 \) -print -quit)" ]]; then
    sudo find -P "$cache/interactive-appliance-evidence" -xdev \
      \( -type d -o \( -type f -links 1 \) \) \
      -exec chown --no-dereference "$(id -u):$(id -g)" -- {} + || ownership_status=4
  fi
fi
if (( ownership_status == 0 )); then
  resource="$cache/interactive-appliance-evidence/systemd-result.txt"
  if [[ -d $cache/interactive-appliance-evidence && ! -L $cache/interactive-appliance-evidence ]]; then
    sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
      --property=MemorySwapPeak --property=CPUUsageNSec --property=ExecMainCode \
      --property=ExecMainStatus > "$resource" || true
    if [[ -L $resource || ! -f $resource ]] || (( $(stat --format=%s "$resource") > 4096 )); then
      rm -f -- "$resource"
      ownership_status=5
    fi
  fi
fi
(( status == 0 )) || exit "$status"
exit "$ownership_status"
