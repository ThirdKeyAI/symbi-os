#!/usr/bin/env bash
set -euo pipefail

# Intentionally no local fallback: keep native compilation off the workstation.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Image tool compilation requires a GitHub-hosted runner.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/image-tool-evidence"
mkdir -p "$evidence"
unit="symbi-image-tools-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe \
  --uid="$(id -u)" --gid="$(id -g)" --working-directory="$root" \
  --property=MemoryMax=4G --property=MemorySwapMax=0 \
  --property=CPUQuota=200% --property=TasksMax=256 --property=Nice=10 \
  --property=RuntimeMaxSec=45min --property=KillMode=control-group \
  /usr/bin/env -i "PATH=$PATH" "HOME=$HOME" "USER=$USER" \
  "GITHUB_ACTIONS=true" "RUNNER_ENVIRONMENT=github-hosted" \
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_SERVER_URL=$GITHUB_SERVER_URL" \
  "GITHUB_SHA=$GITHUB_SHA" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
  "GITHUB_EVENT_PATH=$GITHUB_EVENT_PATH" "GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME" \
  "GITHUB_REF_NAME=$GITHUB_REF_NAME" "GITHUB_REF=$GITHUB_REF" \
  "CARGO_BUILD_JOBS=1" "CARGO_PROFILE_DEV_DEBUG=0" "CARGO_PROFILE_DEV_INCREMENTAL=false" \
  "CARGO_PROFILE_DEV_CODEGEN_UNITS=1" "RAYON_NUM_THREADS=1" "RUST_TEST_THREADS=1" \
  "CARGO_TARGET_DIR=$root/.cache/bluebuild-target" "NO_COLOR=1" \
  python3 image/toolchain/build.py 2>&1 | tee "$evidence/hosted-build.log"
status=${PIPESTATUS[0]}
set -e
# Successful transient units may be collected before this query. Never present
# default properties of a missing unit as measured runtime statistics.
load_state=$(sudo systemctl show "$unit" --property=LoadState --value)
if [[ "$load_state" == not-found ]]; then
  printf 'LoadState=not-found\nObservation=unit collected; use cgroup-final.json and completion log\n' > "$evidence/systemd-result.txt"
else
  sudo systemctl show "$unit" \
    --property=LoadState --property=Result --property=ExecMainStatus --property=MemoryPeak --property=MemoryMax \
    --property=MemorySwapMax --property=CPUQuotaPerSecUSec --property=CPUUsageNSec \
    --property=TasksMax --property=RuntimeMaxUSec > "$evidence/systemd-result.txt"
fi
exit "$status"
