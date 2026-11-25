#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Runtime compilation requires a GitHub-hosted runner.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/runtime-workspace-evidence"
mkdir -p "$evidence"
unit="symbi-runtime-workspace-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe \
  --uid="$(id -u)" --gid="$(id -g)" --working-directory="$root" \
  --property=MemoryMax=8G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=110min \
  --property=KillMode=control-group \
  /usr/bin/env -i "PATH=$PATH" "HOME=$HOME" "USER=$USER" \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  "CARGO_HOME=$root/.cache/runtime-cargo" "CARGO_TARGET_DIR=$root/.cache/runtime-target" \
  CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 RAYON_NUM_THREADS=1 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_INCREMENTAL=false CARGO_PROFILE_TEST_INCREMENTAL=false \
  CARGO_PROFILE_DEV_CODEGEN_UNITS=1 CARGO_PROFILE_TEST_CODEGEN_UNITS=1 \
  CMAKE_BUILD_PARALLEL_LEVEL=1 NUM_JOBS=1 MAKEFLAGS=-j1 PYTHONDONTWRITEBYTECODE=1 \
  python3 image/container/upstream/check_workspace.py 2>&1 | tee "$evidence/hosted-checks.log"
status=${PIPESTATUS[0]}
set -e
load_state=$(sudo systemctl show "$unit" --property=LoadState --value)
if [[ "$load_state" == not-found ]]; then
  printf 'LoadState=not-found\nObservation=unit collected; use cgroup-final.json\n' > "$evidence/systemd-result.txt"
else
  sudo systemctl show "$unit" --property=LoadState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUUsageNSec,RuntimeMaxUSec > "$evidence/systemd-result.txt"
fi
exit "$status"
