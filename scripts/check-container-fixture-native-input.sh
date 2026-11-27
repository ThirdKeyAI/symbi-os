#!/usr/bin/env bash
set -euo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted \
  && "${GITHUB_REPOSITORY:-}" == ThirdKeyAI/symbi-os \
  && "${SYMBI_REQUESTED_QUALIFICATION:-}" == containers ]] || {
  echo 'Native fixture intake requires the disposable hosted container gate.' >&2
  exit 1
}
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ \
  && "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ \
  && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'Native fixture intake requires exact consumer run identity.' >&2
  exit 1
}

root=$(git rev-parse --show-toplevel)
unit="symbi-fixture-input-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
evidence="$root/.cache/container-fixture-native-evidence"
set +e
sudo systemd-run --unit="$unit" --remain-after-exit \
  --uid="$(id -u)" --gid="$(id -g)" \
  --working-directory="$root" --property=MemoryMax=1G --property=MemorySwapMax=0 \
  --property=CPUQuota=100% --property=TasksMax=64 --property=RuntimeMaxSec=30min \
  --property=TimeoutStopSec=15 --property=Nice=10 --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_SHA=$GITHUB_SHA" \
  "GITHUB_RUN_ID=$GITHUB_RUN_ID" "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" \
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs --root "$root" consume \
  --bundle "$root/.cache/container-native-fixture-image.zip" \
  --run-metadata "$root/.cache/container-native-fixture-run.json" \
  --artifact-metadata "$root/.cache/container-native-fixture-artifact.json" \
  --destination "$root/.cache/container-native-fixture-inputs" \
  --evidence "$evidence"
status=$?
set -e
if (( status == 0 )); then
  deadline=$((SECONDS + 1860))
  while true; do
    set +e
    exec_code=$(sudo systemctl show "$unit" --value --property=ExecMainCode)
    exec_status=$?
    active_state=$(sudo systemctl show "$unit" --value --property=ActiveState)
    active_status=$?
    set -e
    if (( exec_status != 0 || active_status != 0 )); then
      status=1
      break
    fi
    if [[ "$exec_code" =~ ^[1-9][0-9]*$ ]]; then
      break
    fi
    if [[ "$active_state" == failed || "$active_state" == inactive ]]; then
      status=1
      break
    fi
    if (( SECONDS >= deadline )); then
      status=1
      break
    fi
    sleep 1
  done
fi
mkdir -p "$evidence"
set +e
# shellcheck disable=SC2024
sudo systemctl show "$unit" --property=LoadState --property=Result --property=MemoryPeak \
  --property=MemorySwapPeak --property=ExecMainCode --property=ExecMainStatus \
  --property=ControlGroup --property=ActiveState --property=SubState \
  > "$evidence/systemd-result.txt"
show_status=$?
set -e
if (( show_status != 0 )); then
  status=1
elif ! PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs \
    --root "$root" validate-unit-result --result "$evidence/systemd-result.txt"; then
  status=1
fi
sudo systemctl stop "$unit" >/dev/null 2>&1 || status=1
exit "$status"
