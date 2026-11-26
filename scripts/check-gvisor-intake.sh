#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'gVisor source intake requires disposable GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] || {
  echo 'gVisor source intake requires numeric hosted run identity.' >&2
  exit 1
}
cache="$root/.cache"
evidence="$cache/gvisor-intake-evidence"
hosted_log="$cache/gvisor-intake-hosted-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.log"
if [[ -e "$cache" || -L "$cache" ]]; then
  [[ -d "$cache" && ! -L "$cache" ]] || { echo 'Intake cache root must be a direct directory.' >&2; exit 1; }
else
  mkdir -- "$cache"
fi
[[ ! -e "$evidence" && ! -L "$evidence" && ! -e "$hosted_log" && ! -L "$hosted_log" ]] || {
  echo 'gVisor source intake refuses stale or linked output paths.' >&2
  exit 1
}
umask 0077
unit="symbi-gvisor-intake-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --uid="$(id -u)" --gid="$(id -g)" \
  --property=MemoryMax=512M --property=MemorySwapMax=0 --property=CPUQuota=100% \
  --property=TasksMax=32 --property=Nice=10 --property=RuntimeMaxSec=15min \
  --property=TimeoutStopSec=15 --property=KillMode=control-group \
  --property=NoNewPrivileges=yes --property=CapabilityBoundingSet= \
  --property=PrivateTmp=yes --property=ProtectSystem=strict \
  --property="ReadWritePaths=$root/.cache" --property=UMask=0077 \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  python3 -m image.container.intake 2>&1 | tee "$hosted_log"
pipeline_status=("${PIPESTATUS[@]}")
set -e
status=${pipeline_status[0]}
if (( pipeline_status[1] != 0 )); then status=1; fi
[[ ! -L "$hosted_log" && -f "$hosted_log" ]] || { echo 'Hosted intake log is not a regular file.' >&2; exit 1; }
if [[ -e "$evidence" || -L "$evidence" ]]; then
  [[ -d "$evidence" && ! -L "$evidence" ]] || { echo 'Intake evidence must be a direct directory.' >&2; exit 1; }
else
  mkdir -- "$evidence"
fi
[[ ! -e "$evidence/hosted-intake.log" && ! -L "$evidence/hosted-intake.log" ]] || {
  echo 'Hosted intake evidence log already exists.' >&2
  exit 1
}
mv -- "$hosted_log" "$evidence/hosted-intake.log"
exit "$status"
