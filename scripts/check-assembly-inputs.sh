#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Assembly input acceptance requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/assembly-input-evidence"
mkdir -p "$evidence"
case "${1:-}" in
  builder)
    unit="symbi-builder-reuse-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    set +e
    sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
      --uid="$(id -u)" --gid="$(id -g)" \
      --property=MemoryMax=512M --property=MemorySwapMax=0 --property=CPUQuota=100% \
      --property=TasksMax=64 --property=Nice=10 --property=RuntimeMaxSec=16min --property=KillMode=control-group \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      "HOME=$HOME" "USER=$USER" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
      "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_SERVER_URL=$GITHUB_SERVER_URL" \
      "GITHUB_SHA=$GITHUB_SHA" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
      "GITHUB_EVENT_PATH=$GITHUB_EVENT_PATH" "GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME" \
      "GITHUB_REF_NAME=$GITHUB_REF_NAME" "GITHUB_REF=$GITHUB_REF" PYTHONDONTWRITEBYTECODE=1 \
      python3 -m image.assembly.builder_reuse 2>&1 | tee "$evidence/hosted-builder.log"
    status=${PIPESTATUS[0]}
    set -e
    ;;
  runtime)
    unit="symbi-runtime-reuse-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    set +e
    sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
      --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
      --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=25min \
      --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      HOME=/root USER=root GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
      "GITHUB_SHA=$GITHUB_SHA" PYTHONDONTWRITEBYTECODE=1 \
      python3 -m image.assembly.runtime_compatibility 2>&1 | tee "$evidence/hosted-runtime.log"
    status=${PIPESTATUS[0]}
    set -e
    sudo chown -R "$(id -u):$(id -g)" "$evidence"
    ;;
  *) echo 'Select builder or runtime.' >&2; exit 2 ;;
esac
exit "$status"
