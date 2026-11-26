#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Desktop image assembly requires a disposable GitHub-hosted runner.' >&2
  exit 1
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic || "${SYMBI_IMAGE_VARIANT:-}" == nvidia ]] || exit 2
root=$(git rev-parse --show-toplevel)
evidence="$root/.cache/desktop-image-evidence"
mkdir -p "$evidence"
case "${1:-}" in
  prepare)
    unit="symbi-desktop-prep-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    set +e
    sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
      --uid="$(id -u)" --gid="$(id -g)" \
      --property=MemoryMax=512M --property=MemorySwapMax=0 --property=CPUQuota=100% \
      --property=TasksMax=64 --property=Nice=10 --property=RuntimeMaxSec=15min --property=KillMode=control-group \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      "HOME=$HOME" "USER=$USER" GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
      "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_SERVER_URL=$GITHUB_SERVER_URL" \
      "GITHUB_SHA=$GITHUB_SHA" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
      "GITHUB_EVENT_PATH=$GITHUB_EVENT_PATH" "GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME" \
      "GITHUB_REF_NAME=$GITHUB_REF_NAME" "GITHUB_REF=$GITHUB_REF" \
      "SYMBI_IMAGE_VARIANT=$SYMBI_IMAGE_VARIANT" PYTHONDONTWRITEBYTECODE=1 \
      python3 -m image.desktop.prepare 2>&1 | tee "$evidence/hosted-prepare.log"
    status=${PIPESTATUS[0]}
    set -e
    ;;
  build)
    unit="symbi-desktop-build-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
    set +e
    sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
      --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
      --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=55min \
      --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
      /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      HOME=/root USER=root GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
      "GITHUB_SHA=$GITHUB_SHA" PYTHONDONTWRITEBYTECODE=1 \
      python3 -m image.desktop.build 2>&1 | tee "$evidence/hosted-build.log"
    status=${PIPESTATUS[0]}
    set -e
    sudo chown -R "$(id -u):$(id -g)" "$evidence"
    if [[ -d "$root/.cache/desktop-image-output" ]]; then
      sudo chown -R "$(id -u):$(id -g)" "$root/.cache/desktop-image-output"
    fi
    ;;
  *) echo 'Select prepare or build.' >&2; exit 2 ;;
esac
exit "$status"
