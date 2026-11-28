#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Container fixture execution requires GitHub-hosted CI.' >&2
  exit 1
}
root=$(git rev-parse --show-toplevel)
cache="$root/.cache"
evidence="$cache/container-fixture-evidence"
[[ ${GITHUB_RUN_ID:-} =~ ^[1-9][0-9]*$ \
  && ${GITHUB_RUN_ATTEMPT:-} =~ ^[1-9][0-9]*$ ]] || {
  echo 'Container fixture run identity must be canonical.' >&2
  exit 1
}
staging="$cache/.container-fixture-evidence-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.staging"
if [[ -L $cache || ( -e $cache && ! -d $cache ) ]]; then
  echo 'Container fixture cache must be a direct directory.' >&2
  exit 1
fi
mkdir -p -- "$cache"
[[ -d $cache && ! -L $cache ]] || exit 1
if [[ -e $evidence || -L $evidence || -e $staging || -L $staging ]]; then
  echo 'Container fixture evidence paths must be new.' >&2
  exit 1
fi
mkdir -m 0700 -- "$staging"
[[ -d $staging && ! -L $staging \
  && "$(stat --format=%a -- "$staging")" == 700 ]] || exit 1
unit="symbi-container-fixtures-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
set +e
sudo systemd-run --unit="$unit" --wait --pipe --working-directory="$root" \
  --property=MemoryMax=4G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=Nice=10 --property=RuntimeMaxSec=75min \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  "GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME" "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" \
  "GITHUB_SHA=$GITHUB_SHA" "GITHUB_RUN_ID=$GITHUB_RUN_ID" \
  "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT" "GITHUB_REF_NAME=$GITHUB_REF_NAME" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
  PYTHONDONTWRITEBYTECODE=1 python3 image/container/hosted/check.py \
  2>&1 | tee "$root/.cache/container-fixture-hosted.log"
status=${PIPESTATUS[0]}
set -e
load_state=$(sudo systemctl show "$unit" --property=LoadState --value)
result="$staging/systemd-result.txt"
[[ ! -e $result && ! -L $result ]] || exit 1
temporary=$(mktemp --tmpdir="$staging" .systemd-result.XXXXXX)
if [[ "$load_state" == not-found ]]; then
  printf 'LoadState=not-found\nObservation=unit collected; use cgroup-final.json\n' > "$temporary"
else
  sudo systemctl show "$unit" --property=LoadState,Result,ExecMainStatus,MemoryPeak,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUUsageNSec,RuntimeMaxUSec > "$temporary"
fi
chmod 0600 -- "$temporary"
[[ -f $temporary && ! -L $temporary \
  && "$(stat --format=%h -- "$temporary")" == 1 \
  && "$(stat --format=%s -- "$temporary")" -le 4096 ]] || exit 1
mv --no-clobber -- "$temporary" "$result"
[[ ! -e $temporary && ! -L $temporary \
  && -f $result && ! -L $result \
  && "$(stat --format=%h -- "$result")" == 1 ]] || exit 1

shopt -s nullglob dotglob
entries=("$staging"/*)
shopt -u nullglob dotglob
(( ${#entries[@]} == 1 || ${#entries[@]} == 2 )) || exit 1
public_seen=0
result_seen=0
for entry in "${entries[@]}"; do
  case "${entry##*/}" in
    public)
      (( public_seen == 0 )) || exit 1
      [[ -d $entry && ! -L $entry ]] || exit 1
      public_seen=1
      ;;
    systemd-result.txt)
      (( result_seen == 0 )) || exit 1
      [[ -f $entry && ! -L $entry \
        && "$(stat --format=%h -- "$entry")" == 1 ]] || exit 1
      result_seen=1
      ;;
    *) exit 1 ;;
  esac
done
(( result_seen == 1 )) || exit 1
if (( status == 0 )); then
  (( public_seen == 1 && ${#entries[@]} == 2 )) || exit 1
fi
mv --no-clobber -- "$staging" "$evidence"
[[ ! -e $staging && ! -L $staging \
  && -d $evidence && ! -L $evidence \
  && "$(stat --format=%a -- "$evidence")" == 700 ]] || exit 1
[[ -n "${GITHUB_OUTPUT:-}" && -f $GITHUB_OUTPUT \
  && ! -L $GITHUB_OUTPUT ]] || exit 1
printf 'evidence_ready=true\n' >> "$GITHUB_OUTPUT"
exit "$status"
