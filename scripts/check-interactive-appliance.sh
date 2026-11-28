#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(git rev-parse --show-toplevel)
cache="$root/.cache"
evidence_ready="$cache/interactive-appliance-evidence.ready"
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
if [[ -e $evidence_ready || -L $evidence_ready ]]; then
  rm -f -- "$evidence_ready"
fi
[[ ! -e $evidence_ready && ! -L $evidence_ready ]] || exit 3
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'Interactive appliance production requires a disposable GitHub-hosted runner.' >&2
  exit 1
}
[[ "${SYMBI_IMAGE_VARIANT:-}" == generic && "${SYMBI_QUALIFICATION:-}" == appliance ]] || exit 2
[[ "${SYMBI_APPLIANCE_EXPECTED_EXPIRY:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || exit 2
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] || exit 2
for path in "${paths[@]}"; do
  if [[ -e $path || -L $path ]]; then
    echo "Appliance output path must be new: $path" >&2
    exit 3
  fi
done
unit="symbi-appliance-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
unit_started=0
unit_terminal=0
unit_outcome=
unit_control_group=
expected_control_group="/system.slice/${unit}.service"

capture_control_group() {
  local control='' control_seen=0 key load='' load_seen=0 snapshot value
  snapshot=$(sudo systemctl show "$unit" --property=LoadState \
    --property=ControlGroup 2>/dev/null) || return 1
  while IFS='=' read -r key value; do
    case "$key" in
      LoadState)
        (( load_seen == 0 )) || return 1
        load=$value
        load_seen=1
        ;;
      ControlGroup)
        (( control_seen == 0 )) || return 1
        control=$value
        control_seen=1
        ;;
      *) return 1 ;;
    esac
  done <<< "$snapshot"
  (( load_seen == 1 && control_seen == 1 )) || return 1
  [[ $load == loaded && $control == "$expected_control_group" ]] || return 1
  unit_control_group=$control
}

stop_and_reset_unit() {
  local captured=1 cgroup_path control control_seen deadline key load load_seen parsed snapshot value
  (( unit_started == 1 )) || return 0
  if [[ -z $unit_control_group ]] && ! capture_control_group; then
    captured=0
  fi
  timeout 30 sudo systemctl stop "$unit" >/dev/null 2>&1 || true
  timeout 30 sudo systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    load=
    control=
    load_seen=0
    control_seen=0
    parsed=1
    if snapshot=$(sudo systemctl show "$unit" --property=LoadState \
        --property=ControlGroup 2>/dev/null); then
      while IFS='=' read -r key value; do
        case "$key" in
          LoadState)
            if (( load_seen == 1 )); then parsed=0; break; fi
            load=$value
            load_seen=1
            ;;
          ControlGroup)
            if (( control_seen == 1 )); then parsed=0; break; fi
            control=$value
            control_seen=1
            ;;
          *) parsed=0; break ;;
        esac
      done <<< "$snapshot"
      if (( parsed == 1 && load_seen == 1 && control_seen == 1 && captured == 1 )) \
          && [[ $load == not-found && -z $control ]]; then
        cgroup_path="/sys/fs/cgroup${unit_control_group}"
        if [[ ! -e $cgroup_path && ! -L $cgroup_path ]]; then
          unit_started=0
          return 0
        fi
      fi
    fi
    sleep 1
  done
  return 1
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap.
cleanup_on_exit() {
  stop_and_reset_unit || true
}
trap cleanup_on_exit EXIT

wait_for_terminal_unit() {
  local active deadline grace key load observed snapshot sub value
  deadline=$((SECONDS + 7020))
  grace=$((SECONDS + 10))
  observed=0
  while (( SECONDS < deadline )); do
    load=
    active=
    sub=
    if snapshot=$(sudo systemctl show "$unit" --property=LoadState \
        --property=ActiveState --property=SubState 2>/dev/null); then
      while IFS='=' read -r key value; do
        case "$key" in
          LoadState) load=$value ;;
          ActiveState) active=$value ;;
          SubState) sub=$value ;;
        esac
      done <<< "$snapshot"
      if [[ $load == loaded ]]; then
        observed=1
      elif (( observed == 1 || SECONDS >= grace )); then
        return 125
      fi
      if [[ $load == loaded && $active == active && $sub == exited ]]; then
        unit_outcome=success
        return 0
      fi
      if [[ $load == loaded && $active == failed && $sub == failed ]]; then
        unit_outcome=failure
        return 0
      fi
    elif (( observed == 1 || SECONDS >= grace )); then
      return 126
    fi
    sleep 2
  done
  return 124
}

set +e
sudo systemd-run --unit="$unit" --no-block --working-directory="$root" \
  --property=Type=oneshot --property=RemainAfterExit=yes \
  --property=OOMPolicy=stop \
  --property=MemoryMax=5G --property=MemorySwapMax=0 --property=CPUQuota=200% \
  --property=TasksMax=256 --property=TimeoutStartSec=115min \
  --property=TimeoutStopSec=30s --property=RuntimeMaxSec=115min --property=Nice=10 \
  --property=Delegate=yes --property=DelegateSubgroup=supervisor --property=KillMode=control-group \
  /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "GITHUB_SHA=$GITHUB_SHA" \
  SYMBI_IMAGE_VARIANT=generic SYMBI_QUALIFICATION=appliance PYTHONDONTWRITEBYTECODE=1 \
  "SYMBI_APPLIANCE_EXPECTED_EXPIRY=$SYMBI_APPLIANCE_EXPECTED_EXPIRY" \
  python3 -m image.atomic.hosted
launch_status=$?
status=$launch_status
if (( launch_status == 0 )); then
  unit_started=1
  wait_for_terminal_unit
  wait_status=$?
  if (( wait_status == 0 )); then
    unit_terminal=1
    if [[ $unit_outcome == success ]]; then
      status=0
    else
      status=1
    fi
  else
    status=$wait_status
  fi
fi
set -e
if (( unit_started == 1 && unit_terminal == 0 )); then
  stop_and_reset_unit || true
fi
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

sanitize_evidence() {
  sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH="$root" \
    GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m image.appliance.hosted --sanitize-failure
}

adopt_evidence() {
  local directory="$cache/interactive-appliance-evidence"
  [[ -d $directory && ! -L $directory ]] || return 1
  [[ -z "$(sudo find -P "$directory" -xdev ! -type d ! \( -type f -links 1 \) -print -quit)" ]] || return 1
  sudo find -P "$directory" -xdev \( -type d -o \( -type f -links 1 \) \) \
    -exec chown --no-dereference "$(id -u):$(id -g)" -- {} +
}

write_systemd_result() {
  local control_seen=0 key raw resource temporary valid=1 value
  (( unit_started == 1 && unit_terminal == 1 )) || return 1
  resource="$cache/interactive-appliance-evidence/systemd-result.txt"
  [[ ! -e $resource && ! -L $resource ]] || return 1
  raw=$(mktemp --tmpdir="$(dirname "$resource")" .systemd-result.raw.XXXXXX) || return 1
  temporary=$(mktemp --tmpdir="$(dirname "$resource")" .systemd-result.XXXXXX) || {
    rm -f -- "$raw"
    return 1
  }
  # The adopted evidence directory is intentionally written by the runner shell.
  # shellcheck disable=SC2024
  if ! sudo systemctl show "$unit" --property=LoadState --property=Type \
      --property=RemainAfterExit --property=ActiveState --property=SubState \
      --property=Result --property=OOMPolicy --property=MemoryPeak \
      --property=MemoryMax --property=MemorySwapMax --property=MemorySwapPeak \
      --property=CPUUsageNSec --property=ExecMainCode \
      --property=ExecMainStatus --property=ControlGroup > "$raw"; then
    rm -f -- "$raw" "$temporary"
    return 1
  fi
  while IFS='=' read -r key value; do
    if [[ $key == ControlGroup ]]; then
      if (( control_seen == 1 )) || [[ $value != "$expected_control_group" ]]; then
        valid=0
        break
      fi
      unit_control_group=$value
      control_seen=1
    elif [[ ! $key =~ ^[A-Za-z][A-Za-z0-9]*$ || -z $value ]]; then
      valid=0
      break
    elif ! printf '%s=%s\n' "$key" "$value" >> "$temporary"; then
      valid=0
      break
    fi
  done < "$raw"
  rm -f -- "$raw"
  if (( valid == 0 || control_seen == 0 )); then
    rm -f -- "$temporary"
    return 1
  fi
  if [[ -L $temporary || ! -f $temporary ]] || \
     (( $(stat --format=%h "$temporary") != 1 || $(stat --format=%s "$temporary") > 4096 )); then
    rm -f -- "$temporary"
    return 1
  fi
  mv -- "$temporary" "$resource"
  /usr/bin/sync -f "$resource"
}

validate_evidence() {
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin PYTHONPATH="$root" \
    GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted PYTHONDONTWRITEBYTECODE=1 \
    "SYMBI_APPLIANCE_EXPECTED_EXPIRY=$SYMBI_APPLIANCE_EXPECTED_EXPIRY" \
    /usr/bin/python3 -m image.appliance.hosted --validate-evidence
}

discard_appliance_output() {
  local failed=0 path
  for path in "$cache/interactive-appliance-evidence" \
              "$cache/interactive-appliance-stage" \
              "$cache/interactive-appliance-artifact"; do
    if [[ -e $path || -L $path ]]; then
      sudo rm -rf --one-file-system -- "$path" || failed=1
    fi
    [[ ! -e $path && ! -L $path ]] || failed=1
  done
  if [[ -e $evidence_ready || -L $evidence_ready ]]; then
    rm -f -- "$evidence_ready" || failed=1
  fi
  [[ ! -e $evidence_ready && ! -L $evidence_ready ]] || failed=1
  return "$failed"
}

evidence_prepared=0
evidence_status=0
evidence_valid=0
if (( status != 0 || ownership_status != 0 )) && ! sanitize_evidence; then
  evidence_status=4
elif ! adopt_evidence; then
  evidence_status=4
elif ! write_systemd_result; then
  evidence_status=5
else
  evidence_prepared=1
fi
cleanup_status=0
if ! stop_and_reset_unit; then
  cleanup_status=9
fi
if (( evidence_prepared == 1 && cleanup_status == 0 )); then
  if ! adopt_evidence; then
    evidence_status=6
  elif ! validate_evidence; then
    evidence_status=7
  elif (( status != 0 || ownership_status != 0 )) && \
      [[ -e $cache/interactive-appliance-artifact || \
         -L $cache/interactive-appliance-artifact ]]; then
    evidence_status=7
  else
    evidence_valid=1
  fi
fi
if (( evidence_valid == 1 )); then
  if [[ -n "${GITHUB_OUTPUT:-}" && -f "$GITHUB_OUTPUT" && ! -L "$GITHUB_OUTPUT" ]] \
      && printf 'evidence_ready=true\n' >> "$GITHUB_OUTPUT"; then
    :
  else
    evidence_valid=0
    evidence_status=8
  fi
fi
if (( evidence_valid == 0 )); then
  if ! discard_appliance_output && (( evidence_status == 0 )); then
    evidence_status=10
  fi
fi
(( status == 0 )) || exit "$status"
(( ownership_status == 0 )) || exit "$ownership_status"
(( cleanup_status == 0 )) || exit "$cleanup_status"
exit "$evidence_status"
