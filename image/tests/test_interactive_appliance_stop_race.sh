#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
temporary=$(mktemp -d)
fixture="$temporary/repository"
commands="$temporary/commands"
writer_pid=

cleanup() {
  if [[ -f $temporary/writer.pid ]]; then
    writer_pid=$(<"$temporary/writer.pid")
    kill "$writer_pid" 2>/dev/null || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

mkdir -p "$fixture/image/appliance" "$commands"
printf '' > "$temporary/github-output"
printf '' > "$fixture/image/__init__.py"
printf '' > "$fixture/image/appliance/__init__.py"

cat > "$fixture/image/appliance/hosted.py" <<'PY'
from pathlib import Path
import sys

root = Path.cwd()
evidence = root / ".cache/interactive-appliance-evidence"
if sys.argv[1:] == ["--sanitize-failure"]:
    raise SystemExit(0)
if sys.argv[1:] != ["--validate-evidence"]:
    raise SystemExit(2)

names = {path.name for path in evidence.iterdir()}
receipt = (evidence / "result.json").read_bytes()
systemd = (evidence / "systemd-result.txt").read_bytes()
mutated = receipt != b'{"passed":true}\n'
added = "stop-time-extra.txt" in names
credential = b"PRIVATE KEY-----" in systemd
if mutated or added or credential:
    if mutated and added and credential:
        (root / "validator-observed-stop-race").touch()
    raise SystemExit(1)
if names != {"result.json", "systemd-result.txt"}:
    raise SystemExit(1)
PY

cat > "$commands/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == rev-parse && ${2:-} == --show-toplevel ]]
printf '%s\n' "$FIXTURE_ROOT"
SH

cat > "$commands/sudo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exec "$@"
SH

cat > "$commands/systemd-run" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
evidence="$FIXTURE_ROOT/.cache/interactive-appliance-evidence"
artifact="$FIXTURE_ROOT/.cache/interactive-appliance-artifact"
mkdir -p "$evidence" "$artifact"
printf '{"passed":true}\n' > "$evidence/result.json"
printf 'public appliance bytes\n' > "$artifact/fixture.qcow2"
if [[ $RACE_MODE == mutate ]]; then
  (
    while [[ ! -e $FIXTURE_STATE/stop-writer ]]; do
      sleep 0.01
    done
    printf '{"passed":false,"mutated_during_stop":true}\n' > "$evidence/result.json"
    printf 'unapproved evidence\n' > "$evidence/stop-time-extra.txt"
    printf 'PRIVATE KEY-----injected-during-stop\n' >> "$evidence/systemd-result.txt"
    touch "$FIXTURE_STATE/writer-done"
  ) &
  printf '%s\n' "$!" > "$FIXTURE_STATE/writer.pid"
else
  touch "$FIXTURE_STATE/writer-done"
fi
SH

cat > "$commands/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
operation=${1:-}
shift || true
case "$operation" in
  show)
    if [[ -e $FIXTURE_STATE/unit-cleaned ]]; then
      if [[ " $* " == *" --value "* ]]; then
        printf 'not-found\n'
      else
        printf 'LoadState=not-found\nControlGroup=\n'
      fi
    elif [[ " $* " == *" --property=MemoryPeak "* ]]; then
      if [[ $RACE_MODE == cleanup-survival ]]; then
        active=failed
        sub=failed
        result=exit-code
        status=1
      else
        active=active
        sub=exited
        result=success
        status=0
      fi
      cat <<EOF
LoadState=loaded
Type=oneshot
RemainAfterExit=yes
ActiveState=$active
SubState=$sub
Result=$result
OOMPolicy=stop
MemoryPeak=1
MemoryMax=5368709120
MemorySwapMax=0
MemorySwapPeak=0
CPUUsageNSec=1
ExecMainCode=1
ExecMainStatus=$status
ControlGroup=/system.slice/symbi-appliance-1-1.service
EOF
    elif [[ " $* " == *" --property=ControlGroup "* ]]; then
      printf 'LoadState=loaded\nControlGroup=/system.slice/symbi-appliance-1-1.service\n'
    elif [[ $RACE_MODE == cleanup-survival ]]; then
      printf 'LoadState=loaded\nActiveState=failed\nSubState=failed\n'
    else
      printf 'LoadState=loaded\nActiveState=active\nSubState=exited\n'
    fi
    ;;
  stop)
    touch "$FIXTURE_STATE/stop-writer"
    for _ in $(seq 1 500); do
      [[ -e $FIXTURE_STATE/writer-done ]] && exit 0
      sleep 0.01
    done
    exit 1
    ;;
  reset-failed)
    [[ -e $FIXTURE_STATE/writer-done ]]
    touch "$FIXTURE_STATE/unit-cleaned"
    ;;
  *)
    exit 2
    ;;
esac
SH

chmod 0755 "$commands/git" "$commands/sudo" "$commands/systemctl" \
  "$commands/systemd-run"

run_wrapper() {
  local mode=$1
  (
    cd "$fixture"
    PATH="$commands:/usr/bin:/bin" \
    FIXTURE_ROOT="$fixture" FIXTURE_STATE="$temporary" RACE_MODE="$mode" \
    GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
    GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 GITHUB_SHA="$(printf 'a%.0s' {1..40})" \
    GITHUB_OUTPUT="$temporary/github-output" \
    SYMBI_IMAGE_VARIANT=generic SYMBI_QUALIFICATION=appliance \
    SYMBI_APPLIANCE_EXPECTED_EXPIRY=2026-11-30T00:00:00Z \
    bash "$repository/scripts/check-interactive-appliance.sh"
  )
}

set +e
run_wrapper mutate
status=$?
set -e

[[ $status -ne 0 ]]
[[ -e $fixture/validator-observed-stop-race ]]
[[ ! -s $temporary/github-output ]]
[[ ! -e $fixture/.cache/interactive-appliance-evidence ]]
[[ ! -e $fixture/.cache/interactive-appliance-artifact ]]
if grep -qx 'evidence_ready=true' "$temporary/github-output"; then
  touch "$temporary/uploaded"
fi
[[ ! -e $temporary/uploaded ]]

rm -f -- "$temporary/stop-writer" "$temporary/writer-done" \
  "$temporary/unit-cleaned" "$temporary/writer.pid"
printf '' > "$temporary/github-output"
set +e
run_wrapper cleanup-survival
status=$?
set -e
[[ $status -ne 0 ]]
[[ ! -s $temporary/github-output ]]
[[ ! -e $fixture/.cache/interactive-appliance-evidence ]]
[[ ! -e $fixture/.cache/interactive-appliance-artifact ]]

rm -f -- "$temporary/stop-writer" "$temporary/writer-done" \
  "$temporary/unit-cleaned" "$temporary/writer.pid"
printf '' > "$temporary/github-output"
run_wrapper clean
grep -qx 'evidence_ready=true' "$temporary/github-output"
[[ -d $fixture/.cache/interactive-appliance-evidence ]]
[[ -d $fixture/.cache/interactive-appliance-artifact ]]
if grep -qx 'evidence_ready=true' "$temporary/github-output"; then
  touch "$temporary/clean-uploaded"
fi
[[ -e $temporary/clean-uploaded ]]
