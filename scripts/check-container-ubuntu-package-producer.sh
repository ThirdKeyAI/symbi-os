#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 || ( "$1" != discover && "$1" != produce ) ]]; then
  echo 'Usage: check-container-ubuntu-package-producer.sh discover|produce' >&2
  exit 2
fi
mode=$1
[[ "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || {
  echo 'Ubuntu package production requires a manual GitHub-hosted run.' >&2
  exit 1
}

root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
root=$(realpath -e -- "$root")
cache_parent="$root/.cache"
cache="$cache_parent/ubuntu-fixture-package-producer"
work="$cache/private"
evidence="$cache/evidence"
output="$cache/output"
unit="symbi-ubuntu-packages-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
runner_uid=$(id -u)
runner_gid=$(id -g)

verify_direct_directory() {
  python3 - "$1" "$2" "$runner_uid" "$runner_gid" "${3:-}" <<'PY'
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
parent = Path(sys.argv[2]).resolve(strict=True)
expected_uid = int(sys.argv[3])
expected_gid = int(sys.argv[4])
expected_identity = sys.argv[5]
assert path.parent == parent
assert path.name not in ("", ".", "..")
before = os.lstat(path)
assert stat.S_ISDIR(before.st_mode) and not path.is_symlink()
assert path.resolve(strict=True) == path
assert before.st_dev == os.stat(parent).st_dev
assert before.st_uid == expected_uid and before.st_gid == expected_gid
assert stat.S_IMODE(before.st_mode) == 0o700
identity = f"{before.st_dev}:{before.st_ino}"
assert not expected_identity or identity == expected_identity
print(identity)
PY
}

# A hosted checkout is fresh.  Refuse residue rather than recursively deleting
# an unverified name.  The exact direct cache root is created beneath the exact
# checkout and retained without later recursive pathname mutation.
if [[ -e "$cache" || -L "$cache" ]]; then
  echo 'Ubuntu package producer cache already exists; refusing cleanup by name.' >&2
  exit 1
fi
if [[ -e "$cache_parent" || -L "$cache_parent" ]]; then
  verify_direct_directory "$cache_parent" "$root"
else
  install -d -m 0700 "$cache_parent"
fi
install -d -m 0700 "$cache" "$work" "$evidence" "$output"
cache_parent_identity=$(verify_direct_directory "$cache_parent" "$root")
cache_identity=$(verify_direct_directory "$cache" "$cache_parent")
work_identity=$(verify_direct_directory "$work" "$cache")
evidence_identity=$(verify_direct_directory "$evidence" "$cache")
output_identity=$(verify_direct_directory "$output" "$cache")

metadata_input=
metadata_input_identity=
if [[ "$mode" == produce ]]; then
  if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo 'Production repository code requires GITHUB_TOKEN only for reviewed metadata transfer.' >&2
    exit 1
  fi
  metadata_input="$cache/metadata-input"
  set +e
  env -i \
    "PATH=/usr/bin:/bin" \
    "HOME=$work" \
    "LANG=C.UTF-8" \
    "LC_ALL=C.UTF-8" \
    "PYTHONDONTWRITEBYTECODE=1" \
    "GITHUB_TOKEN=$GITHUB_TOKEN" \
    python3 -m image.container.ubuntu_fixture_metadata \
      --root "$root" --destination "$metadata_input" \
      >"$evidence/metadata-transfer.json" \
      2>"$evidence/metadata-transfer.stderr"
  transfer_status=$?
  set -e
  unset GITHUB_TOKEN
  if [[ $transfer_status -ne 0 ]]; then
    printf 'retained metadata transfer failed with status %d\n' \
      "$transfer_status" >&2
    exit "$transfer_status"
  fi
  metadata_input_identity=$(
    verify_direct_directory "$metadata_input" "$cache")
elif [[ -n "${GITHUB_TOKEN:-}" ]]; then
  echo 'Discovery refuses a workflow token.' >&2
  exit 1
fi

systemd_args=(
  "--unit=$unit"
  "--wait"
  "--pipe"
  "--working-directory=$root"
  "--property=MemoryMax=2147483648"
  "--property=MemorySwapMax=0"
  "--property=CPUQuota=100%"
  "--property=CPUQuotaPeriodSec=100ms"
  "--property=TasksMax=128"
  "--property=RuntimeMaxSec=3000"
  "--property=TimeoutStopSec=30s"
  "--property=KillMode=control-group"
  "--property=OOMPolicy=kill"
  "--property=UMask=0077"
  "--property=User=$runner_uid"
  "--property=Group=$runner_gid"
  "--property=NoNewPrivileges=yes"
  "--property=PrivateDevices=yes"
  "--property=PrivateMounts=yes"
  "--property=PrivateTmp=yes"
  "--property=ProtectSystem=strict"
  "--property=ProtectHome=read-only"
  "--property=ProtectControlGroups=yes"
  "--property=ProtectKernelModules=yes"
  "--property=ProtectKernelTunables=yes"
  "--property=RestrictSUIDSGID=yes"
  "--property=ReadWritePaths=$cache"
  "--property=LockPersonality=yes"
  "--property=SystemCallArchitectures=native"
)
if [[ "$mode" == discover ]]; then
  systemd_args+=(
    "--property=RestrictNamespaces=yes"
    "--property=CapabilityBoundingSet="
    "--property=AmbientCapabilities="
  )
else
  # Production is unreachable while metadata pins are pending.  Once reviewed
  # ready pins exist, CAP_SYS_ADMIN is used only for exact `unshare --net` calls.
  systemd_args+=(
    "--property=RestrictNamespaces=net"
    "--property=CapabilityBoundingSet=CAP_SYS_ADMIN"
    "--property=AmbientCapabilities=CAP_SYS_ADMIN"
  )
fi
clean_env=(
  "PATH=/usr/bin:/bin"
  "HOME=$work"
  "LANG=C.UTF-8"
  "LC_ALL=C.UTF-8"
  "PYTHONDONTWRITEBYTECODE=1"
  "GITHUB_ACTIONS=true"
  "RUNNER_ENVIRONMENT=github-hosted"
  "RUNNER_OS=$RUNNER_OS"
  "RUNNER_ARCH=$RUNNER_ARCH"
  "GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME"
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY"
  "GITHUB_REPOSITORY_ID=$GITHUB_REPOSITORY_ID"
  "GITHUB_SHA=$GITHUB_SHA"
  "GITHUB_RUN_ID=$GITHUB_RUN_ID"
  "GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT"
  "GITHUB_REF_NAME=$GITHUB_REF_NAME"
  "GITHUB_WORKFLOW_REF=$GITHUB_WORKFLOW_REF"
)
producer_argv=(
  "python3"
  "-m"
  "image.container.ubuntu_fixture_package_hosted"
  "run"
  "--root"
  "$root"
  "--mode"
  "$mode"
  "--work"
  "$work"
  "--evidence"
  "$evidence"
  "--output"
  "$output"
)
if [[ "$mode" == produce ]]; then
  producer_argv+=(
    "--metadata-input"
    "$metadata_input"
  )
fi

set +e
# The hosted account owns evidence; only the transient unit creation is sudo.
# shellcheck disable=SC2024
sudo systemd-run "${systemd_args[@]}" /usr/bin/env -i "${clean_env[@]}" "${producer_argv[@]}" > >(tee "$evidence/hosted-producer.log") 2> >(tee "$evidence/hosted-producer.stderr" >&2)
status=$?
set -e

systemd_properties=(
  "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus"
  "--property=MemoryCurrent,MemoryPeak,MemoryMax,MemorySwapCurrent,MemorySwapPeak,MemorySwapMax"
  "--property=CPUQuotaPerSecUSec,CPUQuotaPeriodUSec,CPUUsageNSec"
  "--property=TasksCurrent,TasksMax,RuntimeMaxUSec"
)
set +e
# The hosted account deliberately opens this retained evidence file.
# shellcheck disable=SC2024
sudo systemctl show "$unit" "${systemd_properties[@]}" > "$evidence/systemd-result.txt"
systemd_status=$?
set -e
if [[ $systemd_status -ne 0 ]]; then
  printf 'systemctl show failed with status %d\n' "$systemd_status" >> "$evidence/systemd-result.txt"
  status=1
fi

# Always retain a separate systemd-derived resource record.  A killed process
# can leave cgroup-final.json present but empty or partial; existence is never
# treated as evidence and never suppresses this fallback.
env -i "PATH=/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8" "LC_ALL=C.UTF-8" "PYTHONDONTWRITEBYTECODE=1" python3 -m image.container.ubuntu_fixture_package_hosted resource-fallback --systemd "$evidence/systemd-result.txt" --output "$evidence/systemd-fallback.json"

# Never recursively mutate a pathname after the same-UID unit has run.  Bind
# the exact directories created above and retain all private scratch for the
# ephemeral hosted runner to discard after artifacts have been collected.
verify_direct_directory "$cache_parent" "$root" "$cache_parent_identity" >/dev/null
verify_direct_directory "$cache" "$cache_parent" "$cache_identity" >/dev/null
verify_direct_directory "$work" "$cache" "$work_identity" >/dev/null
verify_direct_directory "$evidence" "$cache" "$evidence_identity" >/dev/null
verify_direct_directory "$output" "$cache" "$output_identity" >/dev/null
if [[ "$mode" == produce ]]; then
  verify_direct_directory \
    "$metadata_input" "$cache" "$metadata_input_identity" >/dev/null
fi

validation=false
if [[ $status -eq 0 && "$mode" == produce ]]; then
  validation_argv=(
    "python3"
    "-m"
    "image.container.ubuntu_fixture_package_hosted"
    "validate-output"
    "--root"
    "$root"
    "--candidate"
    "$output/candidate"
    "--evidence"
    "$evidence"
  )
  env -i "PATH=/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8" "LC_ALL=C.UTF-8" "PYTHONDONTWRITEBYTECODE=1" "${validation_argv[@]}"
  validation=true
fi

env -i "PATH=/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8" "LC_ALL=C.UTF-8" "PYTHONDONTWRITEBYTECODE=1" python3 -m image.container.ubuntu_fixture_package_hosted retention-record \
  --evidence "$evidence" --evidence-identity "$evidence_identity" \
  --output "$output" --output-identity "$output_identity" \
  --work "$work" --work-identity "$work_identity" \
  --mode "$mode" --exit-status "$status" --validated "$validation"

if [[ $status -eq 0 ]]; then
  env -i "PATH=/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8" "LC_ALL=C.UTF-8" \
    "PYTHONDONTWRITEBYTECODE=1" python3 - "$evidence/cgroup-final.json" \
    "$evidence/systemd-fallback.json" "$evidence/cleanup.json" <<'PY'
from pathlib import Path
import sys
from image.container import ubuntu_fixture_package_hosted as hosted

cgroup = hosted._load_json(Path(sys.argv[1]))
fallback = hosted._load_json(Path(sys.argv[2]))
cleanup = hosted._load_json(Path(sys.argv[3]))
hosted.validate_post_unit_records(cgroup, fallback, cleanup)
PY
fi

exit "$status"
