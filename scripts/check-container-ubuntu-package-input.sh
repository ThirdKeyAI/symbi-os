#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted \
  && "${GITHUB_REPOSITORY:-}" == ThirdKeyAI/symbi-os \
  && "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || {
  echo 'Offline fixture package intake requires the manual hosted workflow.' >&2
  exit 1
}
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ \
  && "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ \
  && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'Offline fixture package intake requires exact consumer identity.' >&2
  exit 1
}
github_token=${SYMBI_GITHUB_TOKEN:?Offline fixture package intake requires the Actions token.}
unset SYMBI_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN

root=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
cache="$root/.cache"
if [[ -e "$cache" || -L "$cache" ]]; then
  [[ -d "$cache" && ! -L "$cache" && "$(realpath -e -- "$cache")" == "$cache" ]] || {
    echo 'Offline fixture package intake requires a direct cache directory.' >&2
    exit 1
  }
else
  install -d -m 0700 "$cache"
fi

selection=$(
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.ubuntu_fixture_inputs \
    --root "$root" pre-transfer
) || {
  echo 'Offline fixture selection failed before transfer.' >&2
  exit 1
}
readarray -t selected <<<"$selection"
unset selection
(( ${#selected[@]} == 8 )) || {
  echo 'Offline fixture selection did not return eight exact identities.' >&2
  exit 1
}

run_metadata="$cache/ubuntu-fixture-package-run.json"
candidate_metadata="$cache/ubuntu-fixture-package-candidate-artifact.json"
evidence_metadata="$cache/ubuntu-fixture-package-evidence-artifact.json"
candidate_zip="$cache/ubuntu-fixture-package-candidate.zip"
evidence_zip="$cache/ubuntu-fixture-package-evidence.zip"
destination="$cache/container-ubuntu-fixture-inputs"
for path in "$run_metadata" "$candidate_metadata" "$evidence_metadata" \
  "$candidate_zip" "$evidence_zip" "$destination"; do
  [[ ! -e "$path" && ! -L "$path" ]] || {
    echo 'Offline fixture package intake refuses pre-existing outputs.' >&2
    exit 1
  }
done

download() {
  local seconds=$1
  local endpoint=$2
  local target=$3
  local maximum=$4
  local expected_bytes=${5:-}
  local expected_sha256=${6:-}
  local identity=()
  if [[ -n "$expected_bytes" && -n "$expected_sha256" ]]; then
    identity=(--expected-bytes "$expected_bytes" \
      --expected-sha256 "$expected_sha256")
  fi
  timeout --signal=TERM --kill-after=5s "$seconds" \
    env GH_TOKEN="$github_token" gh api "$endpoint" | \
    PYTHONDONTWRITEBYTECODE=1 python3 \
      -m image.container.ubuntu_fixture_inputs --root "$root" receive \
      --output "$target" --maximum "$maximum" "${identity[@]}"
}

download 30 \
  "repos/ThirdKeyAI/symbi-os/actions/runs/${selected[0]}/attempts/${selected[1]}" \
  "$run_metadata" 16777216
download 30 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[2]}" \
  "$candidate_metadata" 16777216
download 30 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[3]}" \
  "$evidence_metadata" 16777216

PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.ubuntu_fixture_inputs \
  --root "$root" metadata --run-metadata "$run_metadata" \
  --candidate-metadata "$candidate_metadata" \
  --evidence-metadata "$evidence_metadata"

download 600 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[2]}/zip" \
  "$candidate_zip" 2147483648 "${selected[4]}" "${selected[5]}"
download 300 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[3]}/zip" \
  "$evidence_zip" 553648128 "${selected[6]}" "${selected[7]}"

timeout --signal=TERM --kill-after=5s 300s \
  env PYTHONDONTWRITEBYTECODE=1 python3 \
  -m image.container.ubuntu_fixture_inputs \
  --root "$root" consume --run-metadata "$run_metadata" \
  --candidate-metadata "$candidate_metadata" \
  --evidence-metadata "$evidence_metadata" --candidate-zip "$candidate_zip" \
  --evidence-zip "$evidence_zip" --destination "$destination"
