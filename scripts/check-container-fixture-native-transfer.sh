#!/usr/bin/env bash
set -euo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted \
  && "${GITHUB_REPOSITORY:-}" == ThirdKeyAI/symbi-os \
  && "${SYMBI_REQUESTED_QUALIFICATION:-}" == containers ]] || {
  echo 'Native fixture transfer requires the disposable hosted container gate.' >&2
  exit 1
}
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ \
  && "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ \
  && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'Native fixture transfer requires exact consumer run identity.' >&2
  exit 1
}

root=$(git rev-parse --show-toplevel)
cache="$root/.cache"
[[ -d "$cache" && ! -L "$cache" ]] || {
  echo 'Native fixture transfer requires a direct cache directory.' >&2
  exit 1
}

set +e
values_output=$(PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs \
  --root "$root" pre-transfer)
status=$?
set -e
(( status == 0 )) || exit "$status"
readarray -t values <<< "$values_output"
if (( ${#values[@]} != 3 )); then
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs \
    --root "$root" record-transfer-failure --stage selection-output --exit-code 1 || true
  exit 1
fi

record_failure() {
  local stage=$1
  local code=$2
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs \
    --root "$root" record-transfer-failure --stage "$stage" --exit-code "$code" || true
  exit "$code"
}

download() {
  local stage=$1
  local seconds=$2
  local endpoint=$3
  local target=$4
  [[ ! -e "$target" && ! -L "$target" ]] || record_failure "$stage" 1
  set +e
  timeout "$seconds" gh api "$endpoint" > "$target"
  local code=$?
  set -e
  (( code == 0 )) || record_failure "$stage" "$code"
}

download run-metadata 30 \
  "repos/ThirdKeyAI/symbi-os/actions/runs/${values[0]}/attempts/${values[1]}" \
  "$cache/container-native-fixture-run.json"
download artifact-metadata 30 \
  "repos/ThirdKeyAI/symbi-os/actions/artifacts/${values[2]}" \
  "$cache/container-native-fixture-artifact.json"

PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs \
  --root "$root" record-transfer-metadata

download artifact-download 1200 \
  "repos/ThirdKeyAI/symbi-os/actions/artifacts/${values[2]}/zip" \
  "$cache/container-native-fixture-image.zip"

PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.native_fixture_inputs \
  --root "$root" record-transfer-complete
