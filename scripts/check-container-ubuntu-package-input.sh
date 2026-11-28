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

readarray -t selected < <(
  PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.ubuntu_fixture_inputs \
    --root "$root" pre-transfer
)
(( ${#selected[@]} == 4 )) || {
  echo 'Offline fixture selection did not return four exact identities.' >&2
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
  timeout "$seconds" gh api "$endpoint" > "$target"
}

download 30 \
  "repos/ThirdKeyAI/symbi-os/actions/runs/${selected[0]}/attempts/${selected[1]}" \
  "$run_metadata"
download 30 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[2]}" \
  "$candidate_metadata"
download 30 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[3]}" \
  "$evidence_metadata"

PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.ubuntu_fixture_inputs \
  --root "$root" metadata --run-metadata "$run_metadata" \
  --candidate-metadata "$candidate_metadata" \
  --evidence-metadata "$evidence_metadata"

download 1200 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[2]}/zip" \
  "$candidate_zip"
download 300 "repos/ThirdKeyAI/symbi-os/actions/artifacts/${selected[3]}/zip" \
  "$evidence_zip"

PYTHONDONTWRITEBYTECODE=1 python3 -m image.container.ubuntu_fixture_inputs \
  --root "$root" consume --run-metadata "$run_metadata" \
  --candidate-metadata "$candidate_metadata" \
  --evidence-metadata "$evidence_metadata" --candidate-zip "$candidate_zip" \
  --evidence-zip "$evidence_zip" --destination "$destination"
