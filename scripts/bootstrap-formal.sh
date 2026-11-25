#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
jar="$PWD/.tools/tla2tools-1.7.4.jar"
expected=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
mkdir -p .tools
if [[ ! -f "$jar" ]]; then
  part="$(mktemp "$PWD/.tools/tla2tools.XXXXXXXX")"
  trap 'rm -f -- "$part"' EXIT
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --connect-timeout 15 --max-time 180 \
    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
    --output "$part"
  printf '%s  %s\n' "$expected" "$part" | sha256sum --check --status
  mv -- "$part" "$jar"
fi
# Validate cached files too: an existing path is not evidence of integrity.
printf '%s  %s\n' "$expected" "$jar" | sha256sum --check --status
printf 'Verified TLC 1.7.4: %s\n' "$jar"
