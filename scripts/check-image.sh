#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
sha256sum --check --strict image/vendor/SHA256SUMS
bash -n image/harden-image.sh image/overlay/etc/profile.d/*
for helper in image/overlay/usr/libexec/*; do
  case "$(head -n 1 -- "$helper")" in
    '#!/usr/bin/env bash') bash -n -- "$helper" ;;
    '#!/usr/bin/python3')
      python3 -c \
        'import ast, pathlib, sys; p = pathlib.Path(sys.argv[1]); ast.parse(p.read_text(), filename=str(p))' \
        "$helper"
      ;;
    *) printf 'unsupported image helper interpreter: %s\n' "$helper" >&2; exit 1 ;;
  esac
done
python3 scripts/check-security-controls.py
python3 scripts/test-security-controls.py
python3 -m image.desktop.shortcut_coverage >/dev/null
python3 -m unittest discover -s image/tests -v
python3 -m unittest discover -s image/qualification/tests -v
