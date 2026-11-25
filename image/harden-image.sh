#!/usr/bin/env bash
# Build-container only. No package/download changes are guessed before OQ-07.
set -euo pipefail
[[ -e /run/.containerenv || -e /.dockerenv ]] || {
  printf 'Refusing to harden the host; run only inside the image build.\n' >&2
  exit 1
}
source /etc/os-release
[[ $ID == fedora || ( $ID == secureblue && " ${ID_LIKE:-} " == *" fedora "* ) ]] || {
  printf 'Fedora or the selected Fedora-based secureblue family required.\n' >&2
  exit 1
}
# The selected immutable base must include these or a separately pinned RPM
# installation step must be reviewed. No silent network installation fallback.
for executable in Hyprland waybar walker foot bootc; do
  command -v "$executable" >/dev/null
done
# The selected base uses run0 and contains neither sudo nor visudo. Do not add
# sudo merely to validate an absent service. When sudo exists, require its real
# syntax checker; inspect any residual policy even when the executable is absent.
if command -v sudo >/dev/null; then
  command -v visudo >/dev/null
  visudo -c
fi
sudo_paths=()
for sudo_path in /etc/sudoers /etc/sudoers.d; do
  [[ ! -e "$sudo_path" && ! -L "$sudo_path" ]] || sudo_paths+=("$sudo_path")
done
if (( ${#sudo_paths[@]} )); then
  if sudo_matches=$(grep -rE '^[^#]*NOPASSWD[[:space:]]*:' "${sudo_paths[@]}"); then
    printf 'Passwordless sudo remains in base configuration:\n%s\n' "$sudo_matches" >&2
    exit 1
  else
    result=$?
    [[ $result == 1 ]] || exit "$result"
  fi
fi
# Removing the manager alone does not disable the compositor plugin API.
# A compositor build with loading disabled and a negative VM test remain gates.
rm -f /usr/bin/hyprpm
for unit in abrtd.service abrt-journal-core.service abrt-oops.service abrt-xorg.service; do
  ln -sfn /dev/null "/etc/systemd/system/$unit"
done
chmod 0755 /usr/libexec/symbi-seed-config /usr/libexec/symbi-desktop-session
chmod 0644 /etc/profile.d/symbi-privacy.sh
