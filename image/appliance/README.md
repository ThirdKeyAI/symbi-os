# HIGHLY EXPERIMENTAL interactive appliance

This manual hosted producer prepares an **unsigned, HIGHLY EXPERIMENTAL, short-lived**
qcow2 so a human can evaluate the current graphical development image. It is not a
release image, a security-qualified OS, or a safe place for real data or accounts.

The producer consumes the exact retained generic OCI selected by
`image/desktop-images.lock.json`; the OCI bytes remain read-only and unchanged. It
installs a separate 24 GiB disk with `graphical.target`, then supplies two
provisioning units and their scripts through QEMU firmware credentials for that boot
only. Nothing adds those units or scripts to the production image or to the retained
disk.

The fixture creates `symbi-test` only on the appliance disk. The account is locked,
has no password, SSH key, or `wheel` membership, and enters `symbi.desktop` through a
clearly labelled SDDM autologin drop-in. The guest must observe SDDM, Hyprland,
Waybar, Walker, the Hyprland portal payload, and the complete first-login seed. It
also removes the temporary boot wants and proves that no provisioning script or unit
was persisted.

The producer compresses the provisioned disk with qcow2 compressed clusters. A
second isolated container mounts those exact bytes read-only, creates a fresh
overlay, boots with a virtio display, keyboard, and pointer, and requires a nonblank
QMP screenshot. Hashes before and after that boot must match. Both boots have no NIC.
Only then does `manifest.json` bind the source commit and Git tree, retained OCI
artifact, installed disk, qcow2 hash, retained screenshot, two-day expiry, and
offline launch command. The qcow2, manifest, and screenshot share the success-only
two-day download artifact; the always-retained failure evidence excludes the
screenshot.

Run the `HIGHLY EXPERIMENTAL interactive appliance` workflow manually. Ordinary
pushes and pull requests never schedule it. A failed or mismatched run retains only
bounded evidence with all success and qualification claims false. Its controller
receipt records a fixed stage, source commit/tree, local cleanup, and any bounded
cgroup receipts without copying a host path. The qcow2 upload is the final,
success-gated workflow step, so an earlier failure cannot publish it. Artifact
service behavior after a failure inside that final upload remains controlled by the
hosting platform.
