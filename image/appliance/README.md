# HIGHLY EXPERIMENTAL interactive appliance

This manual hosted producer prepares an **unsigned, HIGHLY EXPERIMENTAL, short-lived**
qcow2 so a human can evaluate the current graphical development image. It is not a
release image, a security-qualified OS, or a safe place for real data or accounts.

The selected generic target is image run `46107995231` at
`c6bf3ed9eba34562d886b6b315dd9cb46340c525`. Its retained preparation, package
inventory, and reviewed image summary are in the repository. The combined image
lock also preserves the newer NVIDIA entry. No Atomic preflight is selected for
that combined lock: `image/atomic/preflight.lock.json` is an all-false pending
marker. The reviewed run `46094435550` is retained only as historical evidence
because it covered a different complete image lock and an older verifier. A fresh
generic preflight at the integrated head must be reviewed before this workflow is
dispatched.

After that gate, the producer consumes the exact retained generic OCI selected by
`image/desktop-images.lock.json`; the OCI bytes remain read-only and unchanged. The
controller requires at least 60 GiB free after preparation, then installs a separate
24 GiB disk with
`graphical.target`, then supplies two
provisioning units and their scripts through QEMU firmware credentials for that boot
only. Nothing adds those units or scripts to the production image or to the retained
disk.

Before any download, the workflow invokes the same retained-preflight validator as
the controller and rejects the current all-false selector. It also requires the
60 GiB controller floor plus the exact 4,177,421,526-byte retained ZIP and a 1 GiB
preparation margin. The seven workflow steps have hard limits of 5, 2, 20, 20, 130,
10, and 30 minutes: 217 minutes total inside a 240-minute job, leaving 23 minutes of
outer margin. The download's 30-second metadata and 900-second archive caps leave
4.5 minutes in its 20-minute step for hashing and wrapper work. The 20-minute
prepare step contains a 15-minute unit, and the
130-minute controller step contains a 115-minute unit, leaving bounded cleanup and
evidence time before the two bounded uploads.

The fixture creates `symbi-test` only on the appliance disk. The account is locked,
has no password, SSH key, or `wheel` membership, and enters `symbi.desktop` through a
clearly labelled SDDM autologin drop-in. The guest must observe SDDM, Hyprland,
Waybar, the Hyprland portal payload, and the complete first-login seed. Walker must
also be launched through a 512 MiB, zero-swap, one-CPU, 64-task transient user unit,
observed as `/usr/bin/walker`, receive an exact successful `systemctl stop`, and be
absent after that stop within fixed deadlines. It
also removes the temporary boot wants and proves that no provisioning script or unit
was persisted.

The producer compresses the provisioned disk with qcow2 compressed clusters. A
second isolated container mounts those exact bytes read-only, creates a fresh
overlay, boots with a virtio display, keyboard, and pointer, and requires a nonblank
QMP screenshot. Hashes before and after that boot must match. Both hosted boots use
TCG multi-thread execution with an explicit two-CPU, one-socket, two-core topology
and have no NIC. This generic virtio/TCG gate does not exercise physical NVIDIA
hardware.
Only then does `manifest.json` bind the source commit and Git tree, retained OCI
artifact, installed disk, qcow2 hash, retained screenshot, two-day expiry, and
offline launch command. The qcow2, manifest, and screenshot share the success-only
two-day download artifact; the always-retained failure evidence excludes the
screenshot.

Run the `HIGHLY EXPERIMENTAL interactive appliance` workflow manually only after the
pending integrated-head preflight is replaced by reviewed lock-bound evidence.
Ordinary pushes and pull requests never schedule it. A failed or mismatched run
retains only bounded evidence with all success and qualification claims false. Its controller
receipt records a fixed stage, source commit/tree, local cleanup, and any bounded
cgroup receipts without copying a host path. The qcow2 upload is the final,
success-gated workflow step, so an earlier failure cannot publish it. Artifact
service behavior after a failure inside that final upload remains controlled by the
hosting platform.

No graphical appliance run has passed yet, so there is no current downloadable or
bootable result from this card.
