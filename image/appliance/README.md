# HIGHLY EXPERIMENTAL interactive appliance

This manual hosted producer prepares an **unsigned, HIGHLY EXPERIMENTAL, short-lived**
qcow2 so a human can evaluate the current graphical development image. It is not a
release image, a security-qualified OS, or a safe place for real data or accounts.

The selected generic target is image run `46107995231` at
`c6bf3ed9eba34562d886b6b315dd9cb46340c525`. Its retained preparation, package
inventory, and reviewed image summary are in the repository. The combined image
lock also preserves the newer NVIDIA entry. Atomic preflight run
`46125049529` passed at the exact integrated head
`65244ce3806a4ac4f0b1b3f9d576dc403e531da6` and is selected by the strict
13-key lock. The preflight authenticated the complete retained generic OCI and
its current verifier without making an installation, boot, OS, signature or
release claim. The appliance producer's reviewed pre-download prerequisite is
therefore present.

The producer consumes the exact retained generic OCI selected by
`image/desktop-images.lock.json`; the OCI bytes remain read-only and unchanged. The
controller requires at least 60 GiB free after preparation, then installs a separate
24 GiB disk with
`graphical.target`, then supplies two
provisioning units and their scripts through QEMU firmware credentials for that boot
only. Nothing adds those units or scripts to the production image or to the retained
disk.

Before any download, the workflow invokes the same retained-preflight validator as
the controller and requires selected run `46125049529`. It also requires the
60 GiB controller floor plus the exact 4,177,421,526-byte retained ZIP and a 1 GiB
preparation margin. The nine workflow steps have hard limits of 5, 1, 2, 20, 20,
130, 10, 10, and 30 minutes: 228 minutes total inside a 240-minute job, leaving 12
minutes of outer margin. The download's 30-second metadata and 900-second archive caps leave
4.5 minutes in its 20-minute step for hashing and wrapper work. The 20-minute
prepare step contains a 15-minute unit, and the
130-minute controller step contains a 115-minute unit, leaving bounded cleanup and
evidence time before the evidence upload, final public validation, and download upload.

The fixture creates `symbi-test` only on the appliance disk. The account is locked,
has no password, SSH key, or `wheel` membership, and enters `symbi.desktop` through a
clearly labelled SDDM autologin drop-in. The guest must observe SDDM, Hyprland,
Waybar, the Hyprland portal payload, and the complete first-login seed. Walker must
also be launched through a 512 MiB, zero-swap, one-CPU, 64-task transient user unit,
observed as `/usr/bin/walker`, receive an exact successful `systemctl stop`, and be
absent after that stop within fixed deadlines. QEMU supplies one binary systemd
credential whose exact drop-in starts the two fixture units only for the first boot.
The installer writes no fixture `systemd.wants` kernel argument, so provisioning
does not stage an `rpm-ostree` deployment to remove one. The guest then proves that
the exact root-owned drop-in is loaded from
`/run/systemd/generator.early/graphical.target.d/symbi-appliance.conf`, that no
other loaded drop-in names either fixture unit, and that no fixture unit, target
link, target drop-in, or credential was written to a persistent systemd or
credential-store root. The five provisioning
command deadlines total 60 seconds. Local work has a 30-second reserve and the
120-second unit deadline retains another 30-second margin. Provisioning, the
420-second verifier, 180 seconds of boot and success-only shutdown work, and a
480-second controller margin close exactly inside the first boot's 1,200-second deadline.
The verifier's monotonic application budget is 400 seconds: 260 for the graphical
session and portal, 55 for the exact fixed-command inventory, 70 for Walker's
launch and cleanup lifecycle, and 15 for local validation and report emission.
Every verifier subprocess has an explicit deadline clamped to that outer budget,
both graphical polls have finite attempt counts, and the unit retains 20 seconds
of service margin. Only the verifier unit's successful completion requests poweroff.
A verifier failure or timeout leaves QEMU running until the host rejects it at the
1,200-second controller deadline, including when the report channel received every
byte before a final deadline failure. The provisioner retains its prompt failure
poweroff; the verifier requires the provisioner to have succeeded, so that path
cannot produce a valid report. The verifier's separate 15-second stop bound and
successful shutdown are counted once in the 180-second orchestration allocation.

The producer compresses the provisioned disk with qcow2 compressed clusters. A
second isolated container mounts those exact bytes read-only, creates a fresh
overlay, boots with a virtio display, keyboard, and pointer, and requires a nonblank
QMP screenshot. Hashes before and after that boot must match. Both hosted boots use
TCG multi-thread execution with an explicit two-CPU, one-socket, two-core topology
and have no NIC. Each container has an exact 4 GiB memory limit, zero swap, two CPUs,
and 64 tasks. The exact 5 GiB outer transient unit leaves 1 GiB for
the controller and container monitor while preserving a hard zero-swap boundary.
This generic virtio/TCG gate does not exercise physical NVIDIA hardware.
Only then does `manifest.json` bind the source commit and Git tree, retained OCI
artifact, installed disk, qcow2 hash, retained screenshot, two-day expiry, and
offline launch command. The qcow2, manifest, and screenshot share the success-only
two-day download artifact. A separate seven-day evidence artifact keeps the exact
source-bound `reboot-result.json`, `manifest.json`, and `display.ppm` alongside the
bounded producer, reboot, controller, and outer-systemd records. The controller
accepts only that fixed success inventory, preserves the screenshot's 4 MiB limit,
and enforces a 32 MiB aggregate ceiling before enabling upload. The outer producer
runs in a named retained oneshot. Its numeric terminal status and resource facts are
captured while the unit is still loaded and synced to the evidence filesystem. The
wrapper then stops and resets the unit, requires both `LoadState=not-found` and the
captured control-group path to be gone, and validates the final evidence inventory
and contents only after no unit descendant can still write them. A collection,
cleanup, swap, OOM, or final-validation failure removes the evidence and public
output and emits no upload marker.
A failed run can retain exactly one all-false receipt plus the fixed-field systemd
record. When the appliance controller produced a receipt, the wrapper removes every
other output and validates that source-bound inner receipt. When the outer unit
started, reached a terminal failure, and produced a valid systemd record but no inner
evidence path, the wrapper can instead create a content-free outer receipt with a
fixed stage, failed-command class, cleanup result, and `inner_evidence_available=false`.
Failures before the unit starts or reaches a captured terminal state, and any failed
cleanup or evidence validation, produce no `interactive-appliance-evidence` artifact;
their workflow logs remain available. Immediately before the successful download upload,
a separate validator accepts only the qcow2, manifest, and screenshot, rehashes all
three, scans them for credential markers, and cross-checks them against the
seven-day evidence. The manifest expiry comes from the hosted workflow clock rather
than its own contents. A mismatch at this later check blocks the download. The
bounded evidence may already have uploaded and remains a record of the earlier
controller result; it is not proof that the rejected public bytes were delivered.
After the two-day artifact expires, the longer-lived evidence can still establish
what the independent reboot observed, but it cannot rehash the absent qcow2 bytes.

## Download and inspect a successful run

Use only a successful run of the `HIGHLY EXPERIMENTAL interactive appliance`
workflow at the reviewed commit. The success artifact expires after two days. The
manifest is unsigned, so its hashes check the downloaded files for internal
consistency; they do not turn the appliance into a signed or qualified image.
Inspect the run's `headSha`, conclusion, and workflow name before downloading:

```console
gh run view RUN_ID --repo ThirdKeyAI/symbi-os \
  --json status,conclusion,headSha,workflowName,url
gh run download RUN_ID --repo ThirdKeyAI/symbi-os \
  --name highly-experimental-interactive-appliance-generic \
  --dir symbi-appliance
cd symbi-appliance
```

The directory must contain `manifest.json`, `display.ppm`, and
`symbi-os-highly-experimental-generic.qcow2`. Validate the expiry, fixed safety
claims, screenshot, qcow2 size, and qcow2 hash before the first boot:

```console
python3 - <<'PY'
from datetime import datetime, timezone
from hashlib import file_digest
import json
from pathlib import Path

def require(condition, message):
    if not condition:
        raise SystemExit("validation failed: " + message)

manifest = json.loads(Path("manifest.json").read_text())
require(manifest["schema"] == 1, "unexpected manifest schema")
require(manifest["highly_experimental"] is True, "experimental marker missing")
require(manifest["passed"] is True, "appliance run did not pass")
require(manifest["signed"] is False, "unexpected signature claim")
require(manifest["network"] == "none", "network policy changed")
require(manifest["retention_days"] == 2, "retention window changed")
require(manifest["os_qualified"] is False, "unexpected OS qualification claim")
require(manifest["release_qualified"] is False, "unexpected release claim")
require(manifest["signature_qualified"] is False, "unexpected signature qualification")
expiry = datetime.fromisoformat(manifest["expires_at"].replace("Z", "+00:00"))
require(datetime.now(timezone.utc) < expiry, "artifact expired")

disk = manifest["disk"]
require(disk["name"] == "symbi-os-highly-experimental-generic.qcow2",
        "unexpected qcow2 filename")
require(disk["format"] == "qcow2", "unexpected disk format")
require(disk["virtual_bytes"] == 24 * 1024**3, "virtual disk size changed")
disk_path = Path(disk["name"])
require(disk_path.is_file() and not disk_path.is_symlink(), "unsafe qcow2 path")
screenshot = manifest["reboot"]["screenshot"]
screenshot_path = Path("display.ppm")
require(screenshot_path.is_file() and not screenshot_path.is_symlink(),
        "unsafe screenshot path")
require(disk_path.stat().st_size == disk["bytes"], "qcow2 byte count changed")
require(screenshot_path.stat().st_size == screenshot["bytes"],
        "screenshot byte count changed")
with disk_path.open("rb") as stream:
    disk_digest = file_digest(stream, "sha256").hexdigest()
with screenshot_path.open("rb") as stream:
    screenshot_digest = file_digest(stream, "sha256").hexdigest()
require(disk_digest == disk["sha256"], "qcow2 SHA-256 changed")
require(screenshot_digest == screenshot["sha256"], "screenshot SHA-256 changed")
print("validated", manifest["source_binding"]["source_commit"], manifest["expires_at"])
PY
```

Compare the printed source commit with the run's `headSha`. The downloaded qcow2 is
a compressed 24 GiB virtual disk. Reserve enough space for the download and up to
24 GiB for each writable copy or overlay as it grows.

## Preserve the downloaded bytes

QEMU opens the launch disk writable. Keep the verified download pristine and boot a
working copy:

```console
mkdir -m 700 run
cp --reflink=auto --sparse=always \
  symbi-os-highly-experimental-generic.qcow2 run/
cd run
```

Alternatively, keep the verified qcow2 read-only and create a disposable overlay.
Delete the overlay to reset the appliance:

```console
chmod a-w symbi-os-highly-experimental-generic.qcow2
mkdir -m 700 run
qemu-img create -f qcow2 -F qcow2 \
  -b "$(realpath symbi-os-highly-experimental-generic.qcow2)" \
  run/symbi-os-test.qcow2
```

Use `run/symbi-os-test.qcow2` in place of the fixed filename in the launch commands
below when using the overlay.

## Boot on a Linux host

The manifest's intended launch path requires an x86-64 Linux host, QEMU with its GTK
display frontend, permission to use `/dev/kvm`, 4 GiB of assignable memory, and four
virtual CPUs. From the directory containing the working copy, run:

```console
qemu-system-x86_64 -machine q35 -accel kvm -cpu host \
  -m 4096M -smp 4 -nodefaults -no-user-config -net none \
  -drive file=symbi-os-highly-experimental-generic.qcow2,format=qcow2,if=virtio \
  -device virtio-vga,id=symbi-display \
  -device virtio-keyboard-pci,id=symbi-keyboard \
  -device virtio-tablet-pci,id=symbi-pointer \
  -device virtio-rng-pci,id=symbi-rng \
  -display gtk,gl=off
```

If KVM is unavailable, the slower TCG form is:

```console
qemu-system-x86_64 -machine q35 -accel tcg,thread=multi -cpu max \
  -m 4096M -smp cpus=2,sockets=1,cores=2,threads=1 \
  -nodefaults -no-user-config -net none \
  -drive file=symbi-os-highly-experimental-generic.qcow2,format=qcow2,if=virtio \
  -device virtio-vga,id=symbi-display \
  -device virtio-keyboard-pci,id=symbi-keyboard \
  -device virtio-tablet-pci,id=symbi-pointer \
  -device virtio-rng-pci,id=symbi-rng \
  -display gtk,gl=off
```

The hosted producer independently reboots the retained bytes under headless TCG and
checks a screenshot. It does not exercise either human GTK launch command above, a
KVM boot, or a graphical VM-manager import. A default VM-manager import may add a
virtual NIC and is outside this offline handoff. Keep `-net none`; the appliance has
no network access, and the gate makes no claim about a network-enabled variant.

## What the session provides

SDDM automatically starts `symbi.desktop` as `symbi-test`; there is no credential to
enter. The account is locked, has no password or SSH key, and is not in `wheel`.
Consequently, text-console login as `symbi-test`, password-based screen unlock, SSH
login, and administrative package changes are unavailable. SDDM is configured to
autologin again after logout. If the automatic session cannot start, close or reboot
the VM; there is no password recovery path. Never store real data or accounts in
this disk.

This retained image exercises Hyprland, Waybar, Walker, the Hyprland portal, and the
seeded Tokyo Night defaults. `SUPER + SPACE` opens Walker, `SUPER + Return` opens
Foot, and the implemented window and workspace bindings are available. Foot and
Thunar come from the selected base. Kitty is not installed; its seeded profile is
inactive. Tolaria, Yazi, Glum, Tootles, MPlayer, and mpv are not in this retained
image. Browser, file-manager, editor, lock-screen, system-menu, screenshot, recording,
clipboard, Tmux, and Tolaria shortcuts are reserved no-ops in this slice. The VM has
no virtual NIC, audio device, shared folder, or host-GPU passthrough. It does not
exercise physical NVIDIA hardware.

Run the `HIGHLY EXPERIMENTAL interactive appliance` workflow manually only at a
reviewed commit whose strict lock selects preflight run `46125049529`. Ordinary
pushes and pull requests never schedule it. A controller failure before the evidence
upload can retain only a bounded all-false receipt and the systemd record after the
wrapper validates both files. If the appliance controller produced the receipt, it
contains a fixed stage, source commit/tree, local cleanup, exact cgroup
receipts, and any source-bound child-result diagnostic. That diagnostic is limited to
the child-result type, a fixed producer phase and process status, byte counts for the
approved QEMU and serial logs, explicitly untrusted allowlisted observations of
lifecycle sentinels and traceback classes from bare output or the exact fixed
systemd console identifiers, and bounded guest-report state/size
metadata. Log-derived observations are diagnostic hints only and cannot satisfy a
gate or qualification claim. No private-input digest, log text, result message, or
arbitrary excerpt is retained. Missing, empty, linked,
hard-linked, special, unreadable, changing, and oversized inputs receive fixed refusal
states. If the terminal outer unit produced no inner evidence, the wrapper may instead
create the content-free outer receipt described above; it carries no child diagnostic
or cgroup receipt. A failure before unit start or captured terminal state, an
outer-unit collection or OOM failure, or any failure to clean up or validate the pair
retains no appliance evidence artifact.
A later public revalidation failure
blocks the qcow2 while the already uploaded diagnostic evidence can remain. The
qcow2 upload is the final,
success-gated workflow step, so an earlier failure cannot publish it. Artifact
service behavior after a failure inside that final upload remains controlled by the
hosting platform.

No graphical appliance run has passed yet, so there is no current downloadable or
bootable result from this card.
