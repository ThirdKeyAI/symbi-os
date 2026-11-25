# Hosted graphics prerequisite

The pinned Aquamarine backend requires a DRM allocator; the compiler container
cannot run the full compositor with software-rendering variables alone. This
preflight tests a hosted route toward an isolated virtual GPU without loading
extra kernel modules, starting a local VM or buying a GPU runner.

A private authenticated Xvfb display comes from the existing Ubuntu 24.04 runner.
QEMU, SDL, Mesa and virglrenderer come only from the signature-verified pinned
secureblue image. No package is installed. The non-root read-only container has
no network, devices, capabilities, disks or guest kernel. Its memory limit is
1 GiB, CPU limit is one core and swap is disabled; the hosted parent has 2 GiB
and one CPU. QEMU reserves 256 MiB and remains paused before guest boot.
The display cookie is ephemeral, never logged or uploaded, and removed afterward.

The negative control requires the GL device to fail without an OpenGL display.
The positive control uses software GL, requires a live QMP session, a realized
virtio-vga-gl device, a stopped virtual CPU and clean QMP shutdown. Four small
regressions protect bounded QMP messages, command/result matching and local
refusal. They pass at 21,360 KiB peak RSS under the local 128 MiB/10%-CPU cap.
Hosted run [45716247631](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45716247631)
passed both actual controls. Its report is retained under
`docs/security/reports/P0-03-graphics-preflight/45716247631/`. The QEMU container
peaked at 252,592,128 bytes without limit/OOM events. The 2 GiB parent encountered
memory pressure while pulling the base (60,430 limit events) but no OOM or kill.
This proves device/display initialization; guest rendering, DRM allocation,
Hyprland acceptance and an OS boot are separate checks.

For the subsequent guest test, `fedora-cloud/candidate.json` pins Fedora's cloud
image and its signed checksum file. The checksum signature was verified with the
already pinned Fedora45 primary key; changed-checksum and missing-key controls
both failed. The 606,732,288-byte image is never downloaded locally. The hosted cloud-boot
consumer verifies the retained checksum signature, repeats real changed-checksum
and missing-key controls, and streams the image through its exact size/hash gate
before QEMU receives it. An actual boot result is still pending.
This disposable cloud guest cannot replace the signed Atomic OS acceptance tests.

Primary references:
- [QEMU virtual GPU modes](https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html)
- [GitHub Ubuntu 24.04 runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
- [Fedora45 signed cloud checksums](https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-45-1.4-x86_64-CHECKSUM)

## Disposable Fedora guest boot

`graphics-cloud-boot.yml` runs `check-hosted-cloud-boot.sh` on hosted CI only.
The parent has 4 GiB, two CPUs, no swap and a 45-minute lifetime; the unprivileged
QEMU container has 3 GiB, two CPUs, no swap and no network or host devices. Each
VM gets 1,536 MiB and one software-emulated CPU with a 15-minute deadline.
The existing authenticated base supplies QEMU and xorriso; nothing is installed.

A CIDATA seed ISO carries the public probe through cloud-init. Each of two
sequential boots has a fresh copy-on-write disk and nonce. The no-GPU control
must have no render node; the virtio-vga-gl boot must expose a real, readable and
writable character device owned by the virtio_gpu driver. Both must report
Fedora45, enforcing SELinux, only loopback networking, a loaded GPU module and
a distinct boot ID, then power off cleanly. The probe source hash and nonce bind
each result, delivered over a dedicated output-only virtio serial channel.
There is no SSH login, NIC, host filesystem share, host GPU or KVM passthrough.
Disks, display cookies and guest-generated keys are not uploaded. Output is
bounded and only explicitly listed public logs/reports may be retained.

Six offline regressions reject replay, wrong platform/source, missing or fake
render devices, malformed/oversized reports and wrong image payloads, and check
local-invocation refusal. These tests are synthetic harness checks. A successful
hosted cloud boot still does not prove rendering, native-loading refusal or the
selected Atomic product's boot/signature/update/rollback behavior.

Cloud-init's [NoCloud documentation](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)
defines the local CIDATA seed and copy-on-write boot pattern. QEMU's
[character-device documentation](https://www.qemu.org/docs/master/system/invocation.html#character-device-options)
describes the output-only file channel used for the report.
