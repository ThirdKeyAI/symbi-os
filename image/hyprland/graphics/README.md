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
Neither a passing preflight nor those unit tests prove guest rendering, DRM
allocation, Hyprland acceptance or an OS boot. The actual hosted result is pending.

For the subsequent guest test, `fedora-cloud/candidate.json` pins Fedora's cloud
image and its signed checksum file. The checksum signature was verified with the
already pinned Fedora45 primary key; changed-checksum and missing-key controls
both failed. The 606,732,288-byte image has not been downloaded locally or booted.
A hosted consumer must verify the signature and full image bytes before use.
This disposable cloud guest cannot replace the signed Atomic OS acceptance tests.

Primary references:
- [QEMU virtual GPU modes](https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html)
- [GitHub Ubuntu 24.04 runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
- [Fedora45 signed cloud checksums](https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-45-1.4-x86_64-CHECKSUM)
