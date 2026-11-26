# Hosted Atomic development boot

This harness installs the exact retained **generic unsigned development image**
on a new virtual disk and boots it on disposable GitHub infrastructure. It has
no signing or publication authority and is not a user installation route.
Passing it does not establish desktop, sandbox, release, NVIDIA or rollback
qualification.

The first prerequisite passed in [preflight 45804599421](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45804599421)
at `97e49d111d0d71b5393f4067e713ccd39b74f55f`: complete saved-archive identity,
102 installed files, 2,184 packages, protected kernel/initramfs hashes, bootc
options, exact secureblue/Fedora identity and enforcing trust configuration.
All 41 original small files are retained and independently reconciled. Earlier
runs remain failed: protected-initramfs access in `45799924739`, then incorrect
OS/default-filesystem assumptions in `45802753036`. The latter showed that
bootc has no configured filesystem default; this disposable test explicitly
chooses Btrfs. That choice does not silently define the product installer.

`preflight.lock.json` binds the successful prerequisite to its original report
bytes. The current workflow repeats the exact artifact intake. `contract.py`
streams only OCI metadata and content-addressed blobs from the authenticated
saved archive; it never extracts filesystem paths from a layer. Every blob,
descriptor, manifest and configuration identity is checked, including rejection
of links, path escapes, duplicate/unreferenced entries and size violations.

The installer runs the image's own bootc 1.17.1, with a read-only OCI directory
as the explicit source. The fixed target is a new, private, singly linked
24 GiB regular file, opened exclusively. Its device/inode/owner/mode/size are
checked before and after installation. `--via-loopback` is mandatory; neither
existing disk replacement nor host block-device installation is offered.
The installer container is privileged for loop setup, filesystems and mounts,
but has a private PID namespace, no network, no credentials, private temporary
storage and only read-only host udev metadata. This privilege is confined to
the disposable hosted runner. Cleanup targets only loop devices still bound
to this exact new file after the containers stop.

Future update metadata uses the approved OS repository, exact manifest digest
and `--enforce-container-sigpolicy`. The local artifact has **not** acquired a
release signature: bootc's local-source import is an offline development step.
The digest need not be published in GHCR. Installed default-reject policy bytes
remain unchanged; signature acceptance and negative registry-update controls
remain separate required tests.

QEMU runs as UID 10001 with no capabilities, no new privileges, a read-only
container root and a read-only source disk. A new qcow2 overlay receives guest
writes. There is no NIC, SSH, login account, password, autologin, filesystem
share, host GPU or KVM device. One TCG CPU and 1,536 MiB guest memory boot the
installed bootloader, kernel and initramfs, rather than a substitute cloud OS.
This initial run uses serial-only output and does not claim graphics support.

The temporary systemd unit and public observation inputs arrive as QEMU firmware
credentials. The unit is generated at boot, is skipped in the initramfs, and
does not edit the installed OS. Its short `o.service` name fits QEMU's 55-byte
firmware-key limit. A fresh nonce, probe hash and input hash bind the separate
virtio-serial report. The guest checks the exact running kernel, OS identity,
enforcing SELinux, read-only `/usr` and `/sysroot`, Btrfs backing filesystem,
installed payload/package identities and bootc's booted/future-update reference.
The service has a 256 MiB/half-CPU/32-task/zero-swap ceiling and powers off after
the probe. A stale, incomplete or permissive report fails validation.

Resource limits: current artifact preparation 1 GiB/one CPU; controller
4 GiB/two CPUs/256 tasks; installer 2 GiB/one CPU/128 tasks; QEMU container
3 GiB/two CPUs/64 tasks. All use zero swap. Large inputs, virtual disks and OCI
storage stay hosted and are removed after the attempt. Only bounded original
logs and JSON observations are uploaded. The new workflow has one concurrency
group, does not cancel a running attempt and does not retrigger desktop builds.

Eleven new inert fixture tests were written before implementation; the initial
missing-module failure and first firmware-name-length failure are retained.
All 230 image tests then passed locally at 36,392 KiB peak RSS, 0.78 CPU seconds
and zero swap, under a 128 MiB/10%-CPU ceiling. Python syntax, YAML permission
checks, shell syntax and ShellCheck pass. Actual installation/boot and full
workspace/formal checks for this implementation are pending hosted execution.

Source basis: the installed Fedora bootc NVR is linked to its exact packaging
revision in the [source record](../../docs/security/reports/P0-03-atomic-preflight/bootc-source/).
The reviewed [bootc 1.17.1 installer](https://github.com/bootc-dev/bootc/blob/d01e723ae9480fa53aa9db09a7eff0439548e9f6/crates/lib/src/install.rs)
supports the explicit OCI source without requiring the host PID namespace;
its [status schema](https://github.com/bootc-dev/bootc/blob/d01e723ae9480fa53aa9db09a7eff0439548e9f6/docs/src/host-v1.schema.json)
defines the deployment checks. Systemd 262.1's
[credential import](https://github.com/systemd/systemd/blob/v262.1/src/core/import-creds.c),
[early module setup](https://github.com/systemd/systemd/blob/v262.1/src/core/kmod-setup.c)
and [unit generator](https://github.com/systemd/systemd/blob/v262.1/src/debug-generator/debug-generator.c)
support the probe transport; [QEMU](https://www.qemu.org/docs/master/specs/fw_cfg.html)
defines its name bound. This source review is not distro-binary equivalence
proof. No production dependency, policy exemption or journal event is added.

Affected invariant: INV-12. All other invariants remain requirements; no agent
authorization or trusted-input implementation is introduced. Human TCB review
and protected release approval remain required before the relevant merge/release.
