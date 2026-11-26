# Hosted Atomic development boot

This harness test-signs and installs the exact retained **generic development
image** on a new virtual disk and boots it on disposable GitHub infrastructure.
It generates a temporary offline CI fixture key, destroys its private material,
and has no ThirdKey release-signing or publication authority. This is not a user
installation route.
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

The installer runs the image's own bootc 1.17.1, with a read-only signed `dir:`
source containing the unchanged manifest and opaque OCI blobs. The fixed target is a new, private, singly linked
24 GiB regular file, opened exclusively. Its device/inode/owner/mode/size are
checked before and after installation. `--via-loopback` is mandatory; neither
existing disk replacement nor host block-device installation is offered.
The installer container is privileged for loop setup, filesystems and mounts,
but has a private PID namespace, no network, no credentials, private temporary
storage and read-only live host `/dev` and udev metadata mounts. This privilege is confined to
the disposable hosted runner. Cleanup targets only loop devices still bound
to this exact new file after the containers stop.

Future update metadata uses the approved OS repository, exact manifest digest
and `--enforce-container-sigpolicy`. The source has an ephemeral CI fixture
signature, **not a ThirdKey release signature**. The key attests the checked
input inside this test run; it is not independent release provenance.
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
4 GiB/two CPUs/256 tasks; temporary signer 1 GiB/one CPU/64 tasks; installer
2 GiB/one CPU/128 tasks; QEMU container
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

## First actual installation attempt and device-visibility correction

[Run 45808682061](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45808682061)
at `5ef30a1` passed exact artifact/image identity and all 131 OCI blobs/129 layers
(4,088,888,273 bytes). The fixed new regular-file target passed its guard and
bootc created BIOS/EFI/root partitions. It stopped before filesystem creation:
the private container's initial `/dev` lacked the new `/dev/loop2p3` node.
All 25 original small files are retained. The installer, image, loop attachment,
private image/disk storage and runroot were removed; no OOM/kill/swap occurred.
No VM started and no successful installation or boot is claimed.

The correction binds the hosted runner's live `/dev` read-only and nonrecursively into the already
privileged installer, allowing host udev's new partition nodes to become visible.
This does not make block devices read-only: the installer still needs block I/O
to its guarded private loop file. The bind prevents creating/removing host
device-directory entries. Only the private disk and temporary directories are
writable directory mounts. Private PID/no-network namespaces, exact target-file
identity, resource limits, SELinux and update-policy requirements are unchanged.
Two new tests check those mount properties and reject shared or symlinked input
directories. All 232 image tests pass at 36,792 KiB peak RSS, 0.77 CPU seconds
and zero swap; the original full workspace/formal run `45808699180` also passed.
Actual corrected install/boot remains pending the next hosted attempt.

The device bind uses Podman's documented `bind-nonrecursive` option so host
`/dev/shm`, `/dev/pts` and other submounts are not imported. The new regression
failed on the initial recursive mount before this correction. See
[Podman bind options](https://docs.podman.io/en/latest/markdown/podman-run.1.html).

## Local-source signature refusal and authenticated test input

[Run 45811128993](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45811128993)
at `5c5b4fb` confirms the device correction works: bootc created Btrfs and ESP
filesystems and initialized OSTree. It then correctly rejected the unsigned
`oci:/inputs/oci` source under the shipped default-reject policy. All 25 original
small files and independent reconciliation are retained. The installer, loop
devices, image and private storage/runroot were removed with zero OOM/kill/swap.
Installation did not finish and no VM started. The same commit's full
[workspace/formal check](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45811149524)
passed.

The corrected test source uses the existing image's Skopeo 1.25.1 and GnuPG in a
read-only, offline, unprivileged container. A new test key signs the exact pinned
manifest; no image layer is recompressed or filesystem extracted. A tiny valid
OCI fixture first passes actual `skopeo copy` policy verification, then must
fail with a missing signature, another key, a different signed identity, and an
altered signature. The real development manifest is signed and independently
checked with `standalone-verify`. No native signing test runs locally.

The installer-only policy retains default reject and every original Docker
release/base rule. It adds one `signedBy`/`GPGKeys` rule for `/inputs/signed`,
requiring the ephemeral public key and the exact test identity plus manifest
digest. This policy is mounted read-only only in the installer. Source layers
retain the original ThirdKey release policy; the boot probe still requires its
exact original bytes and enforcing future-update metadata. No test key/rule is
installed in the OS. Private GPG material is deleted before signing acceptance;
only the public key, signature and bounded observations are retained.

Three additional inert regression tests cover unchanged manifest/blob layout,
tamper/path rejection and preservation of release trust. The updated existing
tests require the signed source and read-only policy mount. All 235 image tests
pass locally at 36,872 KiB RSS, 0.79 CPU seconds and zero swap under 128 MiB/10%
CPU limits. The native signature controls and corrected installation/boot still
need hosted execution; they are not claimed by those fixture tests.

The [source review](source-authentication-review.json) binds the upstream
Skopeo/library versions, local directory signature format and exact-reference
policy semantics. This harness adds no production dependency, signing identity,
policy bypass or release qualification. Actual registry update/rollback controls
and human TCB/release approvals remain separate gates.

## Packaged verifier identity correction

[Run 45815145937](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45815145937)
at `ebb82d6` passed image/blob/directory-source preparation. Its first signer
check returned Skopeo 1.25.1 with Fedora's embedded build commit, while the
guard expected only the version text. It correctly stopped there: no key was
generated, no signature control ran, no disk was created and no installation or
boot occurred. All 24 original files and independent reconciliation are kept.
Signer/image/private storage cleanup passed with no OOM/kill/swap. The same
commit's [workspace/formal run](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45815161057)
passed.

The corrected guard requires the complete observed output, including build
`849f8f0f9443e56435f4302f81ccadcf6a56da21`, and independently queries the exact
installed RPM identity `skopeo 1:1.25.1-2.fc45.x86_64`. It does not accept an
arbitrary suffix or a changed version/build/package. The existing exact image
digest binds the executable. This reported build commit differs from the
reviewed upstream release tag; the source record does not claim reproducible
binary equivalence. A new regression fails before this helper exists and
rejects altered build/version/RPM/architecture values afterward.

With the independent desktop package discovery additions, all 244 offline image
tests pass at 37,656 KiB RSS, 0.83 CPU seconds and zero swap, under the same
128 MiB/10%-CPU cap. Actual signature controls and installation/boot remain
pending the corrected hosted attempt.

## Installed-image boot and separate status collector

[Run 45818340666](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45818340666)
at `30d4ab7` completed bootc installation and booted the actual retained image's
kernel `7.3.4-300.secureblue.1.fc45.x86_64`. The native source-policy positive
control and all four rejection controls passed; the ephemeral private keys were
removed. The guest reported secureblue 45, enforcing SELinux, read-only `/usr`
and `/sysroot`, Btrfs, and only loopback. Its probe then failed at `bootc status`:
upstream's booted status path requires `CAP_SYS_ADMIN` to enter a private mount
namespace. Payload/inventory/deployment checks were not reached. The accepted
boot result remains failed, not an OS or release qualification.

All 87 original files and an independent byte-bound reconciliation are retained
under `docs/security/reports/P0-03-atomic-boot/45818340666/`. Three containers,
loop devices, image, private storage and runroot were cleaned up. Hosted parent
memory reached its ceiling (163,476 max events), with no OOM/kill or host swap;
the QEMU container peaked at 3,151,433,728 bytes, with zero max/OOM/kill events.
The guest's own compressed zram swap is not a claim of zero guest swap.
No after-boot disk digest was accepted on this failed path. The same source's
[workspace/formal check](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45818361831)
passed.

The corrected test uses a separate firmware-generated `s.service` that executes
only `/usr/bin/bootc status --json` inside the disposable VM. Its sole capability
is `CAP_SYS_ADMIN`, with a private mount namespace, no new privileges, no imported
credentials or caller-controlled command, and a 256 MiB/half-CPU/32-task/zero-swap
ceiling. Its only report is a private root-owned file in a fresh `/run` directory.
The installed bootc command uses that namespace for its storage query; global
read-only mounts and SELinux are still checked afterward. This collector's guest
privilege is explicit test infrastructure, not a new product service or agent
permission. No collector capability reaches the observation probe or host QEMU.

The original zero-capability Python probe depends on successful completion of
that fixed collector, verifies its service result and bounded regular output,
and then applies every existing kernel, payload, inventory, trust and deployment
check. It also reports and checks its own empty effective/permitted/bounding
capability sets and no-new-privileges state. The short extra unit fits the same
firmware transport; its input hash is retained. No package or image rebuild is
needed. The exact upstream [status source review](status-source-review.json)
records why the namespace is needed; it does not claim distro binary equivalence.

Two new acceptance tests failed before implementation and now pass. Together
with the strengthened existing report/firmware tests, all 246 image fixtures pass
at 36,360 KiB peak RSS, 0.80 CPU seconds and zero swap under the local 128 MiB/10%
CPU limit. These fixtures do not qualify the native collector; that requires the
next hosted run. No release key, signature exception, new dependency, agent
authorization or journal event is introduced. INV-12 and human TCB review remain
required, as do desktop, sandbox, release and rollback qualification.

## Preserve failed collector diagnostics

[Run 45822682886](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45822682886)
at `3a2600a` completed installation and all five native source-policy controls.
The fixed `s.service` then failed in the VM. Its failure prevented the dependent
observer from starting and triggered immediate poweroff, leaving an empty
structured guest report. The serial output does not identify the collector's
underlying error. This run remains failed; earlier kernel/SELinux observations
are not attributed to it. No additional capability is justified by this result.

All 87 original files (193,041 expanded bytes) are retained with independent
hash-bound reconciliation. Ephemeral signing keys, three containers, loop
devices, image and private storage/runroot were removed. The hosted parent
recorded 162,098 memory-ceiling events with no OOM/kill; the QEMU container peaked
at 2,996,633,600 bytes with zero max/OOM/kill events. Host swap was prohibited.
QEMU powered off with exit zero after 213.60 seconds; that is not boot acceptance.
The corresponding workspace/formal runs
[45822700443](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45822700443)
and [45824324041](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45824324041)
passed at `3a2600a` and the evidence-only `e8db3c7`, respectively.

The diagnostic correction orders the zero-capability observer after the fixed
collector with `Wants` rather than a success-dependent `Requires`. The collector
no longer powers off on failure; the observer retains shutdown responsibility.
Before accepting any output file, it records the collector's exact service
result and at most 40 journal lines / 32 KiB. Duplicate service properties and
oversized diagnostics fail closed. A failed collector still fails every accepted
boot path. The fixed command, sole collector capability, private mount namespace,
observer capability checks, report limits and all resource ceilings are unchanged.
No capability, signature, SELinux or product policy is relaxed.

New regression cases failed before implementation. All 248 offline image checks
now pass under the local 128 MiB/10%-CPU cap: 35,900 KiB peak RSS, 0.79 CPU seconds,
zero swap. They verify evidence retention and continued rejection, not native
boot success. The next hosted attempt must supply the actual collector error or
pass all existing acceptance checks. No dependency or journal event is added;
INV-12 and human TCB review, desktop, containment and release gates remain open.

## Correct the status output creation order

[Run 45827646015](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45827646015)
at `0203139` completed installation and all native source-policy controls. The
new observer retained the fixed collector's exit status **209/STDOUT**, which
occurs before its `bootc` command starts. The original errno is not retained.
The nonce/hash-bound partial report also records kernel 7.3.4, enforcing SELinux,
read-only `/usr` and `/sysroot`, Btrfs, loopback only, empty observer capability
sets and no-new-privileges. Complete boot acceptance still failed before the
payload/inventory/deployment checks. All 87 original files (216,619 expanded
bytes) and independent reconciliation are retained.

The [upstream systemd v262 source review](status-output-source-review.json)
shows `setup_output` opening stdout before `setup_exec_directory` creates the
service's `RuntimeDirectory`. The original path therefore depends on a parent
that does not yet exist at the required point. A new regression fixture
reproduced that missing-parent failure before the correction. This upstream
source review does not claim exact Fedora binary/source equivalence.

The fixed collector now writes `/run/symbi-atomic-status.json`, directly under
the already-existing root-controlled runtime directory. The service umask makes
this a root-only 0600 file. The reader opens the parent with `O_DIRECTORY` and
`O_NOFOLLOW`, requires root ownership and no group/other write permission, then
opens the file relative to that descriptor. Its original no-follow, regular,
root-owned, single-link, size, JSON and successful-service checks remain in force.
The unused service runtime directory is removed. No shell, extra program,
capability, SELinux exception or weaker boot acceptance is introduced.

All 249 offline image fixtures pass at 35,956 KiB peak RSS, 0.80 CPU seconds and
zero swap under 128 MiB/10%-CPU limits. The creation-order and directory controls
failed before implementation. Native acceptance still requires the next hosted
attempt. The collector retains only `CAP_SYS_ADMIN`; the observer and host QEMU
retain empty capability sets. Existing private mount and resource limits remain.

The failed hosted run removed private signing keys, all three containers, loop
devices, the image and private storage/runroot. Its parent recorded 163,416
memory-ceiling events and no OOM/kill; QEMU peaked at 3,183,915,008 bytes with
zero max/OOM/kill events and powered off after 312.64 seconds. Host swap was
prohibited; base guest zram is separate. Workspace/formal
[45827669193](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45827669193)
passed at the same source. No dependency or journal event is added. INV-12,
human TCB review, desktop, containment and release gates remain outstanding.

## Native bootc mount-namespace access failure

[Atomic run 45831330164](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45831330164)
at `ba700f2` completed installation and the positive/four negative native source
signature controls. The output-creation correction let the fixed collector
start bootc. Its retained diagnostic now reports exit 1 while reading
`/proc/1/ns/mnt`: permission denied (errno 13). Bootc's pinned 1.17.1 source
calls its mount-namespace preparation from status and reads PID 1's namespace
before comparing it to the collector's private namespace. This explains the
failing operation; the evidence does not distinguish every kernel/LSM denial
path. No extra capability, SELinux change or weaker acceptance was introduced.

The nonce/hash-bound partial report records the exact product kernel 7.3.4,
SELinux enforcing, read-only `/usr` and `/sysroot`, Btrfs, loopback only and a
zero-capability observer. Full payload, package, trust and deployment checks
were not reached. QEMU powered off normally after 329.65 seconds, with a
3,130,916,864-byte container peak and zero memory-ceiling/OOM events. The parent
recorded 163,072 memory-ceiling events, no OOM/kill, and zero allowed host swap.
Private signing keys, all three containers, loop devices, image and private
storage/runroot were removed. All 87 original files (222,005 bytes) and their
independent reconciliation are retained under
`docs/security/reports/P0-03-atomic-boot/45831330164/`.

The collector design remains open; adding debugging authority simply to make
the test pass is not an accepted correction. Installed image bytes and
qualification gates remain unchanged. Workspace/formal checks passed for
`ba700f2` (run 45831349883) and `2c70e38` (run 45833657032); those passes do not
qualify the failed boot test or a desktop session.

## Remove root from the fixed status collector

The retained `ba700f2` journal identifies a read of `/proc/1/ns/mnt` as the
failing operation. The pinned bootc 1.17.1 source performs that read only while
preparing a root process for a writable mount namespace. For a non-root status
query it returns before that preparation, then opens booted storage read-only.

The next collector therefore uses `DynamicUser=yes` and an empty capability
bounding set. It keeps the exact `/usr/bin/bootc status --json` command, private
mount namespace, no-new-privileges, root-created 0600 output file and all
existing resource limits. The observer remains separately capability-free and
continues to reject an unsuccessful service or malformed output. This removes
`CAP_SYS_ADMIN`; it does not add `CAP_SYS_PTRACE`, relax SELinux, edit the image,
or weaken any deployment check.

The new acceptance fixture failed against the prior root service before the
change. All 255 offline image fixtures now pass at 36,884 KiB peak RSS, 0.80 CPU
seconds and zero swap under the 128 MiB/10%-CPU local ceiling. Native success is
still pending the hosted installed-image attempt; ordinary-user readability of
the booted deployment has not been assumed from source inspection alone.
