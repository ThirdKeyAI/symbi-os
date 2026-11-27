# Hosted Atomic development boot

This harness test-signs and installs the exact retained **generic development
image** on a new virtual disk and boots it on disposable GitHub infrastructure.
It generates a temporary offline CI fixture key, destroys its private material,
and has no ThirdKey release-signing or publication authority. This is not a user
installation route.
The ordinary Atomic workflow now extends that harness through an exact retained
predecessor, signed switch and booted rollback. Passing it does not establish
desktop, sandbox, release or NVIDIA qualification.

The current prerequisite passed in [preflight 45910498271](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45910498271)
at `4f435550c1ab63de6adadb2c028f832d53d88255` against the exact generic image
built at `d436c6ee8a7ed159afa59db9bd82377ae8ea2389`: complete saved-archive
identity, 212 installed files, 2,184 packages, protected kernel/initramfs hashes,
bootc options, exact secureblue/Fedora identity and enforcing trust
configuration. The hosted artifact retains all 41 original small files. The repository
retains the two decision reports and a reconciliation binding the complete
artifact identity and hashes. The earlier accepted prerequisite `45804599421` describes the
predecessor image and remains part of the rollback input. Older failed runs
remain failed: protected-initramfs access in `45799924739`, then incorrect
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

Resource limits: current artifact preparation 1 GiB/one CPU; ordinary Atomic
install/update controller 5 GiB/two CPUs/256 tasks; the Landlock and container
qualification wrappers 4 GiB/two CPUs/256 tasks; temporary signer 1 GiB/one
CPU/64 tasks; installer 2 GiB/one CPU/128 tasks; QEMU container
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

## Rejected non-root status collector

The retained `ba700f2` journal identifies a read of `/proc/1/ns/mnt` as the
failing operation. The attempted correction at `79a0a06` changed the collector
to `DynamicUser=yes` with an empty capability bounding set.

[Run 45850389621](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45850389621)
proved that premise wrong. Bootc 1.17.1 rejected the collector with
`Querying root privilege: This command must be executed as the root user`.
The corrected pinned source review now records the actual order: the OSTree
status path calls `prepare_for_write()`, which calls `require_root(false)` before
the mount-namespace check. The failed run remains unqualified.

All 87 original files and independent byte/hash reconciliation are retained.
Installation and the native source-signature positive/four rejection controls
passed. The nonce/hash-bound partial report records kernel 7.3.4, enforcing
SELinux, read-only `/usr` and `/sysroot`, Btrfs, loopback only and a separately
zero-capability observer. Payload, inventory, trust and deployment acceptance
were not reached. Private keys, three containers, loop devices, image and
private storage/runroot were removed. QEMU peaked at 3,168,980,992 bytes with
no memory-ceiling or OOM events; the parent recorded ceiling pressure but no
OOM/kill, and host swap was prohibited.

## Isolate the fixed collector as PID 1

The replacement keeps the exact `/usr/bin/bootc status --json` command as UID 0
with only `CAP_SYS_ADMIN`, which the pinned bootc path requires. It adds
`PrivatePIDs=yes`. Systemd 262.1 documents that this gives a service a private
PID namespace, makes its executed process PID 1 and mounts a private `/proc`
showing only that namespace. Bootc therefore compares its private `/proc/1` to
itself and takes its existing PID-1 branch. The collector does not receive
`CAP_SYS_PTRACE`, does not see host processes and cannot export authority to the
separate zero-capability observer.

The unit retains a private mount namespace, no-new-privileges, empty ambient
capabilities, root-created 0600 output, fixed command and existing memory, CPU,
task and zero-swap ceilings. It is disposable hosted test infrastructure, not a
product service or agent permission. If PID namespacing or native behavior
differs, the command or existing service-result check fails closed.

The new regression failed before implementation. All 256 offline image fixtures
and staged Python/JSON syntax pass at 36,956 KiB peak RSS in 2.03 seconds with
zero swap. Native installed-image success remains a hosted gate; no OS, desktop,
containment or release qualification is claimed.

## Installed disk booted; full inventory exceeded the generic probe limit

[Run 45869526684](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45869526684)
at `88c49ec` completed the native signature positive control and all four
rejection controls, installed the exact retained generic image to a guarded new
24 GiB Btrfs disk, and booted that disk under QEMU/TCG. The nonce-bound guest
report observed kernel 7.3.4, enforcing SELinux, read-only `/usr`, read-only
Btrfs `/sysroot`, loopback-only networking, a zero-capability observer with
no-new-privileges, and the expected bootc deployment protected by
`containerPolicy`.

The full `rpm -qa` inventory then exceeded the probe's generic 60-second command
limit under its single TCG CPU. Package and payload comparison did not complete.
The accepted controller result therefore remains failed, with
`probe_completed`, `os_qualified` and `release_qualified` false. This run uses
the retained pre-font image from source `23a6c72`; it cannot qualify the current
font-bearing generic lock.

All 87 original artifact files (230,440 expanded bytes) and independent
reconciliation are retained under
`docs/security/reports/P0-03-atomic-boot/45869526684/`. QEMU exited normally
after 374.68 seconds. The fixture signing keys, three containers, loop devices,
loaded image, private storage and runroot were removed; no disk or overlay is
retained. Parent and QEMU cgroups show zero OOM/kill events and zero host swap.

The correction keeps the generic 60-second subprocess limit and assigns only
the complete RPM inventory an explicit 180-second allowance. The observer gets
one full guest CPU instead of half of that single CPU, while its 256 MiB memory,
32-task and zero-swap limits remain. `TimeoutStartSec=420` bounds the enlarged
slow path. A fail-first AST/unit regression requires all three limits; the 24
focused guest/controller tests pass afterward. A current-image hosted rerun and
all remaining desktop, containment, update/rollback and release gates remain
required.

The final serial repository gate passes all 280 image tests plus Cedar, Rust,
supply-chain and formal drift checks in 6.20 seconds at 70,188 KiB peak RSS,
with one Cargo job and zero swap.

## Reuse by the Landlock qualification workflow

When the hosted controller receives the fixed `SYMBI_QUALIFICATION=landlock`
mode, it completes this same install and basic boot acceptance first. It then
invokes the separate P0-04 controller for a second offline snapshot boot of the
unchanged installed disk. The second boot adds only a read-only authenticated
source disk and firmware-supplied test services; it does not change the Atomic
installer, local source signature policy, release policy, base image or ordinary
boot result. Its evidence and qualification claim remain separate under
`.cache/landlock-qualification-evidence`.

## Signed update and booted rollback gate

`update-base.lock.json` binds an older retained generic image, its hosted
artifact and the exact preflight evidence that previously inspected it. The
Atomic workflow downloads both that predecessor and the current image by
artifact ID, then validates workflow commit, name, size, digest and expiry. It
uses the already-loaded current image only as the bounded installer and tooling
environment; the predecessor's opaque OCI blobs are independently verified and
signed by a second ephemeral offline fixture key.

The predecessor is installed to a new guarded regular-file disk. The current
image is exposed through a second read-only raw ext4 backend and an explicitly
paired `virtio-blk-pci` device whose fixed serial is `SYMBIUPDATE`. The guest
waits at most 30 seconds for udev, resolves only
`/dev/disk/by-id/virtio-SYMBIUPDATE`, validates its ext4 type, label and
generated UUID against the hash-bound source metadata, and mounts it at
`/run/symbi-update` read-only with `nosuid,nodev,noexec` inside the update
service's private mount namespace. The service has no boot-time mount
dependency, so a missing device still produces a bounded guest report with the
observed block-device names.
A first disposable qcow2 overlay keeps the valid signature and invokes the real
`bootc switch --transport dir --enforce-container-sigpolicy` through the exact
overlayfs mount and fixed `/run/symbi-update-negative/source` path later used by
the rejection cases. It must return zero, keep the predecessor booted, set the
configured default to the exact staged current digest, and change no other
deployment slot. The controller records both state hashes, then deletes that
qcow2 so the staged change cannot reach another case.

Four independent qcow2 overlays then boot from the untouched installed
predecessor. Each receives the same in-memory source overlay containing the
authenticated manifest and blobs with exactly one control: no signature, a
signature from another key, a signature for another reference, or altered
signature bytes. The same command must return nonzero and the complete
configured image reference plus booted, staged, rollback and rollback-queue
state must remain unchanged. Every rejection must begin with the positive
control's recorded starting-state hash. The controller deletes each qcow2 before
the next case begins.

Three later boots reuse a separate persistent qcow2 overlay: the first stages
the correctly signed current digest, the second proves it booted and queues
`bootc rollback`, and the third proves the exact predecessor booted again.
Every boot requires the expected digest and `containerPolicy` status; only
loopback is present and host swap remains disabled. The ordinary
installed-image boot remains a separate harness mode and disk overlay.

This is a development recovery proof, not release signing. Both fixture keys
are generated offline and their private material is removed. The shipped
default-reject policy remains in each image; the temporary update policy exists
only in the disposable service mount namespace. The earlier Skopeo controls
remain required as source-policy evidence; they do not substitute for these
native bootc attempts. The hosted native VM result is not yet claimed.

[Run 45908852827](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45908852827)
at `a417ed1287e11a7ed0e75f686a078ed4ec0951b8` stopped before QEMU. Artifact
intake, OCI verification, current-source authentication and predecessor
installation preparation ran, then the parent rejected the requested
6,000-second controller deadline because its shared subprocess helper permits
at most 3,600 seconds. Evidence upload subsequently could not traverse the
root-owned update evidence directory. This branch keeps that shared limit
unchanged. A dedicated runner accepts only the fixed offline eight-boot Atomic
controller shape, including its local Podman storage, cgroup, isolation and
exact mount arguments. Its 5,400-second, one-MiB-per-stream bounds leave 20
minutes in the existing 110-minute systemd unit for predecessor preparation
and cleanup. The host wrapper refuses linked or special evidence trees before
use, then reclaims
only the three exact, direct evidence directories after the systemd unit stops
and revalidates them first. The failed run does not establish a signature
refusal, boot, update or rollback result.

[Run 45914576818](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45914576818)
then downloaded both retained images, authenticated and streamed the current
image, and refused before disk installation. Its preflight lock still named run
45901694620, whose complete desktop-image lock hash preceded the current NVIDIA
entry. The exact current lock had already passed preflight 45910498271 at
`4f43555`. The retained
62,578-byte evidence artifact, its GitHub digest, both report hashes, exact
generic image artifact, manifest and resource results were independently
reconciled, and the preflight lock now names that run. The failed attempt used
a zero-swap limit and launched no installer or VM; its failure record recorded
zero peak swap and zero OOM, OOM-kill and OOM-group-kill counters. Native update
acceptance still requires a fresh exact-head run.

## Preserve the SELinux install domain for update operations

[Run 45974190039](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45974190039)
at `c3781ebb990f90f82c2e7982c74fe9eb70ef265b` booted the first disposable
guest, selected mount ID 550 for the authenticated `/dev/vdb` ext4 source and
passed the read-only mount binding. Fixture-source authentication and cleanup
also passed. The update service then invoked `/usr/bin/bootc status --json`
directly from Python. Bootc lacked the SELinux install domain and its fallback
copy failed while assigning `security.selinux`: permission denied. No switch,
rejection case, updated boot or rollback ran, so the attempt remains failed and
unqualified.

The compact [failure manifest](../../docs/security/reports/P0-03-atomic-boot/45974190039/summary.json)
binds the 82,721-byte artifact, its 98 files, critical report hashes and resource
counters. The three-GiB controller and five-GiB parent reached their exact
ceilings, recording 6,651 and 172,673 limit events. Both recorded zero OOM,
OOM-kill, OOM-group-kill and swap. Containers, the loaded image, private storage
and private runroot were removed.

Status snapshots now restart the fixed `s.service` direct collector. Each read
requires a new root-owned 0600 bounded file, a successful active/exited service
result, stable file identity and a sequence-bound hash. Direct status execution
from the Python service is rejected by the controller.

Switch and rollback must see the source, overlay and temporary policy bind inside
`update-o.service`'s existing `PrivateMounts` namespace. A separate mutation unit
cannot inherit that arbitrary mount namespace. Instead, the fixed `b.service`
runs only three constant-path preparation commands in `install_t`: copy
`/usr/bin/bootc` to a new root-owned 0700 file, label it by reference to
`/usr/bin/ostree`, and move it to `/run/symbi-update-bootc`. Before every use,
the update service requires regular root-owned source, reference and copy files,
exact source/copy bytes, an independent single-link copy, exact label equality
and the `install_exec_t` type. It then executes only the fixed signed switch or
rollback command through that copy in its own mount namespace. The copy is
revalidated after execution and removed in `finally` on success, native
rejection, timeout or exception; unsafe cleanup fails the report.

The [pinned source review](selinux-launcher-source-review.json) records bootc
1.17.1's own copy, `/usr/bin/ostree` label and re-exec behavior. The correction
does not add a permissive fallback, policy exception, network interface or
caller-selected command. Enforcing SELinux, default-reject signature policy,
read-only source binding and all resource limits remain required. Static review
and offline fixtures cannot establish the expected domain transition. A fresh
hosted run must prove status, switch and rollback under the installed enforcing
policy before any update or OS qualification.

Run 45982201450 reached the fixed launcher preparation under enforcing SELinux,
but `b.service` failed before `o.service` started. The retained artifact did not
include the unit's result fields or journal, so changing the label mechanism
from that observation alone would guess at the failing systemd step.

The next run injects `f.service` as a failure-only diagnostic. `b.service`'s
`OnFailure` starts it; the ordinary boot target does not. Its `ExecStartPre`
requires `b.service` to be in the failed state, then the reporter records exactly
five systemd result fields and a sanitized `b.service` journal excerpt through
the existing virtio report channel. A failed precheck is a unit failure rather
than a clean condition skip, so `OnFailure=poweroff.target` and `ExecStopPost`
retain fail-safe shutdown if reporter validation fails. The excerpt is limited
to 24 lines, 512 bytes per line and 8 KiB overall; control characters and
secret-shaped assignments or long values are redacted. The report is limited to
128 KiB and bound to the diagnostic script's SHA-256. The controller validates
this exact schema and still fails the run. After the write, or if the diagnostic
fails, the guest powers off. The ordinary update path and its existing
`ExecStopPost` shutdown remain unchanged. This permits one bounded diagnostic
rerun and does not qualify or alter the launcher.
