# Atomic development image boot preparation

`desktop-images.lock.json` pins exact saved generic and NVIDIA OCI archives,
including their original manifests, source commits, build runs and artifact
hashes. `inputs.py` verifies the original two-member ZIP and streams the opaque
OCI bytes into new private storage. It never unpacks the image filesystem itself.
Development artifacts remain unsigned and unqualified; this is not an install or
rebase route for users.

`atomic-preflight.yml` consumes the actual hosted archive and rechecks its metadata,
size, complete bytes and loaded image identity. It uses new private Podman storage,
no registry pull and no native compilation. Two unprivileged, read-only containers
with no network, devices, capabilities or writable host mounts recheck all installed
payload files/packages and observe the installer, kernel/initramfs, SELinux
configuration and exact enforcing image-trust bytes. All containers and the private
loaded image must be removed and verified absent. No disk is created or installed.

Preparation is limited to 1 GiB/one CPU/64 tasks; the delegated controller has
4 GiB/two CPUs/256 tasks and each inspection has 512 MiB/one CPU/64 tasks. All use
zero swap. The 4.03/5.03 GB archives stay hosted; only bounded public logs and
reports are retained. Existing live preflights are never cancelled by another run.
Six acceptance tests refuse policy/package/kernel drift, missing observations,
unsafe isolation, false qualification claims, wrong loaded images and local use.
All 213 image tests pass locally under 128 MiB/10%-CPU/zero-swap limits; full hosted
workspace/formal and real preflight results are still pending for this change.

The retained package identities select bootc 1.17.1 and the exact secureblue kernel
7.3.4-300.secureblue.1.fc45.x86_64. Configuration observation does not establish
booted SELinux enforcement. Source research at bootc upstream
[d01e723ae9480fa53aa9db09a7eff0439548e9f6](https://github.com/bootc-dev/bootc/blob/d01e723ae9480fa53aa9db09a7eff0439548e9f6/crates/lib/src/install.rs)
confirms that offline installation and subsequent-update policy are separate paths;
the old no-signature-verification option is a no-op. It does not establish Fedora
installed-source/backport equivalence. Any later installer must preserve the exact
installed trust policy, require update signature enforcement and target only a new
private regular disk file on a disposable hosted runner. Do not copy upstream test
examples that disable SELinux.

Actual installation/Atomic boot, rendering/input, consent interaction, containment,
physical NVIDIA, signed release/update/rollback and human TCB reviews remain gates.
The existing cloud graphics result is infrastructure evidence, not an Atomic boot.


## Protected kernel-file observation

The first real saved-image preflight passed archive ingestion, exact image loading
and all installed files/packages, then failed because the unprivileged probe could
not read the protected initramfs. The original failure and complete cleanup evidence
are retained under `P0-03-atomic-preflight/45799924739/`.
The correction uses [Podman's stopped-container file copy](https://docs.podman.io/en/latest/markdown/podman-cp.1.html)
for only kernel/initramfs, into new private CI storage. The source container must
remain never-started before and after. No code runs as root in a container, no
installed permissions change, and the private copied bytes are deleted after
hashing. The two unprivileged probes receive only hash-bound metadata. Four new
regressions pass; all 217 image tests pass locally. Corrected hosted acceptance
is pending. This still performs no disk installation or boot.
