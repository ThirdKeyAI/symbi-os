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


The second preflight successfully inspected the protected kernel inputs and kept
all permissions intact. Its controller then rejected the actual secureblue
identity and absent bootc filesystem default because the harness expected plain
Fedora and a configured default. The corrected validator requires the exact
selected secureblue variant and explicitly reports that a later installer must
choose a filesystem. It does not silently pick or install one. The original failed
run and complete 41-file evidence remain retained under `45802753036/`.
All 219 local image tests pass; the corrected hosted result is pending.

## Exact retained pre-font image compatibility

[Preflight 45869526766](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45869526766)
verified the locked 4.03 GB archive, loaded its exact image, copied and hashed the
protected kernel files from a never-started container, then stopped before the
installed-file comparison. The current desktop verifier imported the new font
module, but this retained image and its preparation record predate the font
payload. The failure is a verifier-generation mismatch; it is not a failed font
parse or a changed image byte.

The verifier now permits a missing font record only when the preparation source
is exactly `23a6c721092ad77c3af33c11cab230ecaaa54cff`, the source bound to both
locks when this failure occurred and still bound to the retained pre-font NVIDIA
image. It reports `checked: false` and makes no native font claim. Any other
fontless record is refused. The generic lock now selects the font-bearing
`d436c6e` image. Atomic preflight stages and hashes `font_verify.py`, so that
image must execute the native scan. The desktop builder requires fonts
unconditionally.

All 35 original evidence files and the original 53,710-byte artifact are retained
and independently hash-reconciled under `P0-03-atomic-preflight/45869526766/`.
Both temporary containers, the private kernel copy and the loaded image were
removed; there were no OOM or kill events and swap remained disabled. A hosted
rerun is required. Fourteen focused tests and the final 279-test serial repository
gate pass; the latter took 4.13 seconds at 67,436 KiB peak RSS with zero swap.
This correction adds no boot, installation or OS claim.
