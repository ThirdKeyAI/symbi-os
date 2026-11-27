# Fedora runtime qualification

These drivers are preparation for P0-04/P0-05. Offline tests of report validation
are not a qualification of Symbiont, Fedora or any sandbox.

## Landlock procedure

1. P0-03 must produce an authenticated Fedora OSTree/bootc image and an
   authenticated runtime build from `upstream/symbiont.toml`'s full revision.
   Use an isolated clean source checkout at that revision. The public v3.0.0
   binary was built from `6e93a5f4a88b1a8d70a31df214c6ddf8993d6f0e`, not the plan's
   `deddb9e997244d2289c217ad76b8fde0e9b0339b`; its version string is insufficient.
   Do not reuse the large, older local debug binary as evidence.
2. Provision one disposable QEMU/KVM guest: **one vCPU, 2 GiB RAM, no additional
   swap, no host filesystem shares**. Keep its disk on `/vmstore`, not tmpfs.
   Disconnect external networking after verified artifacts are staged. A localhost
   control connection may remain; the upstream providers are synthetic. Do not
   run an image build or another guest alongside it on this workstation.
3. Boot the exact generic image digest with enforcing containers signature
   policy and SELinux. The driver requires the selected secureblue Fedora 45
   identity (`ID=secureblue`, `ID_LIKE=fedora`, and the exact generic
   variant/image IDs); an arbitrary derivative that merely advertises Fedora
   lineage is rejected. Provision a separate non-root runtime/test user with a systemd user
   manager and cgroup v2 delegation. Do not relax user-namespace, SELinux, seccomp
   or host security settings to make a test pass. A default-policy refusal is a
   failure to qualify this image and must be retained separately.
4. `python3 image/qualification/landlock.py --check-host` performs only the guest
   prerequisite check. It always leaves `qualified: false`. The non-root driver
   reads bootc status before and after through the fixed output-only
   `/run/symbi-qualification/status.sock`. The root `q.service` accepts exactly
   two connections and can execute only `/usr/bin/bootc status --json`; it has a
   private PID/mount/network namespace, only `CAP_SYS_ADMIN`, bounded output and
   no request protocol. It never grants sudo or root execution to the runtime.
   The collector accepts OSTree; composefs needs separate digest semantics
   qualification before support is added.
5. Run the driver below using the authenticated binary digest and expected ABI
   for that guest. The output directory must not exist and must live on guest
   disk outside the source checkout and `/tmp`.

```sh
python3 image/qualification/landlock.py \
  --source "$PINNED_SOURCE_CHECKOUT" \
  --binary /usr/bin/symbi \
  --expected-binary-sha256 "$VERIFIED_BINARY_SHA256" \
  --image-ref "$VERIFIED_IMAGE_REFERENCE_WITH_DIGEST" \
  --expected-abi "$GUEST_LANDLOCK_ABI" \
  --bootc-status-socket /run/symbi-qualification/status.sock \
  --output "$NEW_PRIVATE_EVIDENCE_DIRECTORY"
```

The wrapper calls the pinned upstream platform diagnostic with `--expect usable`,
then its full Linux release driver with `--require-clean`. It requires all six
shipping cases and all three independent evidence suites, including verification
and integrity checks. A successful namespace-refusal diagnostic, shortened suite,
wrong source/binary, changed policy, failed cleanup or missing result fails.
No driver has a host fallback. A timeout fails and requires disposal of the guest;
it does not certify cleanup of separately supervised workers.

The same binary/source/deployment bindings are checked afterward. The output's
`summary.json` records an exact allowlist of public report hashes. **Never archive
the whole output tree:** `release/private-actions/` contains test signing keys.
Keep complete evidence private for investigation. Only the reviewed allowlisted
reports/logs and bootc metadata may be copied to the retained report directory.

The bootc policy field records the selected verification mode; it does not itself
prove a signature was checked or that the policy is correctly scoped. Link
P0-03's actual signature verification, unsigned-rebase rejection and rollback
tests before making a release claim. A passing Landlock report is limited to the
listed routes, exact binary, image, architecture and policy. It is not a proof of
every OS invariant, real Claude compatibility, or resistance after host compromise.

## Container procedure

P0-05 uses the same disposable selected Secureblue Fedora 45 guest, authenticated
runtime source and binary, immutable bootc image reference, and fixed two-read
`q.service` status socket as P0-04. The fixture image must already be cached by
digest, and the authenticated `runsc` executable must already be installed; the
driver does not pull, build, reconfigure the daemon or grant root to the runtime
user.

```sh
python3 image/qualification/containers.py \
  --source "$PINNED_SOURCE_CHECKOUT" \
  --fixture-source "$REVIEWED_FIXTURE_CHECKOUT" \
  --binary /usr/bin/symbi \
  --expected-binary-sha256 "$VERIFIED_BINARY_SHA256" \
  --expected-runsc-sha256 "$VERIFIED_RUNSC_SHA256" \
  --fixture-ref "$VERIFIED_FIXTURE_REFERENCE_WITH_DIGEST" \
  --image-ref "$VERIFIED_IMAGE_REFERENCE_WITH_DIGEST" \
  --bootc-status-socket /run/symbi-qualification/status.sock \
  --output "$NEW_PRIVATE_EVIDENCE_DIRECTORY"
```

The runtime checkout remains the exact source of the installed binary. A
separate clean fixture checkout is pinned to reviewed merge
`be3bef1dababb49a68450a883dc1ba97fa6322b0`; its tree and all three driver
digests are checked independently. The driver inspects the daemon, fixture image
and each bounded runc/runsc probe, then runs all three complete fixture drivers
once with runc and once with runsc. Each of the six reports must contain the
exact supported cases, only the selected observed runtime, and no remaining
workers, leases or containers. The two source trees, binary, runsc, deployment,
fixture image and driver hashes are rechecked afterward. Its `qualified` field
deliberately remains false until the managed route, escape suite and required
reviews are complete.

## Hosted container gate preparation

The existing Fedora runtime workflow accepts a manual `containers` selection;
normal `main` execution remains the Landlock gate. The container selection uses
the same authenticated development-image intake and Atomic controller. It
checks out the installed runtime source and the reviewed merged fixture source
separately, re-verifies the retained signed gVisor Debian repository metadata
offline, and binds the complete package inventory plus the shared P0-04 fixed
status-service inputs.

The gate currently stops before allocating the 60 GiB install disk because
`image/container/fedora-runtime.lock.json` does not yet exist. That future lock
must bind the exact passive workflow run and candidate artifact, then retain the
full resolved RPM closure using the fields the discovery job actually produces:
filename, byte count, SHA-256, NEVRA, vendor, license, signature status and the
Fedora signing-key fingerprint. Fedora deliberately uses `repo_gpgcheck=0`, so
the lock must not synthesize a per-package `repository_metadata_sha256`; the
reviewed repository-configuration hash and each RPM's verified signature are
separate evidence. A later installation record must bind that complete closure
and every installed gVisor file to the retained development image. The retained
preflight result keeps `passed`, `qualified`, native-matrix, managed-route and
escape-suite fields false. This is a bounded fail-closed controller skeleton,
not Fedora execution evidence.

## Hosted Landlock execution

`.github/workflows/landlock-qualification.yml` performs a fresh authenticated
installation using the existing Atomic harness and then boots an explicit,
private qcow2 overlay over the read-only installed disk for the Landlock suites.
The exact clean upstream checkout is placed on
an ext4 disk with label `SYMBIQUAL`; its commit, tree, submodules, Cargo lock,
filesystem UUID and bytes are bound before the disk becomes read-only. QEMU gives
that source a fixed `SYMBIQUAL` virtio serial. Systemd mounts the corresponding
`/dev/disk/by-id` path in the main namespace with a 30-second device timeout and
`ro,nosuid,nodev,noexec`. A bounded capability-free root service then verifies
the exact ext4 type, label, UUID and mount before the unprivileged runner starts.

The firmware services create a disposable UID 10001 account and delegated user
manager only in the QEMU overlay. They do not add an account to the product
image. The runner has no capabilities or network device, and it receives only
the fixed driver and public expectations. The status collector retains its sole
`bootc status --json` authority. Systemd powers off the VM after either success
or failure.

Public evidence is limited to the driver's explicit allowlist. Each file is
regular, singly linked, owned by the test user, hash-bound and at most 2 MiB; the
expanded set is at most 12 MiB. The controller rejects private action paths,
key-like names, malformed compression and mismatched hashes before writing the
artifact directory. It opens every retained path component with `O_NOFOLLOW`, so
a report cannot disguise a private path behind a parent symlink. Raw stdout and
stderr from the outer qualification wrapper never cross the guest channel; only
their byte counts and hashes do. Automatic execution is limited to `main`, with
manual dispatch available for a review branch, and stale runs are canceled. The
workflow uses an ephemeral CI fixture signature for the local install source, so
even a passing run is native development-image qualification, not release-signature
or OS-release approval.

## Upstream references

- [Pinned platform diagnostic](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/scripts/test-landlock-platform.py)
- [Pinned full release driver](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/scripts/test-landlock-release.py)
- [Linux qualification scope](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/docs/linux-containment-qualification.md)
- [bootc status schema](https://github.com/bootc-dev/bootc/blob/main/docs/src/host-v1.schema.json)
