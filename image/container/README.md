# Container engine choice and qualification

P0-05 chooses Fedora **moby-engine** plus its Docker CLI for the initial image.
This matches the pinned Symbiont Docker API and gVisor integration. Podman's
Docker-compatible socket is not selected or treated as equivalent without its
own qualification. Podman can still be an image-build tool on a separate runner.

Fedora's [package catalogue](https://packages.fedoraproject.org/pkgs/moby-engine/moby-engine/)
lists the engine and related Docker CLI package. Exact RPM NEVRAs, dependencies,
repository keys and package hashes must be locked for the selected P0-03 base;
the mutable package catalogue is not a release pin. The separate
`container-runtime` discovery profile now prepares those exact candidates on a
hosted Fedora runner without installing them. Select it manually from the
existing Fedora package discovery workflow; ordinary `main` and pull-request
runs continue to use the `hyprland` profile. The workflow validates the selected
choice before passing it as a quoted argument to the wrapper, which also checks
its profile allowlist. Because the selected base already contains the three
requested engine packages, this profile uses `dnf5 download --resolve --alldeps`
with a private destination and the exact installed root NEVRAs. The downloaded
set remains a candidate until its roots match, every RPM signature passes, and
an RPM test transaction resolves against an empty private RPM database using
only that set. The test transaction executes no scripts and installs nothing.

`gvisor-inputs.json` fixes release `release-20261123.1`, its commit and tag
object, the complete x86_64 bzip2 archive, the publisher checksum list, license,
and every archive member. The passive hosted intake refuses aliases, duplicate
paths, links, special files, privileged modes, changed payloads and unexpected
members. It neither extracts nor executes the archive. The tag and commit are
unsigned and no GitHub attestation was found, so this candidate remains
unselected and cannot establish release or OS qualification by itself.

`daemon.json` is a reviewed configuration input, **not installed or enabled on
the host or current image overlay**. After the packages and runsc pin are ready,
validate it with the exact `dockerd --validate --config-file` executable before
installing it into the image. It selects systemd cgroup v2, SELinux, seccomp's
default profile, no-new-privileges and explicit `runsc` registration; live restore
is off because daemon loss can otherwise outlive worker cleanup. It does not set
`hosts`, avoiding conflicts with the package's socket activation. Qualify that
the final unit exposes only its Unix socket and no TCP listener.

The daemon socket grants host-level control. Restrict it to the trusted runtime
service account and administrator; do not add desktop users or agents to its
group. Never mount it in workers, expose it through a broker, or put registry
credentials into worker homes. The final runtime account/unit and SELinux policy
belong to the implementing runtime cards and must be reviewed before enabling
production services. Missing runsc, SELinux denial or daemon errors fail; no
fallback to unconfined Docker/Podman or permissive SELinux is allowed.

## Prepared guest probes

Use the same one-vCPU, 2 GiB, isolated Fedora guest procedure as
[Landlock qualification](../qualification/README.md). Stage an authenticated
fixture OCI image containing `/usr/local/bin/python3` and Git; it must have no
anonymous image volumes or secrets. The scripts never pull an image themselves.

```sh
python3 image/qualification/containers.py \
  --source "$PINNED_SOURCE_CHECKOUT" \
  --fixture-source "$REVIEWED_MERGED_FIXTURE_CHECKOUT" \
  --binary /usr/bin/symbi \
  --expected-binary-sha256 "$VERIFIED_BINARY_SHA256" \
  --expected-runsc-sha256 "$VERIFIED_RUNSC_SHA256" \
  --fixture-ref "$VERIFIED_FIXTURE_REFERENCE_WITH_DIGEST" \
  --image-ref "$VERIFIED_OS_REFERENCE_WITH_DIGEST" \
  --output "$NEW_PRIVATE_EVIDENCE_DIRECTORY"
```

The driver checks source/binary/deployment identities, daemon prerequisites and
the cached fixture digest. It creates one runc and one runsc probe **sequentially**,
each limited to 0.5 CPU, 256 MiB with no extra swap, 32 PIDs and 16 MiB scratch.
Before starting, it inspects immutable container/image IDs, non-root UID, private
namespaces, capability drop, read-only root, network-none and resource limits.
It verifies useful scratch work and several denials, then removes only its own
container and confirms cleanup. Proxy settings and image environment values are
excluded from retained daemon/inspection metadata.

It then runs the reviewed upstream filesystem-grant, source-broker and Git-source
drivers from merge `be3bef1dababb49a68450a883dc1ba97fa6322b0`, separately from
the installed runtime's exact source checkout. Each complete driver runs once
with runc and once with runsc. Validation requires the exact 9/9/14 supported
case sets, the selected runtime in actual worker observations, unchanged source,
binary, deployment, runsc and driver hashes, and empty worker, lease and
container state after every run. Failure is retained; discard the VM after an
uncertain creation/cleanup or timeout. No global Docker prune, daemon restart or
host-policy change is performed.

These are infrastructure probes and bounded tool-worker fixtures. The report
keeps `qualified: false` even if all six runs pass. The reviewed drivers now have
an explicit gVisor selector and must observe runsc; the daemon default remains
runc. This still does not exercise the shipping managed route, its broker socket
transport or the OS escape suite.

The manual `containers` choice in the shared Fedora runtime workflow is a
preflight skeleton. It verifies the retained signed gVisor Debian repository
metadata with the pinned full publisher fingerprint and uses the complete
package inventory as a development input. It does not select that package for a
release. Until a signed Fedora runtime lock binds the engine RPMs and installed
gVisor files, the controller exits before disk allocation and retains an
explicitly unqualified result.

That input preflight runs before the retained desktop-image artifact is
downloaded. A missing or invalid lock therefore fails without transferring the
multi-gigabyte image. A passing input preflight means only that immutable inputs
are ready for the native stage: all qualification fields remain false, and the
native matrix, managed route, escape suite and review stay listed as blockers.
The lock must also retain false qualification fields and use the exact pinned
Fedora 45 RPM-signing fingerprint. It cannot be generated from the passive,
unsigned gVisor release intake alone.

## Required remaining evidence

- Build exact-source supervisor/runtime test executables on the isolated builder.
  Run upstream `symbi-sandbox-supervisor` lifecycle tests and
  `sandbox::docker::tests::e2e::` ignored tests explicitly with **one test thread**.
  Preserve the required synthetic ambient canary and cached-image binding. Do not
  compile the large runtime while a qualification VM runs on this workstation.
- Add/qualify the actual shipping gVisor managed route with prepared-call tools,
  broker socket interoperability, image-volume rejection, cancellation/revoke,
  cleanup and the OS escape suite. Runtime changes and reusable runtime-driver
  changes go upstream first; retain the updated source pin and report.
- Retain engine/RPM/runsc/fixture/binary/OS digests, policy and namespace settings,
  complete case results and cleanup evidence for **both** tiers. Attach the report
  to the scoped upstream controls; do not infer gVisor success from Docker success.

References: [pinned Docker boundary and real-backend tests](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/docs/docker-containment.md),
[pinned gVisor wrapper](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/crates/runtime/src/sandbox/gvisor.rs),
[Docker daemon configuration](https://docs.docker.com/reference/cli/dockerd/),
[gVisor Docker integration](https://gvisor.dev/docs/user_guide/quick_start/docker/).
