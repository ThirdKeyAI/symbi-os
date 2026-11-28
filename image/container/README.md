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
only that set. The database is selected directly instead of changing root, so
the read-only discovery container keeps every Linux capability dropped. The test
transaction executes no scripts and installs nothing.
Because the read-only container reports no installable root space, the test
transaction skips RPM's disk-space check; package bytes are bounded separately,
and dependency and file-conflict checks remain enabled.

Hosted run 45940456063 passed that passive closure check at exact head
`6927b6514e564f92544c7c24a674738f82b2a09c`: all 108 signed RPMs totaling
116,875,288 bytes passed the offline transaction, package inventories stayed
unchanged, and both negative controls passed. The retained
`P0-05-fedora-packages/45940456063/` record is candidate evidence only. It does
not install packages, select gVisor, create `fedora-runtime.lock.json`, or set
`os_qualified` true.

## Candidate image installation

`fedora-runtime-candidates.lock.json` selects successful discovery run
`45940456063` at exact source commit
`6927b6514e564f92544c7c24a674738f82b2a09c`. It binds the workflow and
repository identities, the 108 signed RPMs (116,875,288 bytes), and both hosted
artifact ZIP digests. The separate `Container runtime candidate image` workflow
authenticates those API records and the retained desktop OCI before extracting
anything. It also rechecks the discovery summary, input bindings, complete
closure manifest, Fedora key and gVisor's signed repository metadata.

The hosted build has no network and one job under a 2 GiB, one-CPU, zero-swap
subtree. The 108-RPM empty-database closure is provenance and solvability
evidence; it is not treated as an install delta because it contains clean-root
provider choices that differ from the Secureblue variant. The build verifies
every RPM signature again, binds the retained 2,184-package source inventory,
and requires the exact `moby-engine`, `docker-cli` and `container-selinux` NEVRAs
in both the signed closure and source image. The reviewed RPM transaction is
empty: before and after inventory hashes must match, and no addition or
replacement is allowed. The authenticated gVisor files and reviewed daemon
configuration must have absent destinations and are copied without executing
runsc. A read-only, unprivileged probe then checks the unchanged package
inventory, exact roots, file hashes, ownership, modes and daemon configuration.
Any future source-aware additive RPM transaction requires a separate reviewed
lock and hosted evidence; this candidate cannot infer one from the clean-root
closure.

The workflow emits a derived development OCI and `fedora-runtime.lock.json`.
The contract records before/after inventory hashes and is accepted by the same
fail-closed validator used by native preflight. It deliberately keeps
`qualified`, `os_qualified` and `release_qualified` false. A successful image
build establishes installation evidence only; daemon startup, the six native
fixture runs, managed route, escape suite and required review still block P0-05.

### Native consumer binding

`fedora-runtime-image.lock.json` is the reviewed selector for that generated
output. It is committed as an exact pending slot: producer run, workflow ID,
artifact ID, sizes and hashes, manifest hash, contract hash and OCI identity are
`null`, `selected` is false, and all qualification/signature claims are false.
The native workflow validates this slot before any multi-gigabyte transfer, so
the current pending record cannot download or consume an unavailable artifact.

After the producer has actually passed, the `record-selection` subcommand in
`image.container.native_image_inputs` accepts the real GitHub run metadata,
artifact metadata and downloaded artifact ZIP. It verifies the successful
manual workflow through the attempt-specific run endpoint, repository, head
commit and branch, artifact ID/name/size/digest, the generic-only generated
manifest, false signature/qualification claims, the complete OCI archive hash,
the producer-recorded OCI identity and the generated `fedora-runtime.lock.json`.
The normal contract validator then
rechecks the signed Fedora closure, selected signed gVisor repository package,
unchanged source inventory and installed file hashes. The command prints a
reviewable replacement selector; it does not modify the committed pending slot.

GitHub artifact metadata does not expose the run attempt. The gate therefore
does not claim an independently authenticated artifact-to-attempt relationship:
it authenticates the selected attempt record and separately binds the exact
artifact ID, run ID, head commit, repository, byte count and digest. The
selected bytes remain exact, while the attempt association remains a review
constraint until the producer emits an attempt-bound manifest field.

Once that exact replacement is reviewed, the native workflow records a
structured pending/failure result and requires 30 GiB free before transfer: the
13 GiB maximum artifact ZIP, 12 GiB maximum streamed OCI and a 5 GiB margin. It
then downloads only the selected attempt record and artifact, and rechecks
space before extraction. A one-CPU, 1 GiB, zero-swap, 30-minute hosted input
unit streams the OCI without unpacking its filesystem and retains the generated
contract beside it. Its record binds the hosted source/run identity, cgroup and
zero-OOM observation; native preflight also requires the successful final unit
result and zero swap. Wrong run, head, artifact, ZIP/manifest/contract/OCI hash,
signature claim, variant, linked path or resource record fails before an install
disk is allocated.

The hosted Atomic controller now binds the next stage. Once the reviewed slot
contains a real selected producer, it loads only that streamed OCI archive,
requires the selected image ID and manifest digest, verifies the opaque OCI
layout, and applies the existing ephemeral offline test signature with its
positive and negative policy controls. It then uses the existing `bootc`
installer and first offline QEMU boot. The booted guest checks every runsc path
and hash plus `/etc/docker/daemon.json` from the generated
`fedora-runtime.lock.json` using descriptor-relative traversal that rejects
links in every path component; it also requires the unchanged source RPM
inventory.
The outer native controller remains at 4 GiB, two CPUs and zero swap, matching
the existing Landlock gate. A successful observation records only a candidate
boot pass: `qualified`, `os_qualified` and `release_qualified` stay false, and
`native-fedora-six-run-matrix`, managed-route, escape-suite and review blockers
remain. This stage does not invoke the daemon/fixture controller, and no fixture
profile runs. Its bounded evidence records `candidate_boot_passed=true`, runs
cleanup, and then leaves the overall qualification workflow nonzero until the
six-profile controller and remaining gates pass.

The committed selector is still pending, so this install/boot path has not run
against a real derived artifact. No native-containment result can be inferred
until the producer and selector are retained and the later six-profile
controller passes.

`gvisor-inputs.json` fixes release `release-20261123.1`, its commit and tag
object, the complete x86_64 bzip2 archive, the publisher checksum list, license,
and every archive member. The passive hosted intake refuses aliases, duplicate
paths, links, special files, privileged modes, changed payloads and unexpected
members. It neither extracts nor executes the archive. The tag and commit are
unsigned and no GitHub attestation was found, so this candidate remains
unselected and cannot establish release or OS qualification by itself.

`daemon.json` is a reviewed configuration input and is never installed or
enabled on the host. The hosted candidate-image stage installs its exact bytes
only after the signed package closure and gVisor payload pass. Native
qualification must validate it with the exact `dockerd --validate --config-file`
executable before starting the daemon. It selects systemd cgroup v2, SELinux, seccomp's
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
drivers from merge `cd4b34282ade880c8ac3d5136d31ff80cde92794`, separately
from the installed runtime's exact source checkout. That merge retains PR 24's
driver bytes and adds PR 25's serialized lifecycle CI. Each complete driver runs
once with runc and once with runsc. Validation requires the exact 9/9/14
supported case sets, the selected runtime in actual worker observations,
unchanged source, binary, deployment, runsc and driver hashes, and empty worker,
lease and container state after every run. Failure is retained; discard the VM
after an uncertain creation/cleanup or timeout. No global Docker prune, daemon
restart or host-policy change is performed.

These are infrastructure probes and bounded tool-worker fixtures. The report
keeps `qualified: false` even if all six runs pass. The reviewed drivers now have
an explicit gVisor selector and must observe runsc; the daemon default remains
runc. This still does not exercise the shipping managed route, its broker socket
transport or the OS escape suite.

The controller source now pairs each backend with a narrower observed-negative
probe. It owns positive-control TCP, UDP, abstract Unix and filesystem Unix
listeners plus synthetic private-file controls, then independently requires no
worker delivery or access and confirms removal by its exact container name.
`controller_escape_negatives_passed` is intentionally separate from
`escape_suite_qualified`: only the former can be set by these probes. A compact
`qualification.json` retains the matrix, observations, hashes and cleanup; raw
reports and private controls remain on the discarded guest overlay.

The native fixture OCI itself is not preserved yet. The reviewed
`native-fixture-image.lock.json` slot is therefore `pending`, with null producer,
artifact, manifest and archive digests and no selector-authored image identity.
It is bound to merge
`cd4b34282ade880c8ac3d5136d31ff80cde92794`, its tree and the three driver
hashes. A selected intake authenticates the producer run and artifact API
records, expiry and repository IDs, exact ZIP bytes and members, the inner
archive and the bounded manifest. It then verifies the manifest-derived image ID
and repository digest against the OCI layout. The consumer run has its own exact
identity and need not equal the earlier producer commit. The existing producer
workflow has not emitted this OCI, so the gate remains closed.

A standard-library streaming exporter is wired behind the pending public
package selector and `native-fixture-build.lock.json` prerequisite gate. It
converts one Docker-save image only after checking the ordered uncompressed
layer `diff_id` values, Linux/amd64 configuration, current manual-run identity
and output cleanup. It writes byte-stable gzip/tar output for identical
Docker-save input bytes, independently passes the result through the same
bounded OCI unpacker as the consumer, and permits at most a 64 KiB manifest,
512 MiB compressed OCI and 1 GiB expanded OCI.

The exporter binds three pairwise-distinct digests. `D0`, recorded as
`initial_target_digest`, comes from `--iidfile` and must equal the initial
Docker inspect `Id` and `Descriptor.digest`. `C`, recorded as `config_digest`,
is the selected source manifest's config digest. `G`, recorded as
`generated_target_digest`, is the deterministic generated manifest digest and
carries a source-target annotation for `D0`. A cold load must resolve both
Docker inspect `Id` and `Descriptor.digest` to `G`, with the exact repository
digest `localhost/symbi-ci/native-fixture@G`.

The fixture Dockerfile consumes only the exact selected package archives and
builds with `--network=none`. The hosted source lock selects the native
contract's merge `cd4b34282ade880c8ac3d5136d31ff80cde92794`, exact tree and
driver hashes, and current-source execution has passing evidence; the separate
source-alignment prerequisite remains a blocker. After package selection, the
same run must build the image offline, pass all six profiles from the required
merge, export and remove the tested image, and cold-load the generated OCI by
`G`. Artifact upload remains withheld. The committed prerequisite slot records
all four blockers and keeps every qualification claim false.

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

## Unselected Ubuntu closure producer

The next package-closure slice is now represented by dormant producer code in
`ubuntu_fixture_package_build.py`. It strictly parses the signed Release payload
from each reviewed InRelease, checks suite/codename and Date/Valid-Until
freshness, binds the exact amd64 Packages.xz SHA-256 member, and matches apt's
file-only offline plan to exact signed package rows. It also provides bounded
sequential no-redirect downloads, exact pending-lock Ubuntu Base dpkg-status
binding, a no-act dpkg plan, and exact candidate-directory validation. Download
rows are fully checked before an opener can run, and all payloads share one
Linux real-time aggregate deadline that interrupts a blocking read, in addition
to their per-operation timeout. Its
manifest is always `candidate-unselected`; `producer_passed`, every verification
field and every qualification claim remain false, and the pending public input
contract still refuses it. All staged paths are private and descriptor-relative:
every component is opened without following links and each file is hashed,
parsed or copied through the same stable single-link descriptor.

The separate ubuntu-fixture-packages.yml workflow is manual only. Before the
retained-metadata handoff, its producer contract reached ready with all six
exact InRelease and Packages.xz byte/hash pins independently reviewed from
hosted discovery run 46070755519.
The former pending state remains fail closed: it permits discovery and refuses
production before retained-input validation, cgroup inspection, authenticated
commands or a network opener. The committed ready state instead refuses
discovery and permits the production path to reauthenticate those exact pins,
run file-only apt and no-act dpkg phases in a new network namespace, stream
bound packages one at a time, validate an unselected candidate twice and reach
the conditional candidate upload. The first production attempt authenticated
all pinned metadata, then failed before package planning because its relative
source-list value duplicated the private APT root's etc/apt segment. The
commands now bind an explicit private Dir::Etc, one private source list and an
empty private source-parts directory. Each fixed source row also binds the
reviewed per-source valid-until-max ceiling and enables Check-Valid-Until.
The next exact-head attempt proved that private path and used only the three
exact `file:` repositories, then failed at APT update when the runner's global
command-not-found target requested absent `main/cnf/Commands-amd64` indexes.
The narrow correction fixes the offline command set with
`Acquire::IndexTargets::deb::CNF::DefaultEnabled=false`; its strict policy
validator requires the complete ordered argv for each offline APT phase,
including that exact single index-target override. Alternate option spellings,
late duplicate overrides and source expansion fail closed. A fresh exact-head
run is required to test it.
The Dockerfile, native producer, image consumer and public pending lock remain
unchanged, and every candidate, selection, pass and qualification claim remains
false pending an exact rerun.

Freshness is bound to each exact source URL, suite, codename and signer. The
immutable noble pocket has a unique signed `Date`, no `Valid-Until`, a 15-minute
future-skew ceiling and a reviewed 1,830-day maximum age. The rolling
noble-updates and noble-security pockets have the same future-skew check and a
14-day maximum signed-`Date` age. They may omit `Valid-Until`; when present, the
single field must be unexpired, strictly after `Date`, and no more than 14 days
after `Date`, so it can only shorten the rolling bound. The Python validation
authenticates each Release before production. Its offline APT source rows also
impose matching per-source `valid-until-max` bounds of 1,830 days for noble and
14 days for the two rolling pockets, enable `Check-Valid-Until`, and are
revalidated as an exact set before any APT command runs.

Candidate output is moved from an isolated held staging directory with atomic
no-replace semantics and accepted only after the complete nested identity and
content binding is revalidated through the held destination root. Within that
reusable writer, failure paths do not remove names because same-UID substitution
cannot be excluded. After the hosted systemd unit stops, its wrapper rechecks
each exact direct mode-0700 cache directory under the resolved checkout and
retains the private scratch for disposal with the ephemeral runner. It performs
no recursive pathname cleanup or ownership change. Raw command output, held tool
hashes, cgroup counters, systemd status and retention state remain in the
evidence artifact. A separate systemd-derived fallback resource record is
always written, including when the primary cgroup record is truncated, so swap
and OOM state remain observable.

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

## Durable Ubuntu metadata review boundary

The Ubuntu closure contract is schema 3. Discovery run `46129698065` published
the separate seven-member artifact containing the manifest plus the exact
three InRelease and three signed Packages.xz files. Independent review bound
the producer run/attempt/head/tree/branch, artifact identity and size, matching
API and downloaded ZIP digests, manifest, discovery contract, pending lock and
all six payload hashes. The checked-in contract is now `ready` with canonical
SHA-256 `2c22f3e33c7081c4011a78a247b5f8f845a3386ac4ce44db0d07a03b84a6d841`.

The shared workflow job grants read-only `actions` and `contents` permissions
in both modes, so pinned workflow actions including checkout can use its job
token. Discovery passes no `GITHUB_TOKEN` to repository code and its wrapper
refuses one if injected. Production passes `GITHUB_TOKEN` only to the bounded
pre-transfer repository process, which removes it before the transient service;
it never enters the service's clean environment. The service consumes the
reviewed private files without refetching live repository metadata, then
rechecks signatures, production-time freshness and each signed index row.
Candidate provenance retains the complete source selection and every authority,
selection and qualification field remains false. The ready state permits one
manual unselected production attempt. Production run
`46138934586` reached the exact networkless 68-archive `dpkg --no-act` argv
and then failed closed because dry-run package state does not accumulate across
archives. That run emitted no package or image candidate.

The ordered networkless APT simulation proves the exact signed closure and
install order. Native `dpkg` parses and prepares every exact staged archive
while exactly two reviewed Python pre-dependency warnings are accepted and
bound to the `python3-minimal` and `python3` archives in C-locale stderr. Each
reason must equal its authenticated Packages.xz `Pre-Depends` field; the two
reviewed dependent/target/operator relationships are fixed in code and their
targets must appear earlier in the signed order. Any other waived dependency
event is rejected. This does not prove an installed system, configuration,
triggers, maintainer scripts, container behavior, selection or qualification.
The precise failed-run record, native-proof split and upstream dpkg references
are retained in
[the P0-05 card](../../docs/cards/P0-05.md).

The corrected manual production run
[46142528811](https://github.com/ThirdKeyAI/symbi-os/actions/runs/46142528811)
passed at exact head `6cf7c43f90216c4622dff44cc8f3db6771718cc5` and tree
`ec1c3e625a30e9142ad7364cf1cc857bfd26379c`. It emitted an unselected
68-package candidate totaling 36,832,124 package bytes; the candidate manifest
SHA-256 is `2e769f967bd255041b3db571646bd20008cfa253d6e16cf869beb7992c6a98c8`
and the order SHA-256 is
`cb07815cc13c85b68e7b24934885e0d83d73cd9c37bc1052b0d7df65075bce77`.
The only accepted native dry-run dependency diagnostics were
`python3-minimal` Pre-Depends `python3.12-minimal` with `>=` and `python3`
Pre-Depends `python3-minimal` with `=`.

This proves signed metadata, exact package download and order, and native
`dpkg --no-act` parse/prepare only. It does not prove installed or configured
state, maintainer scripts, container isolation, selection, OS qualification or
release qualification. The manifest remains `candidate-unselected` with
`producer_passed` and every selection or qualification field false. The public
pending lock is unchanged because it requires a separate reviewed selection;
the unselected candidate cannot authorize its own consumption. Exact run,
artifact, resource and proof-limit details are retained in
[the compact record](../../docs/security/reports/P0-05-ubuntu-packages/46142528811/record.json).

## Prepared offline package consumer gate

The manual hosted fixture workflow now fails before artifact transfer unless a
reviewed schema-2 selection binds the exact successful producer run, both
artifact API records and archive digests, the candidate manifest, producer
result, signed metadata, every package row and every retained member. The
committed selector remains `pending`; its package inventory is empty and all
selection, verification and qualification claims remain false.

After that separate review, the consumer can materialize only those exact
bytes. It stages the packages with sequence prefixes derived from the retained
download order and refuses missing, repeated, renamed, linked or changed
archives. The image build uses `--network=none`, unpacks each package in that
order, configures the already unpacked set before the two exact Python
Pre-Depends boundaries, and finishes with `dpkg --configure -a`. A successful
run would provide native install, configuration, maintainer-script and trigger
evidence for this development fixture only.

After all evidence writes, the image normalizes only
`/usr/share/symbi-fixture-evidence`: directories are mode `0755` and files are
mode `0644`, so the unprivileged collector can traverse the complete nested
evidence. The collector admits the existing report and signed InRelease types
plus exactly `noble_main_binary-amd64_Packages.xz`,
`noble-updates_main_binary-amd64_Packages.xz` and
`noble-security_main_binary-amd64_Packages.xz`; every other `.xz` is rejected.

The same run must still pass all six runc/runsc fixture profiles against the
required source merge, export the tested image, remove it and cold-load the OCI
by its manifest digest. Source alignment, cold-load evidence and explicit
artifact-upload approval remain separate pending prerequisites. The workflow
has no native OCI upload step, and none of these source changes selects or
qualifies the retained candidate.
