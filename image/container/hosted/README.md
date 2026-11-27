# Hosted container fixture execution

This is Ubuntu development evidence for P0-05. It does not qualify Fedora,
managed CLI brokers, the escape suite or a release image. The OS runtime pin is
unchanged. Current selected passing evidence uses merge
`cd4b34282ade880c8ac3d5136d31ff80cde92794`, its exact tree and the three driver
hashes bound through `native-fixture.lock.json`. Earlier retained passing
evidence used fixture-only commit
`c1fac8aab6c5d399abb39036ba35b9636212e17f` from
[PR 24](https://github.com/ThirdKeyAI/Symbiont/pull/24) and remains historical.

The workflow reuses the immutable development-binary artifact from passing run
45702056794. Its ZIP, both executable hashes, source, Cargo.lock and cumulative
reviewed patch are bound in `inputs.lock.json`. Every binary is checked before
receiving executable permission; no local rebuild or large download is performed.
The lock records that run under `runtime_artifact_validation`; the distinct
`fixture_execution` record selects the separate successful current-source run
described below. The old binary validation evidence remains a separate binding.

The gVisor 20261123.0 Debian package is authenticated through the retained
publisher-signed repository metadata and full key fingerprint. Its complete
installed executable/sidecar inventory is checked before execution. The fixture
root filesystem is Ubuntu Base 24.04.5, authenticated against the retained signed
checksum manifest. Original public verification records explain the key trust
origins. These are development-test inputs, not chosen Fedora release packages.

On a fresh hosted VM with no existing containers, a dedicated Docker daemon
replaces the idle runner daemon temporarily, using private state and a bounded
parent cgroup. Both runc and runsc host-process membership are checked before
fixture execution. The complete job has 4 GiB, two CPUs, no swap and a 110-minute
deadline. Each fixture-image build has an additional 512 MiB/one-CPU ceiling;
actual workers keep the upstream profile's limits and network restrictions.

Only installation of signed Ubuntu packages into the development fixture image
uses host networking. Its package versions and signed repository metadata are
retained, and the resulting image ID is immutable before tests start. The image
is not reproducible release output; Ubuntu package dependencies still require
their own pinned release process if this fixture ever becomes a shipped input.
No release environment, provider credentials or registry-write permission is
available to the workflow.

The unprivileged trusted test account runs all three drivers sequentially for
both backends. The full container filesystem driver has nine cases: upstream
reserves its two additional root-ceiling cases for Landlock/Firecracker. Source
broker has nine cases and Git source fourteen. No `--case` shortcut is used.
Reports must match the complete supported case list, binary/image/driver hashes,
actual backend and runtime observations, and empty worker/lease state.

Temporary fixture directories contain synthetic private signing keys and remain
outside the artifact. The collector accepts only regular public reports/logs,
refuses links and PEM private-key material, and caps the collection size. The
daemon is stopped on completion or failure. No workstation Docker configuration
or VM is changed.

The source checkout fetches the baseline and fixture revisions explicitly and
verifies their cumulative full-index patch, merge tree and three driver hashes
against both source locks. This allows multiple reviewed fixture commits
without assuming the immediate parent is the runtime baseline. A fresh
0700 `/tmp/sf-*` directory owned by the test account keeps supervisor Unix socket
paths below their bound. It holds private fixture state and is never uploaded.

## Selected current-source execution passed

[Run 45995824985](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45995824985),
pull-request attempt 1 for PR 6, passed all steps in job 140494839919. The API
head was `cdd8e7d931ddf90f1fe8afb22d12df9c539320b4`; the checked synthetic merge
was `2189acad039387cd48116c11934da383bea8e653`. It exercised runtime source
`deddb9e997244d2289c217ad76b8fde0e9b0339b` and fixture revision
`cd4b34282ade880c8ac3d5136d31ff80cde92794` at tree
`2b2379d0de4eaaf4a57cf52c96355015bb3dc25d`. The cumulative patch SHA-256 was
`544ff04152827cedd78aeaf2ef697d9637721f15937a00064e9f0ecbd85ad215`, and the
fixture-source lock SHA-256 was
`6223b18f5d24878a6455a85d7617f7fe7d5f5d9086f75308870b3664db22fbfa`.

Docker/runc and gVisor/runsc each passed the nine filesystem-grant, nine
source-broker and fourteen Git-source cases: six profiles and 64 cases total.
The selected binary SHA-256 was
`1e90af1fe424ec37ad716bbc1e069c0bc7a78f59c49871b7e79506bda69f49c7`, and the
fixture image was
`sha256:c1b6646800da097ddfe04abbe965f07694eac7562bb68e2d0eebb8b19cae2d33`.
Reports retained no workers, leases or containers, and the daemon stopped.

The sole artifact was ID 15196575712, `container-fixture-evidence`: a
293,698-byte ZIP with SHA-256
`8b9d8f59f66348ff42625cb313bffc21cead77bb0b152563c6b236313aa99ad0`, 57
regular entries and 1,531,115 uncompressed bytes. The 4 GiB cgroup used no swap,
peaked at 1,708,941,312 bytes, recorded 361 `memory.events` max events and zero
OOM, OOM-kill or OOM-group-kill events. The outer systemd unit finished with
result `success` and status `0/SUCCESS`.

The retained result is `passed: true` and `qualified: false`. It is Ubuntu
development fixture evidence only; it does not qualify Fedora, a release,
the managed CLI route or the escape suite, and P0-05 remains open.


## Complete Docker and gVisor fixture execution passed

Hosted run 45708951490 at head `f5d922ac3e9bf7e78acbe2d503df2145cdf6a789`
passed all six driver profiles using upstream fixture commit
`c1fac8aab6c5d399abb39036ba35b9636212e17f`. Each backend passed all nine
filesystem-grant, nine source-broker and fourteen Git-source cases: 64 passing
cases in total. Actual runtime observations were runc for Docker and runsc for
gVisor. Reports recorded no remaining workers, leases or containers, and the
dedicated daemon stopped. Report hashes and exact driver hashes were rechecked
against the upstream checkout before retaining the evidence.

The run authenticated the pinned runtime archive and executables, cumulative
fixture patch, gVisor publisher metadata and complete package inventory, and the
Ubuntu root filesystem. The resulting fixture-image digest is recorded; the
image's signed Ubuntu package resolution is development evidence, not a pinned
Fedora release input. The job remained under its 4 GiB/two-CPU/no-swap ceiling,
with 1,708,797,952 bytes peak parent memory, 361 recorded max events and no OOM
or OOM kill. Only the 291,995-byte public evidence ZIP was downloaded locally.
Selected reports, signature results and resource counters are retained under
`P0-05-hosted-containers/45708951490/` with original/retained hashes.

This clears the live Ubuntu tool-worker fixture gap for PR 24. P0-05 remains
open: the selected signed Fedora deployment, managed-CLI broker and escape-suite
acceptance, plus required reviews, are not established by these six drivers.

## Native fixture OCI export remains disabled

The prepared exporter is not an extension of the passing evidence above. The
current Dockerfile resolves Python, Git and CA packages live. The hosted source
contract now selects merge `cd4b34282ade880c8ac3d5136d31ff80cde92794`, and
run 45995824985 exercised that selection, but it produced evidence only: no OCI
was exported or cold-loaded. The `native-fixture-build.lock.json` prerequisite
slot remains pending and unchanged; the producer and upload stay disabled.
Activation requires a reviewed full package closure authenticated by signed
Ubuntu Release/InRelease and Packages metadata, exact package identities,
sizes and hashes, sequential verified downloads, and an offline
`docker build --network=none`. The same producer run must exercise all six
profiles from the required merge, then cold-load the generated OCI and resolve
`localhost/symbi-ci/native-fixture@<manifest digest>`.

The dormant exporter itself uses only Python's standard library. It streams one
Docker-save image into OCI after checking the config digest and every layer
against ordered `diff_id` values, fixes gzip and tar metadata, caps compressed
output at 512 MiB and expanded verification at 1 GiB, and deletes partial
output on failure. The consumer-format verification runs before any output
could be retained. No artifact upload step is enabled.

## Unselected Ubuntu package candidate preparation

`ubuntu_fixture_package_build.py` now defines dormant producer-side validators
and finalization primitives for the missing offline package closure. It does
not invoke system tools or contain or invent repository metadata. For each exact
reviewed source it can require one pinned-fingerprint `gpgv` result for the
InRelease file, parse the authenticated Release text, require the exact suite
and codename, and reject a missing or expired
`Valid-Until`, an excessive validity window, or a future `Date`. The signed
SHA-256 row must name exactly `main/binary-amd64/Packages.xz`; selected apt URIs
are then matched to exact package name, version, architecture, Filename, Size
and SHA256 fields in that compressed index.

The prepared plan uses only staged `file:` repositories. It binds apt's
`--print-uris` and `--simulate --no-download` results to the exact pending-lock
Ubuntu Base dpkg status and requires a separate `dpkg --no-act --unpack` plan.
Before any opener call, every plan/package row, reviewed source, identity,
sequence, size, hash, uniqueness constraint and aggregate byte bound is checked.
Package payloads are then downloaded one at a time without redirects, under one
Linux real-time aggregate deadline that interrupts an in-progress blocking read,
plus a per-operation timeout, and hashed while streaming.
The exact metadata and package bytes can be written only beside a manifest whose state is
`candidate-unselected`; `producer_passed`, all verification fields, `selected`
and every signature, container, OS and release qualification field remain
false.

The staging root and every child directory must be owned by the current uid and
gid with mode `0700`; every retained input and output is mode `0600`, regular,
single-link and exact-sized. The validators open every absolute component from
the filesystem root with `O_NOFOLLOW|O_CLOEXEC`, hold that descriptor chain,
and hash, parse, copy, validate and rename through held directory and
file descriptors. A symlink, hardlink, mode/owner/size change, leaf replacement
or changed named identity fails closed.

Candidate output is built under a new unpredictable private staging parent held
by descriptor. Publication uses `renameat2(RENAME_NOREPLACE)` from that isolated
descriptor and accepts success only after the destination name still matches
the held root and the complete nested identity, byte, hash and manifest binding
has been revalidated. The Linux main-thread download timer restores its prior
signal handler and rejects an already active process timer. Cleanup does not
unlink or remove pathnames inside the reusable writer because a same-user
replacement can race any separate identity check. The hosted wrapper waits for
the service to stop, rechecks its exact direct mode-`0700` cache directories
under the resolved checkout, and retains the private scratch for disposal with
the ephemeral runner. It performs no recursive pathname cleanup or ownership
change.

This preparation is not wired to `container-fixtures.yml` or
`native_fixture_build.py`. The current Dockerfile still performs its historical
live apt installation, the committed Ubuntu lock remains pending and empty, and
its public validator rejects a populated candidate. No image build, OCI export,
cold load, selection or qualification is enabled by this slice.

The new `ubuntu-fixture-packages.yml` workflow is `workflow_dispatch` only. Its
checked-in contract is `pending-discovery`, with all three InRelease and all
three Packages.xz byte/hash identities null. The wrapper creates a bounded
transient unit for either mode; inside it, pending `produce` refuses before
retained-input validation, in-cgroup inspection, authenticated producer
commands or network opening. `discover` runs in a
2 GiB/one-CPU/128-task/zero-swap systemd unit. It binds a clean checkout HEAD and
tree to `GITHUB_SHA`, verifies the exact retained keyring and signed Ubuntu Base
checksum, downloads the exact rootfs, verifies each current InRelease
against the full pinned archive fingerprint, enforces
suite/codename/freshness, and fetches only the Packages.xz member named by the
signed Release. It retains exact argv, reopened tool identity and hash, bounded
raw stdout/stderr, input identities, cgroup/systemd state and retention evidence.
The resulting discovery pins are explicitly non-authoritative. A separate
systemd-derived resource record is always written after the unit stops, so a
killed process or truncated primary cgroup record cannot hide the observable
swap and OOM outcome.

Discovery runs as the hosted account with empty ambient and bounding capability
sets and namespace creation denied. The dormant production branch alone permits
a network namespace and grants `CAP_SYS_ADMIN` for its exact `unshare --net`
calls. Both modes have a private mount and temporary namespace, strict read-only
system/home trees, and one exact writable cache subtree. The production
capability/namespace combination has not run on Ubuntu 24.04; a failure there
must stop production rather than broaden the sandbox.

After a separate review commits all six discovered identities and changes the
contract to `ready`, the production path stages only `file:` repositories and
runs apt update, URI planning and simulation inside a new network namespace. It
binds every planned package to the signed index, downloads one bound package at
a time through the reviewed hard-deadline downloader, and runs
`dpkg --no-act --unpack` in another networkless phase while proving base status
unchanged. It then writes and independently rechecks the unselected candidate.
Only that full successful path reaches the conditional candidate artifact
upload. The candidate manifest still keeps `producer_passed` and every
verification/selection/qualification field false; structured raw evidence is
external and cannot turn those booleans true.

If any current Ubuntu suite omits `Valid-Until` or fails another strict field,
the job must stop; changing the source or freshness policy needs its own review.
GitHub does not expose a new `workflow_dispatch` file until that workflow path
exists on the default branch. Hosted discovery is therefore blocked until a
separately reviewed minimal registration change lands on `main`. The next
producer step is then one reviewed `discover` dispatch. Its exact raw evidence
must be inspected before copying the six byte/hash values into the contract. A
later `produce` dispatch remains unselected; selecting its real run, artifact
and byte identities is a separate committed review, and only that can unblock
an offline `docker build --network=none` change.
