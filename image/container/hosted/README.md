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
fixture execution. The hosted job has a 120-minute deadline. Five authenticated
package transfers total at most 990 seconds, offline consumption has 300
seconds, current-run and runtime-artifact intake have 30 and 600 seconds, and
the 4 GiB/two-CPU/zero-swap fixture unit has 75 minutes. These explicit bounds
total 107 minutes and reserve 13 minutes for the remaining workflow steps. Each
fixture-image build has an additional 512 MiB/one-CPU ceiling; actual workers
keep the upstream profile's limits and network restrictions.

Host networking is limited to authenticated input and artifact transfers.
Installation uses the exact selected Ubuntu package archives during
`docker build --network=none`; package versions and signed repository metadata
are retained. The resulting tested target is immutable before fixture execution.
The image is not reproducible release output, and no release environment,
provider credentials or registry-write permission is available to the workflow.

One run-bound disposable account, distinct from the checkout owner, runs all
three drivers sequentially for both backends. Direct filesystem ownership and
write permission are granted only for its private work and evidence-output
directories; Docker-group membership grants authority through the dedicated
daemon. Root kills and proves the absence of all
processes for that UID immediately after execution. It then rechecks the exact
six-run result/report/log inventory and every recorded digest before copying
public evidence. The full container filesystem driver has nine cases: upstream
reserves its two additional root-ceiling cases for Landlock/Firecracker. Source
broker has nine cases and Git source fourteen. No `--case` shortcut is used.
Reports must match the complete supported case list, binary/image/driver hashes,
actual backend and runtime observations, and empty worker/lease state.

Temporary fixture directories contain synthetic private signing keys and remain
outside the artifact. The final root collector binds the exact selected package
manifest, three InRelease files, three Packages.xz files and package inventory;
it accepts only regular public reports/logs, refuses links, unexpected package
paths and PEM private-key material, and caps the collection size. The artifact
root must be newly created at mode `0700` and have only `public` when produced
plus `systemd-result.txt`. The daemon is stopped on completion or failure. No
workstation Docker configuration or VM is changed.

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

## Native fixture OCI export remains blocked

The prepared exporter is not an extension of the passing evidence above.
Package production run 46142528811 emitted an exact unselected package
candidate, but no reviewer has selected it for consumption. The public package
lock and `native-fixture-build.lock.json` prerequisite slot remain pending; the
native fixture export remains blocked and artifact upload is absent. Native
preflight runs before artifact transfer and reports
`offline-ubuntu-package-selection` while that remains true.

After a reviewed selection binds the exact run, artifact API records, archive
digests, manifest, producer result and every retained member, the consumer can
stage the packages in the retained order. The Docker build has no network and
runs real `dpkg --unpack` operations. It configures the earlier package set
before each of the two reviewed `python3-minimal` and `python3` Pre-Depends
boundaries, then runs a final `dpkg --configure -a`. That is the first gate that
can execute pre-install, post-install and trigger behavior. It has not run.
After all evidence writes, the image normalizes only
`/usr/share/symbi-fixture-evidence`: directories are mode `0755` and files are
mode `0644`, so the unprivileged collector can traverse the complete nested
evidence. The collector admits the existing report and signed InRelease types
plus exactly `noble_main_binary-amd64_Packages.xz`,
`noble-updates_main_binary-amd64_Packages.xz` and
`noble-security_main_binary-amd64_Packages.xz`; every other `.xz` is rejected.

The same producer run must next exercise all six profiles from merge
`cd4b34282ade880c8ac3d5136d31ff80cde92794`, export the tested image, remove it,
cold-load the generated OCI and resolve
`localhost/symbi-ci/native-fixture@<manifest digest>`.

The wired exporter remains unreachable while those gates are pending. It uses
only Python's standard library, fixes gzip and tar metadata, caps compressed
output at 512 MiB and expanded verification at 1 GiB, deletes partial output on
failure and completes consumer-format verification before retaining output.
It binds three pairwise-distinct digests. `D0`, recorded as
`initial_target_digest`, comes from `--iidfile` and must equal the initial
Docker inspect `Id` and `Descriptor.digest`. `C`, recorded as `config_digest`,
is the selected source manifest's config digest. `G`, recorded as
`generated_target_digest`, is the deterministic generated manifest digest and
carries a source-target annotation for `D0`. A cold load must resolve both
Docker inspect `Id` and `Descriptor.digest` to `G`, with the exact repository
digest `localhost/symbi-ci/native-fixture@G`. No artifact upload step is
enabled.

## Unselected Ubuntu package candidate preparation

`ubuntu_fixture_package_build.py` now defines dormant producer-side validators
and finalization primitives for the missing offline package closure. It does
not invoke system tools or contain or invent repository metadata. For each exact
reviewed source it can require one pinned-fingerprint `gpgv` result for the
InRelease file, parse the authenticated Release text, require the exact suite
and codename, and apply an exact source-bound freshness policy. Noble requires
no `Valid-Until` and has a reviewed 1,830-day signed-`Date` age ceiling. The
updates and security pockets have a 14-day signed-`Date` age ceiling and may
omit `Valid-Until`; one present field must be unexpired, after `Date`, and no
more than 14 days after `Date`. Every pocket rejects a `Date` more than 15
minutes in the future. The signed
SHA-256 row must name exactly `main/binary-amd64/Packages.xz`; selected apt URIs
are then matched to exact package name, version, architecture, Filename, Size
and SHA256 fields in that compressed index. APT documents an MD5 field in
`--print-uris` output. The producer treats it only as a redundant membership
value: the Filename, Size and MD5 must all match one row in the authenticated
index, and that row's SHA256 replaces the MD5 before any package download.

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

The fail-closed consumer is wired to the manual `container-fixtures.yml`
workflow, but its public lock remains pending and empty. Native preflight runs
before any artifact API or archive request and rejects both the package
selection and the separate source-alignment, cold-load and upload-approval
prerequisites. No image build, package or maintainer-script execution, OCI
export, cold load, selection or qualification is enabled by this source slice.

The manual ubuntu-fixture-packages.yml workflow remains workflow_dispatch only.
Before the schema-3 retained-metadata handoff, its contract was promoted to
ready with the six exact InRelease and Packages.xz byte/hash identities
independently reviewed from run 46107541478.
The ready state rejects discovery and permits only production. Production run
46109461949 authenticated those pins, completed the private offline APT update
and emitted a 68-row URI plan, then rejected APT's canonical lowercase `%7e`
escape as an unsafe path. APT also emitted lowercase `%2b` and `%3a` escapes
and `MD5Sum` plan fields. The corrected parser normalizes only percent-hex
letter case before enforcing its stricter decoded-path canonical form. It uses
the plan MD5 only to bind the exact filename and size to one row in the
authenticated Packages.xz index, then discards MD5 and constructs the download
plan with that signed row's SHA-256. Encoded separators, traversal,
unnecessary escapes and literal aliases still fail closed. No candidate,
selection, producer pass, image consumer or qualification claim followed. A
fresh exact-head run is required; every claim remains false.

Production runs 46112459016 and 46112713726 subsequently stopped before any
candidate when rolling noble-updates metadata no longer matched the reviewed
pin. Discovery run 46112845334 was correctly blocked because the contract was
still ready. The contract was returned to `pending-discovery` with all six
payload identities cleared. Exact-head discovery run 46113900468 then
authenticated the current three InRelease and three signed Packages.xz rows.
Independent refetches matched all six identities, all signatures reverified,
and the committed freshness and Release-row validators passed. That earlier
contract was again `ready` with those reviewed pins. Discovery downloaded no
packages and created no candidate; production, selection and qualification
remained pending.

The wrapper creates a bounded
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
system/home trees, and one exact writable cache subtree. Run `46142528811`
successfully exercised the production capability/namespace combination on
Ubuntu 24.04; any failure there must stop production rather than broaden the
sandbox.

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

The Python validator authenticates each Release before production. The staged
offline APT source rows independently impose exact per-source
`valid-until-max` bounds: 1,830 days for noble and 14 days for noble-updates
and noble-security, with `Check-Valid-Until` enabled. Production revalidates
the complete exact row set before writing the private source list or running
APT. Each exact discovery artifact must be inspected before pins are copied
into the contract. A later `produce` dispatch remains
unselected; selecting its real run, artifact and byte identities is a separate
committed review, and only that can unblock the already-wired offline image
consumer.

## Retained metadata handoff

The schema-3 producer contract makes authenticated repository bytes, rather
than only their identities, the reviewed production input. Discovery run
`46129698065` published exactly seven flat private files: one bounded manifest,
three InRelease files and the three Packages.xz files named by their signed
Release rows. The manifest binds the manual run, attempt, head commit and tree,
branch, discovery contract and pending lock while keeping authority, selection
and every qualification claim false.

A reviewer must bind the exact producer identity, artifact ID/name/size, the
artifact API digest, an independently observed ZIP digest, the manifest hash,
the discovery-contract hash, the lock hash and all six payload identities in
the ready contract. The shared workflow job grants read-only `actions` and
`contents` permissions in both modes, so pinned actions including checkout can
use its job token. Discovery passes no `GITHUB_TOKEN` to repository code.
Production passes `GITHUB_TOKEN` only to the pre-service transfer process. It
validates the run and artifact API records, follows one token-free signed
download URL on an allowlisted host, streams the exact ZIP under fixed member
and expansion bounds, and accepts only the seven reviewed flat members. The
transfer removes the token before the transient service starts, and the token
is absent from its clean environment.

Production never fetches an InRelease or Packages.xz from the live repository.
It copies the retained private files through stable single-link descriptors,
reruns `gpgv`, applies freshness at the production time, and rechecks the exact
signed Packages.xz row before offline APT planning. The unselected package
candidate records the complete retained-metadata provenance. Rootfs and bound
package payload transfers remain separate authenticated operations. The exact
private ZIP and scratch are left for disposal with the ephemeral runner; no
post-transfer pathname deletion is attempted.

Independent review selected metadata artifact `15257187872` and its exact
4,637,216 ZIP bytes, seven payload members and manifest. The checked-in state is
now `ready`, with canonical contract SHA-256
`2c22f3e33c7081c4011a78a247b5f8f845a3386ac4ce44db0d07a03b84a6d841`.
It permitted one manual unselected production attempt. Run `46142528811`
completed that path at exact head
`6cf7c43f90216c4622dff44cc8f3db6771718cc5` and tree
`ec1c3e625a30e9142ad7364cf1cc857bfd26379c`, producing 68 exact package
archives totaling 36,832,124 bytes. Their order SHA-256 is
`cb07815cc13c85b68e7b24934885e0d83d73cd9c37bc1052b0d7df65075bce77`.
Native `dpkg --no-act` parsed and prepared that exact order while accepting
only the fixed `python3-minimal` to `python3.12-minimal` `>=` and `python3` to
`python3-minimal` `=` Pre-Depends diagnostics.

The candidate remains `candidate-unselected`; its manifest keeps
`producer_passed`, selection and every qualification field false. It proves
signed metadata, exact package download and order, and native dry-run
parse/prepare only. It does not prove installed or configured state, maintainer
scripts, container isolation, selection, OS qualification or release
qualification. The pending public package lock remains unchanged because a
separate reviewed selection is required before any offline image consumer can
use the candidate.
