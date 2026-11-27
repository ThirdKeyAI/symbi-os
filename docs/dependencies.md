# Source and tool pins

No third-party crates are linked into the workspace. `cargo-deny` and
`cargo-vet` currently check an empty third-party graph; this is a baseline,
not a claim that the build tools or future runtime have been audited.

| Component | Exact pin | Reason and scope |
| --- | --- | --- |
| Workspace Rust | 1.89.0 | Plan's MSRV; used for fmt, Clippy, tests, and docs |
| Build-tool Rust | 1.95.0 | Separate reproducible compiler selection for installing checkers |
| Cedar CLI | 4.5.2 | Matches Cedar in the selected runtime's Cargo.lock; schema fixture tests only |
| cargo-deny | 0.20.2 | Advisory, licence, version, and source checks |
| cargo-vet | 0.10.3 | Enforces explicit audit requirements as crates enter the graph |
| actions/checkout | 34e114876b0b11c390a56381ad16ebd13914f8d5 (v4.3.1) | Workspace checkout; credential persistence disabled |
| Symbiont | deddb9e997244d2289c217ad76b8fde0e9b0339b (3.0.0) | Plan's revision resolved to full SHA; metadata only, not yet integrated |

Primary references: [pinned runtime lockfile](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/Cargo.lock),
[Cedar schema grammar](https://docs.cedarpolicy.com/schema/human-readable-schema.html),
[cargo-deny configuration](https://embarkstudios.github.io/cargo-deny/checks/cfg.html),
[cargo-vet configuration](https://mozilla.github.io/cargo-vet/config.html), and
[checkout revision](https://github.com/actions/checkout/commit/34e114876b0b11c390a56381ad16ebd13914f8d5).

## Build-tool review notes

The three checkers are installed from exact crates.io versions with `--locked`,
preserving their published transitive lockfiles and registry checksums. They
are development tools and are not included in the OS image. These notes record
purpose and boundaries, not source audits. Neither a commit pin nor a registry
checksum is a publisher-signature check.

Cedar 4.5.2's published CLI lockfile includes yanked `keccak 0.1.5` and
`slab 0.4.10`. Bootstrap reports these warnings. Keep the compatibility pin;
review and refresh that tool's transitive lockfile or move the upstream runtime
pin through a separate reviewed change before relying on it for release
qualification. Do not remove `--locked` to hide the warnings. See OQ-05.

The documentation advertises cargo-vet 0.10.4, but the registry lookup in this
session returned 0.10.3 as the available release. The bootstrap uses the version
actually fetched and executed. Reassess new releases through a reviewed pin bump.

## P0-02 model-checking tools

P0-02 adds no Cargo dependencies. Its design checker uses Java 11+ (the local
run used OpenJDK 25.0.5.1), the `jaschadub/skill-formal-proofs` action at full
commit `bb984f2e4427d3f5515cc56d5a54c6ce8ce26d1e` (0.5.3, MIT), and TLC 1.7.4
(MIT) at SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`.
The action's checker/fault/drift scripts were inspected; bootstrap verifies
the jar on download and reuse. The scripts invoke Java and use temporary
state directories, without repository or release credentials. The existing
upstream action supplies CI orchestration; none of its code is vendored into
the product. The commit is not publisher-signature evidence, and these tools
remain outside the runtime cargo-vet graph. Java is host/runner-provided,
not part of a reproducible image toolchain claim. See `formal/VERIFY.md`.

## P0-03 signature-verification tool

Input authentication and dedicated OS key generation used upstream Cosign
**v3.1.5**, source `e5a0818ca5729481095773409e9c1b60cc278e8d`, with the Linux
amd64 binary pinned to SHA-256
`912502def4baf810eaf36b210a4f51e1da214f9f6d664e2a9a2154cfc67ee0d6`.
The publisher's KMS signature was verified before executing the binary. Its
signed checksum manifest was then verified with normal transparency and SCT
checks, exact certificate identity `keyless@projectsigstore.iam.gserviceaccount.com`
and issuer `https://accounts.google.com`. Public authentication inputs and
results are retained under `security/reports/P0-03-base-signatures/`.

This Go executable is a build/admin tool, not a Cargo workspace dependency or
an OS payload. Publisher authentication is not a source audit. Initial key
trust comes from the pinned official HTTPS publisher source, with no separate
out-of-band claim. A full-binary bundle check exceeded its 128 MiB limit; the
small signed checksum check passed under that same cap. No verification flag
or resource ceiling was relaxed. Release signing must explicitly emit legacy
image attachments until the installed bootc verifier supports and qualifies
another format; Cosign's current default is not assumed compatible.

## Adding a dependency

Pin a registry dependency to an exact version and commit Cargo.lock. For Git
dependencies use a full reviewed commit and an explicit source allowlist entry.
Explain the dependency and features in this file and the card. Add genuine audit
coverage to `supply-chain/` (or explicitly reviewed, scoped exceptions with an
owner and removal condition); do not fabricate certifications. Run both gates.
Tooling installs have their own published lockfiles and are outside this
workspace graph; release-tool supply-chain coverage remains work for P0-03.

## P0-03 experimental image-tool source build

The BlueBuild compatibility workflow checks out
[`a654ee8810c637aa00356999488e97259061275d`](https://github.com/blue-build/cli/commit/a654ee8810c637aa00356999488e97259061275d),
Apache-2.0, using the existing pinned checkout action. This is six commits after
v0.9.42 (`cdca92e8d65d9fd4f6bedac0e88a8f9479d70da6`). The reviewed comparison
contains dependency/advisory updates and removal of optional git2, build
provenance changes, chunkah logging, a digest-print fix, lint fixes and a README
typo. It does not add v2 validation: `ValidateCommand` still requests the v1
schema and deserializes `RecipeV1`. GitHub reports the selected commit signature
verified; that is not a full source/dependency audit.

The BlueBuild build uses Rust 1.100.0, `--locked --no-default-features --features v1_0_0`,
one Cargo job, no debug symbols or incremental output, and a hosted cgroup
with 4 GiB memory, zero swap and at most two CPUs. It records the source SHA,
lockfile SHA-256, compiler version, binary SHA-256 and actual CLI results.
It is an unqualified build-tool experiment, outside the OS/runtime payload
and workspace Cargo graph. No cargo-vet audit or release-tool approval is
claimed; no blanket exemptions are introduced.

Public evidence upload uses
[`actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02)
(v4.6.2, MIT), the pin used by Symbiont. GitHub reports its merge signature
verified. Public `.cache/image-tool-evidence/` is retained for fourteen days.
The current workflow also retains the bounded compiled CLI, original upstream
license and source/compiler-bound manifest as a separate development artifact;
no signing environment, private material or compiler target directory is attached.

The first hosted attempt on Rust 1.95.0 failed with E0658 at three upstream
`Option::map_or_default` calls; recipe tests did not run. The dedicated BlueBuild
compiler is now pinned to [Rust 1.100.0](https://github.com/rust-lang/rust/releases/tag/1.100.0),
where [that API is stable](https://doc.rust-lang.org/1.100.0/std/option/enum.Option.html#method.map_or_default).
The workspace MSRV and existing checker toolchain pins are unchanged. This uses
a stable supported API rather than enabling unstable compiler features.

The downstream `0001-validate-os-recipe-v2.patch` adds a standalone schema and
a validation route for the closed OS profile. It reuses BlueBuild's already
locked `jsonschema` and recipe crates, adding no crate and changing no lockfile.
The patch preserves the existing v1 validator, does not use skip flags, and
checks schema plus upstream typed/OCI parsing. Hash checks bind the patch before
application, and actual applied source differences are retained with the tool
result. Twelve rejected profile cases and both real rendered recipes exercise
the compiled CLI; an offline Python schema preflight is only preliminary evidence.

The BlueBuild tests require Cosign. Their hosted prerequisite reuses authenticated
Cosign v3.1.5, source `e5a0818ca5729481095773409e9c1b60cc278e8d`, binary SHA-256
`912502def4baf810eaf36b210a4f51e1da214f9f6d664e2a9a2154cfc67ee0d6`.
`image/toolchain/cosign.json` binds the exact download and release KMS bundle;
`image/toolchain/keys/cosign-release-v3.1.5.pub` is the publisher public key already
used by the retained base-verification bootstrap. OpenSSL verifies the signature
before execution. The initial key trust remains the pinned publisher HTTPS
source, as documented in the earlier verification record. This adds no Cargo
crate, no release credential and no dependency-audit exemption. Tests use only
upstream fixture/disposable keys; retained failure logs omit private test PEMs.

## P0-05 hosted fixture inputs

`image/container/hosted/inputs.lock.json` binds the passing runtime development
artifact, executable hashes and exact fixture-only upstream commit. The runtime
and Cargo.lock are unchanged. gVisor 20261123.0 uses its authenticated Debian
package (SHA-256 `3b78fe64d212d0d1a753660b0a9e95488e5e264d36dce04c36e7245b81151e18`),
including all sidecar executables. Retained signed repository metadata and the
pinned full publisher key authenticate the package before execution. Ubuntu Base
24.04.5's signed checksum authenticates the Python/Git fixture root filesystem.
Public provenance records include original key sources and verification scope.

These dependencies are disposable Ubuntu test inputs, not Fedora product
packages or audited release binaries. The hosted Docker engine is runner-provided
and its exact version is retained; source auditing and release qualification are
not implied. No Cargo dependency or fabricated audit is added. The complete
fixtures and runtime resource-membership probes must actually pass before any
container-route execution claim is made.

`image/container/native-fixture.lock.json` separately pins upstream PR 24's
reviewed merge `be3bef1dababb49a68450a883dc1ba97fa6322b0`, tree
`207616f4326f83b00c2c8717294f4689c969d093`, and all three driver hashes. This
source supplies fixture drivers only; the installed runtime binary remains bound
to `deddb9e997244d2289c217ad76b8fde0e9b0339b`. The Fedora preflight re-verifies
the retained signed Debian repository metadata and complete package inventory as
a development input. A separate selected Fedora runtime lock and native evidence
are still required before product use.

## P0-05 Fedora container candidate inputs

`image/container/gvisor-inputs.json` fixes gVisor `release-20261123.1` at commit
`81f68cb7d4661a9313d891a1758a765abe8eb27e`. It binds the official 84,944,091-byte
x86_64 bzip2 archive by SHA-256 and SHA-512, the complete official SHA-512 list,
the Apache-2.0 license and all ten archive members. Standard-library streaming
inspection requires no candidate execution or third-party decompressor. The tag
and commit are unsigned and no GitHub attestation was found, so the input is not
selected or qualified.

`image/container/runtime-requirements.json` separately requests Fedora
`moby-engine`, `docker-cli` and `container-selinux`. Hosted run 45940456063
resolved and authenticated a 108-package, 116,875,288-byte candidate closure
against the selected Fedora 45 base. Its compact manifest is retained under
`P0-05-fedora-packages/45940456063/`. The passive transaction installed nothing,
so the candidate does not supply the installed package/file inventory required
by `image/container/fedora-runtime.lock.json`. Neither the mutable package
catalogue nor the passive gVisor intake supplies that installed-runtime
acceptance.

## P0-03 Fedora compositor development inputs

`image/hyprland/build-rpms.lock.json` records 162 exact Fedora 45 RPMs and their
Fedora signing fingerprint, bytes, hashes, NEVRAs and RPM license metadata.
The authenticated hosted bundle is used only in a disposable offline build
container. It includes Mesa versions older than the selected secureblue base;
that transaction is not approved for the product. Runtime compatibility and
final-package license/SBOM review remain separate gates.

The compositor and seven native libraries use the full Git commits already
recorded in `image/hyprland/candidate-inputs.json`, plus pinned Glaze and udis86.
The selected CMake dependency requirements and build entry points were inspected.
Network-free compilation uses a private prefix and RPATH; it cannot fetch a
replacement for a missing dependency. Exact Git object checks establish source
selection, not publisher-signature evidence or a full source audit. This is a
development build, with no release publication or new Cargo dependencies.

P0-03's offline build exposed missing hyprctl inputs. Its own CMake file requires
hyprwire and readline. The candidate source set now includes hyprwire at
`a546e42d45e161682f729ebf52375bd4800d7041`, from the selected Hyprland flake lock
(version file 0.3.1; BSD-3-Clause, original notice retained). It requires already
selected hyprutils/pugixml plus `pkgconfig(libffi)`; the RPM request now explicitly
includes libffi and readline. Signed Fedora resolution must finish and its exact
artifact be reviewed before updating the build lock. Existing verified RPMs
remain immutable; the guard refuses compilation with stale requirements. This
is candidate input discovery, not a completed dependency/security audit.

The expanded P0-03 Fedora discovery (45702843932) verified 165 candidate build
RPMs. The unchanged prior 162 records are supplemented by readline-devel
8.3-6.fc45 (Fedora license field: GPL-3.0-or-later AND GPL-2.0-or-later AND
GFDL-1.3-no-invariants-or-later), ncurses-devel and ncurses-c++-libs 6.6-3.fc45
(MIT-open-group). Exact bytes, licenses and signatures are in the build lock and
retained report. These are development-stage inputs, not a completed audit or
permission to overwrite the product base libraries.


Walker source/runtime run 45741018580 passed the exact v2.17.2 build with the
unchanged 284-entry Cargo.lock, all 14 upstream tests and four real CLI controls
on the original secureblue base. Source, compiler/RPM inputs, executable bytes
and the original GPL-3.0 license file are bound in
`image/launcher/walker-development-binary.lock.json`. Compilation and tests are
compatibility evidence, not an audit of the 283 registry dependencies. No Cargo
vet audits/exemptions are added; final source/dependency/license/SBOM review and
actual desktop/image acceptance remain open.

## Symbiont runtime compatibility RPM discovery

The retained default-feature development runtime at `deddb9e` needs the OpenSSL
3 ABI. Actual loader controls on the authenticated Fedora 45 base failed because
it provides OpenSSL 4. Fedora's maintained `openssl3-libs` compatibility package
provides both missing SONAMEs (Apache-2.0); see the linked package source in
`image/runtime_packages/requirements.json`. This is candidate discovery, not an
installed dependency or a completed audit. Only signed Fedora release/updates
inputs may be selected; exact RPM/manifest hashes and full signature/identity
evidence must precede an offline additive installation. Existing OpenSSL 4 and
all other base package identities must remain unchanged. No Ubuntu libraries,
source edits, new Cargo dependency/feature, audit exemption or release claim.

Signed runtime compatibility discovery 45748551523 selected only
`openssl3-libs-1:3.5.9-1.fc45.x86_64`, Apache-2.0, 2,890,302 bytes, SHA-256
`60fdefdada231053ca4da86e69ecd2706fd09bab7690cf978c7f0b24d41c17fc`.
The complete Fedora 45 signature and real missing-key/tamper refusals passed.
`image/assembly/runtime-rpms.lock.json` binds the exact archive, manifest, base,
key and requirements. The isolated offline acceptance must preserve original
packages and crypto configuration; actual TLS policy compatibility and final
release review remain open. This is not a cargo-vet audit or exemption.

## P0-03 portal and share-picker candidate inputs

The already pinned Hyprland 0.57.2 flake selects
`xdg-desktop-portal-hyprland` 1.5.0 at
`85450448ea40a54ec4f10bd607e68019d8f5cc41` and `hyprtoolkit` 0.6.0 at
`92646e15fb295285b10de626f2d9597216465f7b`. Both are BSD-3-Clause; original
license bytes and the selected CMake/version inputs are retained under
`image/portal/reviewed/`, with Git object IDs, lengths and SHA-256 hashes in
`source-inputs.json`. These are primary-source identity and build-scope checks,
not publisher signatures or complete source/dependency audits.

The portal needs PipeWire, SPA and sdbus-c++; the toolkit additionally needs
iniparser and abseil's flat-hash-map provider. The discovery profile reuses the
existing compositor build requirement list plus these five explicit providers,
so the retained prefix's transitive pkg-config dependencies remain available.
All RPMs must come from the existing reviewed Fedora release/update inputs and
pass full signature, identity and negative controls before a build lock can be
adopted. The discovery does not install packages or rebuild native components.
Later compilation must reuse the exact retained compositor prefix, enforce
the upstream version requirements offline and refuse subproject fetching.
No Cargo dependencies, audit records or exemptions are added. Actual portal
build, license/SBOM review, consent/token behavior and desktop qualification
remain open. See [portal preparation](../image/portal/README.md).


## cve.bz security-information source

The owner selected cve.bz for security information via its API or MCP. The
[public API](https://cve.bz/cve/api) supplies advisory records, a filtered feed
and lockfile/SBOM stack checks; the optional MCP endpoint is
`https://cve.bz/mcp`. This adds an information source, not a runtime dependency
or a source-audit exemption. No MCP client, skill, plugin or credential was
installed. Future governed-service use requires the reviewed Phase 4 manifest.

The first real query on 26 Nov 2026 checked the public Symbiont `deddb9e` lockfile:
1,108 packages, 48 advisory matches across 27 packages, including 13 packages
with maintenance-only warnings. All matches remain open pending applicability
review. Six priority advisory records were fetched separately. Exact raw
responses retain all attribution and upstream update times; request/response
hashes and a static reverse-dependency map are in
[the retained report](security/reports/P0-03-cve-bz/2026-11-26/README.md).
No private source or project inventory was sent. Cargo.lock covers more than
the shipped feature set, so match counts are not confirmed exploit counts.
The actual runtime, image, source and tool pins are unchanged. A fix must be
reviewed upstream first and the OS must rebuild/requalify the resulting pin.

## Portal build closure review

Hosted discovery 45766212374 authenticated 173 Fedora build RPMs. Compared with
the earlier compositor closure, 161 records are identical, four development
packages moved to newer signed Fedora versions (at-spi2-atk-devel,
at-spi2-core-devel and atk-devel 2.62.1 to 2.62.2; libdav1d-devel 1.5.4 to
1.5.5), and eight packages were added: their four runtime counterparts,
iniparser/iniparser-devel 4.2.6, pipewire-devel 1.6.11 and sdbus-cpp-devel 2.3.1.
Exact releases, bytes, licenses and signature fingerprints are in
`image/portal/build-rpms.lock.json`. The prior compositor lock and compiled
prefix remain unchanged. This explicitly reviewed delta is confined to the
disposable compiler container; it does not authorize replacing product base
libraries. Runtime ABI compatibility and additive package preservation remain
independent acceptance gates. No audit or license approval is inferred.
