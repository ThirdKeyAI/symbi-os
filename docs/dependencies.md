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
verified. Only `.cache/image-tool-evidence/` is uploaded for fourteen days;
no signing environment, private material or compiler target directory is attached.

The first hosted attempt on Rust 1.95.0 failed with E0658 at three upstream
`Option::map_or_default` calls; recipe tests did not run. The dedicated BlueBuild
compiler is now pinned to [Rust 1.100.0](https://github.com/rust-lang/rust/releases/tag/1.100.0),
where [that API is stable](https://doc.rust-lang.org/1.100.0/std/option/enum.Option.html#method.map_or_default).
The workspace MSRV and existing checker toolchain pins are unchanged. This uses
a stable supported API rather than enabling unstable compiler features.
