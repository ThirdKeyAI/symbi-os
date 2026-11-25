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

## Adding a dependency

Pin a registry dependency to an exact version and commit Cargo.lock. For Git
dependencies use a full reviewed commit and an explicit source allowlist entry.
Explain the dependency and features in this file and the card. Add genuine audit
coverage to `supply-chain/` (or explicitly reviewed, scoped exceptions with an
owner and removal condition); do not fabricate certifications. Run both gates.
Tooling installs have their own published lockfiles and are outside this
workspace graph; release-tool supply-chain coverage remains work for P0-03.
