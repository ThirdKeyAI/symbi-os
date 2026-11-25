# Symbiont OS

A desktop Linux system where AI agents are visible, least-privileged principals
and the human is the only source of authority. The target platform is a signed
Fedora Atomic image with Hyprland and the upstream Symbiont runtime.

**Current state: P0-01 scaffold.** This repository is not a bootable image and
does not launch agents. It contains the Rust workspace, a Cedar schema skeleton,
policy fixture tests, dependency checks, and Gitea-compatible CI. There are no
production permits, daemons, or runtime dependencies yet.

## Start here

- [Build plan and task cards](docs/build-plan.md)
- [P0-01 implementation and handoff](docs/cards/P0-01.md)
- [Security invariants and evidence status](docs/security/invariants.md)
- [Open implementation questions](docs/open-questions.md)
- [Pinned dependencies and tools](docs/dependencies.md)

## Development

Prerequisites: Linux, Bash, Git, a C toolchain, and an existing trusted Rustup
installation. The build scripts never download and pipe an installer into a
shell. Tool bootstrap needs network access and compiles pinned crates with
their published lockfiles into `.tools/`; it is not an OS installation step.

```sh
bash scripts/bootstrap-tools.sh
bash scripts/check.sh
```

The workspace builds with **Rust 1.89.0**. Build tools use Rust 1.95.0; Cedar is
pinned to **4.5.2**, matching the selected runtime's lockfile. `check.sh` runs
formatting, Clippy, policy tests, documentation, cargo-deny, and cargo-vet. A
missing or incorrect checker fails the checks; it is never silently skipped.

Local builds default to one compiler job and one test/checker thread, with
debug symbols and incremental compilation disabled. Bootstrap also builds
tools serially without optimization. Reuse installed tools rather than rebuilding
them for each check; VM/image builds belong to their later cards.

For just the tests after bootstrapping:

```sh
export PATH="$PWD/.tools/bin:$PATH"
cargo test --workspace --locked
```

The tests invoke the actual Cedar CLI on synthetic entities. They verify schema
typing, rejection of undeclared actions, and denial without permits for all
three documented session classes and both model locations. A test-only permit
also exercises the allow path. These are schema checks, not evidence of OS
containment or confidential-session enforcement.

## Repository boundaries

`crates/symbi-common` establishes the first crate boundary; its runtime API is
reserved for P1-01. `policy/` holds the schema and test fixtures. The other
top-level component directories reserve the boundaries in the build plan
without providing mock services. `upstream/symbiont.toml` records the full
upstream source revision; the runtime remains a separate project.

`.gitea/workflows/ci.yml` runs the same checks on pushes and pull requests. It
needs an enabled Linux runner labeled `ubuntu-latest` with Rustup, Node (for
checkout), Git, and a C toolchain. A hosted run has not yet been observed.
P0-03 adds the signed image build; P0-04 qualifies the runtime on that image.
Host checks do not substitute for either card.

## Licence

The build plan leaves the product licence open. All workspace crates currently
have `publish = false`; no licence grant is inferred from the upstream
runtime's Apache-2.0 licence. Resolve this before publishing a release.
