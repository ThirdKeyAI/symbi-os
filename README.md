# Symbiont OS

> **Symbi OS is highly experimental.** Security boundaries, image updates, and
> recovery paths are still being developed and qualified. Use only in disposable
> testing environments; this is not a production-ready operating system.

A desktop Linux system where AI agents are visible, least-privileged principals
and the human is the only source of authority. The target platform is a signed
Fedora Atomic image with Hyprland and the upstream Symbiont runtime.

**Current state: P0 image development.** The scaffold and five TLA+ design models
are complete. Generic and NVIDIA development OCI images now build with maintained
Hyprland, Walker, the restricted Elephant application provider, Symbiont 3.0
and its sandbox supervisor, plus the patched Hyprland portal and share picker.
Their installed-file, package, loader, CLI and
configuration checks pass; see the retained [generic evidence](docs/security/reports/P0-03-desktop/45792057599/independent-check.json)
and [NVIDIA evidence](docs/security/reports/P0-03-desktop/45793771499/independent-check.json).
Actual image boot, desktop interaction, Fedora sandbox qualification and signed
updates/rollback remain open. No OS release has been published. The desktop
trusted approval surface and OS agent services are planned in later phases.

The requested [Ombuntu desktop profile](docs/desktop-profile.md), including its
shortcuts, Kitty, Tokyo Night, Nerd Fonts and MPlayer, still needs integration.
Tolaria is now the selected default second-brain application: its Git-backed
Markdown vaults are intended for the human and governed agents. The exact source,
tool input and fail-closed OS patch are prepared, but the application is not yet
present in the built images; signed Fedora build inputs, an offline source build,
loader checks and a real desktop launch remain required.
The requested desktop set also includes Yazi as the terminal file manager, Glum
as a terminal Markdown reader, and Tootles as the keyboard-first Mastodon and
Bluesky client. These are selected requirements, not claims about the current
images; exact signed inputs, disabled runtime package downloads, credential
handling and installed-image tests remain gates.
Security review uses the [cve.bz API](https://cve.bz/api/public/openapi.json);
[retained findings](docs/security/reports/P0-03-cve-bz/2026-11-26/native/README.md)
remain open where source, package or reachability verification is incomplete.

## Installing applications and tools

The supported install path depends on what the software needs:

- Desktop applications are installed per user from Flathub with Flatpak through
  the graphical software menu. Flatpak permissions remain visible and revocable.
- Command-line tools, language packages and development stacks go in a Toolbox
  or Distrobox workspace, where ordinary Fedora, Debian or Ubuntu package
  managers can be used without modifying the host image.
- Host drivers, system services and other software that must live under
  immutable system paths are added to the reviewed image recipe. They arrive as
  a signed Atomic update and retain the previous deployment for rollback.

Direct host-side `dnf install`, `rpm-ostree install`, Snap, AUR helpers and
`curl | sh` installers are outside the supported model. The current base
contains Homebrew tooling, but it is not the v1 package path until its proxy,
containment and update behavior have passed the same installed-image checks.

## Start here

- [Build plan and task cards](docs/build-plan.md)
- [P0-01 implementation and handoff](docs/cards/P0-01.md)
- [P0-02 design models and verification](formal/VERIFY.md)
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

`.github/workflows/ci.yml` runs the same checks on GitHub-hosted `ubuntu-latest`
runners. The job has read-only contents permission and no signing credentials.
The equivalent `.gitea/workflows/ci.yml` remains available for a configured Gitea
runner with Rustup, Node, Git, Java 11 or later, and a C toolchain. Hosted results
are recorded in the card report; configuring a workflow alone is not a passing
check. Both workflows run the five design models and eighteen deliberate fault
checks after the workspace checks.
P0-03 adds the signed image build; P0-04 qualifies the runtime on that image.
Host checks do not substitute for either card. The formal checks run serially
after the workspace checks using the pinned formal-proofs action; see
[VERIFY.md](formal/VERIFY.md) to reproduce them with the same resource limits.

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2024-2026 Jascha Wanger / ThirdKey AI
