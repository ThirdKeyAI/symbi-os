# Fedora Atomic image preparation

P0-03 uses the owner-selected strategy **retain secureblue hardening and package
maintained Hyprland**. The GitHub release environment and dedicated signing key
are configured. Generic and NVIDIA base signatures have been verified at the
digests in `base-images.json`. Hyprland/RPM inputs and release execution remain incomplete.
No Symbiont OS image has been built, signed, booted or qualified.

The original plan names secureblue's `wayblue-hyprland-main-userns-hardened`.
[secureblue's pinned deprecation notice](https://github.com/secureblue/secureblue/blob/353366bb6d031e66fc565b0b101a8a069f32fcdb/files/system/usr/libexec/deprecated-images.json.md)
retires the Hyprland family and the separate `userns` images. Its suggested
`sericea` replacement uses Sway and would change the planned trusted compositor.
The owner selected the strategy above on 25 Nov 2026. A maintained secureblue
desktop can supply the base hardening; Hyprland must still be packaged and
qualified as Symbiont's compositor. See [the implementation decisions](RELEASE-PLAN.md)
and OQ-07. A Sericea base does not make Sway the product's trusted compositor.

## Implemented preparation

- `overlay/` contains minimal Hyprland, Waybar and Walker defaults, managed
  Firefox/Chromium privacy policies, developer opt-outs and the NetworkManager
  probe setting. Sources, revisions and licenses are in [THIRD_PARTY.md](THIRD_PARTY.md).
- The Symbiont session copies defaults from `/usr/share/symbiont/defaults` before
  Hyprland starts. Existing user files and file symlinks are preserved. Directory
  symlinks are refused. This is an ordinary user-session helper, not a privileged
  writer or a defense against concurrent changes by that same user.
- `harden-image.sh` runs only inside a Fedora build container. It checks required
  desktop tools, rejects detected passwordless sudo, masks ABRT services and
  removes `hyprpm`. It deliberately fails when the selected base lacks packages;
  package installation and RPM key pins must be reviewed for that base.
- `recipe.py` renders BlueBuild v2 JSON, which is valid YAML. It accepts only
  SHA-256 image references and a hash-checked local public key. It refuses to
  render an absent variant or changed key. The selected secureblue desktop bases
  have retained [signature evidence](../docs/security/reports/P0-03-base-signatures/result.json).
  No placeholder digest or tag-only base is provided. Only the built-in `containerfile` module is used;
  no moving module image or CLI is installed in the desktop image.

- `signing.py` prepares a default-reject containers/image policy with hash-bound
  public keys, exact signed repository identities and signature-attachment lookup.
  Base rollback is restricted to the selected digest. `release-trust.json` now
  binds the dedicated OS public key and two GHCR destinations; see
  [the trust-policy procedure](SIGNING.md). Symbiont's GitHub workflow signing
  identity remains an additional attestation identity, not the OS update key.

Run `bash scripts/check-image.sh` for the small offline checks.
`python3 image/recipe.py --variant generic` emits the recipe; `--variant nvidia`
uses its separately verified base pin. The
renderer is not a signature verifier. Do not build until the signature and all
release prerequisites below are satisfied.

## Required build and release sequence

1. Implement the selected secureblue plus maintained Hyprland strategy,
   using the verified generic/NVIDIA digests and publisher key in `base-images.json`.
   Recheck those signatures
   at build time. Review RPM repositories, their GPG key fingerprints and every
   downloaded asset; use only checksummed, signed artifacts.
2. Provision a trusted isolated runner with a reviewed, hash-pinned BlueBuild
   build that enables and validates recipe v2, cosign, an SBOM generator and Podman.
   Recipe v2 is feature-gated upstream, and both v0.9.42 and the reviewed
   post-release source still route validation through the v1 schema/parser.
   The hosted compatibility check below must pass for the actual CLI and generated Containerfile.
   All external `FROM`/mount images must be digest-pinned. Never bypass validation
   or signature verification to get a build through.
3. Generate/build one architecture and one variant at a time. Use one build
   process, a 2 GiB build-container memory ceiling, one CPU and no extra swap.
   Keep layers on disk, not `/tmp`. A resource-limit failure fails the build;
   do not automatically raise limits or start a second build on this workstation.
4. Apply base-specific hardening: disable the actual compositor plugin-loading
   API (removing `hyprpm` is insufficient); authenticate RPM repos; prevent
   autologin; enforce repeated screen-share consent; qualify keyring storage for
   the installed browser. Existing user configs remain user-owned and are not
   silently replaced. The privacy files alone do not prove these properties.
5. Build the pinned Symbiont source and capture its binary digest/build provenance.
   Run P0-04 and P0-05 inside the built Fedora deployment. Retain their reports,
   the compositor plugin negative test, signed/unsigned rebase test and rollback
   boot smoke test. A host test or mocked report cannot satisfy this step.
6. Generate an SPDX SBOM for the exact output digest and a SLSA provenance
   predicate binding source commit, base digest, tool pins and actual builder
   invocation. Sign the image and attestations with the selected ThirdKey key.
   Verify signatures, subjects and identities before promoting a release tag.
   Publishing a provenance statement alone does not establish a SLSA level.
7. Ship an enforcing containers signature policy scoped to the selected image
   repository and ThirdKey public key. Use the documented signed rebase transport;
   do not emit an unsigned installation fallback. A nightly base-update candidate
   must repeat these checks and open a review PR only after they pass.

The owner selected Symbiont's release infrastructure: GitHub Actions and GHCR.
The public OS execution repository and protected signing environment are now
configured. Image publishing remains disabled pending the real build and
qualification gates (OQ-03). See
[RELEASE-PLAN.md](RELEASE-PLAN.md) for the concrete destinations and gates to
configure. Signing with an invented test key, omitting VM gates or silently
changing compositor would violate the plan.
The Agents menu and runtime units arrive with their implementing cards; the
current launcher exposes local applications only.

## Hosted BlueBuild compatibility check

`image/toolchain/bluebuild.json` pins the experimental source build to
`a654ee8810c637aa00356999488e97259061275d`, with Rust 1.100.0, the unchanged
upstream lockfile and the explicit `v1_0_0` feature. The separate
`Image tool compatibility` workflow compiles it only on a GitHub-hosted runner,
under a verified 4 GiB memory limit, no swap, two CPUs, one Cargo job and a
45-minute deadline. These hosted tool limits do not change the workstation's
existing VM limits or the image-container limits above.

The acceptance script invokes the actual CLI with validation enabled for both
OS recipes, then malformed/unpinned recipe cases, then Containerfile generation.
Positive cases run first so tool/network failures cannot count as negative-test
evidence. The strict cases describe the OS recipe profile, not every recipe
that upstream BlueBuild may support. The first unmodified-source run is expected
to expose the v1-only validator; its outcome must be retained before a fix.
No validation bypass is available in this workflow.

The workflow has read-only repository permission, no release environment, no
OIDC permission and no registry write permission. It uploads public logs, pins
and generated text as evidence, not a compiler binary or image. Even a passing
CLI check does not establish source audit coverage, authenticate an OS build,
or qualify generated external image references; those remain separate gates.
