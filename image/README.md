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

## Hosted validation scheduling

Workspace, policy and formal checks still run on every pull-request update.
The twelve heavier input/build/VM workflows use component-specific push paths
for branches in this repository. GitHub compares each push's old and new heads,
so an unrelated launcher or documentation edit does not rebuild the compositor.
Their same-repository pull-request jobs are skipped before runner allocation;
fork contributions retain pull-request validation, and manual dispatch remains
available. A newer relevant run supersedes the same workflow/ref's older run.

The workflow bodies, pinned actions, resource ceilings, permissions and acceptance
checks are unchanged. Skipped or cancelled jobs are not passing qualification
evidence. Retained results remain bound to their source/input hashes; changed
inputs require their actual tests before adoption or release. Hyprland default
changes run the retained-binary runtime checks without repeating compilation.
See [GitHub's path comparison rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

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
local resource limits or the image-container limits above. The local VM remains off.

The acceptance script invokes the actual CLI with validation enabled for both
OS recipes, then malformed/unpinned recipe cases, then Containerfile generation.
Positive cases run first so tool/network failures cannot count as negative-test
evidence. The strict cases describe the OS recipe profile, not every recipe
that upstream BlueBuild may support. The unmodified-source run on Rust 1.100.0
[compiled successfully and rejected the v2 recipe](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45671852999)
through its v1 validator. That result is retained before the downstream fix.
No validation bypass is available in this workflow.

The workflow has read-only repository permission, no release environment, no
OIDC permission and no registry write permission. Earlier passing runs retained
public logs, pins and generated text, but not the compiled executable. The next
hosted run also retains the exact development CLI and original upstream license
as `bluebuild-development-tool`, so later image assembly can reuse those bytes.
The runner is Ubuntu 24.04, matching the planned assembly host. The binary is
bounded to 128 MiB; its immutable manifest binds the OS commit, upstream source,
configuration, unchanged Cargo.lock, applied patch, compiler, features, profile,
license and executable hashes. Retention occurs after compilation and before
later acceptance, so a retained artifact alone never means those later checks
passed. Reuse must verify the artifact/manifest digests and the same run's 17
CLI cases and complete upstream suite before execution. No image is uploaded by
this workflow. Source/dependency review, external-reference authentication and
actual OS qualification remain separate gates.

`toolchain/reuse.py` prepares that artifact-consumption boundary. It requires
reviewed passing CLI/upstream flags, a byte-identical current tool configuration,
matching source/compiler/patch bindings and exact archive/manifest/file hashes.
Only the executable, original license and manifest are accepted; duplicate,
escaping, linked, special, encrypted, oversized or ambiguous JSON inputs fail
before execution, and partial extracted output is removed. Seven fixture tests
exercise this boundary with non-executable bytes. A real artifact lock is added
only after the next hosted tool run and its retained evidence are reviewed.

The downstream patch in `toolchain/patches/` adds a closed, embedded schema for
this OS's v2 recipe profile, then requires successful upstream typed parsing and
OCI-reference parsing. It supports only the two OS image names, amd64, local
key paths, nonzero SHA-256 base digests and built-in Containerfile snippets.
Remote schemas/includes, additional stages, other modules and moving tool images
are outside this profile and rejected. The legacy v1 validation code remains
in place; this is not general BlueBuild v2 support. The patch is hash-checked
before application to the exact source revision and recorded in build evidence.

Containerfile generation is denied access to a container daemon. If registry
metadata lacks the OS version and BlueBuild tries to run an image as a fallback,
this check fails instead of pulling/executing that image. Public registry
metadata inspection remains allowed; generated external references still need
a separate review before any image build.

After the CLI acceptance cases pass, the same hosted unit runs the upstream
workspace unit tests with the selected features, one test thread and no debug
symbols. A failure is retained as a failure; no test is omitted to pass this gate.

The patched CLI run
[45673507028](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45673507028)
passed both positive recipes, all twelve rejection cases and both Containerfile
generations. Their only external FROM reference is the corresponding verified
secureblue digest; scratch/local stages and extracted scripts are recorded in
`docs/security/reports/P0-03-bluebuild/45673507028/generated-reference-review.json`.
The full workspace test gate failed on the missing Cosign test prerequisite.

`toolchain/cosign.json` now pins the same Cosign v3.1.5 artifact used to authenticate
the base images. The hosted bootstrap downloads it under the existing cgroup,
checks size/hash and verifies the release KMS signature using the pinned public
publisher key and OpenSSL before running any downloaded code. The authenticated
binary enters only this job's test PATH; small public verification records are
retained. No release credential is provided. The full upstream tests remain
mandatory, including the previously failing Cosign/Sigstore compatibility tests.

The complete rerun [45676688773](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45676688773)
passed the actual CLI checks and all 151 upstream workspace tests with authenticated
Cosign available. Its source, compiler, lockfile, patch, binary and generated-file
hashes are retained in the P0-03 report. Tool compatibility is now evidenced for
these exact inputs; it does not qualify a built OS image or complete dependency
audits. The initial and final cgroup counters are collected inside the unit;
a post-exit systemd query labels a garbage-collected unit instead of showing
default limits as measured values. The first success predates the final-counter
fix and records that evidence limitation explicitly.
