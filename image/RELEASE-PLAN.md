# Selected base and release setup

Owner decisions, 25 Nov 2026: keep secureblue hardening and package maintained
Hyprland; use the same release infrastructure as Symbiont; create a dedicated
OS key in protected GitHub secrets. The owner initially selected a private
repository, then explicitly made it public so the current GitHub plan could
enforce release reviewers. Key custody is configured below; image acceptance
tests remain outstanding.

## Base and desktop

Use a maintained secureblue **desktop** as the hardening base, with a separately
built Hyprland package and its required libraries. The current upstream
[Sericea recipe](https://github.com/secureblue/secureblue/blob/353366bb6d031e66fc565b0b101a8a069f32fcdb/recipes/general/recipe-sericea-main.yml)
is a Fedora 45 desktop candidate. The securecore family uses CoreOS and is not
an interchangeable desktop base. Both selected variants passed Cosign signature
verification on 25 Nov 2026. Discovery used `latest`, followed by a second
verification against each exact digest and signed repository identity. Only
those immutable references enter `base-images.json`; the tag is not a build pin.
The publisher key comes from the pinned official secureblue source above.
See [the retained commands and signature output](../docs/security/reports/P0-03-base-signatures/result.json).
This authenticates base inputs; it does not qualify the resulting OS.

Hyprland remains the product compositor. Its
[v0.57.2 release](https://github.com/hyprwm/Hyprland/releases/tag/v0.57.2)
resolves to `11cbc6c577b84ffb1edf4df3fc5b6128c3ae6947`. This is a researched
candidate, not a qualified package pin. Fedora's official
[package listing](https://packages.fedoraproject.org/pkgs/hyprland/hyprland/)
does not list a Fedora 45 build. The maintained
[Hyprland-Fedora packaging source](https://github.com/AshBuk/Hyprland-Fedora/tree/c07451155a79183e54c24e969e02fa46f72e9fd5)
is a useful MIT-licensed reference; its personal COPR is not automatically a
trusted package source. No COPR has been enabled.

Build and sign the compositor package in the isolated release pipeline. Review
and pin all source/dependency inputs, prohibit configure-time network fetching,
and implement plugin rejection inside the compositor. `NO_HYPRPM` only removes
the plugin manager. The patched build must reject plugin loading through both
configuration and IPC, including a shared object's constructor side effects.
The current Lua configuration interface, portal consent, browser/keyring
behavior and inherited secureblue user-namespace policy also require testing
on the exact image. None is established by these source observations.

## Symbiont infrastructure reference

Inspected the existing Symbiont checkout at
`e0958db371a219c6cea36f1567f27b253d31ec33`, specifically
`.github/workflows/docker-build.yml`, `.github/workflows/release-binaries.yml`
and `docs/release-verification.md`. No credentials were read or copied.

| Concern | Existing Symbiont configuration | OS setup to configure |
| --- | --- | --- |
| Builder | GitHub Actions `ubuntu-latest` | Ephemeral GitHub-hosted Linux jobs; serial variant builds and bounded build containers |
| Registry | `ghcr.io/thirdkeyai` | Selected repositories `ghcr.io/thirdkeyai/symbiont-os` and `ghcr.io/thirdkeyai/symbiont-os-nvidia` |
| Release signing | Keyless Cosign, issuer `https://token.actions.githubusercontent.com` | Dedicated OS key in the protected release environment; exact OS workflow identity for additional attestations |
| Source review | Symbiont has its own Gitea/GitHub synchronization | Keep OS review in `git.dx.pe/ThirdKeyAI/symbi-os`; configure the OS GitHub execution repository explicitly |

Created the owner-authorized public repository
[ThirdKeyAI/symbi-os](https://github.com/ThirdKeyAI/symbi-os). Its initial `main`
contains the scaffold and the prominent experimental notice at `f6487b0`.
[PR 1](https://github.com/ThirdKeyAI/symbi-os/pull/1) enables the hosted scaffold
checks; [its first run passed](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45660849000).
No OS release tag or container package was published. Existing Symbiont
GPG/SSH synchronization credentials were not reused.

The dedicated image workflow will be `.github/workflows/release-images.yml`.
For this repository, the exact release certificate identity will be
`https://github.com/ThirdKeyAI/symbi-os/.github/workflows/release-images.yml@refs/tags/<release-tag>`.
This is a template to fill with an approved tag, not a broad trust matcher.
Do not accept the Symbiont runtime workflow identity as if it signed the OS.

## Compatible image signing

The current container-libs verifier only matches Fulcio email identities; the
GitHub workflow certificate has a URI identity. See [SIGNING.md](SIGNING.md)
for the pinned source evidence. Neither a URI placed in `subjectEmail` nor an
unsigned rebase followed by a separate verification step enforces this policy.

The dedicated ECDSA P-256 key is stored as `COSIGN_PRIVATE_KEY` (encrypted PEM)
and `COSIGN_PASSWORD` in the `symbi-os-release` environment. The environment
requires review by `jaschadub`, prevents self-approval, and accepts only `v*`
tags. A run initiated by that reviewer needs a different authorized reviewer
before release; do not silently disable self-approval protection. Repository
administrators retain their ordinary GitHub administration powers.

Only [the public key and custody metadata](keys/thirdkey-os-2026.json) are kept
in the repository. Local private material was removed after the API confirmed
both secrets were stored and the environment protections were rechecked. The
image policy binds the public-key hash and exact registry repositories.
Generate a legacy attachment compatible with the selected verifier, then verify
that exact digest using both Cosign and the installed bootc/rpm-ostree path.

## Workflow contract

Prepare ordinary PR checks with read-only contents access, no OIDC issuance and
no registry login. Release jobs must require a reviewed protected tag/environment
and use commit-pinned actions and authenticated tools. Build one variant at a
time; local work keeps the existing resource caps and does not run an OS build
beside the runtime validation VM.

Before publishing a release tag, bind evidence to the exact source and image
digests: verified base signature; compositor package provenance; SPDX SBOM;
SLSA provenance; Fedora P0-04/P0-05 qualification; plugin refusal; signed,
unsigned, wrong-key and wrong-repository update tests; and a booted rollback.
Push candidates by digest, sign and verify that digest, and only then promote a
release tag. Failed or absent evidence must prevent promotion. A manually
authored success flag does not replace those executions.

Publishing remains disabled until the pins, actual image build and acceptance
evidence are established. Creating protected secrets alone does not qualify a
signing workflow, a built image, or an update/rollback path.

## Implemented release-evidence gate

`image/release/contract.py` now defines the fail-closed evidence bundle that a
release must satisfy. It reconciles both exact registry subjects, SPDX and SLSA
subjects, the dedicated-key Cosign verification reports and native P0-03,
P0-04 and P0-05 results at one source commit and one image per variant. It also
binds the artifact to the reviewed producer workflow run. These are structural
checks: authored JSON can satisfy their schema and therefore cannot establish
authentic execution by itself. The `release-candidate.yml` workflow has no
upload step and fails explicitly until the real native and signing producers
are bound by run path, source SHA/ref, conclusion, artifact ID, digest and name.

The protected `release-images.yml` currently has read-only permissions and
performs only this reconciliation; it cannot sign, attest, push or promote an
image. It runs only on a selected `v*` tag and accepts evidence only from the
candidate workflow at the same tag and source commit.

The scheduled `upstream-check.yml` applies the same evidence gate to candidate
base digests, preserves the existing repositories and trust roots, reruns the
serial repository checks and opens a review PR only after independent artifact
revalidation. The candidate workflow deliberately cannot create either expected
artifact while actual image builds, native qualification, signing and
publication remain outstanding. Therefore both paths fail before an upload or
Git write today; authored success flags do not qualify a release.
