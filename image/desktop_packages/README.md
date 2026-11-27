# Requested desktop package discovery

P0-03 owner requirements are recorded in [desktop-profile.md](../../docs/desktop-profile.md).
This separate hosted step resolves and authenticates candidate terminal/media
packages before source review, fixed-version selection, installation and real
desktop testing. It does not add them to either built image or to the local
workstation. The initial requested set includes Kitty, **MPlayer and mpv**, bat,
fd, eza, zoxide, fzf, ripgrep, btop, fastfetch, lazygit, tmux, Neovim, jq, Bash
completion, wl-clipboard, grim, slurp, playerctl, pamixer, brightnessctl, imv
and ffmpegthumbnailer. A separate metadata query records availability of
Starship, mise and gum; it does not fetch or execute unofficial installers.

The controller verifies and pulls the existing exact secureblue generic base.
Its discovery container has a read-only root, private PID namespace, no
capabilities or privilege escalation, private writable download/cache paths,
and public repository network access. `dnf5 install --downloadonly` performs
no RPM transaction. Package identities before and after must match. Candidate
programs and package scriptlets are never executed by this step.

Only Fedora 45/x86_64 release/stable updates and RPM Fusion Free release/stable
updates are configured. The two committed public keys are imported only into
private disposable keyrings. Nothing changes system or release trust. Each
downloaded RPM needs a verified full-fingerprint signature and payload digest;
the complete NEVRA, source RPM, license, vendor, size and SHA-256 are recorded.
Real missing-key, wrong-key and modified-package checks must fail separately
for both signers. The installed base's crypto policy stays unchanged.

The [repository input record](repository-inputs.json) binds the public upstream
release configuration and MPlayer source spec. The RPM Fusion public key was
also matched to the pinned distribution-gpg-keys copy; its fingerprint is
`E9A491A3DE247814E7E067EAE06F8ECDD651FF2E`. The Fedora key and base bindings reuse
the already-reviewed [Fedora trust record](../hyprland/fedora-package-trust.json).
The source spec is provenance research, not evidence of a particular released
binary. HTTPS metalinks and required RPM signatures preserve the upstream
unsigned repository-metadata model; no metadata signature or freshness proof
is invented.

The [cve.bz desktop assessment](../../docs/security/reports/P0-03-cve-bz/2026-11-26/desktop-profile/)
identified Kitty preview sanitization and askpass ownership checks that must
be present in the eventual OS package. Discovery records candidates even if a
repository still offers an older version, with `security_qualified=false` and
`packages_selected=false`. Upstream 0.51.0 is the reviewed source reference for
those two fixes; an exact signed Fedora source/backport review and the remaining
advisories must be assessed before selection. Signatures alone do not show that
a vulnerability is fixed, and the local Kitty 0.45.0 is a behavior reference.

The hosted parent is limited to 3 GiB/two CPUs/256 tasks and 65 minutes; the
container to 2 GiB/one CPU/128 tasks. Both prohibit swap. Downloads are limited
to one concurrent transfer with the existing 5 MB/s DNF throttle; accepted
candidates are capped at 512 RPMs/2 GiB. Public guest evidence is capped at
1,100 files, 1 MiB per file and 16 MiB total. Container/image/private storage
cleanup and final OOM/kill/resource counters are checked. Only the bounded
logs/manifest and successful candidate artifact remain on GitHub. Large RPM
artifacts are not downloaded locally.

The workflow runs once per relevant push, skips duplicate internal PR jobs,
does not cancel an active discovery run, has read-only repository permission,
and receives no release environment, signing credential or provider token.
The original compositor and package resolvers are unchanged, so this addition
does not start unrelated desktop builds or supersede a running Atomic test.

Eight inert tests were written before their helpers. They cover exact keyring
membership, signature/payload failures, repository restrictions, candidate-only
security state, altered or linked host inputs, and bounded public evidence.
Native RPM checks remain hosted acceptance work. After discovery, still review
additive compatibility with both bases (including FFmpeg and crypto), exact
source fixes, licenses and SBOM/provenance before integration. Fonts, Tokyo
Night, menus and all 190 reference shortcuts remain separate required work.

Affected invariant: INV-12. This step introduces no agent authorization gate,
production dependency selection, audit exemption, release key or journal event.

## Retained signed candidates and Kitty selection blocker

[Discovery 45818341284](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45818341284)
passed at `30d4ab7`. All 218 original small evidence files are retained and
independently reconciled: 39 RPMs totaling 46,606,537 bytes, 37 verified against
the Fedora key and two against RPM Fusion Free. Both signers' missing-key,
wrong-key and modified-RPM controls failed as required (six native controls).
The installed base inventory stayed byte-identical; container/image/private
storage cleanup passed. The parent had 60,246 memory-limit events with no OOM,
kill or swap; the discovery container peaked at 412,282,880 bytes with zero
memory-limit/OOM/kill events. The large candidate archive remains hosted.

Candidates include MPlayer `1.5.1-0.26.r38531.20260727.f401198.fc45`, mpv
`0.41.0-10.fc45`, and Kitty `0.48.2-1.fc45`. The separately queried gum version
was `2.0.2-1.fc45`; the stable repositories returned no Starship or mise rows.
These are discovered inputs, not installed additions or release pins. The
MPlayer spec reviewed earlier was release 0.27 and is not source proof for the
actual 0.26 candidate; that exact source review remains required.

The [exact Kitty source review](../../docs/security/reports/P0-03-cve-bz/2026-11-26/desktop-profile/fedora-kitty/README.md)
rejects the candidate for integration: three reviewed cve.bz fixes are absent
from the checksum-bound source and are not backported by its three Fedora
patches. Kitty remains absent from the built image. Select an authenticated
maintained fixed package/source, assess the remaining advisories and run native
tests before enabling it as the default. No blanket audit exemption, security
clearance or claim about the owner's current workstation is made.

Both-base additive installation, remaining dependency/security/license review,
fonts, Tokyo Night, menus, all 190 shortcuts and actual desktop acceptance are
still pending. No production dependency or trust selection changes in this
evidence-only follow-up; INV-12 remains a release requirement.

## Closed MPlayer and mpv install gate

[`media-rpms.lock.json`](media-rpms.lock.json) freezes the three authenticated
root RPMs already observed in discovery: MPlayer and `mplayer-common` from the
exact RPM Fusion Free fingerprint, and mpv from the exact Fedora 45
fingerprint. It also binds both target base digests and the retained discovery
manifest. This is a candidate-root lock, not an install selection.

Installation remains closed for two concrete missing inputs. The aggregate
desktop artifact does not prove the minimal additive dependency closure for
only MPlayer and mpv, and no authenticated source RPM bytes are retained for
the exact binary header values. The two source slots therefore contain null
size/digest fields and `signature_verified=false`. Changing a slot, marking the
closure complete or setting `install_ready` without the complete authenticated
records is rejected before an artifact can be opened.

The lock also binds the retained 26 November cve.bz MPlayer and mpv product-name
search responses to these exact candidate versions and source-RPM names. Those
responses are incomplete text searches with unrelated matches. The lock keeps
`package_version_assessed=false` and `cleared=false`; image assembly performs no
live security lookup and cannot turn the searches into a clearance claim.

When a dedicated media-only closure and its two source RPMs are available, the
prepared installer rechecks every byte, full signing fingerprint, RPM header,
binary-to-source version/release relationship and both negative-control
signers. The closure lock also freezes the producing repository, workflow, run,
head commit, artifact name and Fedora base digest. Image assembly compares the
live GitHub artifact and workflow-run metadata with those fields before it
downloads the archive. It imports the two public keys only into a temporary
filesystem keyring under `/run`. DNF receives a read-only, preverified local
closure with
all repositories and plugins disabled. The system RPM key inventory and
repository configuration under Fedora Atomic's `/usr/share`, `/usr/etc`, the
factory and secureblue defaults under `/usr/share`, and mutable `/etc`
locations must be identical before and after. That snapshot binds the owner,
group and mode of every covered directory, file and link as well as each
link's effective target bytes and metadata. Oversized files and special nodes
fail the build, so RPM Fusion trust does not become image trust.

The future ready lock deliberately uses a two-commit relink. The first commit
may contain the complete authenticated package inputs with
`image_source_commit=null`; that commit can build an image whose manifest
records `media_selection_sha256`. After the retained image exists, a second
commit sets `image_source_commit` to the first commit and updates the retained
image lock. The selection digest excludes only this coordination field, so it
does not change during the relink. Playback refuses a null, stale or mismatched
commit and independently requires the in-image selection digest. This makes
the future ready state constructible without claiming that a commit contains
its own resulting hash.

The manual hosted playback workflow is also closed by the same lock. Once new
retained generic and NVIDIA images are bound to the selected package/source
digest and their exact build commit, it runs one variant at a time under a
3 GiB/one-CPU controller. An unprivileged, read-only, networkless 512 MiB
container first matches all three installed RPM identities, then makes small
deterministic WAV and YUV4MPEG fixtures and requires MPlayer and mpv to decode
both to null outputs. The retained report has an exact scope and schema, exact
fixture digests and controller limits, and final zero OOM, OOM-kill and group
OOM-kill counters. That gate does not qualify an audio device, display, GPU
decode, arbitrary media or a release image.
