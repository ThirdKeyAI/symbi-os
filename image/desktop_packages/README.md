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
