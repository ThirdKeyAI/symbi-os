# Kitty candidate intake

The Fedora 0.48.2 candidate is rejected after the retained
[cve.bz source review](../../docs/security/reports/P0-03-cve-bz/2026-11-26/desktop-profile/kitty-source-followup/README.md).
Kitty remains absent from the built images. The owner's requested default and
keyboard/profile compatibility requirements remain unchanged.

Upstream 0.51.0 publishes both signed source and a signed x86-64 Linux bundle.
The source archive/tag are authenticated; corresponding fixes were inspected.
The bundle is a separate candidate. This workflow checks its exact 47,103,100
bytes and detached signature against the Fedora-pinned upstream public key,
then inventories every regular member by size/hash without extracting or
executing it. Real missing-key and altered-archive controls must fail. No image
is selected and no dependency or version is declared secure by this intake.

The hosted inspector runs as the ordinary runner user with empty capabilities,
no new privileges, a read-only system, private temporary directory, one CPU,
512 MiB memory, zero swap, 32 tasks and a 15-minute service deadline. It receives
no release environment, signing authority or token. Only public downloads and
verification logs are involved; downloaded bundle/control copies are removed.
The signature verifier is the trusted runner's installed gpgv, whose version and
binary hash are recorded. Local checks use only synthetic tiny archives and
signature-status fixtures; the real bundle stays off the workstation.

Reject absolute/traversing/duplicate paths, control characters, special files,
hard links, setuid/setgid modes, escaping/dangling/cyclic symlinks and excessive
member counts/sizes. Required entrypoints must be regular executable members.
This is passive inspection, not an extraction procedure or native program test.
The complete member inventory must still be reviewed for bundled libraries,
their licenses and security records. Publisher authentication does not establish
reproducible source/binary equivalence.

The source build also remains an option. Its release archive contains no generated
shader directory; `--skip-code-generation` cannot supply one. Upstream requires
the Slang shader compiler to build it. Exact Fedora Koji lookups for
`shader-slang` and `slang-shader` returned no package; Fedora's `slang` is a
different S-Lang extension-language library. No unsigned shader compiler binary
has been downloaded or selected. A cve.bz search returned a slangpy image-loader
record, which is not by itself a finding in the Slang compiler. These metadata
observations are not an exhaustive repository or vulnerability assessment.

Before installation, review the actual bundle dependency/license inventory,
validate entrypoints and loaders in the approved base without replacing base
libraries, exercise the security regressions and terminal rendering/input,
bind source/package evidence, and complete the Ombuntu profile checks. The final
image still requires its independent signature/provenance and human TCB review.
INV-12 remains in force. No product runtime, permission, dependency or journal
event is added by this passive intake workflow.

## Authenticated bundle inventory and link validation

[Hosted run 45833636460](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45833636460)
at `2c70e38` passed the pinned publisher signature, missing-key and altered-data
controls. It inventoried 764 entries and 169,261,985 regular-file bytes without
extracting or executing the candidate. Its 47,103,100-byte archive remained on
the hosted runner and was removed. The inspector peaked at 182,231,040 bytes
with no memory-ceiling or OOM events and no host swap. Eleven original evidence
files and their independent reconciliation are retained under
`docs/security/reports/P0-03-kitty-bundle/45833636460/`.

Two regression fixtures exposed limitations in the initial passive validator:
lexical link normalization could miss an escape through an intermediate directory
link, and an archive could list a payload beneath a non-directory member.
The validator now resolves components in archive order of traversal, expanding
links before later `..` components; it rejects non-directory member parents,
dangling/cyclic/excessive chains and root escapes. Valid relative links still
resolve. All 255 offline image fixtures pass under 128 MiB/10%-CPU caps, using
36,524 KiB peak RSS, 0.82 CPU seconds and zero swap. The hosted signed bundle
must pass the corrected validator before this step can be accepted.

The inventory includes private Python, OpenSSL, graphics and shader libraries.
The upstream SPDX metadata is a separate public publisher claim, not proof of
binary/source correspondence or a Symbi OS attestation. Its 80 package entries
include build/test dependencies as well as runtime candidates. The bundle has
no entry named as a license, copyright, SBOM or SPDX document in the inspected
inventory; license texts and corresponding source obligations require explicit
review and packaging. The candidate remains unselected and uninstalled pending
that work, cve.bz/primary-source dependency assessment and native compatibility.

The cve.bz follow-up recognized 47 of the publisher SPDX document's 80 entries
and returned no OSV matches for that subset. Separate native-library searches
identified Expat 2.6.2 / CVE-2024-45490 and PCRE2 10.43 / CVE-2026-103111 as
metadata-based review candidates, checked against maintainer fixes. Actual
bundled versions, backports and exposure are not yet proven. The candidate
remains unselected; this is not a clean security result. Full responses,
coverage limits and primary references are retained under
`docs/security/reports/P0-03-cve-bz/2026-11-26/desktop-profile/kitty-bundle-dependencies/`.

The corrected hosted rerun
[45849459625](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45849459625)
passed the publisher signature, missing-key and altered-data controls and the
component-wise link validator at `b25ef5c`. Its 764-member inventory is byte-for-
byte identical to the first run. The candidate was neither extracted nor
executed; private downloads were removed. The inspector peaked at 181,805,056
bytes with no memory-limit, OOM or swap events. All 11 original evidence files
and independent reconciliation are retained. This closes the archive-link
validation rerun only; dependency, license, native desktop and selection gates
remain open.
