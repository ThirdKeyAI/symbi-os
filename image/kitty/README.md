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
