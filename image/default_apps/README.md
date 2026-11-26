# Requested terminal applications

This directory binds the first reviewed candidate versions for Yazi, Glum and
Tootles. They are selected desktop requirements, but they are not installed or
qualified in the current images. The source records pin Yazi v26.9.1, Glum
v0.4.1 and Tootles v0.2.0 to exact commits, archive bytes, required files,
licences and complete Cargo dependency identities.

`desktop-source-intake.yml` passively downloads and inventories these archives
beside the existing Tolaria intake. It does not extract, execute, compile or
install candidate code. The combined workflow replaces the former Tolaria-only
workflow, so this work does not add another workflow to the hosted queue. Each
inspector runs unprivileged with one CPU, 512 MiB memory, no swap, 32 tasks and
no capabilities.

The Yazi tag is lightweight. The Glum and Tootles tags are annotated but
unsigned. Exact commit and archive hashes prevent silent input changes after
review, but the source intake does not claim release authenticity or security
qualification. `glum-release-inputs.json` separately fixes Glum's official
v0.4.1 x86_64 Linux release asset, GitHub release and asset IDs, exact archive
inventory, detached signature bytes and certificate identity. The signature
verifies over the asset and the certificate binds the release workflow, tag and
source commit. The Fulcio trust chain and transparency log are not yet verified,
so the candidate remains unselected and unqualified. Yazi and Tootles still
need authenticated executable provenance.

Yazi is the terminal file manager launched in Kitty. Only the `yazi` binary is
in the planned payload: the `ya` package manager is explicitly excluded, and
the immutable profile ships no downloaded plugins or themes. Its one pinned Git
dependency and 557-package Cargo lock remain review inputs. Glum is the local
terminal Markdown reader. Tootles is the human's Mastodon and Bluesky client,
starts with Tokyo Night, and may use the already-requested mpv for explicit
media playback. Tootles real-account support stays blocked until its credentials
are stored through a qualified secret boundary and cannot enter governed
sessions.

The convenience installation commands in upstream documentation are never OS
build inputs. Exact toolchains, complete release trust verification, dependency
audits, native package compatibility and installed-image acceptance remain
unresolved.

## Offline image-payload boundary

`payload-contract.json` fixes the only files a future hosted build may add to
an image payload. The allowlist contains the three ELF executables, the exact
Yazi and Tootles desktop files from their pinned source archives, the Glum and
Tootles man pages, Glum's shipped Bash, Fish and Zsh completions, and the
upstream licence and notice files. It excludes Yazi's `ya`
package manager and every updater, plugin and downloaded-theme path. The
contract is hash-bound to `source-inputs.json` and
`glum-release-inputs.json`. Source-backed and Glum release-backed files must
retain the exact size and digest recorded for their authenticated input.

`payload.py` supplies the offline staging and verification path. It accepts
only an exact, bounded ZIP with a retained manifest and artifact lock, plus a
verified GitHub build-provenance record whose subject digest is the ZIP digest.
The manifest must bind every executable to the exact application version,
revision and source-archive digest, and bind Glum to the exact signed release
asset. Archive members, install destinations and
modes are a closed allowlist; links, special files, overwrites and extra members
fail before any payload file is copied. A failed copy removes files created by
that attempt.

No development-payload lock or executable artifact exists in this tree, so the
desktop preparer does not call this path yet. Source intake is not executable
payload authentication. The contract, security and OS qualification flags
remain false until a separately attested build is retained, dependencies are
reviewed, and native image tests cover launches, file operations, previews,
desktop entries, media handoff, egress and Tootles credential storage. Real
accounts remain disabled until that final secret-storage gate passes.
