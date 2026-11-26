# Requested terminal applications

This directory binds the first reviewed candidate versions for Yazi, Glum and
Tootles. They are selected desktop requirements, but they are not installed or
qualified in the current images. The source records pin Yazi v26.9.1, Glum
v0.2.2 and Tootles v0.2.0 to exact commits, archive bytes, required files,
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
qualification. Glum and Tootles also publish signed Linux release material; a
later payload gate must verify the expected repository, workflow identity and
subject digest before considering those artifacts. Yazi needs either an audited
source build or separately authenticated release provenance.

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
build inputs. Exact toolchains, release signatures or provenance, dependency
audits, native package compatibility and installed-image acceptance remain
unresolved.
