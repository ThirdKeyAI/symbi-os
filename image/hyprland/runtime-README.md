# Retained compositor runtime compatibility

`development-prefix.lock.json` binds the completed source build, its compiled
binaries, source revisions, native-loading patch, RPM lock and hosted archive.
`runtime-rpms.lock.json` pins only the three signed libraries missing from the
original base. The full compiler RPM set, including Mesa downgrade candidates,
is never an input to this runtime transaction.

`hyprland-runtime.yml` downloads the exact artifacts on hosted CI. The resource
unit verifies the base signature and all artifact contents before use. Prefix
extraction rejects path escapes, special/hard-linked entries, linked parents,
duplicate names and mismatched binaries. Internal shared-library symlinks are
retained; archive owner and privileged/writable permission bits are discarded.

`runtime_guest.py` rechecks every RPM's Fedora signature and permits only an
additive transaction: every original package identity must remain, and the
added set must exactly match the reviewed three RPMs. It stages the retained
prefix, checks both binaries' library resolution and preserves the installed
inventory. The parent then runs actual configuration parser controls as the
unprivileged test UID. No C++ compiler runs in this workflow, and no local image,
VM or compiler is started.

A passing result qualifies only these runtime dependencies and parser inputs.
Native constructor/IPC/reload refusal still needs the real graphics route;
launcher packaging, image assembly, browser/keyring/portal controls, release
signatures, boot/update/rollback and P0-04/P0-05 acceptance remain separate gates.
