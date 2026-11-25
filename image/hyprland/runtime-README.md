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

The pinned [Hyprland installer](https://github.com/hyprwm/Hyprland/blob/11cbc6c577b84ffb1edf4df3fc5b6128c3ae6947/CMakeLists.txt#L636)
creates `bin/hyprland` as an absolute alias of the installed `bin/Hyprland`.
Extraction relocates only the exact pair
`hyprland/bin/hyprland -> /usr/lib/symbi/hyprland/bin/Hyprland` to `Hyprland`.
The target remains a regular executable checked against the retained hash;
all other absolute links, escaping relatives and linked parents are rejected.
The hosted result records the original and relative targets actually converted.
Refusal diagnostics quote and bound the rejected name and target.

The first reuse run, 45722401293, failed at link validation before package
installation. Its retained report did not identify the particular link; the
source-backed alias conversion still requires confirmation on the actual
locked archive. No acceptance claim follows from synthetic archive tests.
