# Patched portal desktop integration — offline acceptance

The original six strict-consumer tests and four desktop-selection tests were
written and run before implementation. Both runs failed because their respective
implementation modules did not exist. After implementation, all ten pass. The
combined suite passes **201 tests**, including the original 191 regressions.
The exact current source, patch, parent, RPM and consent-prefix lock bindings also
validate. The three shared file-helper function ASTs are identical before and
after their move from `prepare.py` to `files.py`.

Original logs are indexed by byte count and SHA-256 in `evidence-files.json`.
Local checks used a 128 MiB memory cap, 10% of one CPU, zero swap and 32 tasks;
the combined run peaked at **35,772 KiB**, used 0.71 CPU seconds and no swap.
No compiler, native artifact download, image, VM or GPU workload ran locally.

The implementation validates the original parent's 91+1+1 tests independently
from the patched portal's one data test and three negative controls. It accepts
only the two changed executable files and exact new Apache license, with all 46
other parent entries unchanged. Archive checks retain full hash/size, unique
member, path, type, mode, link and cleanup constraints.

The desktop selects eleven native runtime entries: eight private binary/library/
license files or links and three systemd/D-Bus/portal activation files. Headers
and pkgconfig metadata are omitted. Activation commands use the fixed patched
executable. The vendor preference routes ScreenCast and Screenshot to Hyprland
and otherwise uses GTK. This is an overridable desktop default, not an immutable
agent authorization gate. The original descriptor still advertises upstream
GlobalShortcuts/InputCapture; those are not selected by this preference file.

The recipe additionally selects only the signed iniparser runtime RPM from the
already authenticated portal build bundle, making six checked runtime RPMs in
total. Missing libraries may be added, but no base package replacement or extra
transaction is accepted. The existing isolated install and crypto preservation
checks remain in force. The new installed-image probes check three portal loaders,
version, both CLI refusals and activation files, in addition to prior checks.

The scheduled hosted image build has not yet passed. This is offline preparation
acceptance only. Full workspace/formal checks at predecessor `ab3ddfc` passed in
[45787702108](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45787702108).
That does not certify the new implementation. Atomic boot, visible picker and
full D-Bus/capture/cancellation/restart acceptance, source/dependency review,
applicable consent model/fault checks and human TCB review remain open. No
qualification flag is promoted, no new Cargo dependency/audit exemption/journal
event is introduced, and this change must not be merged as release-qualified.
