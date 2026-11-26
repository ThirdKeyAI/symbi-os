# Exact development-image consumer

Six tests were run before implementation and failed because the consumer module
did not exist. All six pass after implementation. The combined image suite now
passes 207 tests. The final combined run additionally flips payload bytes without
changing length, exercising streaming hash rejection and partial-output cleanup.
The ZIP writer warning is the deliberately duplicated manifest negative control.

`image/boot/inputs.py` validates the selected variant, base, tested source, run,
artifact and exact manifest identity before streaming the one opaque OCI archive.
It refuses missing/extra/duplicate/linked ZIP entries, oversized data, changed
bytes, preexisting destinations and linked parent paths. It uses 64 KiB buffers,
releases its own file cache after bounded batches and preserves mode-0700 staging.
The OCI filesystem is never unpacked by this helper. No real image archive was
downloaded or processed locally; the fixture payloads are tiny inert strings.

The lock explicitly remains development-only, with OS/signature qualification
false. This consumer does not implement an installer, verify release signatures
or prove Atomic boot. Its actual large-artifact consumption remains a hosted
boot-harness task, as do image startup, rendering and interactive permissions.
