# First fresh-consent build: artifact access failure

[Run 45784560037](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45784560037)
tested `bcc91ed1e549693c1b0f5a428b7d6561430be256`. It failed before native
compilation or formatter tests. The verified prefix extractor intentionally
creates a mode-0700 staging parent. The compiler account (UID 10001) could not
traverse `/inputs/portal-prefix` to copy its already verified public toolkit.
The original permission traceback is retained unchanged.

The narrow correction mounts the validated `portal` child read-only at
`/retained-portal` in the compiler container and copies from that mount. The
private staging directory keeps its permissions. The existing exact-file
inventory comparison runs immediately after copying; native toolkit files,
source/patch/package pins, compiler identity, network isolation and resource
ceilings remain unchanged. The read-only compositor mount uses the same
existing pattern. Actual acceptance of the corrected mount is pending the
next hosted run; no local privileged container or native compilation ran.

All 391 original files (313,636 expanded bytes) are retained with their hashes.
The 159,107-byte original ZIP has SHA-256
`aaab4d2ae563ac2b5e325b3b2b3e7e800c81f031267071c6b25d26dc680c2b27`.
`artifact-metadata.json` binds the run and source. Independent reconciliation
verifies the base signature subject, 173 full Fedora package signatures,
source/patch/helper bindings, failure status, container removal and absence,
and unchanged limits with no OOM/kill. No compiled prefix was produced and no
runtime container was started.

The parent recorded 5,255 memory-max events with a peak of 8,601,964,544 bytes;
the compiler guest peaked at 1,359,740,928 bytes without memory-max events.
Both recorded zero OOM/kill events. These are hosted counters, not workstation
measurements. Reconciliation and 191 offline checks passed under local
128 MiB / 10%-CPU / zero-swap limits: 35,864 KiB peak RSS, 0.66 CPU seconds.
The corrected drivers parse and refuse local execution. Complete native,
GUI/D-Bus/capture, product-image and human TCB acceptance remain pending.
