# First native portal build: report-selection failure

[Hosted run 45770130727](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45770130727)
used OS revision `6a516a75fc6733ef68218ac1d852c04469f733f3`. Its workflow
failed after both pinned components compiled and all native tests passed:
91 Debug toolkit unit tests, one surfaceless renderer test and one Release
portal picker-data test. The distinct Release toolkit is not certified by
the Debug test result. No physical desktop/consent qualification is claimed.

The local acceptance wrapper expected the CTest case name alone. CTest's real
JUnit output supplies the same value in both `classname` and `name`, which our
parser correctly preserves as
`hyprland-share-picker-data.hyprland-share-picker-data`. The incorrect expected
value stopped installation. Portal installation, loader/version probes and
prefix retention did not run; no usable portal artifact was produced. The
workflow remains failed. This was neither a compiler failure nor an OOM.

The correction checks the exact class/name pair inside the existing report
validator. Its regression fixture is the original `guest/portal-tests.xml`.
Changed names/classes and failed, skipped, disabled or incomplete cases remain
refused. Before/after checks are in `../../P0-03-portal-build-inputs/ctest-followup/`.

`artifact-metadata.json` records the 179,325-byte ZIP and its SHA-256;
`evidence-files.json` indexes all 427 original files (400,409 expanded bytes).
The independent reconciliation checks the source/base bindings, base signature
subject, all 173 full Fedora RPM signatures, actual test XML and hashes,
successful container removal and absence, resource limits and zero OOM/kill
counters. The parent reached 8,596,008,960 bytes and recorded 4,151 memory-max
events; the compiler container peaked at 2,281,254,912 bytes with no max events.
Memory pressure is recorded; this is not a pressure-free claim.

All 172 offline tests and the evidence reconciliation pass after the fix.
Local validation used 34,632 KiB peak RSS, 0.59 CPU seconds and zero swap under
128 MiB / 10% CPU / 32-task limits. An initial verifier path mistake for the
retained rmcp source was corrected, with its failed check retained. No local
compiler, image pull, VM or GPU workload ran. The corrected native workflow
must still pass and produce an installable prefix; existing compositor outputs
and authenticated inputs remain unchanged.
