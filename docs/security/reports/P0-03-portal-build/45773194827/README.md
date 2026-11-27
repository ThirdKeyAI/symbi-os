# Native portal output retained; original-base runtime check failed

[Hosted run 45773194827](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45773194827)
used OS revision `6f719685d0eaaac0ff66378d9b117244e21a8283`. Both pinned
components compiled and installed into the private development prefix. All
91 Debug toolkit unit tests, one surfaceless renderer test and the Release
portal picker-data test passed. The separate Release toolkit is not certified
by the Debug test result. Three compiler-container loader/readelf probes and
the actual portal `--version` check passed.

The workflow then failed at its first unchanged-base loader check:
`libiniparser.so.4 => not found`. The other two base loader checks did not run.
The failure remains recorded. Compilation, native testing and prefix retention
passed; the original base alone cannot run these binaries. This is not desktop,
consent, OS or release qualification.

`artifact-metadata.json` records the original 194,948-byte evidence archive and
the separate 1,460,632-byte retained prefix artifact. `evidence-files.json`
indexes all 452 original evidence files (455,533 expanded bytes). The compiled
prefix has 48 files/links including original BSD-3-Clause notices; its archive
remains hosted. `image/portal/development-prefix.lock.json` binds that archive,
payload, manifest, exact sources, RPM lock, compositor prefix and test reports.
All qualification/product-installation flags remain false.

The independent reconciliation verifies all original file hashes, the base
signature subject, 173 complete Fedora RPM signatures, exact native XML counts
and hashes, version/loader output, original license identities, both container
removals/absence and unchanged resource limits. Host memory peaked at
8,601,284,608 bytes with 11,558 memory-max events; the compiler container peaked
at 2,298,773,504 bytes with no max events. Both recorded zero OOM or kill events.
This does not claim absence of memory pressure.

The separately prepared runtime workflow reuses the prefix and selects only
the already signed 26,470-byte `iniparser-4.2.6-5.fc45.x86_64` RPM from the
existing authenticated build artifact. It repeats real missing-key/tamper
controls, preserves every original package and crypto configuration entry,
and runs all three loaders plus `--version` as UID/GID 10001 with no capabilities
or new privileges. Its result is pending; no package was installed locally or
in the product image by this change.

All 183 offline image checks, evidence reconciliation, workflow syntax,
ShellCheck and local-execution refusals passed. Eleven new checks cover exact
archive reuse, malformed/escaping/tampered inputs, runtime package selection,
missing native results, privilege drops and OOM/resource failures. Tests were
written before their implementations. Logs are in `../../P0-03-portal-runtime-inputs/`.
Local validation used 36,080 KiB peak RSS, 0.69 CPU seconds and zero swap under
128 MiB / 10%-CPU / 32-task limits. No local native build, image download, VM
or GPU workload ran. Workspace/formal CI for the runtime change remains pending.
