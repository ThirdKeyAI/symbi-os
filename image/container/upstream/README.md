# Validate the upstream fixture draft

This directory carries a patch for validation, not a shipping runtime override.
The OS runtime pin remains unchanged. The six-file draft extends the upstream
filesystem/source/Git fixture drivers to select and record a gVisor runtime,
including adjacent executable hashes and Docker runtime registration checks.
It changes Python tests and documentation only. Runtime integration must use an
upstream reviewed commit after the required checks pass.

`Pinned runtime workspace` runs on a disposable GitHub-hosted Ubuntu runner.
It checks the clean full source revision and unchanged Cargo.lock, uses Rust
1.100.0, then runs all four required workspace gates. Only a passing baseline
allows the hash-bound patch to be applied. The same unit then runs the sixteen
focused Python tests and all four workspace gates on the patched source.
No feature, test or timeout is altered to pass validation. Upstream's ordinary
ignored integration tests are not claimed as executed by `cargo test`.

The compiler has one job and one test thread, no debug symbols or incremental
compilation, and a verified 8 GiB/two-CPU/zero-swap hosted cgroup. The unit has a
110-minute deadline. Timeouts end the run rather than starting another build;
failures retain evidence and prevent upstream commit. The workflow has read-only
repository permission, no release environment and no publishing authority.
Local invocation is refused. These limits do not change the local VM's limits.

The workflow retains commands, outcomes, source/lock/patch/binary hashes and
live resource counters. Checked development binaries may be reused in later
Fedora tests only after their artifact and provenance bindings are verified.
This is not a release build or a Fedora qualification report. It does not run
the actual Docker/gVisor lifecycle, managed-CLI or escape suites.

The earlier local baseline and focused failures are retained in P0-04. Its
scheduler test assumes two simultaneous default allocations of 512 MiB and one
CPU each, exceeding the small helper VM's capacity. Hosted validation supplies
that capacity without increasing workstation usage. The separate coordinator
failure remains an unresolved observation until the unchanged hosted tests run.


The first Rust 1.100 hosted attempt hit the 4 GiB build cgroup ceiling while
compiling the runtime crate. No workspace check completed and no fixture patch
was applied. Its logs and outer systemd OOM/peak counters are retained under
`docs/security/reports/P0-05-runtime-workspace/45685781772/`. The next attempt
requires at least 14 GiB total and 10 GiB currently available on the hosted VM
before starting the bounded 8 GiB compiler. One build/test thread, two CPUs,
zero swap, source/lock/compiler/profile pins and all four gates stay unchanged.
This is hosted build capacity, not a worker security-policy change. The local
helper VM remains off. Started checks are now saved before execution so an
abrupt termination cannot erase which gate was active.
