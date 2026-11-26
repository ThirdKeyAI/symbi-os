# Hosted Walker source and CLI acceptance

The separate workflow builds the exact Walker v2.17.2 revision in
`../launcher/walker-source.json`. Both its compiler and runtime RPM artifacts
were already reviewed and locked; this job rechecks their bytes, full Fedora
signatures and exact identities before offline installation. All original base
package identities must remain unchanged. The 91 compiler/native packages stay
in a disposable compiler stage. A separate runtime stage starts from the
publisher-authenticated secureblue base and adds only the one reviewed
gtk4-layer-shell runtime RPM.

The source has 284 locked packages: Walker and 283 checksummed crates.io
dependencies. Source manifest, lockfile and build-script hashes must match
before and after use. Alternative registries, Git/local dependencies, source
Cargo configuration, dependency replacement and duplicate lock entries are
refused. `/usr/bin/cargo`, `/usr/bin/rustc` and `/usr/bin/protoc` come from the
authenticated RPMs; Rust/Cargo must report stable 1.100.0 for the exact host,
and protoc must report 33.5. The repository's `stable` rustup file does not
select a compiler because the signed system tools are invoked directly.

Acquisition uses a fresh Cargo home, the fixed crates.io registry and the
unchanged checksummed lock. Compilation is offline/frozen, with one job,
incremental compilation disabled, one codegen unit and no debug symbols.
The complete upstream workspace/all-target test suite runs serially. Compiled
bytes and their source/compiler bindings are retained before later acceptance
so a test-fixture failure does not require an unchanged source rebuild.

Actual runtime controls resolve the libraries and run version, help, rejected
unknown option and repeated-version cases as UID 10001 with no network, a
read-only root and no capabilities. These establish CLI compatibility only.
They do not qualify the graphical application, Elephant integration, input,
desktop menu behavior, dependency audits or the final OS. Source/dependency
review remains a release gate; no blanket Cargo audit or exemption is added.

The hosted parent has 4 GiB/two CPUs/no swap and a 115-minute deadline. Package
installation has 2 GiB/one CPU; source acquisition and compilation have 3 GiB/two
CPUs; CLI checks have 512 MiB/one CPU. Stages run serially and every named
container is removed and checked absent, including failures. Partial public
logs/counters are retained. The workflow has read-only repository/artifact
permissions, no signing environment and no publication authority.

Local tests use only small source fixtures and real Python child processes to
check refusal and probe behavior. The local entry points reject compilation;
no local Rust/GTK build, VM or large artifact download is needed. Path filters
start this workflow only for Walker inputs and shared build dependencies, and
skip duplicate internal PR jobs before runner allocation.


## Exact RPM epoch comparison

[Walker run 45739493292](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45739493292)
authenticated both archives, the base and pinned source. The first 14 package
signature/payload checks passed, then a mistaken zero-epoch assumption rejected
`gpgmepp-devel-1:2.0.0-2.fc45.x86_64`. That exact epoch is already present in the
signed discovery manifest and current lock. No package transaction, source
compilation or CLI acceptance occurred. The compiler container was removed and
verified absent. The 2 GiB guest peaked at 59,740,160 bytes with no limit/OOM
events; the parent had memory pressure but no OOM/kill. Raw failure evidence is
retained under `P0-03-walker-toolchain/45739493292/`.

The identity comparison now includes the recorded nonzero epoch when matching
NEVRA. Tests reproduced the four already-pinned nonzero epochs (gpgmepp, libpng,
OpenSSL and xz), then exercise changed name/epoch/version/release/architecture and
missing/noncanonical epochs. Every changed identity still fails. No package,
hash, signature, source pin, sandbox or resource limit changes. Actual installation,
compiler identity, source build and runtime acceptance remain hosted gates.


## Walker toolchain installed; commit output separated

[Run 45740248043](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45740248043)
verified all 91 RPM signatures, full identities and hashes, then installed them
offline while preserving all 2,178 original package identities. Exact stable
Rust/Cargo 1.100.0, protoc 33.5 and all required native versions passed. The
2 GiB installation guest peaked at 1,000,763,392 bytes without limit/OOM events.
Full package, compiler and inventory evidence is retained under
`P0-03-walker-toolchain/45740248043/`.

Podman committed that disposable compiler successfully, but its progress output
was combined with stdout, making the wrapper's exact image-ID check fail.
Source compilation was not reached. The container was removed and verified
absent. The wrapper now retains stdout and stderr separately, accepts exactly
one complete image ID only from successful stdout, and preserves progress logs.
Two real-process regressions reproduce the mixed-stream failure and reject
ambiguous stdout or a nonzero exit even when it prints a plausible ID. No input,
identity, signature or resource gate changes; the next hosted run must still
complete acquisition, offline compilation, upstream tests and runtime controls.
