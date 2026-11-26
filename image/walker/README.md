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
