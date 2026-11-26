# Launcher input preparation

Walker v2.17.2 and Elephant v2.22.1 are candidates for the required application
launcher. `candidates.json` pins their observed source revisions and three release
archives: Walker, Elephant and its desktopapplications provider. The 21 MB of
archives matched the SHA-256 values published by GitHub. Static ELF inspection
ran under a 128 MiB/10%-CPU local cap (32,948 KiB peak RSS, 0.32 CPU seconds);
the programs were neither executed nor installed. Binary/source correspondence,
upstream artifact signatures and release approval are not established by this
inspection. Upstream licence texts are retained without modification.

The Walker ELF requires `libgtk4-layer-shell.so.0`, whose provider is absent from
the selected base's observed package inventory. `runtime-requirements.json`
requests that SONAME through a separate hosted discovery profile. It preserves
the existing compositor requirements/lock, pinned Fedora key, selected repository
configuration, full signature/payload verification and real negative controls.
No RPM is installed. The same 3 GiB parent / 2 GiB guest, two/one CPU and no-swap
limits apply. Discovery results must be inspected and pinned before use.

The selected Elephant source can load providers from user configuration paths,
`ELEPHANT_PROVIDER_DIR`, and a development directory. Shipping the application
launcher therefore also requires restricted normal launch paths, only the
selected built-in provider, and actual extension-refusal tests. No optional menu
or remote provider is selected here. Runtime testing on the final base, release
input authentication/provenance and dependency/licence review remain open.

`elephant-build-requirements.json` is a separate signed-Fedora compiler discovery
profile for the exact Elephant source and go.mod/go.sum hashes in
`elephant-source.json`. Go must satisfy the source's1.27.1 minimum; later builds
must disable automatic toolchain downloads and preserve the upstream lockfile.
GCC/glibc development inputs support the actual executable/provider CGO builds.
Discovery itself neither installs the compiler nor executes launcher artifacts.
The native-provider constructor acceptance driver is prepared; no
provider-refusal result or product qualification is claimed yet.


## Hosted source build and provider acceptance

The prepared `elephant-build.yml` workflow authenticates the selected base and
installs only the four previously signed Go compiler RPMs into a disposable
stage. `GOTOOLCHAIN=local`, one Go job and one Go scheduler thread prevent
implicit compiler downloads or parallel builds. Module acquisition uses the
fixed upstream go.mod/go.sum and the Go checksum service; compilation has no
network and requires both upstream files to remain byte-identical. Source and
module/dependency review remain release gates; no blanket audit is asserted.

The compiler identity gate pins Fedora's observed `go1.27.4-X:nodwarf5` and
`GOEXPERIMENT=nodwarf5`, alongside linux/amd64 and CGO enabled. These exact values
were retained after installing the authenticated four-RPM bundle in hosted run
45727353652. The initially assumed undecorated version was refused before any
source compilation. No version prefix matching or arbitrary suffix is accepted;
the RPM hashes, signatures and unchanged-base checks remain required.

The source build emits unmodified and patched executables, the actual packaged
desktopapplications provider and a Go constructor marker using the same compiler
and flags. Compiled bytes are retained before later acceptance. The downstream
patch admits only `/usr/lib/symbi/elephant/providers/desktopapplications.so`,
requiring a regular root-owned file under root-owned, non-writable, nonsymlinked
parents. Environment, user/system/explicit config and development provider
locations cannot introduce native menu extensions. Other normal application
behavior is not qualified by this patch.

The acceptance driver was prepared before patch adoption. Its17 real-loader
cases require unmodified-loader constructors to execute, then reject override,
extra/nested, linked, writable and user-owned provider fixtures while retaining
the real application provider where appropriate. Each invocation has a fresh
read-only fixture, nonce-bound marker and isolated256 MiB/one-CPU/no-network
container running as UID10001. Output is capped while streaming, timeout kills
the client, and explicit container removal plus absence checks precede success.
Only authenticated hosted build or retained-binary workflows may invoke the driver.

The parent is capped at4 GiB/two CPUs/no swap; compiler stages at3 GiB/two CPUs,
with one Go job. Source compilation has passed; the full upstream suite, provider
controls and actual launcher/session integration remain incomplete. Product installation,
Walker validation, browser/portal controls and OS qualification remain open.

## Walker source-build inputs

`walker-source.json` pins v2.17.2 by full source revision and the Cargo manifest,
lockfile and build-script hashes. The lock contains 284 package entries: 283 registry dependencies and Walker itself.
Checksummed crate metadata establishes Rust 1.92, GTK 4.12/GIO 2.80 features,
gtk4-layer-shell 1.0 and `protoc` from PATH as input requirements. The source's
build script uses protobuf-codegen's default system compiler; it does not select
the vendored protoc executable. This is metadata review, not a dependency audit.

`walker-packages.yml` resolves the separate `walker-build` profile in the signed
base, downloads candidates, verifies their complete RPM signatures/payloads and
exercises missing-key/tampered-byte refusals without installing any package.
It uses the existing 3 GiB/two-CPU/no-swap hosted parent and 2 GiB/one-CPU guest.
The actual compiler versions and native dependencies must be reviewed and locked
after discovery, then compiled offline with the unchanged upstream Cargo.lock.
Existing compositor, Elephant and launcher runtime locks are unchanged. No local
Rust/GTK build, source-to-binary correspondence or Walker acceptance is claimed.

Hosted Walker discovery45729431180 passed. `walker-build-rpms.lock.json` records
91 signed candidate packages, including Rust/Cargo1.100.0, GTK development
headers and protoc33.5. None shares a package name with the installed base.
Discovery preserved the installed inventory and rejected a missing key and
tampered payload. The bundle stays on hosted storage; installation, source
compilation and runtime acceptance have not occurred.

Elephant run45728665797 compiled all four planned binaries with the authenticated
Fedora compiler, then failed upstream `TestRunOCR` because its result was empty.
`development-binaries.lock.json` binds the retained bytes for later independent
acceptance without recompilation. This does not turn the failed suite into a
pass: native-provider controls have not run and upstream-test qualification
remains incomplete. The source's OCR helper invokes `tesseract` and suppresses
execution errors; the next test step must establish the actual tool failure.

## Independent provider acceptance without recompilation

`elephant-runtime.yml` downloads the exact retained binary artifact only on a
hosted runner. Before execution, the archive byte count/hash, manifest bytes and
all four binary hashes must match the reviewed lock. The loader refuses duplicate,
unexpected, linked, special, encrypted and oversized members and requires a fresh
destination. Current base, source/module locks, compiler RPM lock, patch and marker
source must still match the retained build. The marker source was checked unchanged
from build head 525e390 before its hash was added to the reuse lock.

The same 17 actual provider cases run against the original publisher-authenticated
base, without installing compiler packages. A separate UID 10001 diagnostic records
the real `convert`/`tesseract` paths, outputs and errors for the pinned OCR example.
Both probes use read-only, no-network containers with all capabilities dropped,
256 MiB/one CPU/no swap and explicit removal/absence checks. The hosted parent is
limited to 4 GiB/two CPUs/no swap and 25 minutes. No local executable or large
artifact download is used. A provider pass cannot clear the failed upstream suite:
the reuse report explicitly retains `upstream_tests_passed: false` and
`os_qualified: false`. Actual results remain pending until the hosted run finishes.

The first independent run (45732324253) confirmed the missing `tesseract` CLI and
passed the three baseline constructor controls. Its first patched case refused
the external constructor but failed to list the real application provider. The
other thirteen cases were not reached. Because upstream `listproviders` discards
all loader logs, a separate five-second normal-startup diagnostic now retains
path ownership/modes and debug output under the same isolation limits. Acceptance
expectations remain unchanged. The actual source lock has 283 registry packages
plus Walker; the original discovery artifact's count wording is historical and
its authenticated bytes are retained unchanged.

Normal-startup logs from run45733459959 identify a Go plugin compatibility error:
`desktopapplications` was compiled before the patch changed `internal/providers`.
The next build must compile the real provider from the same patched source as
the patched launcher. That diagnostic later timed out; its missing final guest
report is not a pass. Cleanup was verified and raw output retained. Separately,
the source-bound compiler requirements now request the signed `tesseract` test
prerequisite. The old four-RPM lock must fail the current-requirements check until
new discovery is reviewed; no RPM is installed merely because it was requested.
