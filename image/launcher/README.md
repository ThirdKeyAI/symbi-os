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
The native-provider constructor acceptance driver is under preparation; no
provider-refusal result or product qualification is claimed yet.


## Hosted source build and provider acceptance

The prepared `elephant-build.yml` workflow authenticates the selected base and
installs only the four previously signed Go compiler RPMs into a disposable
stage. `GOTOOLCHAIN=local`, one Go job and one Go scheduler thread prevent
implicit compiler downloads or parallel builds. Module acquisition uses the
fixed upstream go.mod/go.sum and the Go checksum service; compilation has no
network and requires both upstream files to remain byte-identical. Source and
module/dependency review remain release gates; no blanket audit is asserted.

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
Only this authenticated hosted workflow may invoke the driver.

The parent is capped at4 GiB/two CPUs/no swap; compiler stages at3 GiB/two CPUs,
with one Go job. This is development work: compilation, provider controls and
actual launcher/session integration have not yet passed. Product installation,
Walker validation, browser/portal controls and OS qualification remain open.
