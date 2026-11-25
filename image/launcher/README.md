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
