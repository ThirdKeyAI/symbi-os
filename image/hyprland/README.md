# Maintained Hyprland on secureblue

P0-03 keeps the signed secureblue base and packages Hyprland at
`11cbc6c577b84ffb1edf4df3fc5b6128c3ae6947` (v0.57.2). The sources in
`candidate-inputs.json` come from that release's own lockfile. They are candidate
build inputs, not qualified RPMs. No local compositor build has run.

The hosted `Fedora base inventory` workflow authenticates Cosign, verifies the
exact base signature and repository identity, then pulls only that digest.
A read-only container without networking records installed RPM versions, public
RPM key files and repository configuration from the normal, bootc and
secureblue backup locations. An empty repository/key discovery fails and retains
partial output for diagnosis. RPM-owned DNF5 paths are also inspected. The Fedora
45 key selected in `fedora-package-trust.json` matches the authenticated image
and Fedora's published fingerprint; no RPM signature result is claimed by that
key inspection. It installs nothing. The outer
hosted unit has 2 GiB RAM, one CPU, zero swap and a 30-minute deadline; the
inventory container has 512 MiB, half a CPU and no swap. It has no host mounts,
release secrets or publishing permission. Local invocation is refused.

Use the retained inventory to select exact signed build-package inputs before
compilation. Provide the pinned Glaze source before CMake configuration and
disable FetchContent network fallback. The selected source requires CMake 3.30,
C++26, Lua 5.5 and newer Hyprland libraries than the older Fedora packages.
Version requirements and build-system source were inspected; compiler and RPM
compatibility still need execution on Fedora.

## Native-loading policy and acceptance

The downstream patch refuses both public and internal native-plugin entry
points before `dlopen`. A rejected plugin's constructor must never execute.
It also removes Lua's C-module searchers and replaces `package.loadlib` before
configuration runs, while retaining ordinary Lua modules. Removing `hyprpm`
alone would leave these loading paths available.

The patch applies exactly to the source blobs recorded in `patch-inputs.json`.
It has not compiled or passed runtime acceptance. `tests/qualify_native_loading.py`
is the acceptance driver prepared before the patch: it builds a constructor
probe, proves the probe works with a separate loader, then starts a private
headless compositor and checks Lua and IPC rejection before and after reload.
Its test config explicitly permits plugins so a permission denial cannot mask
a working native loader. Existing desktops are never selected. Run the driver
as a disposable non-root Fedora user with at most 2 GiB, one CPU and zero swap.

A passing headless result will cover these entry points only. Lua configuration
is still trusted user code, with subprocess facilities; this is not a Lua
sandbox. Desktop configuration integrity, trusted surfaces and input provenance
remain P2 work. Real image boot, plugin refusal in the packaged deployment,
browser/keyring behavior, update signatures and rollback remain P0-03 gates.

Invariants touched: INV-12 (reviewed image inputs); no new authorization gate,
journal event or Cargo dependency. The compositor patch remains in the draft
review until compilation, acceptance evidence and required review are complete.

## Resolve Fedora build inputs

`Fedora package input discovery` uses the verified base and the committed Fedora
45 package key. `package-repository-inputs.json` binds the observed repository
bytes and records the narrow configuration changes; only the release and update
binary repositories are selected. `build-requirements.json` lists providers from
the pinned upstream CMake requirements. These names are candidates, not a lock.

The hosted job downloads without installing, verifies signatures and payload
digests in an isolated one-key RPM keyring, exercises missing-key and tampered-RPM
controls, and retains a manifest plus RPM artifacts. It also verifies installed
RPMs did not change. The source base, input hashes and resource counters are kept
with the evidence. Use a reviewed exact manifest for the later offline build;
never rerun floating package resolution implicitly during a release build.

No package or compositor is qualified by the offline parser tests. The discovery
job has no release secrets or registry writes, and never executes locally.
