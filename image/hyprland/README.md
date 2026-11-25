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

## Verified RPM inputs and offline compositor build

[Run 45695030159](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45695030159)
verified all 162 Fedora RPM candidates (150,552,075 bytes), rejected an RPM with
no trusted key and a modified payload, and confirmed the installed RPM database
was unchanged. Exact NEVRAs, hashes, full signing fingerprints, original evidence
hashes and cryptographic logs are retained under
`docs/security/reports/P0-03-fedora-packages/45695030159/`. The guest peaked at 529,846,272 bytes with
no memory-limit events. The outer pull/discovery unit recorded memory pressure
but no OOM or OOM kill; its raw counters are retained.

`image/hyprland/build-rpms.lock.json` binds that immutable hosted artifact and
every package. These are disposable build-stage inputs: the six proposed Mesa
downgrades are not product installation inputs. The new hosted build checks the
bundle before extraction, re-verifies RPM signatures, installs offline in a
private container, and compiles exact source revisions as an unprivileged user.
The product base is not modified. Private Hyprland libraries use a dedicated
prefix and RPATH. Glaze is preinstalled from its pin, FetchContent is disconnected,
Tracy and hyprpm are disabled, and compilation uses one job without debug symbols.

The parent hosted unit has 8 GiB/two CPUs/zero swap and a 130-minute deadline;
the compiler container has 6 GiB/two CPUs and the separate native-loading probe
has 2 GiB/one CPU. Both containers have no network. The workflow has read-only
repository/artifact access and no release authority. Seven archive-validation
regressions cover changed packages, traversal/extra/missing/duplicate entries,
symlinks, signature requirements and real negative-control evidence. Local
compilation and large artifact downloads remain disabled.

Dependency compilation has run, but the compositor configure step failed and
the constructor probe has not run. Even a passing
result covers this disposable development stage only; compatibility against the
selected secureblue runtime libraries, packaged Fedora boot, signing, rollback
and dependency review remain required. The development artifact must not be
copied into a release image without those checks.

The second hosted attempt (45698096912) installed the previously verified RPMs
offline and compiled all eight prerequisite projects. Hyprland then stopped at
hyprctl configuration because hyprwire and readline were absent. The source set
now adds the exact hyprwire revision from Hyprland's own lockfile and builds it
after hyprutils; its libffi dependency and hyprctl's readline provider are in the
RPM requirements. Source and license evidence are retained. The old RPM artifact
is deliberately not relabeled as satisfying these additions. Compilation now
refuses stale requirements before downloading that large bundle; the package
discovery workflow must produce a reviewed replacement lock first.

## Expanded signed RPM set accepted for the build stage

Run 45702843932 successfully resolved the expanded requirements. All 165 RPMs
passed full-fingerprint signature and payload checks against the pinned Fedora
45 key, and the actual missing-key/tampered-payload controls both failed as
required. Reinspection of every retained signature log agrees with the manifest.
Installed RPM state remained unchanged. The prior 162 package records are
identical; the three additions are readline-devel 8.3-6.fc45, ncurses-devel and
ncurses-c++-libs 6.6-3.fc45. libffi-devel was already in the verified set.

The immutable 151,655,394-byte hosted RPM ZIP and its 165 package records now
replace the stale lock. The manifest hash is
`9556ccf3d57f745b9de520d24d4545619a8cc3be474e93b76e96c6969e25c306`;
the ZIP hash is
`b24ccbcc952c24102cf5dea0fcf5f912145d91b2f99a692a754d9474db65859a`.
Only the 166,765-byte evidence artifact was downloaded locally. Retained evidence
is under `P0-03-fedora-packages/45702843932/`. The discovery guest peaked at
526,548,992 bytes with no memory-limit events; its parent had memory pressure
but no OOM or OOM kill. These remain build-stage inputs, including the unchanged
six Mesa downgrade candidates; product installation and dependency approval
remain separate. The offline compositor build can now resume against the current
requirements and exact hyprwire source pin.
