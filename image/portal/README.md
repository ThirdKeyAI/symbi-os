# Hyprland portal candidate inputs

The current images have GTK and wlroots portal backends but do not yet contain
the Hyprland backend. `source-inputs.json` selects the exact portal and toolkit
revisions from the already selected compositor's `flake.lock`. It also binds
the retained full compositor prefix, source/build inputs and native-loading
patch. Both upstream licenses are BSD-3-Clause; their original bytes are kept.

The `reviewed/` files are exact source snapshots used to review dependency and
build entry points. Every file has a SHA-256, byte length and Git blob ID.
`inputs.py` rejects changed sources, widened package requests, stale prefix
bindings, nonregular/escaping/oversized files and altered snapshot bytes before
hosted discovery. Git object identity and these checks are not source audits
or publisher-signature evidence. No release qualification is claimed.

Primary source selections:

- [Hyprland lockfile](https://github.com/hyprwm/Hyprland/blob/11cbc6c577b84ffb1edf4df3fc5b6128c3ae6947/flake.lock).
- [Portal build entry point](https://github.com/hyprwm/xdg-desktop-portal-hyprland/blob/85450448ea40a54ec4f10bd607e68019d8f5cc41/CMakeLists.txt).
- [Share-picker build entry point](https://github.com/hyprwm/xdg-desktop-portal-hyprland/blob/85450448ea40a54ec4f10bd607e68019d8f5cc41/hyprland-share-picker/CMakeLists.txt).
- [Toolkit build entry point](https://github.com/hyprwm/hyprtoolkit/blob/92646e15fb295285b10de626f2d9597216465f7b/CMakeLists.txt).

`build-requirements.json` preserves the compositor's reviewed requirement list
and adds five explicit pkg-config providers: PipeWire, SPA, sdbus-c++, iniparser
and abseil flat_hash_map. This is one signed build closure for the retained
prefix's public dependencies; it does not rebuild the ten existing compositor
source components. Candidate RPMs remain on the hosted runner.

`scripts/check-portal-packages.sh` refuses local execution. On a disposable
GitHub-hosted runner it uses the existing publisher-signature bootstrap and
Fedora RPM resolver. The base root stays read-only; full RPM signatures and
real missing-key/tamper controls must pass, installed packages must match before
and after, and the temporary container must be absent after cleanup. Evidence
and candidate RPMs are retained separately. The workflow has read-only repository
permission and no release environment, signing secrets or publishing rights.

Before the portal can enter a development image:

1. Retain and review the actual signed-RPM result, then pin the exact artifact.
2. Authenticate and reuse the existing full compositor development prefix.
3. Build only the pinned toolkit and portal offline, with upstream version
   constraints enforced and fallback downloads disabled; run applicable tests.
4. Verify exact installation, runtime library closure and original licenses on
   the selected base without replacing its original packages or crypto policy.
5. Qualify actual portal activation, physical selection, capture isolation,
   cancellation and repeated consent with no reusable restore token on a
   booted desktop. Packaging and command-line checks cannot prove these.


## Authenticated build inputs and native workflow

Discovery [45766212374](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45766212374)
passed; the 375 original evidence files and an independent reconciliation are
retained under `docs/security/reports/P0-03-portal-packages/45766212374/`.
The new lock binds 173 signed Fedora RPMs to their exact hosted artifact. It
preserves 161 earlier compositor records, reviews four development-package
updates and adds eight packages. The old compositor lock/prefix is unchanged.

`portal-build.yml` and `scripts/check-portal-build.sh` reuse that retained prefix
read-only and compile only hyprtoolkit and the Hyprland portal. Source Git
revisions and reviewed file bytes are checked before the offline build.
Required sdbus-c++/protocol providers must exist before CMake; dependency
fetches are disabled and the compiler container has no network. Signed build
RPMs are checked again before their disposable filesystem installation. Root
is dropped to UID 10001 before source scripts, compilation or tests run.

The parent has an 8 GiB/two-CPU/no-swap cap after checking available headroom;
the build container has 6 GiB/two CPUs/no swap, with one compiler job. Toolkit
unit and surfaceless renderer tests use its upstream Debug test configuration.
The separately built Release toolkit and Release portal are installed into
`/usr/lib/symbi/portal`; the portal's picker-data test runs via CTest. Failed,
empty, disabled or skipped XML results are refused. These tests do not prove
physical selection or desktop isolation, and Debug toolkit tests do not
certify the distinct Release library.

Build evidence and the compiled prefix are separate artifacts. The prefix is
retained before checking its dynamic loaders on the unchanged secureblue base,
so a missing runtime RPM can be addressed without rebuilding the compositor.
All qualification flags remain false. No release environment, signing secret,
publication right or local compilation is used. The first native run compiled both components and passed 93 native test cases,
then stopped before portal installation because the report wrapper expected a
CTest name without its class prefix. The exact-pair correction and raw results
are retained in [the first-build report](../../docs/security/reports/P0-03-portal-build/45770130727/README.md).
The corrected [native build](../../docs/security/reports/P0-03-portal-build/45773194827/README.md)
compiled and installed both components, passed all 93 native cases and the
three compiler-container loader checks, and retained the full prefix. Its first
unchanged-base loader check failed for `libiniparser.so.4`; the other two base
loaders did not run. The failed workflow remains failed.

## Retained runtime verification

`development-prefix.lock.json` binds the exact 48-file development prefix,
sources, tests, package closure and original notices. `prefix_input.py` refuses
altered archives, unsafe paths/links, hardlinks, special files, unexpected modes,
oversized inputs, stale bindings and incomplete native test accounting.

`portal-runtime.yml` reuses this prefix and the retained compositor without
recompilation. It selects only the authenticated iniparser runtime RPM from the
existing 173-package build artifact. The disposable writable base has no network;
real full-key signature, missing-key and tampered-package checks precede an
offline additive install. Original packages and all crypto configuration slots
must remain unchanged. Native loader/version probes drop to UID/GID 10001,
verify zero effective/permitted/inheritable/ambient capabilities and no new
privileges, and use read-only mounted prefixes.

The hosted controller has 4 GiB/two CPUs/no swap/256 tasks, and the runtime
container has 2 GiB/one CPU/no swap/128 tasks. The controller checks headroom,
limits, OOM counters and container removal/absence. Download credentials are
read-only and never enter the resource unit or container. The local wrappers
refuse execution; all 183 offline checks pass. Actual hosted runtime acceptance,
image integration, immutable fresh-consent behavior and booted portal acceptance
remain pending. No qualification flag is promoted by artifact retention.
