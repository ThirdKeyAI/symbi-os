# Fresh screen-sharing consent

Symbi OS requires a new selection for each screen-sharing session. The pinned
upstream portal intentionally supports remembered selections: it accepts
`restore_data`, can bypass the picker when that data still identifies a source,
and can return persistence mode 2 with new restore data. The current
`allow_token_by_default=false` setting only changes the initial checkbox state.
This is a mismatch with the OS requirement, not a claim that upstream promises
to prohibit persistence.

The [backend ScreenCast protocol](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.ScreenCast.html)
allows lowering the requested persistence mode. An omitted result inherits the
request's mode, so this patch explicitly returns `persist_mode=0` and never
returns restore data.

## Prepared change

`consent-inputs.json` binds the existing portal revision, signed RPM build lock
and retained portal/toolkit prefix. Fourteen upstream source files have exact
Git object IDs, byte counts and SHA-256 hashes. The original BSD-3-Clause license
is retained. The downstream patch uses the repository's Apache-2.0 license and
its unchanged `Copyright 2024-2026 Jascha Wanger / ThirdKey AI` notice; the exact
license is added under `share/licenses/symbi-os-portal-patch/LICENSE`.

The production patch changes eight files:

- Ignore `restore_data` and `persist_mode` inputs without decoding their payloads,
  and always invoke the picker when selecting sources.
- Remove restore-data construction and stored persistence fields; explicitly
  return zero persistence from a successful Start response.
- Invoke only `/usr/lib/symbi/portal/bin/hyprland-share-picker`, with no configurable
  command or PATH lookup. Existing configuration keys remain accepted for
  compatibility but have no effect on this choice or persistence.
- Reject remembered and unknown picker output flags.
- Remove the remember checkbox and its backing fields; explain that permission
  applies only to the current sharing session.
- Refuse picker command-line options before display initialization, including
  the old `--allow-token` option. The formatter cannot emit a persistence flag,
  even when a caller requests one.

No session class, agent grant, physical-input provenance or trustd authority is
implemented by this patch. In particular, it does not claim that synthetic
input cannot operate an ordinary desktop picker. Trusted-path work remains
Phase 2.

## Native build and test procedure

The test patch was written before the implementation patch. The hosted driver
first applies only the test patch to the exact upstream source, builds the real
formatter test and requires it to fail with the persistence regression message.
It then applies the production patch, checking Git's actual changed-file list,
dry run and every reviewed file's expected resulting hash for both stages.

Only the portal and picker are rebuilt. The retained compositor stays read-only;
the toolkit is copied from its authenticated prefix and every original file
except the two rebuilt executables must remain identical. The only new installed
file is the exact downstream license. CMake downloads are disabled and the
compiler container has no network. Source compilation and tests run as UID
10001 with a single compiler job.

The full upstream picker-data test, including the new output/window/workspace/
region and empty/invalid selection expectations, must pass without missing,
failed or skipped cases. Installed picker binaries must reject both the old
persistence flag and an unknown option with the expected exit status and error,
before trying to open a display. All three loaders, readelf checks and the actual
portal version must pass. A separate disposable original-base container then
repeats the authenticated additive iniparser install and unprivileged runtime
checks. Existing base packages and crypto configuration must remain unchanged.

The controller has an 8 GiB/two-CPU/no-swap/256-task cap after checking headroom.
The build guest has 6 GiB/two CPUs/no swap/128 tasks; the later runtime guest has
2 GiB/one CPU/no swap/128 tasks. All temporary containers must be removed and
observed absent, with unchanged limits and no OOM/kill events. Download tokens
are read-only and never enter these processes. Compiled output is retained
before runtime probing to avoid unnecessary recompilation after a later failure.

The prepared implementation passes 191 small offline checks, exact source and
patch binding checks, real Git dry runs, syntax/ShellCheck and local-execution
refusals. Native results are pending. Local validation used 35,976 KiB peak RSS,
0.69 CPU seconds and no swap under 128 MiB / 10%-CPU limits.

## Required acceptance before qualification

Native formatter and CLI checks do not prove the complete portal interaction.
The following remain required on a booted desktop, using the installed frontend
and backend rather than a substitute implementation:

- Fresh and repeated sessions for the same application, including valid v2/v3
  restore data for existing outputs/windows/workspaces and each requested
  persistence mode, must present a fresh picker. Malformed restore payloads must
  not crash or restore a selection.
- Successful Start results must have persistence zero and no restore data.
  Cancellation, request closure, invalid selection and Start without successful
  source selection must expose no stream or retained permission.
- Monitor, window, workspace and region selection must preserve the intended
  capture boundary. Closed/disappearing sources and repeated/restarted sessions
  must not reuse an earlier selection.
- Enabling the old default-persistence setting, supplying a custom picker and
  putting a replacement picker on PATH must not restore persistence or execute
  the replacement. Existing frontend permission-store entries must not bypass
  the new selection.
- D-Bus activation, service restart, picker cancellation and capture teardown
  must behave correctly with the complete installed desktop and its actual
  portal preference configuration.
- Compositor/TCB review, applicable model/fault checks and human review must be
  completed before merge. Existing design models alone do not certify this
  implementation or the physical-input boundary.

All consent, OS and product-installation qualification flags remain false.
Current development images are unchanged; this procedure produces a separate
development prefix for subsequent integration and testing.
