# Retained inputs for desktop assembly

This stage reuses the reviewed BlueBuild and Symbiont development executables.
It compiles no native source, builds no image, and has no signing or publication
authority. The final desktop/image acceptance gates remain open.

The runtime archive came from [workspace run 45702056794](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45702056794),
which built and tested `deddb9e997244d2289c217ad76b8fde0e9b0339b` both before and
after the six-file fixture patch proposed in upstream PR 24. Those changed files
are tests/documentation; no production Rust or Cargo input changed. Only the
final binary hashes were retained, so this does not claim a recorded
baseline/final binary hash comparison. The original result JSON is retained
verbatim here and hash-bound to the archive, binaries and current source pin.
Full original evidence is on the P0-05 card. Upstream test acceptance does not
establish Fedora compatibility, a source audit or an installed runtime.

`inputs.py` refuses stale source/build records, incomplete workspace acceptance,
changed archive or binary bytes, oversized members, links, duplicate names and
existing or symlinked output paths. It streams the two exact members and grants
execute permission only after both pass. Fixture tests execute neither binary.

The hosted workflow runs serially on Ubuntu 24.04. The retained BlueBuild CLI
runs unprivileged under 512 MiB/one CPU/zero swap/64 tasks, with all 17 existing
CLI cases and a fresh context for its embedded scripts. The runtime controller
authenticates the secureblue generic digest before pulling, then executes only
loader and CLI controls as UID 10001 in read-only, networkless, capability-free
containers. Each is capped at 512 MiB/one CPU/zero swap/64 tasks; the parent pull
unit is capped at 4 GiB/two CPUs/zero swap/256 tasks. Every probe has bounded
output and time, and its named container is removed and verified absent.

Both `ldd` results and real version/help/parser results are retained even when
dependencies fail. The selected base inventory contains OpenSSL 4; the retained
runtime was built on Ubuntu with default features. Compatibility must be
observed, not inferred. No compatibility RPM or feature change is introduced
by this check. Run only through `scripts/check-assembly-inputs.sh` on hosted CI;
local large downloads, compilation and VM work stay disabled.
