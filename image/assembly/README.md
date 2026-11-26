# Retained inputs for desktop assembly

This stage reuses the reviewed BlueBuild and Symbiont development executables.
It compiles no native source and has no signing or publication authority.
An isolated compatibility stage adds one reviewed signed library to the base;
this disposable container is not an assembled or booted OS image. The final desktop/image acceptance gates remain open.

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
observed, not inferred. The additive compatibility RPM below addresses the
observed loader failure without changing source or features. Run only through `scripts/check-assembly-inputs.sh` on hosted CI;
local large downloads, compilation and VM work stay disabled.

## OpenSSL compatibility input and offline acceptance

The original-base loader/CLI run 45747059051 failed: `symbi` needs
`libssl.so.3` and `libcrypto.so.3`, whereas the base provides OpenSSL 4. Signed
discovery 45748551523 passed for exactly `openssl3-libs-1:3.5.9-1.fc45.x86_64`,
including real missing-key and tampered-package rejection and unchanged base
package inventories. The archive/manifest/RPM hashes are pinned in
`runtime-rpms.lock.json`; signature and identity evidence is retained under
`docs/security/reports/P0-03-runtime-packages/45748551523`.

The acceptance workflow verifies those RPM bytes and signatures again in an
offline installation guest capped at 2 GiB/one CPU/no swap/128 tasks. Its writes are
limited to the disposable image and private output. It requires an
additive package transaction and unchanged original crypto-configuration hashes,
retains the compatibility package's configuration for review, and commits the
result only into private runner storage. The same six actual loader/CLI checks
then run as UID 10001 with the existing read-only/networkless/capability-free
boundaries. Installer and probe containers are removed and checked absent, also
on failure. Runtime bytes, source, features, base, signature checks and CLI
expectations are unchanged. No runtime executable is installed into the stage.

Configuration preservation and CLI loading do not prove TLS policy equivalence
or Fedora isolation. Crypto-policy behavior and the full final-image acceptance
gates remain separate work; no product or crypto-policy qualification is claimed.

## Passed additive runtime compatibility

[Run 45749688344](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45749688344)
at `669de4383347a17c86d4dc60060a1f238727df34` passed all 17 retained builder
CLI cases and all six real runtime loader/CLI controls. Installation adds only
`openssl3-libs-1:3.5.9-1.fc45.x86_64`; all 2,178 original package identities,
32 existing crypto configuration files/links and eight absent configuration slots
are unchanged. The original OpenSSL 4 package remains installed. All nine
installer/probe containers were removed and checked absent.

The original `openssl3.cnf` includes Fedora's system crypto-policy file. Those
bytes are retained verbatim; inclusion and preservation do not establish actual
TLS behavior. Both `crypto_policy_qualified` and `os_qualified` remain false.
The installer peaked at 338,669,568 bytes under its 2 GiB limit and the builder
at 241,360,896 bytes under 512 MiB, with no limit/OOM events. The 4 GiB parent
recorded memory pressure but no OOM or kill; its raw counters are retained.
Evidence is in `docs/security/reports/P0-03-assembly-inputs/45749688344/`.

The Walker reader at `image/launcher/walker_binary_inputs.py` prepares reuse of
its already-passed artifact for desktop assembly. It validates current source,
RPM-lock, manifest, binary and original-license bindings, bounds extraction and
refuses unsafe entries or output paths. Its five fixture tests execute no native
binary. Actual image installation, desktop operation and Fedora containment are
still separate acceptance work.
