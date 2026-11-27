# Retained portal runtime passed

[Hosted run 45777761262](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45777761262)
passed at OS source `ddb34fce5ae13d6e521f719e145fb36cafa59732`.
It reused the exact compiled portal/toolkit and compositor prefixes without
recompiling any source. The current [workspace/formal checks](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45777774350)
also passed.

The disposable, network-isolated authenticated generic base accepted only
`iniparser-4.2.6-5.fc45.x86_64` (26,470 bytes, MIT, full Fedora 45 signing
fingerprint `4F50A6114CD5C6976A7F1179655A4B02F577861E`). Its exact package
hash and identity match the earlier 173-RPM build lock. Actual missing-key and
changed-package signature checks failed as required. The transaction preserved
all 2,178 original packages and added exactly this one package, for 2,179 total.
All 40 original crypto configuration entries remained identical.

All three dynamic-loader checks passed: the toolkit library, share picker and
portal executable. The portal returned `xdg-desktop-portal-hyprland v1.5.0`.
Every native probe used UID/GID 10001, no supplementary groups, zero effective,
permitted, inheritable and ambient capabilities, and no new privileges. Both
native prefixes were mounted read-only. The temporary container was removed
and independently observed absent.

This closes the observed runtime-library gap on this exact generic base and
these exact retained binaries. It installs nothing into the existing product
images or local workstation. Portal activation, physical selection, cancellation,
capture isolation, fresh consent and real Atomic desktop acceptance remain open.
All OS, consent and product-installation qualification flags remain false.

`artifact-metadata.json` binds the original 74,296-byte archive. All 53 original
files (262,281 expanded bytes) are indexed in `evidence-files.json`. Independent
reconciliation checks original hashes, source/input/prefix bindings, publisher
signature subject, complete RPM signature/identity and negative controls,
before/after package and crypto records, real unprivileged identity and loader
outputs, version, cleanup and resource counters.

The parent had a 4 GiB/two-CPU/no-swap/256-task limit and reported a
4,360,118,272-byte peak with 41,706 memory-max events. The 2 GiB/one-CPU/no-swap/
128-task guest peaked at 350,724,096 bytes with no memory-max events. Both
recorded zero OOM and OOM-kill events. Memory pressure is reported explicitly.
Local reconciliation used 21,244 KiB peak RSS, 0.04 CPU seconds and no swap
under the 128 MiB / 10%-CPU cap. No local compiler, large download, VM or GPU
workload ran. The already passing 183-test suite covers the unchanged code;
this follow-up adds evidence and documentation only.
