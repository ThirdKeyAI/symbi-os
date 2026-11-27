# Passing native fresh-consent build and runtime

[Run 45785837716](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45785837716)
passed at `1e93208bb190e7d041aab11bdcf063cad5028a30`, as did its
[workspace/formal checks](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45785853331).
The prior staging-permission failure remains recorded under `45784560037/`.
The dedicated read-only prefix mount allowed the existing UID-10001 compiler
to copy the retained toolkit without changing staging permissions.

The actual new formatter regression failed against the original implementation
with the required persistence message. After applying the exact behavior patch,
the portal/picker compiled and the complete upstream picker-data CTest case
passed. Its added expectations cover fresh output/window/workspace/region
formatting for both requested persistence values, plus empty/invalid selections.
This is one native CTest executable, not separate end-to-end capture tests.
Both installed picker CLI controls returned exit 2 and the exact refusal before
opening a display. Compiler loader/readelf checks and actual version passed.

The toolkit and compositor were not rebuilt. The output has 49 files/links:
46 unchanged original entries, two rebuilt executables and the exact additional
Apache-2.0 license with the existing ThirdKey copyright. Source, test and
implementation patch hashes, actual Git changed-file scopes, test-report hashes,
all 173 Fedora build-package signatures and helper identities reconcile.

A separate original-base runtime container verified the one iniparser RPM,
rejected real missing-key and modified-package controls, and preserved all
2,178 original packages and 40 crypto configuration entries. It added only
iniparser, yielding 2,179 packages. All three native loader probes and the real
portal version passed as UID/GID 10001, no supplementary groups, zero inherited,
permitted/effective/ambient capabilities, and no new privileges. Both temporary
containers were removed and observed absent.

All 477 original files (598,811 expanded bytes) are retained unchanged, with
`evidence-files.json`, original artifact metadata and independent reconciliation.
The 234,311-byte evidence ZIP has SHA-256
`c6f42144e332fb4c3a3c24337412f8c66d94ed26e0c2a1d75af39538bcc4f74c`.
The 1,461,777-byte compiled artifact remains hosted. Its metadata and exact
manifest are pinned separately in `image/portal/consent-prefix.lock.json`;
a future consumer must verify the complete archive before extraction and must
not apply the original toolkit-only manifest assumptions to this new output.
The original parent lock remains unchanged.

The 8 GiB/two-CPU/no-swap host recorded a peak of 8,605,421,568 bytes and
17,961 memory-max events. The 6 GiB/two-CPU compiler guest peaked at
1,848,508,416 bytes; the 2 GiB/one-CPU runtime guest peaked at 194,068,480 bytes.
Both guests recorded zero memory-max events. All limits remained unchanged,
and all three groups recorded zero OOM/kill events. Independent local
reconciliation used 21,696 KiB RSS, 0.05 CPU seconds and no swap under
128 MiB / 10%-CPU limits; no local native artifact or compiler was used.

This establishes native regression, build, reuse and additive runtime behavior.
It does not establish full frontend/backend D-Bus interaction, a visible picker,
physical-input provenance, capture boundaries, session cancellation/restarts,
booted product integration or a signed release. Existing models do not certify
those implementation properties. Applicable model/fault checks and human TCB
review remain required. All consent/OS/product-installation flags stay false.
