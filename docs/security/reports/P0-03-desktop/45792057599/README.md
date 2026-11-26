# Generic desktop with the patched portal — passed

[Hosted run 45792057599](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45792057599)
passed at `23a6c721092ad77c3af33c11cab230ecaaa54cff`. All 192 original small
evidence files (407,959 expanded bytes) are retained
and independently reconciled. Exact source, patched prefix, parent toolkit,
compositor, package and artifact bindings passed before image assembly. Native
components were reused; no compiler rebuild or local image/GPU workload ran.

The resulting image verifies **102 installed files/links**, all **six signed
runtime RPM identities**, **2,178 preserved original packages**, **2,184 final
packages**, and all **40 original crypto configuration slots**. It passes nine
dynamic-loader checks, four version/provider probes, both picker-option refusals,
portal activation/default checks and three valid/invalid/repeated-good Lua parser
controls. All **20 temporary containers** are removed and observed absent.
The same approved signature-policy bytes remain installed. Bootc lint passes
13 checks, skips one and retains the original kernel-symvers warning.

The portal artifact contributes eleven runtime/activation entries and three
original/downstream licenses. Vendor ScreenCast/Screenshot defaults select the
patched Hyprland backend and use fixed absolute activation commands; other
interfaces default to GTK. User preference overrides are still possible, and
this is not an immutable authorization boundary or an end-to-end dialog test.
The compiler headers and pkgconfig metadata are excluded.

All resource ceilings remain in force: 1 GiB/one CPU for preparation, 4 GiB/two
CPUs for the controller, 2 GiB/one CPU/128 tasks for the nested build, and
512 MiB/one CPU/64 tasks for sequential read-only installed-image probes, with
zero swap. Retained counters show memory pressure but no OOM, kill or group kill:

| Stage | Peak bytes | Memory-max events |
| --- | ---: | ---: |
| preparation | 1,073,741,824 | 2112 |
| controller | 4,311,535,616 | 39115 |
| build_tree | 2,147,483,648 | 1613 |
| installer | 367,988,736 | 0 |

The large OCI archive stays hosted; its exact ZIP and inner archive identities
are in `image/desktop-images.lock.json`. The new boot-input consumer must verify
the real ZIP before a later installer uses it; only tiny synthetic fixtures have
exercised that consumer so far. This result does not prove Atomic boot, graphical
input/rendering, full portal consent/capture/lifecycle, physical NVIDIA behavior,
TLS equivalence, containment, release-signature enforcement, update or rollback.
Applicable model/fault/source/dependency review and human TCB approval remain
open. No OS/signature/consent qualification flag is promoted.
