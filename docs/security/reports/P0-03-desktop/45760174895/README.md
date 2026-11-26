# NVIDIA development image assembly: passed

Hosted [run 45760174895](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45760174895)
at `1e171d1820b473141df4c300dd657056a171b98a` succeeded. It ran serially after
the generic build and used the separately pinned, publisher-authenticated
NVIDIA base. Native compiler outputs were reused by exact hashes.

The original 146 files (377,858 bytes) are retained unchanged, bound by
`retention.json` to the 116,899-byte GitHub evidence artifact. The 5.03 GB image
archive stays on GitHub. Its API metadata and small image manifest are retained;
a hosted consumer must verify the large archive before using it.

Independent reconciliation rechecked five Fedora RPM signatures and complete
identities. All 2,324 base packages are preserved. Exactly four packages are
added, producing 2,328 final packages: the NVIDIA base already contains the
identical pinned `openssl3-libs-1:3.5.9-1.fc45.x86_64`. All 40 original crypto
configuration slots are preserved.

All 88 installed files/links, including both public trust-policy files, match
the reviewed payload; the policy hashes also match fresh rendering from the
approved public inputs. Six dynamic-loader checks, three CLI/provider controls,
three Lua controls and all 13 temporary-container removals pass. The bootc
linter reports 13 passed, one skipped and one kernel-symvers warning, as in
the generic image. Memory-pressure events remain in the original counters;
there was no OOM or OOM kill.

The independent local reconciliation used 21,384 KiB peak RSS and 0.04 CPU
seconds under a 128 MiB / 10% CPU / zero-swap scope. It reconciles producer
evidence, without downloading or executing the OCI image locally.

This does not qualify an Atomic boot, physical NVIDIA driver/display behavior,
compositor interaction, TLS policy, Fedora sandbox or escape behavior, release
signature enforcement or rollback. Those acceptance gates remain open.
