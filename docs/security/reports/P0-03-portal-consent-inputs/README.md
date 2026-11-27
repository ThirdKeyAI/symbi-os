# Fresh-consent source and build-input checks

All 191 offline image checks pass. Eight new checks were written before their
input/installation helpers and cover exact source/parent/patch scope, each patch
phase, symlink and special-file refusals, unchanged reused libraries and the
required downstream Apache license. The logs retain the missing-implementation
failures and both full validation passes; the latter adds the exact OS license
to the patched prefix instead of omitting its notice.

The real upstream snapshots and both patch files are hash- and Git-object-bound.
Git's actual changed-file lists, dry runs and resulting file hashes match the
declared single test file and eight production files. Workflow syntax, ShellCheck,
artifact IDs/hashes and all three local-execution refusals pass. Local validation
used 35,976 KiB RSS, 0.69 CPU seconds and no swap under 128 MiB / 10%-CPU limits.

These are small source/input tests. No native compiler, image download, VM or
GPU workload ran locally. The real native formatter before/after regression,
installed CLI controls, complete D-Bus/GUI acceptance and human review remain
pending. See `image/portal/CONSENT-REVIEW.md` for the implementation and required
acceptance scope; no consent or OS qualification is claimed.
