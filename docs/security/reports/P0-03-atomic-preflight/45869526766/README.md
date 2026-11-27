# Atomic preflight 45869526766

This run loaded the exact retained generic development image and completed its
protected kernel observation. Installed-file verification then failed because
the current desktop verifier imported `font_verify` before reading the exact
retained preparation record, which predates font integration.

- `artifact.zip` is the original 53,710-byte GitHub artifact.
- `artifact-metadata.json` binds its run, source and SHA-256 digest.
- `original/` retains all 35 original files without modification.
- `independent-check.json` hashes every expanded file and reconciles the failed
  result, exact image/kernel identity, cleanup and resource events.
- `tests-before.log` records the compatibility regression failing before the
  implementation; `tests-after.log` records 14 focused passing tests.
- `repository-check.log` and `repository-check.time` retain the final 279-test
  serial repository gate: 4.13 seconds, 67,436 KiB peak RSS and zero swap.

The correction accepts a missing font record only for the full locked pre-font
source commit and reports that fonts were not checked. Future image records must
stage and pass the native font verifier. Hosted rerun acceptance remains pending;
this evidence makes no installation, boot, security or OS qualification claim.
