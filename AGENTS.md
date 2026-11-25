# Working on Symbiont OS

Read the architecture overview and all fourteen security invariants in
`docs/build-plan.md` before changing code. Read the current card and
`docs/open-questions.md` before selecting work.

- Claim one eligible task card, update its owner/status, and use the prescribed
  `card/<ID>-<slug>` branch. Keep one card per review.
- Write meaningful acceptance tests before the implementation. Never loosen an
  invariant, source pin, signature check, or sandbox boundary to pass a test.
- Keep unresolved product/security decisions in `docs/open-questions.md` and
  link them from the build plan's risks section; do not guess them into code.
- Use the upstream Symbiont runtime at `upstream/symbiont.toml`'s full revision.
  Runtime changes go upstream first, under its own AGENTS.md and evidence rules.
- TCB implementations require TLA+ models, fault checks, and human review before
  merge. P0-01's schema fixture tests do not implement an authorization gate.
- Do not put permissive example policies into `policy/base.cedar`; fixtures
  belong under `policy/tests/fixtures` and must never enter a release image.
- New dependencies require exact pins, Cargo.lock, a review note, and genuine
  cargo-vet audit evidence. Do not generate blanket exemptions or invented audits.
- Run `bash scripts/check.sh` after `bash scripts/bootstrap-tools.sh`. Record
  the result and its limits in the card report. Never call host tests Fedora VM,
  escape-suite, signature, or runtime qualification evidence.
- Document new events in `docs/journal-events.md`. Use the PR template with
  invariant IDs, acceptance-test links, a threat note, and open questions.
- The licence, CI runner provisioning, signing-key custody, image pins, and the
  runtime integration are not settled by this scaffold.
- Keep local CPU and RAM use low: one Cargo job, one test/checker thread, no
  debug symbols or incremental compilation, and no simultaneous builds. Reuse
  existing artifacts. Do not start large VM/image builds without first sizing
  their resource limits for this host.
