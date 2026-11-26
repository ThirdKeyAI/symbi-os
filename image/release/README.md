# Release evidence gate

The release gate reconciles evidence; it does not manufacture a successful
result. `contract.py` requires generic and NVIDIA image subjects from the exact
release repositories, then checks seven separately hash-bound JSON records per
variant:

- an SPDX 2.3 SBOM whose described operating-system package is the exact image;
- SLSA v1 provenance binding the source commit, selected base digest, protected
  workflow identity, variant and output subject;
- Cosign signature and provenance-attestation verification reports for the
  dedicated OS public key and pinned Cosign build;
- native P0-03, P0-04 and P0-05 reports from the same source and booted image.

P0-03 must include the real signature rejection controls, plugin-constructor
refusal, booted rollback, smoke suite and desktop profile. P0-04 must include
the Cedar allow/deny and independently verified journal-before-effect vertical
slice. P0-05 must include the managed gVisor route and escape suite. Both image
variants need every gate. A changed blob, linked path, duplicate JSON key,
development-only result, host-only check, missing report or cross-image report
fails the reconciliation.

The JSON checks are structural reconciliation. A committed or manually authored
report can satisfy their shape, so those bytes alone are not authentic release
evidence. `release-candidate.yml` therefore contains no artifact upload. It
checks the contract and then fails explicitly until real native and signing
workflows bind their run path, source SHA/ref, conclusion and exact artifact
identity and digest. When authenticated artifact metadata is supplied, each
provenance invocation URL must name that exact producer run. Upstream candidate
identifiers must also be `upstream-check-<producer-run-id>`, preventing evidence
from two otherwise valid runs from being combined. The manifest still separates
the future builder identity from the consumer identity so a consumer cannot
bless its own earlier output.

`release-images.yml` is currently a protected, read-only evidence consumer. It
can run only for a selected `v*` tag and has neither registry write nor OIDC
signing authority. It accepts a complete bundle only from a successful
`release-candidate.yml` dispatch at the same tag and source commit. No such
artifact can be emitted by the current workflow. Signing and digest promotion
stay disabled until the actual image, signing and P0 producers are integrated.

`upstream-check.yml` consumes a separately built candidate artifact. The
artifact contains `base-images.json` plus a complete `release-evidence/` bundle
with purpose `upstream-candidate`. The manual job preserves repositories and
trust roots, permits digest changes only, reruns the serial repository gate and
revalidates the artifact in a separate job before opening a review PR. Both
jobs check out and verify the dispatch SHA without persisting credentials. The
write token is exposed only to the final push/PR step; validation and tests do
not receive it. Missing, stale or incomplete evidence stops before any Git
write. The configured
`SYMBI_UPSTREAM_EVIDENCE_RUN_ID` must identify the qualifying
`release-candidate.yml` run. That workflow currently refuses every candidate
before upload. The weekly trigger remains disabled until the authentic producer
exists, avoiding recurring failures while retaining manual contract review.

These offline validators are acceptance machinery, not evidence that an image
was built, signed, booted, rolled back, or qualified.
