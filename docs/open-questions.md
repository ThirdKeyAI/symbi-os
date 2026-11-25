# Implementation questions raised while starting the plan

The original product questions and their resolution status are in
`build-plan.md`. These entries record additional decisions or prerequisites;
none grants authority or weakens a rule.

| ID | Question or prerequisite | Affected cards | Current treatment |
| --- | --- | --- | --- |
| OQ-01 (resolved) | What product licence will be chosen? | P0-01, release | Owner selected Apache-2.0 on 25 Nov 2026, with Copyright 2024-2026 Jascha Wanger / ThirdKey AI; see [LICENSE](../LICENSE) |
| OQ-02 (setup resolved) | Where will the OS's GitHub workflow execute, and how will its review and protected release environment be configured? | P0-01, P0-03 | Owner selected GitHub Actions and GHCR, then public visibility for `ThirdKeyAI/symbi-os` to enable required environment reviewers. Gitea `main` exists at the approved scaffold commit. GitHub PR 1's first hosted scaffold check passed. The release environment requires jaschadub, prevents self-approval and accepts `v*` tags only. See [release setup](../image/RELEASE-PLAN.md); a passing OS build remains a separate gate. |
| OQ-03 (inputs and custody resolved) | Which verified secureblue digests and verifier-compatible OS signing key should the first image use? | P0-03 | Dedicated OS key generated and stored in the protected GitHub release environment, with its public key/hash committed under `image/keys`. Generic and NVIDIA base digests in `image/base-images.json` passed publisher-signature verification. Symbiont-style keyless attestations remain additional release evidence. Real OS image signature/update tests remain engineering gates; no unsigned path. |
| OQ-04 | What are model cost units, provider/jurisdiction identifiers, and the trusted source of session-class values? | P1-04, P1-05 | Schema captures documented attribute shapes only; no routing/grant semantics |
| OQ-05 | How will the Cedar 4.5.2 CLI's yanked transitive dependencies and the build-tool audit graph be addressed for release qualification? | P0-03, runtime pin update | Preserve upstream compatibility and lockfiles; development fixture tests only; no release claim |
| OQ-06 | Where will the fourteen upstream control entries and Fedora qualification reports be reviewed and retained? | P0-04, TCB cards | Review scope and proposed OS IDs in [the registration plan](security/upstream-controls-plan.md); no local catalogue claims upstream registration |
| OQ-07 (strategy resolved) | Which maintained base should replace the retired secureblue Hyprland/userns image without losing the planned trusted compositor? | P0-03, P0-04, P0-05 | Owner selected secureblue hardening plus maintained Hyprland packaging on 25 Nov 2026. Exact base/package pins and plugin-disabled compositor build remain engineering work; see [implementation decisions](../image/RELEASE-PLAN.md). |
| OQ-08 (development build resolved) | Where will an authenticated build of Symbiont revision deddb9e997244d2289c217ad76b8fde0e9b0339b be produced? | P0-04, P0-05 | [Hosted run 45688918098](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45688918098) passed baseline and fixture-patched build/test/Clippy/fmt with Rust 1.100.0. Source, lock, patch, binary and immutable artifact hashes are retained in the P0-05 report for verified hosted reuse. The resource-limited local failures remain historical observations; the local VM is off. These are checked development binaries, not a signed release or Fedora qualification. |

The supplied plan also describes subscription tokens inside workspace-mode
sandboxes as an exception to INV-6, while the invariant itself forbids secrets
there. This must be resolved in the relevant design review before implementing
subscription mode; P0-01 neither enables nor normalizes that exception.
