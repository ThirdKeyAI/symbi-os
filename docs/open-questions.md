# Implementation questions raised while starting the plan

The original product questions and their resolution status are in
`build-plan.md`. These entries record additional decisions or prerequisites;
none grants authority or weakens a rule.

| ID | Question or prerequisite | Affected cards | Current treatment |
| --- | --- | --- | --- |
| OQ-01 (resolved) | What product licence will be chosen? | P0-01, release | Owner selected Apache-2.0 on 25 Nov 2026, with Copyright 2024-2026 Jascha Wanger / ThirdKey AI; see [LICENSE](../LICENSE) |
| OQ-02 | Which isolated Gitea-compatible runner is available, and how is the empty repository's first review target established? | P0-01 | PR 1 targets the scaffold branch; hosted execution is unverified. Creating main was rejected by automatic approval review and needs explicit destination approval. No shared branch was changed. |
| OQ-03 | Which verified secureblue digest and signing identity/key custody should the first image use? | P0-03 | No placeholder image digest, tag-only base, or unsigned release path |
| OQ-04 | What are model cost units, provider/jurisdiction identifiers, and the trusted source of session-class values? | P1-04, P1-05 | Schema captures documented attribute shapes only; no routing/grant semantics |
| OQ-05 | How will the Cedar 4.5.2 CLI's yanked transitive dependencies and the build-tool audit graph be addressed for release qualification? | P0-03, runtime pin update | Preserve upstream compatibility and lockfiles; development fixture tests only; no release claim |
| OQ-06 | Where will the fourteen upstream control entries and Fedora qualification reports be reviewed and retained? | P0-04, TCB cards | Review scope and proposed OS IDs in [the registration plan](security/upstream-controls-plan.md); no local catalogue claims upstream registration |
| OQ-07 | Which maintained base should replace the retired secureblue Hyprland/userns image without losing the planned trusted compositor? | P0-03, P0-04, P0-05 | See [image preparation](../image/README.md); no Sway substitution or obsolete base selected |
| OQ-08 | Where will an authenticated build of Symbiont revision deddb9e997244d2289c217ad76b8fde0e9b0339b be produced? | P0-04, P0-05 | Published v3.0.0 names a different source revision; use a bounded isolated builder, not the old local debug executable |

The supplied plan also describes subscription tokens inside workspace-mode
sandboxes as an exception to INV-6, while the invariant itself forbids secrets
there. This must be resolved in the relevant design review before implementing
subscription mode; P0-01 neither enables nor normalizes that exception.
