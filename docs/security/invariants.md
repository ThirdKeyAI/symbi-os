# Security evidence status

The full normative wording is in [the build plan](../build-plan.md#security-invariants).
No OS invariant is qualified by this scaffold. A schema fixture test cannot
establish a runtime or compositor security property.

| Control | Property | Evidence status |
| --- | --- | --- |
| INV-1 | Complete mediation | Pending runtime integration and escape qualification |
| INV-2 | Only the human grants | Bounded GrantLifecycle/TrustedInput models pass; trusted path pending |
| INV-3 | Revocation is final | Bounded revocation race model passes; integration tests pending |
| INV-4 | Physical input only | Bounded input-provenance model passes; compositor and fuzzing pending |
| INV-5 | Journal before effect | Bounded crash/durability model passes; real runtime and traces pending |
| INV-6 | No secrets in sandboxes | Pending worker and broker tests; subscription conflict unresolved |
| INV-7 | One way out | Pending Fedora image/network namespace qualification |
| INV-8 | Session-class confinement | Bounded routing/class model passes; confinement implementation pending |
| INV-9 | Transport-independent decisions | Pending service broker and model |
| INV-10 | Stop-the-world | Bounded freeze race model passes; runtime coordination pending |
| INV-11 | Skills only narrow | Pending manifest integration and property checks |
| INV-12 | Pinned and signed | Scaffold has source/tool pins; signatures, artifacts, and image qualification pending |
| INV-13 | Project config only narrows | Pending launcher and routing integration |
| INV-14 | Voice is never authority | Pending voice implementation after trustd |

Register the controls in the upstream runtime's `docs/security/controls.json`
using its evidence conventions when those integrations are implemented. Do not
interpret this local status table as upstream control registration.

Retained local evidence: [P0-01 report](reports/P0-01.md),
[P0-02 design-model report](reports/P0-02.md). These model results do not qualify
any implementation; their bounds and assumptions are in [VERIFY.md](../../formal/VERIFY.md).
