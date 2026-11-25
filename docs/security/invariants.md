# Security evidence status

The full normative wording is in [the build plan](../build-plan.md#security-invariants).
No OS invariant is qualified by this scaffold. A schema fixture test cannot
establish a runtime or compositor security property.

| Control | Property | Evidence status |
| --- | --- | --- |
| INV-1 | Complete mediation | Pending runtime integration and escape qualification |
| INV-2 | Only the human grants | Pending formal models and trusted path |
| INV-3 | Revocation is final | Pending formal race model and integration tests |
| INV-4 | Physical input only | Pending compositor protocol, model, fuzzing |
| INV-5 | Journal before effect | Pending runtime client, model, crash/trace checks |
| INV-6 | No secrets in sandboxes | Pending worker and broker tests; subscription conflict unresolved |
| INV-7 | One way out | Pending Fedora image/network namespace qualification |
| INV-8 | Session-class confinement | Schema field exists; confinement is unimplemented |
| INV-9 | Transport-independent decisions | Pending service broker and model |
| INV-10 | Stop-the-world | Pending formal model and freeze coordination |
| INV-11 | Skills only narrow | Pending manifest integration and property checks |
| INV-12 | Pinned and signed | Scaffold has source/tool pins; signatures, artifacts, and image qualification pending |
| INV-13 | Project config only narrows | Pending launcher and routing integration |
| INV-14 | Voice is never authority | Pending voice implementation after trustd |

Register the controls in the upstream runtime's `docs/security/controls.json`
using its evidence conventions when those integrations are implemented. Do not
interpret this local status table as upstream control registration.

Retained local evidence: [P0-01 report](reports/P0-01.md).
