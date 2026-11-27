# Security evidence status

The full normative wording is in [the build plan](../build-plan.md#security-invariants).
The OS-owned [control catalogue](controls.json) gives each invariant a stable
`OSI-001` through `OSI-014` identifier and is checked by
`scripts/check-security-controls.py`. Every catalogue entry currently has
`validation_status: untested` and an empty qualification list. A partial
implementation state means that repository code exists for a narrower part of
the property; it is not a runtime or release claim.

| Invariant | OS control | Implementation state | Current evidence boundary |
| --- | --- | --- | --- |
| INV-1 Complete mediation | OSI-001 | Partial | Qualification drivers exist; exact installed routes and the OS-wide escape suite remain pending |
| INV-2 Only the human grants | OSI-002 | Planned | Bounded GrantLifecycle/TrustedInput models pass; composed approval-to-grant use and trusted path remain pending |
| INV-3 Revocation is final | OSI-003 | Planned | Bounded revocation model passes; observable network completion and runtime races remain pending |
| INV-4 Physical input only | OSI-004 | Planned | Bounded receipt-provenance model passes; explicit delivery exclusion, compositor and fuzzing remain pending |
| INV-5 Journal before effect | OSI-005 | Partial | Runtime fixture validation is prepared; exact installed runtime, crash and trace evidence remain pending |
| INV-6 No secrets in sandboxes | OSI-006 | Planned | Worker and broker inspection is pending; the subscription-token conflict is unresolved |
| INV-7 One way out | OSI-007 | Partial | Landlock/container drivers exist; exact image namespace and network escape results remain pending |
| INV-8 Session-class confinement | OSI-008 | Planned | Bounded routing/class model passes; trusted attributes and broker implementation remain pending |
| INV-9 Transport-independent decisions | OSI-009 | Planned | Service broker, model and cross-transport traces remain pending |
| INV-10 Stop-the-world | OSI-010 | Planned | Bounded freeze model passes; observable executor acknowledgements and timed runtime evidence remain pending |
| INV-11 Skills only narrow | OSI-011 | Planned | Manifest intersection and property checks remain pending |
| INV-12 Pinned and signed | OSI-012 | Partial | Authenticated input and fail-closed intake paths exist; a qualified signed release and complete artifact coverage remain pending |
| INV-13 Project config only narrows | OSI-013 | Planned | Launcher, routing integration and malicious-project matrix remain pending |
| INV-14 Voice is never authority | OSI-014 | Planned | Voice implementation, trusted-path refusal and audio isolation remain pending |

The local catalogue is the preparation artifact for OQ-06. It does not add
entries to the upstream runtime catalogue, copy upstream validation to a wider
OS claim or record owner approval of the proposed evidence-retention policy.
The [upstream review plan](upstream-controls-plan.md) identifies the narrower
upstream controls that may be cited after their exact scope is preserved.

Retained local evidence: [P0-01 report](reports/P0-01.md) and
[P0-02 design-model report](reports/P0-02.md). Model results do not qualify an
implementation; their bounds and assumptions are in
[VERIFY.md](../../formal/VERIFY.md).
