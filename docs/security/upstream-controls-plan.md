# Upstream control registration plan

This is a review proposal for OQ-06, not an installed or validated control
catalogue. The pinned Symbiont catalogue currently scopes its six entries to
supported OSS runtime routes. OS-specific controls need an agreed namespace
and owner before adding them upstream; proposed IDs below are `OS-INV-01` through
`OS-INV-14`. No previous qualification is copied to a broader OS claim.

| OS rule | Existing upstream evidence to reuse within its stated scope | Additional OS evidence required |
| --- | --- | --- |
| INV-1 Complete mediation | OUT-001, OUT-003; native/full release drivers | Every desktop launcher/broker route and escape suite on the exact Fedora image |
| INV-2 Human grants | Shared exact-approval receipts | Physical trusted path and designation/grant tests; GrantLifecycle model |
| INV-3 Final revocation | OUT-003's execution-scoped authority | Revoke races, cancellation and acknowledgement across all brokers |
| INV-4 Physical input | No compositor-level upstream control | TrustedInput model, synthetic-input fuzzing and capture exclusion |
| INV-5 Journal before effect | AUD-001 | JournalBeforeEffect model, crash tests and OS trace conformance |
| INV-6 Sandbox secret exclusion | OUT-002 for supported routes | Worker canaries and memory/file/env inspection; resolve subscription exception |
| INV-7 One network exit | ISO-001 (currently untested in the pinned catalogue) | Fedora namespace/network escape tests and actual broker-only channels |
| INV-8 Session-class confinement | No complete OS session-class control | SessionClass model and model/voice/API routing tests |
| INV-9 Transport-independent decision | No OS service-broker control | Identical decisions across API/browser/shared-tab requests |
| INV-10 Freeze | No OS-wide freeze control | Freeze model, cgroup/broker races and bounded acknowledgement tests |
| INV-11 Skills narrow | Existing signed skill loading is a separate property | Grant/manifest intersection tests and Z3 checks |
| INV-12 Pinned and signed | Existing runtime artifact/manifest verification, by route | Base/output/asset signatures, immutable pins, signed SBOM/provenance and rebase rejection |
| INV-13 Project config narrows | Runtime source/control separation | Malicious repository configuration tests for all desktop harness profiles |
| INV-14 Voice never grants | No OS voice control | Local audio/wake tests, trusted-path refusal and model mapping |

Initial catalogue entries must identify each rule's real implementation state
and retain `validation_status: untested` for unexecuted OS behavior. Link model
results as design evidence only. After a real qualification, add the retained
report path and SHA-256, exact supported route/backend, binary/image pins and
remaining limitations. Registering an entry does not validate it.

The P0-04 guest driver produces evidence only for the pinned Landlock platform
and full Linux release suites. That can support scoped portions of INV-1/INV-7;
it cannot turn all fourteen entries into validated controls. Upstream runtime
changes and catalogue edits must follow upstream AGENTS.md and its review flow.
