# OS control catalogue and upstream review plan

The OS-owned [catalogue](controls.json) prepares fourteen entries under the
`OSI-001` through `OSI-014` namespace. It is a review artifact for OQ-06, not an
upstream registration or an owner-approved evidence-retention decision. Every
entry is `untested`; no qualification is attached. The pinned Symbiont
catalogue has six narrower entries for supported runtime routes. Reuse those
results only within their named route and backend scope.

| OS rule | OS control | Existing upstream evidence to review within its stated scope | Additional OS evidence required |
| --- | --- | --- | --- |
| INV-1 Complete mediation | OSI-001 | OUT-001, OUT-003; native/full release drivers | Every desktop launcher/broker route and escape suite on the exact Fedora image |
| INV-2 Human grants | OSI-002 | Shared exact-approval receipts | Physical trusted path, designation/grant tests and composed receipt-to-grant use trace |
| INV-3 Final revocation | OSI-003 | OUT-003 execution-scoped authority | Revoke races, observable completion and acknowledgement across every broker |
| INV-4 Physical input | OSI-004 | No compositor-level upstream control | Explicit delivery exclusion, synthetic-input fuzzing and capture exclusion |
| INV-5 Journal before effect | OSI-005 | AUD-001 | JournalBeforeEffect mapping, crash tests and OS trace conformance |
| INV-6 Sandbox secret exclusion | OSI-006 | OUT-002 for supported routes | Worker canaries and memory/file/environment/descriptor inspection; resolve subscription exception |
| INV-7 One network exit | OSI-007 | ISO-001, currently untested in the pinned catalogue | Fedora namespace/network escape tests and actual broker-only channels |
| INV-8 Session-class confinement | OSI-008 | No complete OS session-class control | SessionClass mapping and model/voice/API routing tests |
| INV-9 Transport-independent decision | OSI-009 | No OS service-broker control | Identical decisions across API/browser/shared-tab requests |
| INV-10 Freeze | OSI-010 | No OS-wide freeze control | Freeze mapping, cgroup/broker races and timed observable acknowledgements |
| INV-11 Skills narrow | OSI-011 | Existing signed skill loading is a separate property | Grant/manifest intersection tests and Z3 checks |
| INV-12 Pinned and signed | OSI-012 | Existing runtime artifact/manifest verification by route | Base/output/asset signatures, immutable pins, signed SBOM/provenance and rebase rejection |
| INV-13 Project config narrows | OSI-013 | Runtime source/control separation | Malicious repository configuration tests for all desktop harness profiles |
| INV-14 Voice never grants | OSI-014 | No OS voice control | Local audio/wake tests, trusted-path refusal and model mapping |

## Formal engineering and evidence follow-ups

These are future executable tasks. The existing five bounded models remain
unchanged and no catalogue control is considered implemented or qualified by
this register.

| Task | Engineering change | Required evidence | Target cards |
| --- | --- | --- | --- |
| FML-01 | Compose one physical trusted-path receipt with grant creation or widening and its exact first use; bind card nonce, principal, action, resources, expiry and single-use consumption across the boundary | Bounded composed model with deliberate mismatch/replay faults, then a real journal trace from the same approval through broker dispatch | P2-03, P2-04, P5-05 |
| FML-02 | Represent delivery to the trusted surface explicitly, so a synthetic event that reaches the surface and is ignored still violates INV-4 | Delivery-exclusion invariant and fault, compositor event trace, synthetic-input fuzzing and screen-capture exclusion | P2-02, P2-03, P2-05 |
| FML-03 | Give every freeze/revoke executor an observable completion condition and acknowledgement frontier, including the case where a remote peer accepted a request before local cancellation | Updated mapping or composed model, rejected early-ack fault, real concurrent network traces and timed tests for the 500 ms freeze target | P1-03, P1-04, P2-03, P2-04, P5-05 |

## Evidence-retention proposal awaiting owner approval

Keep compact reports in this repository: exact source revision, image and
configuration digests, driver/verifier hashes, route/backend scope, observed
checks, resource counters, OOM/swap state and cleanup result. Keep large raw
logs, disk images and captured trees outside Git as signed, digest-addressed
Actions or release artifacts. A compact report would record the external URI,
artifact SHA-256 and signature/bundle digest.

That external-reference schema and retention location are proposed only. Until
the owner approves them, the local validator accepts only exact
repository-retained reports and rejects any validation status without passing
evidence. After approval, change the schema and checker in review before adding
an external reference. Registration upstream must follow upstream review and
must not broaden a report beyond its exact routes, backends, image and binary.

The P0-04 guest driver can eventually support scoped portions of OSI-001 and
OSI-007, and P0-03/P0-05 evidence can support scoped portions of OSI-005 and
OSI-012. None currently supplies a catalogue qualification. Upstream runtime
changes and catalogue edits remain subject to the upstream repository's own
review flow.
