# P0-02 design verification

These are executable design contracts for INV-2, INV-3, INV-4, INV-5, INV-8,
and INV-10. They check every reachable state within the bounds below. There
is no implementation-refinement or Fedora qualification claim: P0-02 precedes
the desktop TCB implementation. The closest existing tests,
`crates/symbi-common/tests/policy.rs`, check schema acceptance and default deny;
they cannot exercise concurrent revoke/freeze, physical input, disk durability,
or confidential routing. TLA+ fits these cross-process and storage orderings.

## Properties and design mapping

| Model / rule | Promise and harm if broken | Design source and transition mapping |
| --- | --- | --- |
| GrantLifecycle / HumanAuthority | Only physical human acts can create, widen, or extend authority; otherwise an agent can authorize itself. | INV-2; Create/Widen/Extend consume authenticated provenance supplied by TrustedInput. |
| GrantLifecycle / NoCompletionAfterRevoke | No call completes after its grant's revoke acknowledgement; otherwise revoked work still affects the world. | INV-3; Check and Dispatch are separate; RequestRevoke closes dispatch, Cancel/Complete drain external work, AckRevoke records the completion frontier. |
| TrustedInput / PhysicalReceipts | Every minted receipt comes from physical input; otherwise synthetic input or voice can grant. | INV-2/4; Confirm reads device provenance, Reject covers uinput, virtual-keyboard, agent and voice sources. |
| TrustedInput / TrustedSurfaceOnly | Every receipt comes from a compositor-owned trusted surface; otherwise an app can spoof consent. | Trusted-path architecture; Open and Confirm distinguish app and trusted surfaces. |
| TrustedInput / BoundReceiptUses | A receipt applies only to its exact card nonce; otherwise approval can be redirected to a replacement request. | Exact, single-use receipts in the runtime integration design; ReplaceCard can race with Consume. |
| TrustedInput / SingleUse | A receipt can be consumed at most once; otherwise one human confirmation authorizes repeated effects. | Same receipt contract; Consume owns the replay check. |
| Freeze / NoCompletionWhileFrozen | After freeze acknowledgement, completion stops until resume; otherwise the stop control lies to the user. | INV-10; RequestFreeze closes dispatch, Cancel/Complete drain, AckFreeze records the frontier, Resume reopens it. |
| Freeze / NoDispatchWhileFrozen | No queued call starts while freeze is acknowledged; otherwise an asynchronous effect can escape the barrier. | INV-10; Check is separate from Dispatch and queued work may remain across the barrier. |
| JournalBeforeEffect / DurableBeforeEffect | Every released effect has a durable journal record; otherwise a crash erases its audit trail. | INV-5; Reserve, Hash, Sign, AppendRecord, Sync and Release are distinct steps. |
| JournalBeforeEffect / SignedBeforeEffect | Every released effect's durable record is signed; otherwise its audit evidence can be forged. | INV-5; Sign sets the abstract signature fact before append/sync. |
| JournalBeforeEffect / HashChainBeforeEffect | Every released effect's record has an intact hashed prefix; otherwise records can be reordered or detached. | INV-5; Reserve selects the predecessor under the writer lock, Hash binds it, Crash loses only unsynced bytes. |
| SessionClass / NoRemoteConfidential | Confidential content never leaves through a remote model, voice service, or API; otherwise private content leaks. | INV-8; Select distinguishes claimed from actual destination, Gate and Dispatch recheck the current class. |
| SessionClass / NoDowngrade | A session cannot discard its confidential label; otherwise routing restrictions can be bypassed. | INV-8 and class-at-grant design; Tighten is allowed, LowerClass is a fault only. |
| All / TypeOK | States remain within the declared domains; otherwise the model's state space is ill-defined. | Structural checker assertion, not an additional OS security claim. |

The covered artifact is the **design**, not Rust/C++ code. Each implementation
card must replace this mapping with concrete call sites, locks, awaits,
cancellation points and journal events before it cites these models as runtime
evidence. An await, process boundary or storage acknowledgement is not one
atomic step without evidence. No implementation function is invented here.

## Scope, bounds, and assumptions

| Model | Checked bound | Assumptions requiring implementation evidence |
| --- | --- | --- |
| GrantLifecycle | One non-reused grant, two calls, read/write scope, two abstract expiry levels, four actors | Provenance cannot be forged; checking/dispatch revocation state is serialized; cancellation means the external effect cannot later complete. Expiry levels model authorization to extend, not wall-clock expiration. |
| TrustedInput | Two exact-card nonces, one receipt, five source types, trusted/app surfaces, up to two attempted uses | Compositor/device provenance and surface ownership are authenticated; a card binds principal, action, resources, expiry and session. Physical hardware impersonation and confused human consent are outside the model. |
| Freeze | Two calls, two freeze/resume cycles | Every effect executor participates in the barrier; cancellation drains kernel/network work, not merely application tasks. Resume authorization is a separate trusted-path obligation. |
| JournalBeforeEffect | Two effects/records, one writer, one crash/recovery, write/sync failures | Successful sync survives a crash; the writer lock covers predecessor selection through append; hashes and signatures are ideal authenticated facts. Released effects persist as ghost history across crashes. |
| SessionClass | One session, two calls, three classes, three routes, local/remote destinations, arbitrary claimed location | Actual destinations come from authenticated system registry data; class updates and final dispatch are serialized; labels describe all outgoing content. |

All normal configs have `Faults = {}`. No state constraint silently truncates
exploration. These are safety checks, without fairness or liveness claims:
they do not prove timely cancellation, availability, eventual resume, expiry
clock behavior, or successful remote requests. Larger populations and composed
interactions between the five models have not been checked. Independence of
their checks is not a composition proof. Storage corruption after a successful
sync, cryptographic primitives, real Cedar policies, kernel/compositor behavior,
and implementation behavior remain outside this evidence.

## Run and interpret

Use the **tla-check** and **maintain-formal-verification** skills from
[`jaschadub/skill-formal-proofs`](https://github.com/jaschadub/skill-formal-proofs),
version **0.5.3**, commit `bb984f2e4427d3f5515cc56d5a54c6ce8ce26d1e`.
Their current instructions define checker, fault and drift commands; do not
substitute a different version silently. The repository CI invokes that pinned
action in both GitHub and Gitea workflows. GitHub run
[45664230005](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45664230005)
passed all five models (7,315 distinct states) and all eighteen faults at
`789efb6e49da7ce3dc3b17ad20e2b9fe6d003df0`; its invocation is now covered by
this drift record. A checksum-pinned TLC 1.7.4 jar (internal banner 2.19) is used.

From the repository root, prepare this repository's resource limits and jar:

```bash
bash scripts/bootstrap-formal.sh
export JAVA="$PWD/scripts/formal-java.sh"
export TLA2TOOLS="$PWD/.tools/tla2tools-1.7.4.jar"
```

Then use tla-check on each of the five `.tla` files with its neighboring `.cfg`,
sequentially, and request action coverage. The Java wrapper limits visible CPUs
to one, heap to 256 MiB, and each invocation to 180 seconds. Heap is not total
resident memory. Do not remove these limits or run the models concurrently.
Java 11 or later, curl, sha256sum, timeout, nice and a POSIX shell are required.
TLC opens a local management socket, so a sandbox may require permission for it.

A pass means all five runs exit zero, each exhausts its queue, no unexpected
warning appears, and every non-fault Next action has a nonzero execution count.
`SessionClass.LowerClass` is the only intentionally unreachable action: its
declassification fault is off. A count of zero **new** states with nonzero
executions is fine. Normal termination uses explicitly guarded terminal steps;
TrustedInput instead permits closing/reopening a surface.

Use tla-check's fault operation once for each row in `formal/faults.tsv`; all
18 rows must report that the named fault breaks the named invariant. A parser
error, timeout, OOM or wrong invariant is not a successful fault check. Each
fault is checked against its target rule alone, so an earlier failure cannot
mask a missing detector. Do not enable faults in committed normal configs.

Use the drift check from maintain-formal-verification at the repository root.
It must report this record in sync. A passing model that was not updated from
a changed design or implementation says nothing about that change.

## Fault evidence and known design limits

The complete fault-to-rule matrix is `formal/faults.tsv`. These faults expose
unsafe variants, not findings that the default model is broken:

- Nonhuman create/widen/extend introduces an agent, app or voice actor into
  the authority history. Rejecting only initial creation is insufficient.
- Early revoke acknowledgement lets an already-running call finish afterward;
  a stale grant cache can instead dispatch a checked call after acknowledgement.
- Synthetic input, app surfaces, a replaced card and a replayed receipt break
  separate provenance, surface, binding and single-use checks.
- Early freeze acknowledgement permits later completion; a dispatch cache can
  start queued work while the freeze is acknowledged.
- Releasing before sync leaves no durable record; skipping signing leaves an
  unsigned record; corrupting a predecessor leaves a broken chain.
- Allowing remote confidential routing, trusting a caller's location claim,
  using an old class decision, or lowering the label can each bypass confinement.

No default-model invariant failure is known. The model **does** permit a grant
revoke or freeze to remain pending indefinitely when work does not drain. This
is a documented availability limitation of the safety contract, not a proven
deadline. The implementation must not hide that state by acknowledging early.

The build plan and OS control review plan now track three reviewer follow-ups as
future executable work: FML-01 composes physical approval with exact grant use;
FML-02 models exclusion at synthetic-event delivery, rather than only receipt
minting; and FML-03 defines observable and timed completion semantics for
freeze/revoke network effects. These entries document gaps already outside the
five bounded models. They add no transition, assumption or proof claim to the
current models, and no control is qualified by recording them.

There are no runtime traces yet because no covered runtime implementation
exists. Do not relabel model-generated traces as execution logs. Before a TCB
implementation is qualified, instrument real atomic transitions, retain real
concurrent/crash traces, add strict event/value trace adapters using tla-check,
and demonstrate that a missing or reordered event is rejected. The event
mapping belongs in `docs/journal-events.md` when actual events are introduced.

## Change procedure

1. Read the changed design and, when present, real implementation before editing
   the models. Map every changed atomic step; split steps at awaits and disk or
   IPC boundaries unless a real lock proves indivisibility.
2. Update the model/config and property mapping without weakening the promises.
   If a new step is added, step-naming rules must include it while preserving
   their plain-language meaning.
3. Run normal checks with coverage. Replay a failing path against the design or
   real code to distinguish a bug from a modeling error. Keep a buggy variant's
   updated model on its branch and **do not sync it**.
4. Run every affected fault, and real trace conformance once an implementation
   exists. A rename/comment-only edit may instead be read against the model and
   synced after confirming that it changes no behavior.
5. Only after the evidence matches the changed design/code, use the sync mode
   of maintain-formal-verification's drift tool on this record. Inspect the
   reported regions. Review the diff and retain fresh evidence.
6. For a change already landed without rechecking, use the
   maintain-formal-verification skill rather than refreshing hashes blindly.

The cold-reader exercise is recorded in `docs/security/reports/P0-02.md`.
Because the product code does not exist, its seeded regression/refactor apply
to the executable design model. That exercises this handoff; it does not test
whether a future implementation change is reflected in the model.

covered:
  - docs/build-plan.md 5fca0f12b092
    > ## Building on Symbiont 3.0
    > ## Base OS and image pipeline
  - formal/GrantLifecycle.tla 3eb20542d5d1
  - formal/GrantLifecycle.cfg bbc1f3b6b3b5
  - formal/TrustedInput.tla 4a29c8bd2f36
  - formal/TrustedInput.cfg fa1cdacba32e
  - formal/Freeze.tla a08897d4eb0a
  - formal/Freeze.cfg e5b6a6475ca4
  - formal/JournalBeforeEffect.tla becc83d1c86c
  - formal/JournalBeforeEffect.cfg 09ae65fb4613
  - formal/SessionClass.tla 194557936225
  - formal/SessionClass.cfg 2989edadc2c9
  - formal/faults.tsv 4ad54fee3b0f
  - scripts/formal-java.sh f3d1483501e0
  - scripts/bootstrap-formal.sh 44016df21782
  - .gitea/workflows/ci.yml c9bf9c618d8d
  - .github/workflows/ci.yml a34e0b2476e5
