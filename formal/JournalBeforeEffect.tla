----------------------- MODULE JournalBeforeEffect -----------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANTS Effects, Faults
VARIABLES volatile, durable, phase, owner, parents, signatures, hashes,
          released, up, crashed, failed
vars == <<volatile, durable, phase, owner, parents, signatures, hashes,
          released, up, crashed, failed>>
Ids(log) == {log[i].id : i \in 1..Len(log)}

\* INV-5. The writer lock serializes choosing the predecessor, hashing,
\* signing, and append. Sync is a separate acknowledgement from storage.
Init == /\ volatile = <<>> /\ durable = <<>>
        /\ phase = [e \in Effects |-> "idle"] /\ owner = 0
        /\ parents = [e \in Effects |-> 0] /\ signatures = {} /\ hashes = {}
        /\ released = {} /\ up = TRUE /\ crashed = FALSE /\ failed = FALSE

Reserve(e) ==
  /\ up /\ ~failed /\ owner = 0 /\ phase[e] = "idle"
  /\ owner' = e /\ phase' = [phase EXCEPT ![e] = "reserved"]
  /\ parents' = [parents EXCEPT ![e] = IF Len(volatile) = 0 THEN 0
                                      ELSE volatile[Len(volatile)].id]
  /\ UNCHANGED <<volatile, durable, signatures, hashes, released, up, crashed, failed>>

Hash(e) ==
  /\ up /\ ~failed /\ owner = e /\ phase[e] = "reserved"
  /\ hashes' = hashes \cup {e} /\ phase' = [phase EXCEPT ![e] = "hashed"]
  /\ parents' = IF "broken-hash-chain" \in Faults
                 THEN [parents EXCEPT ![e] = e] ELSE parents
  /\ UNCHANGED <<volatile, durable, owner, signatures, released, up, crashed, failed>>

Sign(e) ==
  /\ up /\ ~failed /\ owner = e /\ phase[e] = "hashed"
  /\ signatures' = IF "skip-signature" \in Faults THEN signatures
                    ELSE signatures \cup {e}
  /\ phase' = [phase EXCEPT ![e] = "signed"]
  /\ UNCHANGED <<volatile, durable, owner, parents, hashes, released, up, crashed, failed>>

AppendRecord(e) ==
  /\ up /\ ~failed /\ owner = e /\ phase[e] = "signed"
  /\ volatile' = Append(volatile, [id |-> e, prev |-> parents[e],
                                  signed |-> e \in signatures, hashed |-> e \in hashes])
  /\ owner' = 0 /\ phase' = [phase EXCEPT ![e] = "appended"]
  /\ UNCHANGED <<durable, parents, signatures, hashes, released, up, crashed, failed>>

Sync == /\ up /\ ~failed /\ volatile # durable /\ durable' = volatile
        /\ UNCHANGED <<volatile, phase, owner, parents, signatures, hashes,
                       released, up, crashed, failed>>

Release(e) ==
  /\ up /\ ~failed /\ phase[e] = "appended"
  /\ e \in Ids(durable) \/ "release-before-sync" \in Faults
  /\ released' = released \cup {e} /\ phase' = [phase EXCEPT ![e] = "done"]
  /\ UNCHANGED <<volatile, durable, owner, parents, signatures, hashes, up, crashed, failed>>

\* Crashes lose unsynced bytes and unfinished calls, but never durable records.
\* released is ghost history of effects outside this process and cannot roll back.
Crash ==
  /\ up /\ ~crashed /\ up' = FALSE /\ crashed' = TRUE
  /\ volatile' = durable /\ owner' = 0
  /\ phase' = [e \in Effects |-> IF e \in released THEN "done"
                ELSE IF e \in Ids(durable) THEN "appended" ELSE "idle"]
  /\ signatures' = {} /\ hashes' = {} /\ parents' = [e \in Effects |-> 0]
  /\ UNCHANGED <<durable, released, failed>>

Recover == /\ ~up /\ up' = TRUE /\ failed' = FALSE
           /\ UNCHANGED <<volatile, durable, phase, owner, parents, signatures,
                          hashes, released, crashed>>

WriteFailure ==
  /\ up /\ ~failed /\ owner # 0
  /\ failed' = TRUE /\ phase' = [phase EXCEPT ![owner] = "aborted"] /\ owner' = 0
  /\ UNCHANGED <<volatile, durable, parents, signatures, hashes, released, up, crashed>>

SyncFailure ==
  /\ up /\ ~failed /\ volatile # durable /\ failed' = TRUE
  /\ UNCHANGED <<volatile, durable, phase, owner, parents, signatures, hashes,
                 released, up, crashed>>

Abort(e) ==
  /\ up /\ phase[e] \notin {"done", "aborted"}
  /\ phase' = [phase EXCEPT ![e] = "aborted"]
  /\ owner' = IF owner = e THEN 0 ELSE owner
  /\ UNCHANGED <<volatile, durable, parents, signatures, hashes, released, up, crashed, failed>>

Terminal == /\ up /\ \A e \in Effects : phase[e] \in {"done", "aborted"}
            /\ UNCHANGED vars
Next == \/ \E e \in Effects : Reserve(e) \/ Hash(e) \/ Sign(e) \/ AppendRecord(e)
                              \/ Release(e) \/ Abort(e)
        \/ Sync \/ Crash \/ Recover \/ WriteFailure \/ SyncFailure \/ Terminal

Record == [id : Effects, prev : Effects \cup {0}, signed : BOOLEAN, hashed : BOOLEAN]
TypeOK ==
  /\ volatile \in Seq(Record) /\ durable \in Seq(Record)
  /\ Len(volatile) <= Cardinality(Effects) /\ Len(durable) <= Cardinality(Effects)
  /\ phase \in [Effects -> {"idle", "reserved", "hashed", "signed", "appended", "done", "aborted"}]
  /\ owner \in Effects \cup {0} /\ parents \in [Effects -> Effects \cup {0}]
  /\ signatures \subseteq Effects /\ hashes \subseteq Effects /\ released \subseteq Effects
  /\ up \in BOOLEAN /\ crashed \in BOOLEAN /\ failed \in BOOLEAN
DurableBeforeEffect == released \subseteq Ids(durable)
SignedBeforeEffect ==
  \A e \in released : \E i \in 1..Len(durable) : durable[i].id = e /\ durable[i].signed
ValidLink(i) == /\ durable[i].hashed
                /\ durable[i].prev = IF i = 1 THEN 0 ELSE durable[i - 1].id
HashChainBeforeEffect ==
  \A e \in released : \E i \in 1..Len(durable) :
    /\ durable[i].id = e /\ \A j \in 1..i : ValidLink(j)
=============================================================================
