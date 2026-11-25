------------------------- MODULE GrantLifecycle -------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Calls, Faults
Actors == {"physical", "agent", "app", "voice"}
VARIABLES phase, scope, expiry, authorityActors, call, completed, atAck
vars == <<phase, scope, expiry, authorityActors, call, completed, atAck>>

\* Design contract for INV-2/3. TrustedInput supplies the physical provenance.
\* One grant identity is never reused; a later grant needs a different identity.
Init == /\ phase = "absent" /\ scope = {"read"} /\ expiry = 1
        /\ authorityActors = {} /\ call = [c \in Calls |-> "idle"]
        /\ completed = {} /\ atAck = {}

Create(a) ==
  /\ phase = "absent"
  /\ a = "physical" \/ "nonhuman-create" \in Faults
  /\ phase' = "active" /\ authorityActors' = authorityActors \cup {a}
  /\ UNCHANGED <<scope, expiry, call, completed, atAck>>

Widen(a) ==
  /\ phase = "active" /\ scope = {"read"}
  /\ a = "physical" \/ "nonhuman-widen" \in Faults
  /\ scope' = {"read", "write"}
  /\ authorityActors' = authorityActors \cup {a}
  /\ UNCHANGED <<phase, expiry, call, completed, atAck>>

Extend(a) ==
  /\ phase = "active" /\ expiry = 1
  /\ a = "physical" \/ "nonhuman-extend" \in Faults
  /\ expiry' = 2 /\ authorityActors' = authorityActors \cup {a}
  /\ UNCHANGED <<phase, scope, call, completed, atAck>>

\* Checking and starting an effect are different steps: a revoke can intervene.
Check(c) ==
  /\ phase = "active" /\ call[c] = "idle"
  /\ call' = [call EXCEPT ![c] = "checked"]
  /\ UNCHANGED <<phase, scope, expiry, authorityActors, completed, atAck>>

Dispatch(c) ==
  /\ call[c] = "checked"
  /\ phase = "active" \/ "stale-grant-cache" \in Faults
  /\ call' = [call EXCEPT ![c] = "running"]
  /\ UNCHANGED <<phase, scope, expiry, authorityActors, completed, atAck>>

Complete(c) ==
  /\ call[c] = "running"
  /\ call' = [call EXCEPT ![c] = "completed"]
  /\ completed' = completed \cup {c}
  /\ UNCHANGED <<phase, scope, expiry, authorityActors, atAck>>

RequestRevoke ==
  /\ phase = "active" /\ phase' = "revoking"
  /\ UNCHANGED <<scope, expiry, authorityActors, call, completed, atAck>>

Cancel(c) ==
  /\ phase \in {"revoking", "revoked"} /\ call[c] \in {"checked", "running"}
  /\ call' = [call EXCEPT ![c] = "cancelled"]
  /\ UNCHANGED <<phase, scope, expiry, authorityActors, completed, atAck>>

\* Cancellation means the external effect cannot subsequently complete.
AckRevoke ==
  /\ phase = "revoking"
  /\ (\A c \in Calls : call[c] # "running") \/ "early-revoke-ack" \in Faults
  /\ phase' = "revoked" /\ atAck' = completed
  /\ UNCHANGED <<scope, expiry, authorityActors, call, completed>>

Terminal ==
  /\ phase = "revoked" /\ \A c \in Calls : call[c] \notin {"checked", "running"}
  /\ UNCHANGED vars

Next == \/ \E a \in Actors : Create(a) \/ Widen(a) \/ Extend(a)
        \/ \E c \in Calls : Check(c) \/ Dispatch(c) \/ Complete(c) \/ Cancel(c)
        \/ RequestRevoke \/ AckRevoke \/ Terminal

TypeOK ==
  /\ phase \in {"absent", "active", "revoking", "revoked"}
  /\ scope \in {{"read"}, {"read", "write"}} /\ expiry \in 1..2
  /\ authorityActors \subseteq Actors
  /\ call \in [Calls -> {"idle", "checked", "running", "completed", "cancelled"}]
  /\ completed \subseteq Calls /\ atAck \subseteq Calls
HumanAuthority == authorityActors \subseteq {"physical"}
NoCompletionAfterRevoke == phase = "revoked" => completed = atAck
=============================================================================
