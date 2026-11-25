----------------------------- MODULE Freeze -----------------------------
EXTENDS Naturals
CONSTANTS Calls, MaxFreezes, Faults
VARIABLES phase, count, call, completed, atAck, dispatchedWhileFrozen
vars == <<phase, count, call, completed, atAck, dispatchedWhileFrozen>>

\* INV-10: the freeze barrier covers brokers and outstanding external work,
\* not just stopped CPU threads. It is reopened only by Resume.
Init == /\ phase = "running" /\ count = 0
        /\ call = [c \in Calls |-> "idle"] /\ completed = {} /\ atAck = {}
        /\ dispatchedWhileFrozen = FALSE

Check(c) ==
  /\ phase = "running" /\ call[c] = "idle"
  /\ call' = [call EXCEPT ![c] = "checked"]
  /\ UNCHANGED <<phase, count, completed, atAck, dispatchedWhileFrozen>>

Dispatch(c) ==
  /\ call[c] = "checked"
  /\ phase = "running" \/ "dispatch-while-frozen" \in Faults
  /\ call' = [call EXCEPT ![c] = "in-flight"]
  /\ dispatchedWhileFrozen' = (dispatchedWhileFrozen \/ phase = "frozen")
  /\ UNCHANGED <<phase, count, completed, atAck>>

Complete(c) ==
  /\ call[c] = "in-flight"
  /\ call' = [call EXCEPT ![c] = "completed"]
  /\ completed' = completed \cup {c}
  /\ UNCHANGED <<phase, count, atAck, dispatchedWhileFrozen>>

RequestFreeze ==
  /\ phase = "running" /\ count < MaxFreezes
  /\ phase' = "stopping" /\ count' = count + 1
  /\ UNCHANGED <<call, completed, atAck, dispatchedWhileFrozen>>

Cancel(c) ==
  /\ phase = "stopping" /\ call[c] \in {"checked", "in-flight"}
  /\ call' = [call EXCEPT ![c] = "cancelled"]
  /\ UNCHANGED <<phase, count, completed, atAck, dispatchedWhileFrozen>>

AckFreeze ==
  /\ phase = "stopping"
  /\ (\A c \in Calls : call[c] # "in-flight") \/ "early-freeze-ack" \in Faults
  /\ phase' = "frozen" /\ atAck' = completed
  /\ UNCHANGED <<count, call, completed, dispatchedWhileFrozen>>

Resume ==
  /\ phase = "frozen" /\ phase' = "running"
  /\ UNCHANGED <<count, call, completed, atAck, dispatchedWhileFrozen>>

Terminal ==
  /\ phase = "running" /\ count = MaxFreezes
  /\ \A c \in Calls : call[c] \in {"completed", "cancelled"}
  /\ UNCHANGED vars

Next == \/ \E c \in Calls : Check(c) \/ Dispatch(c) \/ Complete(c) \/ Cancel(c)
        \/ RequestFreeze \/ AckFreeze \/ Resume \/ Terminal
TypeOK ==
  /\ phase \in {"running", "stopping", "frozen"} /\ count \in 0..MaxFreezes
  /\ call \in [Calls -> {"idle", "checked", "in-flight", "completed", "cancelled"}]
  /\ completed \subseteq Calls /\ atAck \subseteq Calls
  /\ dispatchedWhileFrozen \in BOOLEAN
NoCompletionWhileFrozen == phase = "frozen" => completed = atAck
NoDispatchWhileFrozen == ~dispatchedWhileFrozen
=============================================================================
