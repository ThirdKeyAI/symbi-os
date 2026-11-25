--------------------------- MODULE SessionClass ---------------------------
EXTENDS Naturals
CONSTANTS Calls, Faults
Classes == {"public", "internal", "client-confidential"}
Routes == {"model", "voice", "api"}
Locations == {"local", "remote"}
VARIABLES klass, everConfidential, call, route, actual, claimed, sent
vars == <<klass, everConfidential, call, route, actual, claimed, sent>>

\* INV-8: the routing layer uses trusted destination metadata, never a
\* caller's label. Labels may tighten while a previously checked call waits.
Init == /\ klass \in Classes /\ everConfidential = (klass = "client-confidential")
        /\ call = [c \in Calls |-> "idle"]
        /\ route = [c \in Calls |-> "model"]
        /\ actual = [c \in Calls |-> "local"]
        /\ claimed = [c \in Calls |-> "local"] /\ sent = {}

Select(c, r, a, p) ==
  /\ call[c] = "idle" /\ call' = [call EXCEPT ![c] = "pending"]
  /\ route' = [route EXCEPT ![c] = r] /\ actual' = [actual EXCEPT ![c] = a]
  /\ claimed' = [claimed EXCEPT ![c] = p]
  /\ UNCHANGED <<klass, everConfidential, sent>>

Allowed(c) ==
  \/ klass # "client-confidential"
  \/ (IF "trust-caller-location" \in Faults THEN claimed[c] ELSE actual[c]) = "local"
  \/ "allow-remote-confidential" \in Faults

Gate(c) ==
  /\ call[c] = "pending"
  /\ call' = [call EXCEPT ![c] = IF Allowed(c) THEN "checked" ELSE "denied"]
  /\ UNCHANGED <<klass, everConfidential, route, actual, claimed, sent>>

Dispatch(c) ==
  /\ call[c] = "checked"
  /\ Allowed(c) \/ "stale-class-decision" \in Faults
  /\ call' = [call EXCEPT ![c] = "sent"]
  /\ sent' = sent \cup {[id |-> c, class |-> klass, location |-> actual[c], via |-> route[c]]}
  /\ UNCHANGED <<klass, everConfidential, route, actual, claimed>>

DispatchLocal(c) == actual[c] = "local" /\ Dispatch(c)
DispatchRemote(c) == actual[c] = "remote" /\ Dispatch(c)

DenyAtDispatch(c) ==
  /\ call[c] = "checked" /\ ~Allowed(c)
  /\ call' = [call EXCEPT ![c] = "denied"]
  /\ UNCHANGED <<klass, everConfidential, route, actual, claimed, sent>>

Tighten ==
  /\ klass # "client-confidential" /\ klass' = "client-confidential"
  /\ everConfidential' = TRUE /\ UNCHANGED <<call, route, actual, claimed, sent>>

LowerClass ==
  /\ "declassify-confidential" \in Faults /\ klass = "client-confidential"
  /\ klass' = "public" /\ UNCHANGED <<everConfidential, call, route, actual, claimed, sent>>

Terminal == /\ \A c \in Calls : call[c] \in {"sent", "denied"}
            /\ UNCHANGED vars
Next == \/ \E c \in Calls, r \in Routes, a \in Locations, p \in Locations : Select(c, r, a, p)
        \/ \E c \in Calls : Gate(c) \/ DispatchLocal(c) \/ DispatchRemote(c) \/ DenyAtDispatch(c)
        \/ Tighten \/ LowerClass \/ Terminal

TypeOK ==
  /\ klass \in Classes /\ everConfidential \in BOOLEAN
  /\ call \in [Calls -> {"idle", "pending", "checked", "denied", "sent"}]
  /\ route \in [Calls -> Routes] /\ actual \in [Calls -> Locations] /\ claimed \in [Calls -> Locations]
  /\ sent \subseteq [id : Calls, class : Classes, location : Locations, via : Routes]
NoRemoteConfidential == \A event \in sent :
  event.class = "client-confidential" => event.location = "local"
NoDowngrade == everConfidential => klass = "client-confidential"
=============================================================================
