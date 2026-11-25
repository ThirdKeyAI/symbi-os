-------------------------- MODULE TrustedInput --------------------------
EXTENDS Naturals
CONSTANT Faults
Sources == {"physical", "uinput", "virtual-keyboard", "agent", "voice"}
Surfaces == {"none", "trusted", "app"}
VARIABLES card, surface, receipt, receiptSource, receiptSurface, uses,
          badBinding, rejected
vars == <<card, surface, receipt, receiptSource, receiptSurface, uses,
          badBinding, rejected>>

\* INV-2/4. Source is authenticated compositor/device provenance, never an
\* untrusted request field. Cards stand for exact request/scope/expiry nonces.
Init == /\ card = 1 /\ surface = "none" /\ receipt = 0
        /\ receiptSource = "none" /\ receiptSurface = "none"
        /\ uses = [n \in 1..2 |-> 0] /\ badBinding = FALSE /\ rejected = FALSE

Open(s) == /\ surface = "none" /\ surface' = s
           /\ UNCHANGED <<card, receipt, receiptSource, receiptSurface, uses,
                          badBinding, rejected>>

ReplaceCard ==
  /\ card = 1 /\ card' = 2
  /\ UNCHANGED <<surface, receipt, receiptSource, receiptSurface, uses,
                 badBinding, rejected>>

Trusted(source) ==
  /\ source = "physical" \/ "accept-synthetic" \in Faults
  /\ surface = "trusted" \/ "trust-ui-surface" \in Faults

Confirm(source) ==
  /\ surface # "none" /\ receipt = 0 /\ Trusted(source)
  /\ receipt' = card /\ receiptSource' = source /\ receiptSurface' = surface
  /\ UNCHANGED <<card, surface, uses, badBinding, rejected>>

Reject(source) ==
  /\ surface # "none" /\ ~Trusted(source) /\ ~rejected
  /\ rejected' = TRUE
  /\ UNCHANGED <<card, surface, receipt, receiptSource, receiptSurface, uses,
                 badBinding>>

\* A receipt can remain after the displayed request changes, but cannot grant
\* the replacement. The consumer enforces single use, not the untrusted UI.
Consume ==
  /\ receipt # 0
  /\ receipt = card \/ "accept-stale-card" \in Faults
  /\ uses[receipt] = 0 \/ ("replay-receipt" \in Faults /\ uses[receipt] = 1)
  /\ uses' = [uses EXCEPT ![receipt] = @ + 1]
  /\ badBinding' = (badBinding \/ receipt # card)
  /\ UNCHANGED <<card, surface, receipt, receiptSource, receiptSurface, rejected>>

Close ==
  /\ surface # "none" /\ surface' = "none"
  /\ UNCHANGED <<card, receipt, receiptSource, receiptSurface, uses, badBinding,
                 rejected>>

Next == \/ \E s \in {"trusted", "app"} : Open(s)
        \/ ReplaceCard
        \/ \E source \in Sources : Confirm(source) \/ Reject(source)
        \/ Consume \/ Close

TypeOK ==
  /\ card \in 1..2 /\ surface \in Surfaces /\ receipt \in 0..2
  /\ receiptSource \in Sources \cup {"none"} /\ receiptSurface \in Surfaces
  /\ uses \in [1..2 -> 0..2] /\ badBinding \in BOOLEAN /\ rejected \in BOOLEAN
PhysicalReceipts == receipt # 0 => receiptSource = "physical"
TrustedSurfaceOnly == receipt # 0 => receiptSurface = "trusted"
BoundReceiptUses == ~badBinding
SingleUse == \A n \in 1..2 : uses[n] <= 1
=============================================================================
