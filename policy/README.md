# Cedar schema scaffold

`schema.cedarschema` declares the principal, model attributes, model invocation
action, and session context from the build plan. Strings are intentionally
structural here: this skeleton does not authenticate principals, validate a
session-class vocabulary, assign costs, or enforce local-only routing.

`base.cedar` contains no permits, so all fixture requests are denied. Test-only
permits live under `tests/fixtures` and must not be packaged. The tests use the
same Cedar version as the pinned Symbiont runtime (4.5.2).

The runtime's gate remains authoritative. Adding a runtime gate, forbid rules,
grant semantics, or security assertions belongs to the relevant TCB card with
formal models and human review. This is not a parallel authorization engine.
