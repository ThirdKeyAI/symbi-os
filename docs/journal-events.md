# Journal events

P0-01 introduces no journal event types and no journal writer. Its schema tests
operate on local fixture data and execute no agent actions.

Future event additions must document the producer, fields, principal/session
binding, sensitive-field treatment, ordering relative to effects, and upstream
protected-journal verification. The upstream runtime remains the journal source
of truth; do not replace it with an unsigned local log.
