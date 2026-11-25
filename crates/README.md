# Rust components

P0-01 creates `symbi-common` as a crate boundary with no runtime API. P1-01 adds
IDs, D-Bus types, and upstream runtime/journal clients.

The plan reserves `symbi-run`, `symbi-egressd`, `symbi-modeld`, `symbi-trustd`,
`symbi-grantd`, `symbi-servicesd`, `symbi-browserd`, `symbi-voiced`, `symbi-snapd`,
and `symbi-bar`. Create those crates when their cards are claimed; do not expose
successful no-op daemons or simulated enforcement in their place.
