# Dependency audits

The workspace has no third-party dependencies yet. The canonical TOML files
are managed by cargo-vet 0.10.3 and contain no audits, trust entries, imports,
or exemptions. The empty store is intentional, not an audit certification.

New registry dependencies must acquire real review evidence before the gate
passes. Build tools are outside the workspace graph; their exact pins and
limitations are documented in `docs/dependencies.md`.
