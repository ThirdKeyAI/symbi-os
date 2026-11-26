# P0-03 Atomic image preflight preparation — 26 Nov 2026

The new hosted-only consumer advances the saved image toward real Atomic boot.
It verifies exact artifact metadata and ZIP/OCI bytes before private image loading,
then reuses the original installed-file/package verifier and separately observes
boot inputs and unchanged trust configuration. It performs no installation and
cannot report a boot or release qualification. No signing authority is attached.

Six tests were written and run before implementation; `tests-before.log` records
the missing-module failure. The full 213 image tests now pass. The capped local run
peaked at 34,556 KiB RSS and used 0.74 CPU seconds with zero swap. AST, Bash, YAML
and ShellCheck checks pass. Current exact-head hosted workspace/formal and actual
artifact ingestion results remain pending. No native compilation, large download,
VM, host disk change or GPU work ran locally. No dependency pin, exception, journal
event or authorization implementation changed. Invariant: INV-12.

The original metadata/source/image/installed-trust bindings are checked again on
hosted CI. Actual bootc/kernel package observations, resources, cleanup, success
and failures must be retained before advancing to a disk installer. Product trust
policy is not relaxed to load these hash-pinned development artifacts into the
runner's separate private storage. The loaded archive is not a signed release.
