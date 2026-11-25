# Hosted container fixture execution

This is Ubuntu development evidence for P0-05. It does not qualify Fedora,
managed CLI brokers, the escape suite or a release image. The OS runtime pin is
unchanged. The exact fixture-only upstream commit is
`e17f198a8906780408058f4cc48a2715776bf36b`, in
[draft PR 24](https://github.com/ThirdKeyAI/Symbiont/pull/24).

The workflow reuses the immutable development-binary artifact from passing run
45688918098. Its ZIP, both executable hashes, source, Cargo.lock and six-file
patch are bound in `inputs.lock.json`. Every binary is checked before receiving
executable permission; no local rebuild or large download is performed.

The gVisor 20261123.0 Debian package is authenticated through the retained
publisher-signed repository metadata and full key fingerprint. Its complete
installed executable/sidecar inventory is checked before execution. The fixture
root filesystem is Ubuntu Base 24.04.5, authenticated against the retained signed
checksum manifest. Original public verification records explain the key trust
origins. These are development-test inputs, not chosen Fedora release packages.

On a fresh hosted VM with no existing containers, a dedicated Docker daemon
replaces the idle runner daemon temporarily, using private state and a bounded
parent cgroup. Both runc and runsc host-process membership are checked before
fixture execution. The complete job has 4 GiB, two CPUs, no swap and a 110-minute
deadline. Each fixture-image build has an additional 512 MiB/one-CPU ceiling;
actual workers keep the upstream profile's limits and network restrictions.

Only installation of signed Ubuntu packages into the development fixture image
uses host networking. Its package versions and signed repository metadata are
retained, and the resulting image ID is immutable before tests start. The image
is not reproducible release output; Ubuntu package dependencies still require
their own pinned release process if this fixture ever becomes a shipped input.
No release environment, provider credentials or registry-write permission is
available to the workflow.

The unprivileged trusted test account runs all three drivers sequentially for
both backends. The full container filesystem driver has nine cases: upstream
reserves its two additional root-ceiling cases for Landlock/Firecracker. Source
broker has nine cases and Git source fourteen. No `--case` shortcut is used.
Reports must match the complete supported case list, binary/image/driver hashes,
actual backend and runtime observations, and empty worker/lease state.

Temporary fixture directories contain synthetic private signing keys and remain
outside the artifact. The collector accepts only regular public reports/logs,
refuses links and PEM private-key material, and caps the collection size. The
daemon is stopped on completion or failure. No workstation Docker configuration
or VM is changed.
