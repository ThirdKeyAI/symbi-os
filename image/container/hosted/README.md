# Hosted container fixture execution

This is Ubuntu development evidence for P0-05. It does not qualify Fedora,
managed CLI brokers, the escape suite or a release image. The OS runtime pin is
unchanged. The exact fixture-only upstream commit is
`c1fac8aab6c5d399abb39036ba35b9636212e17f`, in
[draft PR 24](https://github.com/ThirdKeyAI/Symbiont/pull/24).

The workflow reuses the immutable development-binary artifact from passing run
45702056794. Its ZIP, both executable hashes, source, Cargo.lock and six-file
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

The source checkout fetches the baseline and fixture revisions explicitly and
verifies their cumulative full-index patch, allowing multiple reviewed fixture
commits without assuming the immediate parent is the runtime baseline. A fresh
0700 `/tmp/sf-*` directory owned by the test account keeps supervisor Unix socket
paths below their bound. It holds private fixture state and is never uploaded.


## Complete Docker and gVisor fixture execution passed

Hosted run 45708951490 at head `f5d922ac3e9bf7e78acbe2d503df2145cdf6a789`
passed all six driver profiles using upstream fixture commit
`c1fac8aab6c5d399abb39036ba35b9636212e17f`. Each backend passed all nine
filesystem-grant, nine source-broker and fourteen Git-source cases: 64 passing
cases in total. Actual runtime observations were runc for Docker and runsc for
gVisor. Reports recorded no remaining workers, leases or containers, and the
dedicated daemon stopped. Report hashes and exact driver hashes were rechecked
against the upstream checkout before retaining the evidence.

The run authenticated the pinned runtime archive and executables, cumulative
fixture patch, gVisor publisher metadata and complete package inventory, and the
Ubuntu root filesystem. The resulting fixture-image digest is recorded; the
image's signed Ubuntu package resolution is development evidence, not a pinned
Fedora release input. The job remained under its 4 GiB/two-CPU/no-swap ceiling,
with 1,708,797,952 bytes peak parent memory, 361 recorded max events and no OOM
or OOM kill. Only the 291,995-byte public evidence ZIP was downloaded locally.
Selected reports, signature results and resource counters are retained under
`P0-05-hosted-containers/45708951490/` with original/retained hashes.

This clears the live Ubuntu tool-worker fixture gap for PR 24. P0-05 remains
open: the selected signed Fedora deployment, managed-CLI broker and escape-suite
acceptance, plus required reviews, are not established by these six drivers.

## Native fixture OCI export remains disabled

The prepared exporter is not an extension of the passing evidence above. The
current Dockerfile resolves Python, Git and CA packages live, and this workflow
tested fixture commit `c1fac8aab6c5d399abb39036ba35b9636212e17f`; the native
contract binds merge `cd4b34282ade880c8ac3d5136d31ff80cde92794`. The
`native-fixture-build.lock.json` prerequisite slot therefore remains pending.
Activation requires a reviewed full package closure authenticated by signed
Ubuntu Release/InRelease and Packages metadata, exact package identities,
sizes and hashes, sequential verified downloads, and an offline
`docker build --network=none`. The same producer run must exercise all six
profiles from the required merge, then cold-load the generated OCI and resolve
`localhost/symbi-ci/native-fixture@<manifest digest>`.

The dormant exporter itself uses only Python's standard library. It streams one
Docker-save image into OCI after checking the config digest and every layer
against ordered `diff_id` values, fixes gzip and tar metadata, caps compressed
output at 512 MiB and expanded verification at 1 GiB, and deletes partial
output on failure. The consumer-format verification runs before any output
could be retained. No artifact upload step is enabled.
