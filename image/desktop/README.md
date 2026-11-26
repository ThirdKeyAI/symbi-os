# Actual desktop image assembly

This pipeline builds the highly experimental Symbi OS desktop image from the
already-tested development artifacts. It does not compile native code. It uses
the exact BlueBuild CLI to validate the extended recipe and generate the actual
Containerfile. The original foundation renderer remains unchanged.

The image installs the maintained Hyprland compositor and private shared
libraries, the patched Elephant application provider, Walker, `symbi` and its
sandbox supervisor. It includes the original component licenses, source/artifact
bindings, downstream patches and desktop defaults. The application service starts
from the compositor session, with its display environment imported into the user
service manager. No service or UI gains approval authority.

Five signed Fedora runtime libraries are installed offline: libeis, muParser,
tomlplusplus, gtk4-layer-shell and openssl3-libs. Every package is checked again
against the pinned full Fedora fingerprint, payload digest and complete RPM
identity. Existing identical packages are retained; replacements are refused.
The transaction must preserve all original base packages and crypto configuration.
The compilation inputs were produced on the generic base; each target variant
must pass its own installed-image checks. Generic evidence does not qualify NVIDIA.

The hosted preparation unit has 512 MiB, one CPU and no swap. The pull/controller
unit has 4 GiB/two CPUs/no swap. The complete image build runs inside a separate
descendant cgroup capped at 2 GiB/one CPU/no swap/128 tasks, including its Buildah
children. Image RUNs additionally enforce memory/CPU limits and network isolation.
The base signature is checked before pulling. Builds use only local authenticated
inputs and `--pull=never`. Temporary containers, including external Buildah
containers, are removed and verified absent in private storage.

The built OCI archive is retained before runtime probes, so probe corrections
can reuse it. The image is then inspected as UID 10001, with a read-only root,
no network or capabilities, no new privileges, 512 MiB/one CPU/no swap/64 tasks.
Checks cover installed bytes and ownership, the final RPM inventory, dynamic
libraries, actual CLI/provider controls and the installed Lua defaults. A separate
root/no-capability container runs `bootc container lint`. The OCI archive is a
development artifact, with no release signature or publication authority; it is
not a signed installation or rebase route.

Boot, actual compositor rendering/input/IPC/native-loading refusal, browser and
portal behavior, dynamic TLS policy, Fedora sandbox/escape qualification,
source/dependency audits, SBOM/provenance, signed updates and rollback remain
required. The workflow never receives the protected release signing environment.
Generic builds run on relevant pushes; NVIDIA uses the explicit manual variant
after the common assembly path succeeds. No large artifact or VM runs locally.

The six local regressions cover additive transactions, replacement/removal and
extra-package refusals, runtime-only prefix selection, unsafe links, recipe order
and generated external-image/command rejection. They do not substitute for hosted
assembly or final-image acceptance.

Build and cleanup behavior follows the primary
[Podman build documentation](https://docs.podman.io/en/latest/markdown/podman-build.1.html)
and [container removal documentation](https://docs.podman.io/en/latest/markdown/podman-rm.1.html).
