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

The hosted preparation unit has 1 GiB, one CPU and no swap. The pull/controller
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

The seven local regressions cover byte/mode-preserving payload copies, additive transactions, replacement/removal and
extra-package refusals, runtime-only prefix selection, unsafe links, recipe order
and generated external-image/command rejection. They do not substitute for hosted
assembly or final-image acceptance.

The [first assembly attempt](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45754029034)
verified all eight retained input archives, then hit its original 512 MiB
preparation limit after 3.681 seconds. No image build or container started. The
log does not identify the extraction phase or distinguish process memory from
file cache, so the precise cause is unconfirmed. Preparation now retains phase
checkpoints with process and cgroup counters, uses a 1 GiB hosted limit and
flushes/releases this run's copied-file cache in bounded chunks. Extracted files
are synced and their clean cache released between components. No global cache
flush, source rebuild or local resource increase is involved. If systemd has
already unloaded the unit, default fields from `LoadState=not-found` are not
measurement evidence.

[The corrected preparation run](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45755434247)
passed extraction, source bindings and the actual BlueBuild validation/generation.
Its retained cgroup counters show a 1 GiB peak and memory-limit pressure without
OOM or kill; the final checkpoint is dominated by file cache, while Python RSS
is about 26 MiB. Image setup then failed before the base pull: the parent had
not enabled controllers for the nested build cgroup. The controller now enables
CPU/memory/tasks in the empty delegated parent before creating the build child,
reads back every limit and records setup before pulling. The existing enclosing
4 GiB and nested 2 GiB limits remain unchanged. This follows the kernel's
[cgroup v2 controller rules](https://docs.kernel.org/admin-guide/cgroup-v2.html#enabling-and-disabling).
Actual image assembly remains a separate hosted gate.

[Run 45755957778](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45755957778)
verified the delegated limits, base signature and base prerequisites, then failed
at the first image RUN. In the selected Podman 4.9.3,
[Buildah assigns `CgroupParent` directly to OCI `CgroupsPath`](https://github.com/podman-container-tools/podman/blob/v4.9.3/vendor/github.com/containers/buildah/run_linux.go#L456).
The enabled parent cannot contain processes. RUN now uses `image-build/run`,
a leaf beside `image-build/supervisor`; both remain subject to the same enclosing
2 GiB/one-CPU/zero-swap/128-task cap. All temporary containers from the failed
attempt were removed and verified absent. Parent memory pressure is retained
without OOM/kill; the nested build peaked at 23,216,128 bytes without limit events.

Build and cleanup behavior follows the primary
[Podman build documentation](https://docs.podman.io/en/latest/markdown/podman-build.1.html)
and [container removal documentation](https://docs.podman.io/en/latest/markdown/podman-rm.1.html).
