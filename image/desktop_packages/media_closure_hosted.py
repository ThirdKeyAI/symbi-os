"""Run the media-only RPM producer on bounded disposable hosted infrastructure."""
import json
import os
from pathlib import Path
import shutil

from image.desktop_packages.media_closure_contract import (
    require_candidate_manifest,
    require_candidate_request,
    require_media_repositories,
)
from image.desktop_packages.media_contract import (
    MAX_MEDIA_EXPANDED_BYTES,
    MAX_MEDIA_MANIFEST_BYTES,
    require_media_lock,
)
from image.toolchain.bootstrap_cosign import BOOTSTRAP_SUBPROCESS_TIMEOUT_SECONDS
from image.toolchain.reuse import digest, unique_json


BASE_SIGNATURE_TIMEOUT_SECONDS = 180
BASE_PULL_TIMEOUT_SECONDS = 1200
PRODUCER_TIMEOUT_SECONDS = 2700
CLEANUP_CONTAINER_TIMEOUT_SECONDS = 60
CONTAINER_ABSENT_TIMEOUT_SECONDS = 15
REMOVE_IMAGE_TIMEOUT_SECONDS = 300
IMAGE_ABSENT_TIMEOUT_SECONDS = 15
HOSTED_NON_COMMAND_RESERVE_SECONDS = 300
HOSTED_SERVICE_TIMEOUT_SECONDS = 95 * 60
HOSTED_BOUNDED_SECONDS = (
    BOOTSTRAP_SUBPROCESS_TIMEOUT_SECONDS
    + BASE_SIGNATURE_TIMEOUT_SECONDS
    + BASE_PULL_TIMEOUT_SECONDS
    + PRODUCER_TIMEOUT_SECONDS
    + CLEANUP_CONTAINER_TIMEOUT_SECONDS
    + CONTAINER_ABSENT_TIMEOUT_SECONDS
    + REMOVE_IMAGE_TIMEOUT_SECONDS
    + IMAGE_ABSENT_TIMEOUT_SECONDS
)
if HOSTED_BOUNDED_SECONDS + HOSTED_NON_COMMAND_RESERVE_SECONDS > HOSTED_SERVICE_TIMEOUT_SECONDS:
    raise RuntimeError("Media producer command caps exceed its hosted service deadline")


def prepare_inputs(root, inputs, base):
    pins = unique_json((root / "image/base-images.json").read_bytes())
    trust = unique_json((root / "image/desktop_packages/trust.json").read_bytes())
    lock_path = root / "image/desktop_packages/media-rpms.lock.json"
    lock = unique_json(lock_path.read_bytes())
    if require_media_lock(lock, root, pins, trust):
        raise ValueError("Media producer only accepts the exact closed pending lock")
    if base != lock["resolution_base"]:
        raise ValueError("Media producer base differs from the pending lock")
    request = {
        "schema": 1,
        "release": lock["release"],
        "architecture": lock["architecture"],
        "resolution_base": lock["resolution_base"],
        "requirements": ["mplayer", "mpv"],
        "root_packages": lock["root_packages"],
        "trusted_keys": lock["trusted_keys"],
        "source_lock_sha256": digest(lock_path),
    }
    require_candidate_request(request)
    paths = {
        "media_closure.py": "image/desktop_packages/media_closure.py",
        "media_closure_contract.py": "image/desktop_packages/media_closure_contract.py",
        "media_contract.py": "image/desktop_packages/media_contract.py",
        "contract.py": "image/desktop_packages/contract.py",
        "bounded_process.py": "image/launcher/probes/bounded_process.py",
        "fedora-45-primary.asc": "image/hyprland/keys/fedora-45-primary.asc",
        "rpmfusion-free-2020.asc": "image/desktop_packages/rpmfusion-free-2020.asc",
        "dnf.conf": "image/hyprland/package-dnf.conf",
        "repos/media.repo": "image/desktop_packages/media.repo",
    }
    bindings = {}
    for name, relative in paths.items():
        source = root / relative
        if (source.resolve() != source or not source.is_file()
                or source.stat().st_size > 512 * 1024):
            raise ValueError("Unexpected or linked media producer input: " + relative)
        bindings[name] = digest(source)
    if ([bindings[row["file"]] for row in request["trusted_keys"]]
            != [row["sha256"] for row in request["trusted_keys"]]):
        raise ValueError("Pinned media public key changed")
    require_media_repositories((root / paths["repos/media.repo"]).read_text())
    inputs.mkdir(mode=0o755)
    try:
        for name, relative in paths.items():
            target = inputs / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, target); target.chmod(0o644)
            if digest(target) != bindings[name]:
                raise ValueError("Media producer input changed during staging")
        raw = (json.dumps(request, indent=2) + "\n").encode()
        (inputs / "request.json").write_bytes(raw); (inputs / "request.json").chmod(0o644)
        bindings["request.json"] = digest(inputs / "request.json")
    except Exception:
        shutil.rmtree(inputs)
        raise
    return request, bindings


def collect_evidence(source, target):
    if source.resolve() != source or not source.is_dir():
        raise ValueError("Unexpected media producer evidence directory")
    files = list(source.iterdir())
    if len(files) > 1100:
        raise ValueError("Excessive media producer evidence file count")
    total = 0
    for path in files:
        if (path.resolve() != path or not path.is_file() or path.stat().st_size > 1024 * 1024
                or not (path.name == "result.json" or path.name.endswith(".log"))):
            raise ValueError("Unexpected media producer evidence file")
        total += path.stat().st_size
    if total > 16 * 1024 * 1024:
        raise ValueError("Excessive media producer evidence bytes")
    target.mkdir(mode=0o755)
    for path in files:
        shutil.copyfile(path, target / path.name)


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.geteuid() != 0):
        raise SystemExit("Use the disposable hosted media closure unit")
    from image.hyprland.inventory import require_subject
    from image.launcher.probes.bounded_process import run_bounded
    from image.recipe import render
    from image.toolchain.bootstrap_cosign import bootstrap

    root = Path.cwd().resolve()
    process = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    group = process.parent
    if (process.name != "supervisor" or not group.name.startswith("symbi-media-closure-")
            or not group.name.endswith(".service") or (group / "cgroup.procs").read_text().strip()):
        raise ValueError("Unexpected media closure supervisor")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    if limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                  "cpu.max": "200000 100000", "pids.max": "256"}:
        raise ValueError("Unexpected media closure controller limits")
    required = {"cpu", "memory", "pids"}
    if not required.issubset((group / "cgroup.controllers").read_text().split()):
        raise ValueError("Missing media closure cgroup delegation")
    (group / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    if not required.issubset((group / "cgroup.subtree_control").read_text().split()):
        raise ValueError("Media closure cgroup delegation failed")

    evidence = root / ".cache/media-closure-evidence"; evidence.mkdir(parents=True, exist_ok=True)
    output = root / ".cache/media-closure-output"; output.mkdir(mode=0o755)
    inputs = root / ".cache/media-closure-inputs"
    storage = root / ".cache/media-closure-storage"; storage.mkdir(mode=0o700)
    runroot = Path("/run") / group.name.removesuffix(".service")
    if len(os.fsencode(runroot)) > 50:
        raise ValueError("Private Podman runroot path is too long")
    runroot.mkdir(mode=0o700)
    podman = ["podman", "--cgroup-manager=cgroupfs", "--root", str(storage / "root"),
              "--runroot", str(runroot)]
    record = {
        "schema": 1,
        "passed": False,
        "packages_selected": False,
        "security_qualified": False,
        "os_qualified": False,
        "source_commit": os.environ["GITHUB_SHA"],
        "limits": limits,
        "commands": [],
        "scope": (
            "Authenticated media-only candidates and source RPMs; no package transaction, "
            "program execution, security clearance or OS selection"),
    }
    container = None; pulled = False; base = None

    def save():
        (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60, check=True):
        record["active_command"] = {"name": name, "command": command}; save()
        result = run_bounded(command, evidence / (name + "-stdout.log"),
                             evidence / (name + "-stderr.log"), timeout, 1024 * 1024)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]; save()
        if check:
            result.check_returncode()
        return result

    try:
        pins = unique_json((root / "image/base-images.json").read_bytes())
        render(pins, "generic", root)
        base = pins["variants"]["generic"]
        request, bindings = prepare_inputs(root, inputs, base["image"])
        record.update(base=base["image"], request=request, input_bindings=bindings)
        cosign = bootstrap(root, evidence)
        signature = run("base-signature", [str(cosign), "verify", "--key",
                                             str(root / base["public_key"]),
                                             "--output", "json", base["image"]],
                        BASE_SIGNATURE_TIMEOUT_SECONDS)
        require_subject(unique_json(signature.stdout), base["image"])
        auth = storage / "auth.json"; auth.write_text('{"auths": {}}\n')
        run("pull", podman + ["pull", "--authfile", str(auth), base["image"]],
            BASE_PULL_TIMEOUT_SECONDS)
        pulled = True
        container = "symbi-media-closure"
        run("produce", podman + [
            "run", "--rm", "--name=" + container, "--pull=never", "--user=0", "--read-only",
            "--network=bridge", "--pid=private", "--cgroup-parent=/" + str(group.relative_to("/sys/fs/cgroup")),
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128",
            "--memory=2g", "--memory-swap=2g", "--cpus=1",
            "--mount", f"type=bind,src={inputs},dst=/inputs,ro",
            "--mount", f"type=bind,src={output},dst=/output",
            "--env=PYTHONDONTWRITEBYTECODE=1", "--env=LANG=C.UTF-8",
            "--entrypoint=/usr/bin/python3", base["image"], "/inputs/media_closure.py"],
            PRODUCER_TIMEOUT_SECONDS)
        manifest_path = output / "manifest.json"
        if (manifest_path.is_symlink() or not manifest_path.is_file()
                or not 0 < manifest_path.stat().st_size <= MAX_MEDIA_MANIFEST_BYTES):
            raise ValueError("Missing bounded media closure manifest")
        manifest = unique_json(manifest_path.read_bytes())
        require_candidate_manifest(manifest, request)
        expected = {
            "rpms": {row["filename"]: row for row in manifest["packages"]},
            "srpms": {row["filename"]: row for row in manifest["source_packages"]},
        }
        expanded_bytes = manifest_path.stat().st_size
        for directory, rows in expected.items():
            actual = output / directory
            if actual.resolve() != actual or not actual.is_dir() \
                    or {path.name for path in actual.iterdir()} != set(rows):
                raise ValueError("Media artifact payload differs from its manifest")
            for name, row in rows.items():
                path = actual / name
                if (path.is_symlink() or not path.is_file() or path.resolve() != path
                        or path.stat().st_size != row["bytes"] or digest(path) != row["sha256"]):
                    raise ValueError("Media artifact bytes changed after guest verification")
                expanded_bytes += path.stat().st_size
        if expanded_bytes > MAX_MEDIA_EXPANDED_BYTES:
            raise ValueError("Media artifact payload exceeds its consumer contract")
        record.update(passed=True, packages=len(manifest["packages"]),
                      source_packages=len(manifest["source_packages"]),
                      manifest_sha256=digest(manifest_path),
                      expanded_payload_bytes=expanded_bytes)
        shutil.copyfile(manifest_path, evidence / "manifest.json")
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        stopped = True
        if container:
            removed = run("cleanup-container", podman + ["rm", "--force", "--ignore", container],
                          CLEANUP_CONTAINER_TIMEOUT_SECONDS, check=False)
            absent = run("container-absent", podman + ["container", "exists", container],
                         CONTAINER_ABSENT_TIMEOUT_SECONDS, check=False)
            stopped = removed.returncode == 0 and absent.returncode == 1
            record["container_absent"] = stopped
            if not stopped:
                record["passed"] = False
        if (output / "evidence").is_dir():
            try:
                collect_evidence(output / "evidence", evidence / "guest")
            except Exception as error:
                record["passed"] = False
                record["evidence_failure"] = type(error).__name__ + ": " + str(error)
        if pulled:
            removed = run("remove-image", podman + ["image", "rm", "--force", base["image"]],
                          REMOVE_IMAGE_TIMEOUT_SECONDS, check=False)
            absent = run("image-absent", podman + ["image", "exists", base["image"]],
                         IMAGE_ABSENT_TIMEOUT_SECONDS, check=False)
            record["image_removed"] = removed.returncode == 0 and absent.returncode == 1
            if not record["image_removed"]:
                record["passed"] = False
        if stopped and (not pulled or record.get("image_removed")):
            shutil.rmtree(storage); shutil.rmtree(runroot)
            record["private_storage_removed"] = not storage.exists() and not runroot.exists()
        else:
            record["private_storage_removed"] = False; record["passed"] = False
        for name in ("cache", "state", "log", "keyring", "empty-keyring", "fedora-keyring",
                     "fusion-keyring", "rpmdb", "gnupg", "evidence"):
            path = output / name
            if path.is_dir():
                shutil.rmtree(path)
        if inputs.is_dir():
            shutil.rmtree(inputs)
        record["staged_inputs_removed"] = not inputs.exists()
        if not record["staged_inputs_removed"]:
            record["passed"] = False
        final = {name: (group / name).read_text().strip()
                 for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        record["cgroup_final"] = final
        events = dict(row.split() for row in final["memory.events"].splitlines())
        if (any(final[name] != value for name, value in limits.items())
                or any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill"))):
            record["passed"] = False
        save()
    if not record["passed"]:
        raise RuntimeError("Media closure, resource or cleanup checks failed")


if __name__ == "__main__":
    main()
