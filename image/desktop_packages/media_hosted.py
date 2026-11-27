"""Load one exact retained image and run an unprivileged offline media probe."""
import json
import os
from pathlib import Path
import re
import shutil

from image.boot.inputs import require_desktop_image
from image.boot.preflight import validate_loaded_image
from image.desktop_packages.media_contract import (
    media_selection_digest, require_media_image_binding, require_media_lock)
from image.desktop_packages.media_playback import require_playback_report
from image.launcher.probes.bounded_process import run_bounded
from image.toolchain.reuse import digest, unique_json


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.geteuid() != 0):
        raise SystemExit("Use the disposable hosted media playback unit")
    root = Path.cwd().resolve()
    process = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    group = process.parent
    if (process.name != "supervisor" or not group.name.startswith("symbi-media-playback-")
            or not group.name.endswith(".service") or (group / "cgroup.procs").read_text().strip()):
        raise ValueError("Unexpected media playback resource unit")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    if limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                  "cpu.max": "100000 100000", "pids.max": "128"}:
        raise ValueError("Unexpected media playback controller limits")
    required = {"cpu", "memory", "pids"}
    if not required.issubset((group / "cgroup.controllers").read_text().split()):
        raise ValueError("Hosted parent lacks delegated resource controllers")
    (group / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    if not required.issubset((group / "cgroup.subtree_control").read_text().split()):
        raise ValueError("Hosted parent did not enable resource controllers")
    variant = os.environ["SYMBI_IMAGE_VARIANT"]
    pins = unique_json((root / "image/base-images.json").read_bytes())
    images = unique_json((root / "image/desktop-images.lock.json").read_bytes())
    manifest = require_desktop_image(images, pins, variant)
    selected = images["images"][variant]
    media = unique_json((root / "image/desktop_packages/media-rpms.lock.json").read_bytes())
    trust = unique_json((root / "image/desktop_packages/trust.json").read_bytes())
    require_media_lock(media, root, pins, trust, require_ready=True)
    selection_sha256 = media_selection_digest(media)
    require_media_image_binding(media, manifest, selected["tested_commit"])
    prepared = unique_json((root / ".cache/atomic-image-evidence/prepare.json").read_bytes())
    if (prepared.get("passed") is not True or prepared.get("variant") != variant
            or prepared.get("image_source_commit") != selected["tested_commit"]):
        raise ValueError("Current exact retained image preparation has not passed")
    inputs = root / ".cache/atomic-image-inputs"
    archive = inputs / manifest["archive"]["name"]
    if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size != manifest["archive"]["bytes"]
            or digest(archive) != manifest["archive"]["sha256"]):
        raise ValueError("Prepared OCI image bytes changed")
    evidence = root / ".cache/media-playback-evidence"; evidence.mkdir(parents=True, exist_ok=True)
    storage = root / ".cache/media-playback-storage"; storage.mkdir(mode=0o700)
    runroot = Path("/run") / group.name.removesuffix(".service")
    if len(os.fsencode(runroot)) > 50:
        raise ValueError("Private media Podman runroot path is too long")
    runroot.mkdir(mode=0o700)
    podman = ["podman", "--cgroup-manager=cgroupfs", "--root", str(storage / "root"),
              "--runroot", str(runroot)]
    record = {"schema": 1, "passed": False, "os_qualified": False, "release_qualified": False,
              "variant": variant, "source_commit": os.environ["GITHUB_SHA"],
              "image_source_commit": selected["tested_commit"], "limits": limits, "commands": [],
              "image_lock_sha256": digest(root / "image/desktop-images.lock.json"),
              "media_lock_sha256": digest(root / "image/desktop_packages/media-rpms.lock.json"),
              "media_selection_sha256": selection_sha256,
              "scope": "Headless offline MPlayer/mpv software decode on an exact retained development image"}
    target = evidence / "result.json"

    def save():
        target.write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60, check=True):
        record["active_command"] = {"name": name, "command": command}; save()
        result = run_bounded(command, evidence / (name + "-stdout.log"), evidence / (name + "-stderr.log"),
                             timeout, 1024 * 1024)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]; save()
        if check:
            result.check_returncode()
        return result

    image_id = manifest["archive"]["image_id"]
    container = "symbi-media-playback-" + variant
    loaded = False
    output = storage / "output"
    qualification = storage / "qualification"
    try:
        if shutil.disk_usage(storage).free < 20 * 1024**3:
            raise ValueError("Need at least 20 GiB free before loading the retained image")
        run("load-image", podman + ["load", "--input", str(archive)], 1800); loaded = True
        inspected = unique_json(run("inspect-image", podman + ["image", "inspect", image_id]).stdout)
        validate_loaded_image(inspected, image_id)
        qualification.mkdir(mode=0o755); output.mkdir(mode=0o755); os.chown(output, 10001, 10001)
        expected = {"schema": 1, "variant": variant, "lock_sha256": record["media_lock_sha256"],
                    "root_packages": media["root_packages"]}
        (qualification / "expected.json").write_text(json.dumps(expected) + "\n")
        for source, name in ((root / "image/desktop_packages/media_playback.py", "media_playback.py"),
                             (root / "image/launcher/probes/bounded_process.py", "bounded_process.py")):
            shutil.copyfile(source, qualification / name); (qualification / name).chmod(0o644)
        record["probe_sha256"] = digest(qualification / "media_playback.py")
        command = podman + ["run", "--name=" + container, "--pull=never", "--read-only", "--network=none",
            "--user=10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=64",
            "--cgroup-parent=/" + str(group.relative_to("/sys/fs/cgroup")),
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=700,uid=10001,gid=10001",
            "--mount", f"type=bind,src={qualification},dst=/qualification,ro",
            "--mount", f"type=bind,src={output},dst=/output",
            "--env=HOME=/output", "--env=LANG=C.UTF-8", "--env=PATH=/usr/bin:/bin",
            "--env=PYTHONDONTWRITEBYTECODE=1", "--entrypoint=/usr/bin/python3", image_id,
            "/qualification/media_playback.py"]
        run("playback", command, 300)
        report_path = output / "result.json"
        if (report_path.is_symlink() or not report_path.is_file() or not 0 < report_path.stat().st_size <= 128 * 1024):
            raise ValueError("Missing bounded playback report")
        report = unique_json(report_path.read_bytes())
        require_playback_report(report, variant, record["media_lock_sha256"], media["root_packages"])
        shutil.copyfile(report_path, evidence / "playback-result.json")
        record["playback"] = report
        record["passed"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        removed = run("cleanup-container", podman + ["rm", "--force", "--ignore", container], check=False)
        absent = run("container-absent", podman + ["container", "exists", container], check=False)
        record["container_absent"] = removed.returncode == 0 and absent.returncode == 1
        if not record["container_absent"]:
            record["passed"] = False
        if loaded:
            removed = run("remove-image", podman + ["image", "rm", "--force", image_id], 300, check=False)
            absent = run("image-absent", podman + ["image", "exists", image_id], check=False)
            record["image_removed"] = removed.returncode == 0 and absent.returncode == 1
            if not record["image_removed"]:
                record["passed"] = False
        pending = run("remaining-containers", podman + ["ps", "--all", "--external", "--quiet", "--no-trunc"],
                      check=False)
        if pending.returncode != 0 or any(not re.fullmatch(r"[0-9a-f]{64}", row) for row in pending.stdout.splitlines()):
            record["passed"] = False
        if record.get("container_absent") and (not loaded or record.get("image_removed")) and not pending.stdout.strip():
            shutil.rmtree(storage); shutil.rmtree(runroot)
            record["private_storage_removed"] = not storage.exists() and not runroot.exists()
        else:
            record["private_storage_removed"] = False; record["passed"] = False
        if inputs.is_dir():
            shutil.rmtree(inputs)
        record["verified_oci_removed"] = not inputs.exists()
        if not record["verified_oci_removed"]:
            record["passed"] = False
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                   for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(row.split() for row in record["cgroup_final"]["memory.events"].splitlines())
        if (any(record["cgroup_final"][name] != value for name, value in limits.items())
                or any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill"))):
            record["passed"] = False
        save()
    if not record["passed"]:
        raise RuntimeError("Media playback or cleanup did not pass")


if __name__ == "__main__":
    main()
