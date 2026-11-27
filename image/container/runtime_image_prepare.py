"""Prepare exact offline inputs for a derived container-runtime image in hosted CI."""
import json
import os
from pathlib import Path
import shutil

from image.boot.inputs import require_desktop_image, unpack_desktop_image
from image.container.runtime_image_inputs import (
    digest, input_inventory, unpack_discovery_artifacts, unique_json,
    validate_artifact_metadata, validate_discovery_records, validate_runsc_tree,
    validate_selection, validate_source_artifact_metadata, validate_source_package_plan,
    validate_source_workflow_metadata, validate_workflow_metadata,
)
from image.launcher.probes.bounded_process import run_bounded
from image.qualification.container_hosted import load_authenticated_runsc


LIMITS = {"memory.max": "1073741824", "memory.swap.max": "0",
          "cpu.max": "100000 100000", "pids.max": "64"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def copy_regular(source, destination, mode=0o600):
    source, destination = Path(source), Path(destination)
    require(source.is_file() and not source.is_symlink(), "prepared input source is not regular")
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists() and not destination.is_symlink(), "prepared input destination exists")
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def main():
    if (os.geteuid() == 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Use the unprivileged disposable hosted runtime-image preparation unit")
    root = Path.cwd().resolve()
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip() for name in LIMITS}
    require(group.name.startswith("symbi-container-image-prep-") and group.name.endswith(".service")
            and limits == LIMITS, "unexpected hosted runtime-image preparation limits")
    evidence = root / ".cache/container-runtime-image-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    destination = root / ".cache/container-runtime-image-inputs"
    record = {"schema": 1, "phase": "prepare", "passed": False, "installed": False,
              "qualified": False, "os_qualified": False, "release_qualified": False,
              "source_commit": os.environ["GITHUB_SHA"], "limits": limits, "commands": [],
              "scope": "Authenticated offline inputs for a derived development image; no installation or qualification"}

    def save():
        (evidence / "prepare.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60):
        record["active_command"] = {"name": name, "command": command}
        save()
        result = run_bounded(command, evidence / (name + "-stdout.log"),
                             evidence / (name + "-stderr.log"), timeout, 1024**2)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]
        save()
        result.check_returncode()
        return result

    try:
        require(not destination.exists() and not destination.is_symlink(),
                "runtime-image input destination already exists")
        free = shutil.disk_usage(root / ".cache").free
        record["disk_free_before_prepare"] = free
        require(free >= 30 * 1024**3, "at least 30 GiB free is required for runtime-image preparation")
        lock = unique_json(root / "image/container/fedora-runtime-candidates.lock.json")
        validate_selection(root, lock)
        run_metadata = unique_json(root / ".cache/container-runtime-run.json")
        candidate_metadata = unique_json(root / ".cache/container-runtime-candidate-artifact.json")
        evidence_metadata = unique_json(root / ".cache/container-runtime-evidence-artifact.json")
        validate_workflow_metadata(run_metadata, lock)
        validate_artifact_metadata(candidate_metadata, lock["candidate_artifact"], lock)
        validate_artifact_metadata(evidence_metadata, lock["evidence_artifact"], lock)
        destination.mkdir(mode=0o700)
        discovery = destination / "discovery"
        summary, bindings, guest = unpack_discovery_artifacts(
            root / ".cache/container-runtime-rpm-candidates.zip",
            root / ".cache/container-runtime-fedora-evidence.zip",
            lock, discovery)
        guest_raw = (discovery / "guest-result.json").read_bytes()
        bindings_raw = (discovery / "input-bindings.json").read_bytes()
        trust = validate_discovery_records(root, lock, summary, bindings, guest,
                                           guest_raw, bindings_raw)
        package_plan = validate_source_package_plan(
            root, lock, guest["installed_root_nevras"])
        for name in ("container-runtime-rpm-candidates.zip", "container-runtime-fedora-evidence.zip"):
            (root / ".cache" / name).unlink()

        images = unique_json(root / "image/desktop-images.lock.json")
        pins = unique_json(root / "image/base-images.json")
        manifest = require_desktop_image(images, pins, "generic")
        selected = images["images"]["generic"]
        image_metadata = unique_json(root / ".cache/atomic-image-artifact.json")
        image_run = unique_json(root / ".cache/atomic-image-run.json")
        artifact = selected["artifact"]
        validate_source_workflow_metadata(image_run, selected, lock)
        validate_source_artifact_metadata(image_metadata, selected, lock)
        source_image = destination / "source-image"
        unpack_desktop_image(root / ".cache/atomic-development-image.zip",
                             images, pins, "generic", source_image)
        (root / ".cache/atomic-development-image.zip").unlink()

        runsc = load_authenticated_runsc(root)
        runsc_deb = destination / "runsc.deb"
        run("download-runsc", ["curl", "--fail", "--silent", "--show-error", "--location",
            "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
            "--connect-timeout", "20", "--max-time", "900", "--limit-rate", "10M",
            "--max-filesize", str(runsc["package_bytes"]), "--output", str(runsc_deb),
            runsc["package_url"]], 910)
        require(runsc_deb.is_file() and not runsc_deb.is_symlink()
                and runsc_deb.stat().st_size == runsc["package_bytes"]
                and digest(runsc_deb) == runsc["package_sha256"],
                "downloaded runsc package differs from signed metadata")
        runsc_root = destination / "runsc-root"
        run("extract-runsc", ["dpkg-deb", "--extract", str(runsc_deb), str(runsc_root)], 300)
        runsc_deb.unlink()
        inventory = unique_json(root / "image/container/hosted/gvisor/package-inventory.json")
        runsc_files = validate_runsc_tree(runsc_root, inventory)
        require({path: row["sha256"] for path, row in runsc_files.items()}
                == runsc["package_files"], "prepared runsc file set differs from authenticated metadata")

        context = destination / "context"
        inputs = context / "inputs"
        inputs.mkdir(parents=True)
        shutil.move(discovery / "rpms", inputs / "rpms")
        shutil.move(runsc_root, inputs / "runsc")
        copy_regular(root / "image/hyprland/keys/fedora-45-primary.asc",
                     inputs / "fedora-45-primary.asc")
        copy_regular(root / "image/container/daemon.json", inputs / "daemon.json")
        copy_regular(root / "image/container/install.py", inputs / "install.py", 0o644)
        copy_regular(root / "image/container/package_inventory.py",
                     inputs / "package_inventory.py", 0o644)
        copy_regular(root / "image/hyprland/resolve_packages.py", inputs / "resolve_packages.py", 0o644)
        copy_regular(root / "image/launcher/probes/bounded_process.py", inputs / "bounded_process.py", 0o644)
        daemon = inputs / "daemon.json"
        install_manifest = {
            "schema": 1, "qualified": False, "os_qualified": False, "release_qualified": False,
            "packages": guest["packages"], "source_package_plan": package_plan,
            "key": {"fingerprint": trust["key"]["fingerprint"], "sha256": trust["key"]["sha256"]},
            "runsc_files": runsc_files,
            "daemon_configuration": {"bytes": daemon.stat().st_size, "sha256": digest(daemon), "mode": 0o644},
        }
        (inputs / "install-manifest.json").write_text(json.dumps(install_manifest, indent=2) + "\n")
        (context / "Containerfile").write_text(
            "FROM " + manifest["archive"]["image_id"] + "\n"
            "RUN --mount=type=bind,src=inputs,dst=/symbi-container-inputs,ro "
            "PYTHONDONTWRITEBYTECODE=1 python3 /symbi-container-inputs/install.py\n")
        record.update(
            discovery={
                "run": {"id": lock["run_id"], "attempt": lock["run_attempt"],
                        "source_commit": lock["source_commit"]},
                "candidate_artifact": lock["candidate_artifact"],
                "evidence_artifact": lock["evidence_artifact"],
                "summary": summary,
                "packages": guest["packages"],
            },
            source_package_plan=package_plan,
            source_image={"tested_commit": selected["tested_commit"],
                          "manifest_sha256": selected["manifest_sha256"],
                          "artifact": artifact, "manifest": manifest,
                          "producer": lock["source_image_producer"]},
            runsc=runsc,
            runsc_files=runsc_files,
            install_manifest_sha256=digest(inputs / "install-manifest.json"),
            containerfile_sha256=digest(context / "Containerfile"),
            prepared_inputs=input_inventory(inputs),
            passed=True,
        )
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*LIMITS, "memory.peak", "memory.events", "cpu.stat")}
        save()


if __name__ == "__main__":
    main()
