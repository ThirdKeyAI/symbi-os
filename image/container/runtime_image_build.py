"""Build and inspect the exact offline container-runtime candidate on hosted CI."""
import json
import os
from pathlib import Path
import re
import shutil

from image.boot.inputs import require_desktop_image
from image.boot.preflight import validate_loaded_image
from image.container.runtime_image_inputs import (
    build_contract, digest, input_inventory, unique_json, validate_install_record,
    validate_selection,
)
from image.container.package_inventory import inventory_digest
from image.launcher.probes.bounded_process import run_bounded
from image.qualification.container_hosted import load_authenticated_runsc, validate_fedora_contract
from image.toolchain.reuse import unique_json as parse_json


LIMITS = {"memory.max": "4294967296", "memory.swap.max": "0",
          "cpu.max": "200000 100000", "pids.max": "256"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Use the disposable hosted runtime-image build unit")
    root = Path.cwd().resolve()
    process = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    group = process.parent
    limits = {name: (group / name).read_text().strip() for name in LIMITS}
    require(process.name == "supervisor" and group.name.startswith("symbi-container-image-build-")
            and group.name.endswith(".service") and not (group / "cgroup.procs").read_text().strip()
            and limits == LIMITS, "unexpected hosted runtime-image build identity or limits")
    evidence = root / ".cache/container-runtime-image-evidence"
    inputs_root = root / ".cache/container-runtime-image-inputs"
    outputs = root / ".cache/container-runtime-image-output"
    outputs.mkdir(mode=0o700)
    prepared = unique_json(evidence / "prepare.json")
    record = {"schema": 1, "phase": "build", "passed": False, "installed": False,
              "qualified": False, "os_qualified": False, "release_qualified": False,
              "source_commit": os.environ["GITHUB_SHA"], "limits": limits,
              "commands": [], "containers": {},
              "scope": "Offline derived development image assembly and read-only inspection; native containment qualification remains open"}

    def save():
        (evidence / "build.json").write_text(json.dumps(record, indent=2) + "\n")

    def run(name, command, timeout=60, check=True):
        record["active_command"] = {"name": name, "command": command}
        save()
        result = run_bounded(command, evidence / (name + "-stdout.log"),
                             evidence / (name + "-stderr.log"), timeout, 1024**2)
        record["commands"].append({"name": name, "exit_code": result.returncode})
        del record["active_command"]
        save()
        if check:
            result.check_returncode()
        return result

    storage = None
    podman = None
    runroot = None
    source_id = None
    candidate_id = None
    probe_name = None
    try:
        require(prepared.get("passed") is True and prepared.get("phase") == "prepare"
                and prepared.get("source_commit") == record["source_commit"]
                and prepared.get("installed") is False and prepared.get("qualified") is False
                and prepared.get("os_qualified") is False and prepared.get("release_qualified") is False,
                "exact hosted runtime-image preparation has not passed")
        context = inputs_root / "context"
        install_inputs = context / "inputs"
        require(input_inventory(install_inputs) == prepared["prepared_inputs"]
                and digest(install_inputs / "install-manifest.json") == prepared["install_manifest_sha256"]
                and digest(context / "Containerfile") == prepared["containerfile_sha256"],
                "prepared runtime-image inputs changed")
        images = unique_json(root / "image/desktop-images.lock.json")
        pins = unique_json(root / "image/base-images.json")
        source_manifest = require_desktop_image(images, pins, "generic")
        source = images["images"]["generic"]
        require(prepared["source_image"] == {
            "tested_commit": source["tested_commit"], "manifest_sha256": source["manifest_sha256"],
            "artifact": source["artifact"], "manifest": source_manifest,
            "producer": unique_json(
                root / "image/container/fedora-runtime-candidates.lock.json")["source_image_producer"]},
            "prepared source image binding changed")
        source_archive = inputs_root / "source-image" / source_manifest["archive"]["name"]
        require(source_archive.is_file() and not source_archive.is_symlink()
                and source_archive.stat().st_size == source_manifest["archive"]["bytes"]
                and digest(source_archive) == source_manifest["archive"]["sha256"],
                "prepared source OCI archive changed")
        source_id = source_manifest["archive"]["image_id"]
        expected_containerfile = (
            "FROM " + source_id + "\n"
            "RUN --mount=type=bind,src=inputs,dst=/symbi-container-inputs,ro "
            "PYTHONDONTWRITEBYTECODE=1 python3 /symbi-container-inputs/install.py\n")
        require((context / "Containerfile").read_text() == expected_containerfile,
                "runtime-image Containerfile changed")

        required = {"cpu", "memory", "pids"}
        require(required.issubset((group / "cgroup.controllers").read_text().split()),
                "hosted build parent lacks delegated resource controllers")
        (group / "cgroup.subtree_control").write_text("+cpu +memory +pids")
        require(required.issubset((group / "cgroup.subtree_control").read_text().split()),
                "hosted build parent did not enable delegated controllers")
        build_group = group / "image-build"
        build_group.mkdir()
        build_limits = {"memory.max": "2147483648", "memory.swap.max": "0",
                        "cpu.max": "100000 100000", "pids.max": "128"}
        for name, value in build_limits.items():
            (build_group / name).write_text(value)
        require({name: (build_group / name).read_text().strip() for name in build_limits} == build_limits,
                "runtime-image build limits did not apply")
        (build_group / "cgroup.subtree_control").write_text("+cpu +memory +pids")
        require(required.issubset((build_group / "cgroup.subtree_control").read_text().split()),
                "runtime-image build subtree controllers are incomplete")
        (build_group / "supervisor").mkdir()

        storage = root / ".cache/container-runtime-image-storage"
        storage.mkdir(mode=0o700)
        install_output = storage / "install-evidence"
        install_output.mkdir(mode=0o700)
        record["disk_free_before_load"] = shutil.disk_usage(storage).free
        require(record["disk_free_before_load"] >= 24 * 1024**3,
                "at least 24 GiB free is required for derived image assembly")
        runroot = Path("/run") / group.name.removesuffix(".service")
        require(len(os.fsencode(runroot)) <= 50, "container runtime path is too long")
        runroot.mkdir(mode=0o700)
        podman = ["podman", "--cgroup-manager=cgroupfs", "--root", str(storage / "root"),
                  "--runroot", str(runroot)]
        run("load-source-image", podman + ["load", "--input", str(source_archive)], 1800)
        loaded = validate_loaded_image(parse_json(
            run("inspect-source-image", podman + ["image", "inspect", source_id]).stdout), source_id)
        record["source_image"] = {key: loaded[key] for key in ("Id", "Digest", "Architecture", "Os")}

        iid = storage / "candidate-id"
        run_group = build_group / "run"
        build_command = ["/usr/bin/python3", "-m", "image.container.enter_build",
                         *podman, "build", "--pull=never", "--network=none",
                         "--isolation=oci", "--jobs=1", "--layers=false", "--force-rm",
                         "--memory=2g", "--memory-swap=2g", "--cpu-period=100000",
                         "--cpu-quota=100000", "--cgroup-parent=/" + str(run_group.relative_to("/sys/fs/cgroup")),
                         "--cap-drop=ALL", "--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP",
                         "--security-opt=no-new-privileges", "--volume",
                         str(install_output) + ":/symbi-container-evidence:rw",
                         "--iidfile", str(iid), "--file", str(context / "Containerfile"), str(context)]
        try:
            run("build-candidate-image", build_command, 1800)
        finally:
            record["image_build_cgroup_final"] = {
                name: (build_group / name).read_text().strip()
                for name in (*build_limits, "memory.peak", "memory.events", "cpu.stat")}
            (build_group / "cgroup.kill").write_text("1")
        candidate_id = iid.read_text().strip()
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", candidate_id or "")
                and candidate_id != source_id, "derived image ID is missing or unchanged")
        candidate = validate_loaded_image(parse_json(
            run("inspect-candidate-image", podman + ["image", "inspect", candidate_id]).stdout), candidate_id)
        record["candidate_image"] = {key: candidate[key] for key in ("Id", "Digest", "Architecture", "Os")}
        install = unique_json(install_output / "result.json")
        install_manifest = unique_json(install_inputs / "install-manifest.json")
        validate_install_record(install, install_manifest["packages"],
                                install_manifest["source_package_plan"],
                                install_manifest["runsc_files"],
                                install_manifest["daemon_configuration"]["sha256"])
        retained_install = evidence / "install"
        retained_install.mkdir()
        for name, expected_hash in (("installed-before-stdout.log", install["before_inventory_sha256"]),
                                    ("installed-after-stdout.log", install["after_inventory_sha256"])):
            source_path = install_output / name
            require(source_path.is_file() and not source_path.is_symlink()
                    and 0 < source_path.stat().st_size <= 1024**2
                    and inventory_digest(source_path.read_bytes()) == expected_hash,
                    "retained package inventory differs from the installation record")
            shutil.copyfile(source_path, retained_install / name)
        shutil.copyfile(install_output / "result.json", retained_install / "result.json")
        record["installation"] = install

        qualification = storage / "qualification"
        qualification.mkdir(mode=0o755)
        expected = {
            "after_inventory_sha256": install["after_inventory_sha256"],
            "source_inventory_sha256": install["source_inventory_sha256"],
            "requested_root_identities": install["requested_root_identities"],
            "runsc_files": install["runsc_files"],
            "daemon_configuration_sha256": install["daemon_configuration_sha256"],
        }
        (qualification / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
        shutil.copyfile(root / "image/container/verify_installed.py", qualification / "verify_installed.py")
        for path in qualification.iterdir():
            path.chmod(0o644)
        probe_name = "symbi-container-runtime-inspect"
        command = podman + ["run", "--rm", "--name=" + probe_name, "--pull=never",
            "--read-only", "--network=none", "--user=10001:10001", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--memory=512m", "--memory-swap=512m",
            "--cpus=1", "--pids-limit=64", "--cgroup-parent=/" + str(group.relative_to("/sys/fs/cgroup")),
            "--mount", "type=bind,src=" + str(qualification) + ",dst=/qualification,ro",
            "--env=PATH=/usr/bin:/bin", "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint=/usr/bin/python3", candidate_id, "/qualification/verify_installed.py"]
        try:
            probe = parse_json(run("inspect-installed-candidate", command, 300).stdout)
        finally:
            removed = run("cleanup-" + probe_name, podman + ["rm", "--force", "--ignore", probe_name], check=False)
            absent = run("absent-" + probe_name, podman + ["container", "exists", probe_name], check=False)
            record["containers"][probe_name] = {"removed": removed.returncode == 0,
                                                "absent": absent.returncode == 1}
        require(probe.get("passed") is True and probe.get("installed") is True
                and probe.get("qualified") is False and probe.get("os_qualified") is False
                and probe.get("release_qualified") is False
                and probe.get("after_inventory_sha256") == install["after_inventory_sha256"]
                and probe.get("source_inventory_sha256") == install["source_inventory_sha256"]
                and probe.get("requested_root_identities") == install["requested_root_identities"]
                and probe.get("daemon_configuration_sha256") == install["daemon_configuration_sha256"],
                "read-only candidate image inspection failed")
        record["inspection"] = probe

        lock = unique_json(root / "image/container/fedora-runtime-candidates.lock.json")
        validate_selection(root, lock)
        summary = prepared["discovery"]["summary"]
        runsc = load_authenticated_runsc(root)
        contract = build_contract(root, lock, summary, install_manifest["packages"], install, runsc)
        validate_fedora_contract(contract, runsc, root, source["tested_commit"])
        contract_path = outputs / "fedora-runtime.lock.json"
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")
        record["contract_sha256"] = digest(contract_path)

        archive = outputs / "symbi-container-runtime-generic.oci.tar"
        run("save-candidate-image", podman + ["save", "--format=oci-archive", "--output",
            str(archive), candidate_id], 1200)
        run("compress-candidate-image", ["gzip", "--no-name", "-1", str(archive)], 1200)
        archive = archive.with_suffix(".tar.gz")
        candidate_archive = {"name": archive.name, "bytes": archive.stat().st_size,
                             "sha256": digest(archive), "image_id": candidate_id,
                             "manifest_digest": candidate["Digest"]}
        manifest = {
            "schema": 1, "built": True, "installed": True, "qualified": False,
            "os_qualified": False, "release_qualified": False,
            "source_commit": record["source_commit"], "source_image_commit": source["tested_commit"],
            "source_image_id": source_id, "archive": candidate_archive,
            "contract_sha256": record["contract_sha256"],
            "scope": "Derived development image with an offline container runtime; native containment qualification remains open",
        }
        (outputs / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        shutil.copyfile(outputs / "manifest.json", evidence / "candidate-manifest.json")
        shutil.copyfile(contract_path, evidence / "fedora-runtime.lock.json")
        record.update(installed=True, candidate_archive=candidate_archive, passed=True)
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if podman is not None:
            pending = run("remaining-build-containers",
                          podman + ["ps", "--all", "--external", "--quiet", "--no-trunc"],
                          check=False)
            identities = pending.stdout.splitlines()
            if (pending.returncode != 0
                    or any(re.fullmatch(r"[a-f0-9]{64}", value) is None for value in identities)):
                record["passed"] = False
            elif identities:
                run("cleanup-build-containers", podman + ["rm", "--force", *identities], check=False)
            absent_containers = run("all-containers-absent",
                                    podman + ["ps", "--all", "--external", "--quiet"], check=False)
            record["all_containers_absent"] = (
                absent_containers.returncode == 0 and not absent_containers.stdout.strip())
            if not record["all_containers_absent"]:
                record["passed"] = False
            for image, label in ((candidate_id, "candidate"), (source_id, "source")):
                if image:
                    removed = run("remove-" + label + "-image",
                                  podman + ["image", "rm", "--force", image], 300, check=False)
                    absent = run("absent-" + label + "-image",
                                 podman + ["image", "exists", image], check=False)
                    record[label + "_image_removed"] = removed.returncode == 0 and absent.returncode == 1
                    if not record[label + "_image_removed"]:
                        record["passed"] = False
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*LIMITS, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(line.split() for line in record["cgroup_final"]["memory.events"].splitlines())
        if (any(record["cgroup_final"][name] != value for name, value in LIMITS.items())
                or any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill"))):
            record["passed"] = False
        save()
        if storage is not None and record.get("candidate_image_removed") and record.get("source_image_removed"):
            shutil.rmtree(storage)
        if runroot is not None and runroot.exists():
            shutil.rmtree(runroot)
    if not record["passed"]:
        raise RuntimeError("container-runtime candidate image or cleanup did not pass")


if __name__ == "__main__":
    main()
