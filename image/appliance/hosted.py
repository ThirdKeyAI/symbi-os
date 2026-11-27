"""Prepare two isolated containers for appliance production and cold reboot."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import re
import sys

from image.appliance.contract import (ARTIFACT_NAME, SDDM_CONFIGURATION, SCOPE,
                                      build_manifest, controller_failure_record, sha256,
                                      unique_json, validate_reboot_report,
                                      validate_source_binding)


COMPONENT_PATHS = (
    "usr/bin/Hyprland",
    "usr/lib/symbi/hyprland/bin/Hyprland",
    "usr/bin/walker",
    "usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland",
    "usr/lib/systemd/user/xdg-desktop-portal-hyprland.service",
)
PACKAGE_NAMES = ("sddm", "sddm-wayland-sway", "waybar")
RESOURCE_LIMIT_KEYS = {"memory.max", "memory.swap.max", "cpu.max", "pids.max"}
RESOURCE_FINAL_KEYS = RESOURCE_LIMIT_KEYS | {"memory.peak", "memory.events", "cpu.stat"}


def source_tree(root, commit):
    """Resolve the exact committed tree without incorporating working-tree bytes."""
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("Exact appliance source commit required")
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", commit + "^{tree}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
        check=True,
    )
    value = result.stdout.strip()
    if result.stderr or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("Exact appliance source tree unavailable")
    return value


def _resource_receipt(path):
    """Retain only bounded cgroup facts; never copy arbitrary child output."""
    if not path.exists() or path.is_symlink():
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256*1024:
        return None
    try:
        value = unique_json(path.read_bytes())
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    limits, final = value.get("limits"), value.get("cgroup_final")
    if (not isinstance(limits, dict) or set(limits) != RESOURCE_LIMIT_KEYS
            or not isinstance(final, dict) or set(final) != RESOURCE_FINAL_KEYS):
        return None
    fields = list(limits.values()) + list(final.values())
    if any(not isinstance(item, str) or not 0 < len(item) <= 4096 for item in fields):
        return None
    return {"limits": limits, "cgroup_final": final}


def _remove_local_output(path):
    """Remove one known cache output without following a link."""
    try:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
        return not path.exists() and not path.is_symlink()
    except OSError:
        return False


def _write_controller_record(evidence, record):
    info = evidence.lstat()
    target = evidence / "result.json"
    if (evidence.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or target.is_symlink()):
        raise ValueError("Unsafe appliance controller evidence directory")
    target.write_text(json.dumps(record, indent=2) + "\n")


def _prune_failure_evidence(evidence):
    """Remove stale child claims before retaining one controller failure receipt."""
    try:
        info = evidence.lstat()
    except OSError:
        return False
    if evidence.is_symlink() or not stat.S_ISDIR(info.st_mode):
        return False
    removed = [_remove_local_output(path) for path in tuple(evidence.iterdir())]
    return all(removed) and not any(evidence.iterdir())


def _new_directory(path, mode=0o700, owner=None):
    if path.exists() or path.is_symlink():
        raise ValueError("Appliance path must be new: " + str(path))
    path.mkdir(mode=mode, parents=True)
    if owner is not None:
        os.chown(path, owner, owner)


def _copy_regular(source, target):
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 512*1024:
        raise ValueError("Invalid appliance program input: " + str(source))
    shutil.copyfile(source, target)
    target.chmod(0o644)


def _retained_artifact(path, expected=None):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink()
            or not 0 < info.st_size <= 24*1024**3):
        raise ValueError("Appliance artifact is not one bounded regular qcow2")
    value = {
        "name": ARTIFACT_NAME, "bytes": info.st_size, "sha256": sha256(path),
        "format": "qcow2", "compression": "qcow2-zlib-clusters",
        "virtual_bytes": 24*1024**3,
    }
    if expected is not None and value != expected:
        raise ValueError("Appliance artifact changed after producer validation")
    return value


def _copy_public_evidence(source, destination):
    for path in sorted(source.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(source)
        if (path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1
                or path.stat().st_size > 4*1024**2):
            raise ValueError("Unsafe appliance evidence output: " + str(relative))
        data = path.read_bytes()
        if any(token in data for token in (b"PRIVATE KEY-----", b"ssh-rsa ", b"ssh-ed25519 ")):
            raise ValueError("Credential-like material refused from appliance evidence")
        target = destination / str(relative).replace("/", "-")
        target.write_bytes(data)


def _installed_desktop_bindings(root, source):
    """Read component identities from the exact preparation bound by the image lock."""
    lock = unique_json((root / "image/desktop-images.lock.json").read_bytes())
    selected = lock.get("images", {}).get("generic")
    manifest = selected.get("manifest") if isinstance(selected, dict) else None
    artifact = selected.get("artifact") if isinstance(selected, dict) else None
    if (not isinstance(manifest, dict) or not isinstance(artifact, dict)
            or selected.get("tested_commit") != source["image_source_commit"]
            or selected.get("run_id") != source["image_run_id"]
            or artifact.get("id") != source["image_artifact_id"]
            or artifact.get("sha256") != source["image_artifact_sha256"]):
        raise ValueError("Appliance source differs from the current generic image lock")
    evidence = root / "docs/security/reports/P0-03-desktop" / str(selected["run_id"])
    if evidence.resolve() != evidence:
        raise ValueError("Linked retained desktop evidence path")
    preparation_path = evidence / "preparation.json"
    preparation_info = preparation_path.lstat()
    if (preparation_path.is_symlink() or not stat.S_ISREG(preparation_info.st_mode)
            or preparation_info.st_nlink != 1 or preparation_info.st_size > 4*1024**2):
        raise ValueError("Unsafe retained desktop preparation")
    raw = preparation_path.read_bytes()
    preparation_sha = manifest.get("preparation_sha256")
    if sha256(preparation_path) != preparation_sha:
        raise ValueError("Desktop preparation differs from the locked generic image")
    prepared = unique_json(raw)
    payload = prepared.get("payload")
    overlay = prepared.get("overlay")
    if (prepared.get("passed") is not True or prepared.get("variant") != "generic"
            or prepared.get("source_commit") != source["image_source_commit"]
            or not isinstance(payload, dict) or not isinstance(overlay, dict)):
        raise ValueError("Retained generic desktop preparation is incomplete")

    component_files = {}
    for name in COMPONENT_PATHS:
        value = payload.get(name)
        if not isinstance(value, dict):
            raise ValueError("Missing retained desktop component: " + name)
        if name == "usr/bin/Hyprland":
            if value != {"link": "../lib/symbi/hyprland/bin/Hyprland"}:
                raise ValueError("Hyprland launcher link changed")
        elif (set(value) != {"sha256", "bytes", "mode"}
              or not isinstance(value["sha256"], str) or len(value["sha256"]) != 64
              or type(value["bytes"]) is not int or value["bytes"] <= 0
              or type(value["mode"]) is not int):
            raise ValueError("Malformed retained desktop component: " + name)
        component_files["/" + name] = value

    production_names = (
        "usr/share/wayland-sessions/symbi.desktop",
        "usr/libexec/symbi-seed-config",
        "usr/libexec/symbi-desktop-session",
    )
    production_files = {}
    for name in production_names:
        value = overlay.get(name)
        if (not isinstance(value, dict) or set(value) != {"sha256", "bytes", "mode"}):
            raise ValueError("Missing retained desktop overlay input: " + name)
        production_files["/" + name] = value
    seed_files = {}
    prefix = "usr/share/symbiont/defaults/"
    for name, value in sorted(overlay.items()):
        if name.startswith(prefix):
            if (not isinstance(value, dict) or set(value) != {"sha256", "bytes", "mode"}):
                raise ValueError("Malformed retained first-login input: " + name)
            seed_files[name.removeprefix(prefix)] = value
    if not seed_files:
        raise ValueError("Retained first-login defaults are absent")

    inventory_path = evidence / "install/installed-after-stdout.log"
    inventory_info = inventory_path.lstat()
    if (inventory_path.is_symlink() or not stat.S_ISREG(inventory_info.st_mode)
            or inventory_info.st_nlink != 1 or inventory_info.st_size > 1024**2):
        raise ValueError("Unsafe retained package inventory")
    inventory = inventory_path.read_text().splitlines()
    if len(inventory) != len(set(inventory)):
        raise ValueError("Duplicate retained package identity")
    package_identities = {}
    for name in PACKAGE_NAMES:
        matches = [line for line in inventory if line.split("\t", 1)[0] == name]
        if len(matches) != 1 or len(matches[0].split("\t")) != 5:
            raise ValueError("Missing retained desktop package identity: " + name)
        package_identities[name] = matches[0]
    return {
        "preparation_sha256": preparation_sha,
        "files": component_files,
        "packages": package_identities,
        "production_files": production_files,
        "seed_files": seed_files,
    }


def _produce_appliance(root, group, podman, image_id, disk, source, containers, run,
                       evidence, stage, artifact_output, progress):
    """Run the appliance producer while the public wrapper owns fail-closed cleanup."""
    progress["stage"] = "fixture-preparation"
    stage = root / ".cache/interactive-appliance-stage"
    _new_directory(stage, owner=10001)
    program = stage / "program"
    output = stage / "output"
    _new_directory(program, owner=10001)
    _new_directory(output, owner=10001)
    installed = _installed_desktop_bindings(root, source)
    expected = {
        "schema": 1, "nonce": secrets.token_hex(16), "username": "symbi-test",
        "source_binding": source,
        "sddm_config_sha256": hashlib.sha256(SDDM_CONFIGURATION.encode()).hexdigest(),
        "production_files": installed["production_files"],
        "seed_files": installed["seed_files"],
        "desktop_components": {
            "preparation_sha256": installed["preparation_sha256"],
            "files": installed["files"], "packages": installed["packages"],
        },
    }
    for name in ("contract.py", "producer.py", "reboot.py", "p.service", "v.service",
                 "provision.py", "verify.py"):
        _copy_regular(root / "image/appliance" / name, program / name)
    (program / "expected.json").write_text(json.dumps(expected, sort_keys=True) + "\n")
    (program / "expected.json").chmod(0o644)
    raw_before = sha256(disk)
    if raw_before != source["installed_raw_sha256"]:
        raise ValueError("Installed appliance disk changed before conversion")
    parent = "/" + str(group.relative_to("/sys/fs/cgroup"))
    common = ["--pull=never", "--network=none", "--pid=private", "--read-only",
              "--user=10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
              "--memory=3g", "--memory-swap=3g", "--cpus=2", "--pids-limit=64",
              "--cgroup-parent=" + parent, "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1"]
    producer_name = "symbi-interactive-appliance-producer"
    containers.append(producer_name)
    producer_command = podman + ["run", "--rm", "--name=" + producer_name, *common,
        "--mount", f"type=bind,src={program},dst=/inputs,ro",
        "--mount", f"type=bind,src={disk},dst=/inputs/atomic.raw,ro",
        "--mount", f"type=bind,src={output},dst=/output",
        "--entrypoint=/usr/bin/python3", image_id, "/inputs/producer.py"]
    progress["stage"] = "producer"
    try:
        run("interactive-appliance-producer", producer_command, 3000)
        progress["stage"] = "artifact-validation"
        producer = unique_json((output / "result.json").read_bytes())
        artifact_path = output / "public" / ARTIFACT_NAME
        artifact = _retained_artifact(artifact_path, producer.get("artifact"))
        if (producer.get("passed") is not True or producer.get("source_binding") != source
                or producer.get("independent_reboot_passed") is not False
                or producer.get("os_qualified") is not False
                or producer.get("release_qualified") is not False
                or producer.get("signature_qualified") is not False):
            raise ValueError("Appliance producer result is incomplete")
        if sha256(disk) != raw_before:
            raise ValueError("Read-only installed raw disk changed during production")
        progress["stage"] = "reboot-preparation"
        reboot_program = stage / "reboot-program"
        reboot_output = stage / "reboot-output"
        _new_directory(reboot_program, owner=10001)
        _new_directory(reboot_output, owner=10001)
        for name in ("contract.py", "reboot.py"):
            _copy_regular(root / "image/appliance" / name, reboot_program / name)
        reboot_expected = {"schema": 1, "source_binding": source, "artifact": artifact}
        (reboot_program / "expected.json").write_text(json.dumps(reboot_expected, sort_keys=True) + "\n")
        (reboot_program / "expected.json").chmod(0o644)
        reboot_name = "symbi-interactive-appliance-reboot"
        containers.append(reboot_name)
        reboot_command = podman + ["run", "--rm", "--name=" + reboot_name, *common,
            "--mount", f"type=bind,src={reboot_program},dst=/program,ro",
            "--mount", f"type=bind,src={artifact_path},dst=/inputs/retained.qcow2,ro",
            "--mount", f"type=bind,src={reboot_output},dst=/output",
            "--entrypoint=/usr/bin/python3", image_id, "/program/reboot.py"]
        artifact_before = _retained_artifact(artifact_path, artifact)
        progress["stage"] = "reboot"
        run("interactive-appliance-reboot", reboot_command, 1200)
        artifact_after = _retained_artifact(artifact_path, artifact)
        if artifact_before != artifact_after:
            raise ValueError("Retained appliance bytes changed across the read-only reboot")
        reboot = unique_json((reboot_output / "result.json").read_bytes())
        validate_reboot_report(reboot, source, artifact)
        display = reboot_output / "display.ppm"
        display_info = display.lstat()
        if (display.is_symlink() or not stat.S_ISREG(display_info.st_mode)
                or display_info.st_nlink != 1
                or display_info.st_size != reboot["screenshot"]["bytes"]
                or sha256(display) != reboot["screenshot"]["sha256"]):
            raise ValueError("Retained display evidence differs from its source-bound report")
        progress["stage"] = "retention"
        manifest = build_manifest(source, artifact, producer, reboot)
        (output / "public/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        _copy_public_evidence(output / "evidence", evidence)
        _copy_public_evidence(reboot_output, evidence)
        if sha256(evidence / "display.ppm") != reboot["screenshot"]["sha256"]:
            raise ValueError("Copied display evidence differs from its source-bound report")
        shutil.copyfile(evidence / "display.ppm", output / "public/display.ppm")
        if sha256(output / "public/display.ppm") != reboot["screenshot"]["sha256"]:
            raise ValueError("Retained display artifact differs from its source-bound report")
        shutil.copyfile(output / "result.json", evidence / "producer-result.json")
        if artifact_output.exists() or artifact_output.is_symlink():
            raise ValueError("Final appliance artifact directory must be new")
        os.replace(output / "public", artifact_output)
        final = {
            "schema": 1, "passed": True, "guest_booted": True,
            "graphical_desktop_observed": True, "artifact_retained": True,
            "independent_reboot_passed": True, "os_qualified": False,
            "release_qualified": False, "signature_qualified": False,
            "source_binding": source, "artifact": artifact,
            "manifest_sha256": sha256(artifact_output / "manifest.json"), "scope": SCOPE,
        }
        _write_controller_record(evidence, final)
        return final
    except Exception:
        raise


def produce_appliance(root, group, podman, image_id, disk, source_binding, containers, run):
    """Return a passed development result only after the retained-byte reboot."""
    source = validate_source_binding(source_binding)
    evidence = root / ".cache/interactive-appliance-evidence"
    stage = root / ".cache/interactive-appliance-stage"
    artifact_output = root / ".cache/interactive-appliance-artifact"
    _new_directory(evidence)
    progress = {"stage": "initialization"}
    try:
        result = _produce_appliance(
            root, group, podman, image_id, disk, source, containers, run,
            evidence, stage, artifact_output, progress,
        )
        progress["stage"] = "cleanup"
        if not _remove_local_output(stage):
            raise RuntimeError("Appliance stage cleanup incomplete")
        return result
    except Exception as error:
        resources = {}
        if stage.exists() and not stage.is_symlink():
            for name, path in (
                ("producer", stage / "output/result.json"),
                ("reboot", stage / "reboot-output/result.json"),
            ):
                receipt = _resource_receipt(path)
                if receipt is not None:
                    resources[name] = receipt
        cleanup = {
            "stage_directory_removed": _remove_local_output(stage),
            "user_artifact_absent": _remove_local_output(artifact_output),
            "screenshot_artifact_absent": _remove_local_output(evidence / "display.ppm"),
            "non_controller_evidence_removed": _prune_failure_evidence(evidence),
        }
        failure = controller_failure_record(
            source, progress["stage"], type(error).__name__, cleanup, resources,
        )
        _write_controller_record(evidence, failure)
        raise


def invalidate_appliance_output(root, source_binding):
    """Revoke a previously passed appliance result after an outer-controller failure."""
    source = validate_source_binding(source_binding)
    evidence = root / ".cache/interactive-appliance-evidence"
    cleanup = {
        "stage_directory_removed": _remove_local_output(
            root / ".cache/interactive-appliance-stage"),
        "user_artifact_absent": _remove_local_output(
            root / ".cache/interactive-appliance-artifact"),
        "screenshot_artifact_absent": _remove_local_output(evidence / "display.ppm"),
        "non_controller_evidence_removed": _prune_failure_evidence(evidence),
    }
    failure = controller_failure_record(
        source, "cleanup", "AtomicControllerFailure", cleanup, {},
    )
    _write_controller_record(evidence, failure)
    return failure


def finalize_failed_appliance_evidence(root):
    """Leave only one exact failure receipt after any outer-controller failure."""
    evidence = root / ".cache/interactive-appliance-evidence"
    artifact_output = root / ".cache/interactive-appliance-artifact"
    result_path = evidence / "result.json"
    try:
        evidence_info = evidence.lstat()
        if evidence.is_symlink() or not stat.S_ISDIR(evidence_info.st_mode):
            raise ValueError("Unsafe appliance failure evidence")
        info = result_path.lstat()
        if (result_path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > 256*1024):
            raise ValueError("Unsafe appliance failure result")
        result = unique_json(result_path.read_bytes())
        source = validate_source_binding(result.get("source_binding"))
    except (OSError, ValueError, json.JSONDecodeError):
        _remove_local_output(evidence)
        _remove_local_output(artifact_output)
        return False
    try:
        exact = controller_failure_record(
            source, result.get("stage"), result.get("failure"),
            result.get("cleanup"), result.get("resources"),
        )
    except ValueError:
        exact = None
    children = tuple(path.name for path in evidence.iterdir())
    if (result == exact and children == ("result.json",)
            and not artifact_output.exists() and not artifact_output.is_symlink()):
        return True
    invalidate_appliance_output(root, source)
    return True


def main():
    if (sys.argv[1:] != ["--sanitize-failure"] or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Use only the hosted failed-appliance sanitizer")
    if not finalize_failed_appliance_evidence(Path.cwd().resolve()):
        raise SystemExit("No source-bound appliance failure receipt was available")


if __name__ == "__main__":
    main()
