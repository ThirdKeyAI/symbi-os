"""Fail-closed contract for the hosted interactive development appliance."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re


USERNAME = "symbi-test"
ARTIFACT_NAME = "symbi-os-highly-experimental-generic.qcow2"
VIRTUAL_DISK_BYTES = 24 * 1024**3
RETENTION_DAYS = 2
APPLIANCE_CONTAINER_MEMORY_BYTES = 4 * 1024**3
APPLIANCE_CONTROLLER_MEMORY_BYTES = 5 * 1024**3
APPLIANCE_CONTROLLER_MARGIN_BYTES = (
    APPLIANCE_CONTROLLER_MEMORY_BYTES - APPLIANCE_CONTAINER_MEMORY_BYTES
)
APPLIANCE_CONTAINER_LIMITS = {
    "memory.max": str(APPLIANCE_CONTAINER_MEMORY_BYTES),
    "memory.swap.max": "0",
    "cpu.max": "200000 100000",
    "pids.max": "64",
}
FAILURE_LOG_BOUNDS = {
    "producer": {
        "provision-qemu.log": 2 * 1024**2,
        "provision-serial.log": 4 * 1024**2,
    },
    "reboot": {
        "reboot-qemu.log": 2 * 1024**2,
        "reboot-serial.log": 4 * 1024**2,
    },
}
FAILURE_EXCERPT_BYTES = 16 * 1024
SCOPE = (
    "HIGHLY EXPERIMENTAL offline development appliance; no release, signature, "
    "security, containment or production-account qualification"
)
CONTROLLER_STAGES = frozenset({
    "initialization", "fixture-preparation", "producer", "artifact-validation",
    "reboot-preparation", "reboot", "retention", "cleanup",
})
SDDM_CONFIGURATION = """# HIGHLY EXPERIMENTAL disposable development appliance only.
# This locked account has no password or key and is not present in the product image.
[Autologin]
User=symbi-test
Session=symbi.desktop
Relogin=true
"""


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key: " + key)
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Expected one JSON object")
    return value


def exact_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is not None


def installer_arguments(manifest_digest):
    if (not isinstance(manifest_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest) is None):
        raise ValueError("Exact OCI manifest digest required")
    return [
        "/usr/bin/bootc", "install", "to-disk",
        "--source-imgref=dir:/inputs/signed",
        "--target-imgref=ghcr.io/thirdkeyai/symbiont-os@" + manifest_digest,
        "--enforce-container-sigpolicy", "--filesystem=btrfs", "--generic-image",
        "--via-loopback", "--karg=console=ttyS0,115200n8", "--karg=selinux=1",
        "--karg=enforcing=1", "--karg=systemd.unit=graphical.target",
        "--karg=systemd.wants=p.service", "--karg=systemd.wants=v.service",
        "/output/atomic.raw",
    ]


def firmware_arguments(directory=Path("/inputs")):
    if directory != Path("/inputs"):
        raise ValueError("Fixed read-only firmware input mount required")
    files = (
        ("systemd.extra-unit.p.service", "p.service"),
        ("systemd.extra-unit.v.service", "v.service"),
        ("symbi-provision.py", "provision.py"),
        ("symbi-verify.py", "verify.py"),
        ("symbi-expected.json", "expected.json"),
    )
    result = []
    for credential, filename in files:
        name = "opt/io.systemd.credentials/" + credential
        if len(name.encode("ascii")) >= 56:
            raise ValueError("QEMU firmware credential name is too long")
        result += ["-fw_cfg", f"name={name},file={directory / filename}"]
    return result


def interactive_devices():
    return [
        "-device", "virtio-vga,id=symbi-display",
        "-device", "virtio-keyboard-pci,id=symbi-keyboard",
        "-device", "virtio-tablet-pci,id=symbi-pointer",
        "-device", "virtio-rng-pci,id=symbi-rng",
    ]


def provision_qemu_arguments():
    return [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=multi", "-cpu", "max", "-m", "2048M", "-smp",
        "cpus=2,sockets=1,cores=2,threads=1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Interactive-Appliance",
        "-drive", "file=/output/work/provisioned.qcow2,format=qcow2,if=none,id=symbi-disk",
        "-device", "virtio-blk-pci,drive=symbi-disk,id=symbi-root",
        *interactive_devices(),
        "-device", "virtio-serial-pci,id=symbi-serial",
        "-chardev", "file,id=report,path=/output/evidence/guest-report.json",
        "-device", "virtserialport,chardev=report,name=org.symbi.appliance",
        "-serial", "file:/output/evidence/provision-serial.log",
        "-monitor", "none", "-display", "none",
        *firmware_arguments(),
    ]


def reboot_qemu_arguments():
    return [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=multi", "-cpu", "max", "-m", "2048M", "-smp",
        "cpus=2,sockets=1,cores=2,threads=1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Interactive-Appliance-Reboot",
        "-drive", "file=/output/reboot-overlay.qcow2,format=qcow2,if=none,id=symbi-disk",
        "-device", "virtio-blk-pci,drive=symbi-disk,id=symbi-root",
        *interactive_devices(),
        "-serial", "file:/output/reboot-serial.log", "-monitor", "none",
        "-qmp", "unix:/output/qmp.sock,server=on,wait=off", "-display", "none",
    ]


def user_launch_arguments(filename=ARTIFACT_NAME):
    if filename != ARTIFACT_NAME:
        raise ValueError("Fixed appliance filename required")
    return [
        "qemu-system-x86_64", "-machine", "q35", "-accel", "kvm", "-cpu", "host",
        "-m", "4096M", "-smp", "4", "-nodefaults", "-no-user-config", "-net", "none",
        "-drive", f"file={filename},format=qcow2,if=virtio",
        *interactive_devices(), "-display", "gtk,gl=off",
    ]


def failure_record(source_binding, reason):
    return {
        "schema": 1, "passed": False, "guest_booted": False,
        "graphical_desktop_observed": False, "artifact_retained": False,
        "independent_reboot_passed": False, "os_qualified": False,
        "release_qualified": False, "signature_qualified": False,
        "source_binding": source_binding, "scope": SCOPE,
        "failure": reason,
    }


def _safe_diagnostic_text(value, maximum):
    """Accept only bounded printable text after the controller has redacted it."""
    if not isinstance(value, str):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    if not 0 < len(encoded) <= maximum:
        return False
    if any(
        (ord(character) < 32 and character not in "\n\t")
        or 127 <= ord(character) <= 159
        for character in value
    ):
        return False
    lower = value.lower()
    forbidden = (
        "-----begin private key-----", "-----begin rsa private key-----",
        "-----begin openssh private key-----", "authorization: bearer ",
        "authorization: basic ",
        "github_pat_", "ghp_", "glpat-", "ssh-rsa ", "ssh-ed25519 ",
    )
    if (any(token in lower for token in forbidden)
            or re.search(r"-----begin [a-z ]*private key-----", lower)):
        return False
    if (re.search(
            r"(?i)\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|"
            r"PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*[:=]", value)
            or re.search(r"(?i)\b(?:https?|ssh)://", value)):
        return False
    if re.search(r"(?<![A-Za-z0-9._-])/(?:[^\s\"'<>]+)", value):
        return False
    return True


def validate_resource_receipt(value):
    limit_keys = set(APPLIANCE_CONTAINER_LIMITS)
    final_keys = limit_keys | {"memory.peak", "memory.events", "cpu.stat"}
    if (not isinstance(value, dict) or set(value) != {"limits", "cgroup_final"}
            or value.get("limits") != APPLIANCE_CONTAINER_LIMITS
            or not isinstance(value.get("cgroup_final"), dict)
            or set(value["cgroup_final"]) != final_keys
            or any(value["cgroup_final"].get(name) != expected
                   for name, expected in APPLIANCE_CONTAINER_LIMITS.items())):
        return False
    final = value["cgroup_final"]
    if (any(not isinstance(final.get(name), str) for name in final_keys)
            or not 0 < len(final["memory.peak"]) <= 20
            or re.fullmatch(r"[0-9]+", final["memory.peak"]) is None
            or int(final["memory.peak"]) > APPLIANCE_CONTAINER_MEMORY_BYTES
            or not 0 < len(final["memory.events"]) <= 4096
            or not 0 < len(final["cpu.stat"]) <= 4096):
        return False
    for text in (final["memory.events"], final["cpu.stat"]):
        lines = text.splitlines()
        fields = [line.split() for line in lines]
        if (not lines or any(len(items) != 2 for items in fields)
                or len(fields) != len({items[0] for items in fields})
                or any(re.fullmatch(r"[a-z_.]+", items[0]) is None
                       or re.fullmatch(r"[0-9]+", items[1]) is None
                       for items in fields)):
            return False
    events = dict(line.split() for line in final["memory.events"].splitlines())
    if not {"max", "oom", "oom_kill", "oom_group_kill"}.issubset(events):
        return False
    return True


def _validate_failure_diagnostics(value):
    if (not isinstance(value, dict)
            or any(phase not in FAILURE_LOG_BOUNDS for phase in value)):
        return False
    for phase, diagnostic in value.items():
        if not isinstance(diagnostic, dict) or set(diagnostic) != {"result", "logs", "rejected"}:
            return False
        result = diagnostic["result"]
        if (not isinstance(result, dict)
                or set(result) != {"bytes", "sha256", "failure_type", "message", "redacted"}
                or type(result["bytes"]) is not int or not 0 < result["bytes"] <= 256*1024
                or not exact_hash(result["sha256"])
                or not isinstance(result["failure_type"], str)
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,63}", result["failure_type"]) is None
                or not _safe_diagnostic_text(result["message"], 4096)
                or type(result["redacted"]) is not bool):
            return False
        allowed = FAILURE_LOG_BOUNDS[phase]
        logs, rejected = diagnostic["logs"], diagnostic["rejected"]
        if (not isinstance(logs, dict) or any(name not in allowed for name in logs)
                or not isinstance(rejected, list) or rejected != sorted(set(rejected))
                or any(name not in allowed for name in rejected)
                or set(logs).intersection(rejected)):
            return False
        for name, item in logs.items():
            if (not isinstance(item, dict)
                    or set(item) != {"bytes", "sha256", "excerpt", "truncated", "redacted"}
                    or type(item["bytes"]) is not int
                    or not 0 < item["bytes"] <= allowed[name]
                    or not exact_hash(item["sha256"])
                    or not _safe_diagnostic_text(item["excerpt"], FAILURE_EXCERPT_BYTES)
                    or type(item["truncated"]) is not bool
                    or type(item["redacted"]) is not bool):
                return False
    return True


def controller_failure_record(source_binding, stage, error_type, cleanup, resources,
                              diagnostics=None):
    """Return a bounded, path-free failure receipt for the hosted controller."""
    source = validate_source_binding(source_binding)
    if stage not in CONTROLLER_STAGES:
        raise ValueError("Invalid appliance controller stage")
    if (not isinstance(error_type, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,63}", error_type) is None):
        raise ValueError("Invalid appliance failure type")
    expected_cleanup = {
        "stage_directory_removed", "user_artifact_absent",
        "screenshot_artifact_absent", "non_controller_evidence_removed",
    }
    if (not isinstance(cleanup, dict) or set(cleanup) != expected_cleanup
            or any(type(value) is not bool for value in cleanup.values())):
        raise ValueError("Invalid appliance cleanup receipt")
    if (not isinstance(resources, dict)
            or any(name not in {"producer", "reboot"} for name in resources)
            or any(not validate_resource_receipt(value) for value in resources.values())):
        raise ValueError("Invalid appliance resource receipt")
    diagnostics = {} if diagnostics is None else diagnostics
    if (not _validate_failure_diagnostics(diagnostics)
            or not set(diagnostics).issubset(resources)):
        raise ValueError("Invalid appliance failure diagnostics")
    result = failure_record(source, error_type)
    result.update({
        "stage": stage,
        "source": {"commit": source["source_commit"], "tree": source["source_tree"]},
        "cleanup": cleanup,
        "resources": resources,
        "diagnostics": diagnostics,
    })
    return result


def validate_source_binding(value):
    keys = {
        "repository", "source_commit", "image_source_commit", "image_run_id",
        "image_artifact_id", "image_artifact_sha256", "oci_manifest_digest",
        "installed_raw_sha256", "source_tree",
    }
    if (not isinstance(value, dict) or set(value) != keys
            or value.get("repository") != "ThirdKeyAI/symbi-os"
            or not exact_hash(value.get("source_commit"), 40)
            or not exact_hash(value.get("source_tree"), 40)
            or not exact_hash(value.get("image_source_commit"), 40)
            or type(value.get("image_run_id")) is not int or value["image_run_id"] <= 0
            or type(value.get("image_artifact_id")) is not int or value["image_artifact_id"] <= 0
            or not exact_hash(value.get("image_artifact_sha256"))
            or not isinstance(value.get("oci_manifest_digest"), str)
            or not value["oci_manifest_digest"].startswith("sha256:")
            or not exact_hash(value["oci_manifest_digest"][7:])
            or not exact_hash(value.get("installed_raw_sha256"))):
        raise ValueError("Incomplete appliance source binding")
    return value


def validate_guest_report(report, expected, probe_hash, expected_hash):
    source = validate_source_binding(expected.get("source_binding"))
    walker_launch = {
        "unit": "symbi-appliance-walker.service",
        "executable": "/usr/bin/walker",
        "observed": True,
        "stop_succeeded": True,
        "stopped": True,
        "timeout_seconds": 30,
        "limits": {
            "memory_max": "512M", "memory_swap_max": "0",
            "cpu_quota": "100%", "tasks_max": "64",
            "runtime_max_seconds": "60", "no_new_privileges": "yes",
        },
    }
    try:
        valid = (
            isinstance(report, dict) and report.get("schema") == 1
            and report.get("nonce") == expected["nonce"]
            and report.get("source_binding") == source
            and report.get("probe_sha256") == probe_hash
            and report.get("expected_sha256") == expected_hash
            and report.get("passed") is True and report.get("guest_booted") is True
            and report.get("graphical_desktop_observed") is True
            and report.get("os_qualified") is False
            and report.get("release_qualified") is False
            and report.get("signature_qualified") is False
            and report.get("network_interfaces") == ["lo"]
            and report.get("default_target") == "graphical.target"
            and report.get("display_manager") == "sddm.service"
            and report.get("session") == "symbi.desktop"
            and report.get("interactive_devices") == {
                "virtio_gpu": True, "virtio_keyboard": True, "virtio_pointer": True,
            }
            and report.get("fixture_user") == {
                "name": USERNAME, "password_locked": True, "non_wheel": True,
                "authorized_keys_absent": True,
            }
            and report.get("fixture_cleanup") == {
                "boot_wants_removed": True, "persistent_scripts_absent": True,
                "persistent_units_absent": True, "credentials_absent": True,
            }
            and report.get("desktop_components") == {
                "Hyprland": True, "Waybar": True, "Walker": True,
                "portal": True, "first_login_seeded": True,
            }
            and report.get("walker_launch") == walker_launch
            and report.get("scope") == SCOPE
            and "failure" not in report
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise ValueError("Guest graphical appliance report is incomplete or unbound")
    return report


def validate_reboot_report(report, source_binding, artifact):
    source = validate_source_binding(source_binding)
    screenshot = report.get("screenshot") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or report.get("schema") != 1
            or report.get("passed") is not True or report.get("guest_booted") is not True
            or report.get("graphical_desktop_observed") is not True
            or report.get("artifact_retained") is not True
            or report.get("independent_reboot_passed") is not True
            or report.get("os_qualified") is not False
            or report.get("release_qualified") is not False
            or report.get("signature_qualified") is not False
            or report.get("source_binding") != source
            or report.get("artifact_before") != artifact
            or report.get("artifact_after") != artifact
            or report.get("command") != reboot_qemu_arguments()
            or not isinstance(screenshot, dict)
            or set(screenshot) != {"bytes", "sha256", "width", "height", "sampled_colors",
                                   "boot_elapsed_seconds"}
            or type(screenshot.get("bytes")) is not int or not 0 < screenshot["bytes"] <= 4*1024**2
            or not exact_hash(screenshot.get("sha256"))
            or type(screenshot.get("width")) is not int or not 320 <= screenshot["width"] <= 4096
            or type(screenshot.get("height")) is not int or not 200 <= screenshot["height"] <= 2160
            or type(screenshot.get("sampled_colors")) is not int or screenshot["sampled_colors"] < 2
            or type(screenshot.get("boot_elapsed_seconds")) is not int
            or not 90 <= screenshot["boot_elapsed_seconds"] <= 600
            or report.get("scope") != SCOPE or "failure" in report):
        raise ValueError("Independent retained-byte reboot did not pass")
    return report


def build_manifest(source_binding, artifact, producer, reboot, now=None):
    source = validate_source_binding(source_binding)
    validate_reboot_report(reboot, source, artifact)
    if (not isinstance(producer, dict) or producer.get("passed") is not True
            or producer.get("guest_booted") is not True
            or producer.get("graphical_desktop_observed") is not True
            or producer.get("artifact_retained") is not True
            or producer.get("independent_reboot_passed") is not False
            or producer.get("os_qualified") is not False
            or producer.get("release_qualified") is not False
            or producer.get("signature_qualified") is not False
            or producer.get("source_binding") != source):
        raise ValueError("Producer result is incomplete")
    if (not isinstance(artifact, dict)
            or set(artifact) != {"name", "bytes", "sha256", "format", "compression", "virtual_bytes"}
            or artifact.get("name") != ARTIFACT_NAME
            or type(artifact.get("bytes")) is not int or not 0 < artifact["bytes"] <= VIRTUAL_DISK_BYTES
            or not exact_hash(artifact.get("sha256")) or artifact.get("format") != "qcow2"
            or artifact.get("compression") != "qcow2-zlib-clusters"
            or artifact.get("virtual_bytes") != VIRTUAL_DISK_BYTES):
        raise ValueError("Invalid compressed appliance artifact binding")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Timezone-aware manifest time required")
    expires = current.astimezone(timezone.utc) + timedelta(days=RETENTION_DAYS)
    return {
        "schema": 1, "highly_experimental": True, "passed": True,
        "guest_booted": True, "graphical_desktop_observed": True,
        "artifact_retained": True, "independent_reboot_passed": True,
        "os_qualified": False, "release_qualified": False,
        "signature_qualified": False, "signed": False,
        "source_binding": source, "disk": artifact,
        "fixture_user": {
            "name": USERNAME, "password_locked": True, "non_wheel": True,
            "authorized_keys_absent": True, "login": "SDDM development-only autologin",
        },
        "network": "none", "retention_days": RETENTION_DAYS,
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "reboot": {
            "artifact_sha256_before": reboot["artifact_before"]["sha256"],
            "artifact_sha256_after": reboot["artifact_after"]["sha256"],
            "screenshot": reboot["screenshot"],
        },
        "launch": user_launch_arguments(), "scope": SCOPE,
        "warnings": [
            "HIGHLY EXPERIMENTAL development artifact; do not use for real data or accounts.",
            "The disk is unsigned and is separate from every release and security qualification claim.",
            "The disposable account is locked and has no password or SSH key; SDDM autologin is appliance-only.",
            "The first slice has no virtual NIC. QEMU networking must remain disabled.",
        ],
    }
