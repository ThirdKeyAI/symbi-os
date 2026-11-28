"""Prepare two isolated containers for appliance production and cold reboot."""
from datetime import datetime, timedelta, timezone
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

from image.appliance.contract import (APPLIANCE_CONTAINER_LIMITS, ARTIFACT_NAME,
                                      FAILURE_EXCERPT_BYTES, FAILURE_LOG_BOUNDS,
                                      RETENTION_DAYS, SDDM_CONFIGURATION, SCOPE,
                                      build_manifest,
                                      controller_failure_record, failure_record, sha256,
                                      provision_qemu_arguments, unique_json,
                                      validate_guest_report, validate_reboot_report,
                                      validate_resource_receipt,
                                      validate_source_binding)
from image.appliance.reboot import ppm_observation


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
FAILURE_CLAIMS = (
    "passed", "guest_booted", "graphical_desktop_observed", "artifact_retained",
    "independent_reboot_passed", "os_qualified", "release_qualified",
    "signature_qualified",
)
INNER_FAILURE_KEYS = set(failure_record({}, "")).union({"limits", "cgroup_final"})
SENSITIVE_PATTERNS = (
    re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*"),
    re.compile(r"(?im)\bauthorization\s*:\s*(?:bearer|basic)\s+[^\r\n]*"),
    re.compile(
        r"(?im)\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|"
        r"PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*[:=][^\r\n]*"
    ),
    re.compile(r"(?i)\b(?:github_pat_|gh[pousr]_|glpat-)[A-Za-z0-9_-]+"),
    re.compile(r"(?i)\bssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+(?:\s+[^\n]+)?"),
)
URL_PATTERN = re.compile(r"(?i)\b(?:https?|ssh)://[^\s\"'<>]+")
ABSOLUTE_PATH_PATTERN = re.compile(r"(?<![A-Za-z0-9._-])/(?:[^\s\"'<>]+)")
OUTER_MEMORY_MAX_BYTES = 5 * 1024**3
SYSTEMD_UINT64_MAX = (1 << 64) - 1
CREDENTIAL_TOKENS = (b"PRIVATE KEY-----", b"ssh-rsa ", b"ssh-ed25519 ")
PRODUCER_RESULT_KEYS = frozenset({
    "schema", "passed", "guest_booted", "graphical_desktop_observed",
    "artifact_retained", "independent_reboot_passed", "os_qualified",
    "release_qualified", "signature_qualified", "source_binding", "artifact",
    "guest_report_sha256", "limits", "command", "qemu_version", "tools",
    "scope", "cgroup_final",
})
GUEST_REPORT_KEYS = frozenset({
    "schema", "nonce", "source_binding", "probe_sha256", "expected_sha256",
    "passed", "guest_booted", "graphical_desktop_observed", "os_qualified",
    "release_qualified", "signature_qualified", "network_interfaces",
    "default_target", "display_manager", "session", "fixture_user",
    "interactive_devices", "fixture_cleanup", "desktop_components", "walker_launch",
    "autologin_sha256", "scope",
})
REBOOT_RESULT_KEYS = frozenset({
    "schema", "passed", "guest_booted", "graphical_desktop_observed",
    "artifact_retained", "independent_reboot_passed", "os_qualified",
    "release_qualified", "signature_qualified", "source_binding", "artifact_before",
    "artifact_after", "screenshot", "command", "limits", "scope", "cgroup_final",
})
MAX_RETAINED_EVIDENCE_BYTES = 32 * 1024**2
EVIDENCE_FILE_LIMITS = {
    "compress-qcow2.log": 4 * 1024**2,
    "convert-raw.log": 4 * 1024**2,
    "display.ppm": 4 * 1024**2,
    "guest-report.json": 128 * 1024,
    "manifest.json": 4 * 1024**2,
    "producer-result.json": 4 * 1024**2,
    "provision-qemu.log": 2 * 1024**2,
    "provision-serial.log": 4 * 1024**2,
    "reboot-qemu.log": 2 * 1024**2,
    "reboot-result.json": 4 * 1024**2,
    "reboot-serial.log": 4 * 1024**2,
    "result.json": 256 * 1024,
    "systemd-result.txt": 4096,
}
SUCCESS_EVIDENCE_FILES = frozenset(EVIDENCE_FILE_LIMITS)
FAILURE_EVIDENCE_FILES = frozenset({"result.json", "systemd-result.txt"})
OUTER_FAILURE_KIND = "outer-systemd-failure"
OUTER_FAILURE_ATOMIC_RESULT_MAX_BYTES = 256 * 1024
OUTER_FAILURE_COMMAND_STAGES = {
    "load-image": "image-load",
    "inspect-image": "image-inspection",
    "sign-source": "source-authentication",
    "install": "installation",
    "disk-loops-after-install": "installation-validation",
    "interactive-appliance-producer": "producer",
    "interactive-appliance-reboot": "reboot",
}
OUTER_FAILURE_STAGES = frozenset({
    "outer-controller", "image-load", "image-inspection",
    "source-authentication", "installation", "installation-validation",
    "appliance-initialization", "producer", "reboot", "cleanup",
})
OUTER_FAILURE_CLEANUP_COMMANDS = frozenset({
    "disk-loops-cleanup", "disk-loops-absent", "remove-image", "image-absent",
})
SYSTEMD_RESULT_KEYS = frozenset({
    "LoadState", "Type", "RemainAfterExit", "ActiveState", "SubState",
    "Result", "OOMPolicy", "MemoryMax", "MemoryPeak", "MemorySwapMax",
    "MemorySwapPeak", "CPUUsageNSec", "ExecMainCode", "ExecMainStatus",
})
PUBLIC_ARTIFACT_FILES = frozenset({ARTIFACT_NAME, "manifest.json", "display.ppm"})
PUBLIC_ARTIFACT_LIMITS = {
    ARTIFACT_NAME: 24 * 1024**3,
    "manifest.json": EVIDENCE_FILE_LIMITS["manifest.json"],
    "display.ppm": EVIDENCE_FILE_LIMITS["display.ppm"],
}


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


def _checkout_binding(root):
    """Bind upload evidence to the exact checkout root, commit, and committed tree."""
    root = Path(root).resolve()
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel", "HEAD"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=True,
    )
    lines = result.stdout.splitlines()
    if (result.stderr or len(lines) != 2 or Path(lines[0]).resolve() != root
            or re.fullmatch(r"[0-9a-f]{40}", lines[1]) is None):
        raise ValueError("Exact appliance checkout binding unavailable")
    return {"source_commit": lines[1], "source_tree": source_tree(root, lines[1])}


def _manifest_expiry(value=None):
    """Parse the explicit hosted-workflow expiry without deriving it from evidence."""
    candidate = value if value is not None else os.environ.get(
        "SYMBI_APPLIANCE_EXPECTED_EXPIRY")
    if (not isinstance(candidate, str)
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                            candidate) is None):
        raise ValueError("Explicit appliance manifest expiry required")
    try:
        return datetime.strptime(candidate, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError("Invalid explicit appliance manifest expiry") from error


def _schema_one(record):
    return isinstance(record, dict) and type(record.get("schema")) is int and record["schema"] == 1


def _explicit_checkout_binding():
    """Return the workflow-bound checkout without invoking git as root."""
    commit = os.environ.get("GITHUB_SHA")
    tree = os.environ.get("SYMBI_APPLIANCE_SOURCE_TREE")
    if (not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            or not isinstance(tree, str) or re.fullmatch(r"[0-9a-f]{40}", tree) is None):
        raise ValueError("Explicit appliance checkout binding required")
    return {"source_commit": commit, "source_tree": tree}


def _outer_failure_progress(root, checkout):
    """Extract only fixed enums and integers from the private Atomic result."""
    unavailable = ("outer-controller", "unknown")
    try:
        raw = _bounded_regular(
            root / ".cache/atomic-disk-evidence/result.json",
            OUTER_FAILURE_ATOMIC_RESULT_MAX_BYTES,
        )
        record = unique_json(raw)
        lock = unique_json(_bounded_regular(
            root / "image/desktop-images.lock.json", 1024 * 1024))
        selected_commit = lock["images"]["generic"]["tested_commit"]
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return unavailable
    commands = record.get("commands")
    if (not _schema_one(record) or record.get("passed") is not False
            or record.get("qualification") != "appliance"
            or record.get("source_commit") != checkout["source_commit"]
            or record.get("image_source_commit") != selected_commit
            or re.fullmatch(r"[0-9a-f]{40}", selected_commit) is None
            or not isinstance(commands, list) or len(commands) > 256):
        return unavailable
    for claim in (
            "passed", "guest_booted", "graphical_desktop_observed",
            "artifact_retained", "independent_reboot_passed", "os_qualified",
            "release_qualified", "signature_qualified"):
        if claim in record and record[claim] is not False:
            return unavailable

    def fixed_command(name):
        stage = OUTER_FAILURE_COMMAND_STAGES.get(name)
        if stage is not None:
            return stage, name
        if (name in OUTER_FAILURE_CLEANUP_COMMANDS
                or name.startswith("cleanup-")
                or name.startswith("absent-")
                or name.startswith("detach-owned-loop-")):
            return "cleanup", "cleanup"
        return None

    active = record.get("active_command")
    if active is not None:
        if (not isinstance(active, dict) or set(active) != {"name", "command"}
                or not isinstance(active.get("name"), str)
                or not isinstance(active.get("command"), list)):
            return unavailable
        mapped = fixed_command(active["name"])
        if mapped is not None:
            return mapped
        return unavailable
    failed = None
    last_stage = None
    for item in commands:
        if (not isinstance(item, dict) or set(item) != {"name", "exit_code"}
                or not isinstance(item.get("name"), str)
                or type(item.get("exit_code")) is not int
                or not 0 <= item["exit_code"] <= 255):
            return unavailable
        name, status = item["name"], item["exit_code"]
        mapped = fixed_command(name)
        if mapped is not None and mapped[1] != "cleanup":
            stage = mapped[0]
            last_stage = stage
            if status != 0 and failed is None:
                failed = mapped
        elif mapped == ("cleanup", "cleanup") and status != 0 and failed is None:
            failed = mapped
    if failed is not None:
        return failed
    if record.get("installation_completed") is True:
        stage = "appliance-initialization"
    elif record.get("installation_attempted") is True:
        stage = "installation-validation"
    else:
        stage = last_stage or "outer-controller"
    return stage, "unknown"


def outer_failure_record(root):
    """Build a content-free negative receipt for failures before appliance evidence."""
    root = Path(root).resolve()
    checkout = _explicit_checkout_binding()
    stage, command = _outer_failure_progress(root, checkout)
    if stage not in OUTER_FAILURE_STAGES:
        raise ValueError("Invalid outer appliance failure stage")
    cleanup = {
        "stage_directory_removed": _direct_path_absent(
            root / ".cache/interactive-appliance-stage"),
        "user_artifact_absent": _direct_path_absent(
            root / ".cache/interactive-appliance-artifact"),
        "screenshot_artifact_absent": _direct_path_absent(
            root / ".cache/interactive-appliance-evidence/display.ppm"),
        "non_controller_evidence_removed": True,
    }
    return {
        "schema": 1,
        "evidence_kind": OUTER_FAILURE_KIND,
        **{name: False for name in FAILURE_CLAIMS},
        "source": {
            "repository": "ThirdKeyAI/symbi-os",
            "commit": checkout["source_commit"],
            "tree": checkout["source_tree"],
        },
        "stage": stage,
        "failed_command": command,
        "failure": "SystemdUnitFailure",
        "inner_evidence_available": False,
        "cleanup": cleanup,
        "scope": SCOPE,
    }


def _bounded_regular(path, maximum):
    """Read one direct regular file without following links or blocking on specials."""
    try:
        parent = path.parent.lstat()
        info = path.lstat()
    except OSError as error:
        raise ValueError("Missing bounded appliance failure input") from error
    if (path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
            or path.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
        raise ValueError("Unsafe bounded appliance failure input")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory = os.open(path.parent, directory_flags)
    try:
        opened_parent = os.fstat(directory)
        if ((opened_parent.st_dev, opened_parent.st_ino)
                != (parent.st_dev, parent.st_ino)):
            raise ValueError("Appliance failure parent changed during validation")
        descriptor = os.open(path.name, flags, dir_fd=directory)
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns)
                    != (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)):
                raise ValueError("Appliance failure input changed during validation")
            data = bytearray()
            while len(data) <= maximum:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
            if (len(data) != info.st_size
                    or (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)
                    != (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)):
                raise ValueError("Appliance failure input changed while reading")
            return bytes(data)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def _sanitize_diagnostic(raw, maximum):
    """Return printable path-free text and whether any content was removed."""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    elif isinstance(raw, str):
        text = raw
    else:
        raise TypeError("Diagnostic input must be text or bytes")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    redacted = "\ufffd" in text
    text = text.replace("\ufffd", "?")
    for pattern in SENSITIVE_PATTERNS:
        changed, count = pattern.subn("<redacted>", text)
        text, redacted = changed, redacted or count > 0
    changed, count = URL_PATTERN.subn("<url>", text)
    text, redacted = changed, redacted or count > 0
    changed, count = ABSOLUTE_PATH_PATTERN.subn("<path>", text)
    text, redacted = changed, redacted or count > 0
    printable = "".join(
        character
        if character in "\n\t" or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
        else "?"
        for character in text
    )
    redacted = redacted or printable != text
    encoded = printable.encode("utf-8")
    if len(encoded) > maximum:
        printable = encoded[-maximum:].decode("utf-8", errors="ignore")
        redacted = True
    printable = printable.strip()
    if len(printable.encode("utf-8")) > maximum:
        raise ValueError("Sanitized appliance diagnostic exceeds its byte bound")
    return printable, redacted


def _failure_log(path, maximum):
    try:
        raw = _bounded_regular(path, maximum)
    except (OSError, ValueError):
        return None, True
    # Redact the complete bounded input before selecting a tail. Otherwise a
    # credential label just before the tail boundary could be discarded while
    # its value was retained.
    sanitized, redacted = _sanitize_diagnostic(raw, maximum)
    excerpt, tail_redacted = _sanitize_diagnostic(sanitized, FAILURE_EXCERPT_BYTES)
    redacted = redacted or tail_redacted
    if not excerpt:
        return None, False
    return {
        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "excerpt": excerpt,
        "truncated": len(raw) > FAILURE_EXCERPT_BYTES,
        "redacted": redacted,
    }, False


def _failure_diagnostic(output, phase, source):
    """Authenticate one result and sanitize its failure before private cleanup."""
    if phase not in FAILURE_LOG_BOUNDS:
        raise ValueError("Unknown appliance failure phase")
    result_path = output / "result.json"
    try:
        raw = _bounded_regular(result_path, 256*1024)
        value = unique_json(raw)
    except (OSError, ValueError, json.JSONDecodeError):
        return None, None
    receipt = {
        "limits": value.get("limits"), "cgroup_final": value.get("cgroup_final"),
    }
    if not validate_resource_receipt(receipt):
        return None, None
    failure = value.get("failure")
    try:
        failure_bytes = failure.encode("utf-8") if isinstance(failure, str) else b""
    except UnicodeError:
        failure_bytes = b""
    if (set(value) != INNER_FAILURE_KEYS
            or value.get("schema") != 1 or value.get("source_binding") != source
            or value.get("scope") != SCOPE
            or any(value.get(name) is not False for name in FAILURE_CLAIMS)
            or not isinstance(failure, str)
            or not 0 < len(failure_bytes) <= 4096):
        return None, receipt
    failure_type, separator, message = failure.partition(":")
    failure_type = failure_type.strip()
    if (not separator or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,63}", failure_type) is None):
        return None, receipt
    message, redacted = _sanitize_diagnostic(message, 4096)
    if not message:
        message = failure_type
    logs, rejected = {}, []
    log_root = output / "evidence" if phase == "producer" else output
    for name, maximum in FAILURE_LOG_BOUNDS[phase].items():
        path = log_root / name
        if not path.exists() and not path.is_symlink():
            continue
        item, refused = _failure_log(path, maximum)
        if refused:
            rejected.append(name)
        elif item is not None:
            logs[name] = item
    return {
        "result": {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "failure_type": failure_type, "message": message, "redacted": redacted,
        },
        "logs": logs,
        "rejected": sorted(rejected),
    }, receipt


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


def _direct_path_absent(path):
    """Check one cache path without treating an unreadable path as absent."""
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _discard_failed_appliance_outputs(root):
    """Revoke every local output and upload marker after failed cleanup."""
    cache = root / ".cache"
    paths = (
        cache / "interactive-appliance-stage",
        cache / "interactive-appliance-artifact",
        cache / "interactive-appliance-evidence",
        cache / "interactive-appliance-evidence.ready",
    )
    # A second bounded pass handles a path that became removable while the first
    # pass was revoking the remaining outputs. Every path is checked independently.
    for _ in range(2):
        for path in paths:
            if not _direct_path_absent(path):
                _remove_local_output(path)
        if all(_direct_path_absent(path) for path in paths):
            return True
    return False


def _failure_cleanup_complete(root, result):
    """Require claimed cleanup to match all upload-relevant cache postconditions."""
    cleanup = result.get("cleanup") if isinstance(result, dict) else None
    cache = root / ".cache"
    return (
        isinstance(cleanup, dict)
        and cleanup
        and all(value is True for value in cleanup.values())
        and _direct_path_absent(cache / "interactive-appliance-stage")
        and _direct_path_absent(cache / "interactive-appliance-artifact")
        and _direct_path_absent(cache / "interactive-appliance-evidence.ready")
    )


def _decimal(value, label, maximum=None):
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise ValueError("Invalid numeric appliance evidence: " + label)
    number = int(value)
    if maximum is not None and number > maximum:
        raise ValueError("Out-of-range appliance evidence: " + label)
    return number


def _resource_lines(value, label):
    if not isinstance(value, str) or not 0 < len(value) <= 4096:
        raise ValueError("Invalid appliance resource evidence: " + label)
    parsed = {}
    for line in value.splitlines():
        fields = line.split()
        if (len(fields) != 2 or fields[0] in parsed
                or re.fullmatch(r"[a-z_.]+", fields[0]) is None):
            raise ValueError("Invalid appliance resource evidence: " + label)
        parsed[fields[0]] = _decimal(fields[1], label + "." + fields[0])
    if not parsed:
        raise ValueError("Empty appliance resource evidence: " + label)
    return parsed


def _validate_resource_evidence(record):
    limits = record.get("limits") if isinstance(record, dict) else None
    final = record.get("cgroup_final") if isinstance(record, dict) else None
    if not validate_resource_receipt({"limits": limits, "cgroup_final": final}):
        raise ValueError("Appliance child resource receipt changed")
    if limits != APPLIANCE_CONTAINER_LIMITS:
        raise ValueError("Appliance child resource limits changed")
    if any(final.get(name) != value for name, value in limits.items()):
        raise ValueError("Appliance child final limits changed")
    peak = _decimal(final["memory.peak"], "memory.peak")
    if peak > int(limits["memory.max"]):
        raise ValueError("Appliance child exceeded its memory limit")
    events = _resource_lines(final["memory.events"], "memory.events")
    if any(events.get(name) != 0 for name in ("oom", "oom_kill", "oom_group_kill")):
        raise ValueError("Appliance child recorded an OOM event")
    cpu = _resource_lines(final["cpu.stat"], "cpu.stat")
    if "usage_usec" not in cpu:
        raise ValueError("Appliance child CPU evidence is incomplete")


def _systemd_result(path, controller):
    """Parse and bind the fixed-field outer-unit record to the controller outcome."""
    try:
        lines = path.read_text().splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("Invalid appliance systemd result") from error
    values = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator != "=" or key in values or key not in SYSTEMD_RESULT_KEYS or len(value) > 256:
            raise ValueError("Invalid appliance systemd result")
        values[key] = value
    if set(values) != SYSTEMD_RESULT_KEYS:
        raise ValueError("Incomplete appliance systemd result")
    if (values["LoadState"] != "loaded" or values["Type"] != "oneshot"
            or values["RemainAfterExit"] != "yes"):
        raise ValueError("Appliance systemd unit contract changed")

    def systemd_decimal(name, maximum=None):
        number = _decimal(values[name], "systemd." + name, maximum)
        if values[name] != str(number):
            raise ValueError("Non-canonical numeric appliance evidence: systemd." + name)
        return number

    if systemd_decimal("MemoryMax") != OUTER_MEMORY_MAX_BYTES:
        raise ValueError("Appliance systemd memory limit changed")
    memory_peak = systemd_decimal("MemoryPeak", SYSTEMD_UINT64_MAX)
    if (controller.get("passed") is True
            and memory_peak > OUTER_MEMORY_MAX_BYTES):
        raise ValueError(
            "Out-of-range appliance evidence: passed systemd.MemoryPeak "
            "exceeded its memory limit")
    if (systemd_decimal("MemorySwapMax") != 0
            or systemd_decimal("MemorySwapPeak") != 0):
        raise ValueError("Appliance systemd unit used swap")
    systemd_decimal("CPUUsageNSec")
    code = systemd_decimal("ExecMainCode", 3)
    status = systemd_decimal("ExecMainStatus", 255)
    if code not in {1, 2, 3}:
        raise ValueError("Invalid appliance systemd child code")
    outcome = values["Result"]
    if values["OOMPolicy"] != "stop":
        raise ValueError("Appliance systemd OOM policy changed")
    if outcome == "oom-kill":
        if (values["ActiveState"] != "failed" or values["SubState"] != "failed"
                or code != 2 or status != 9):
            raise ValueError("Invalid appliance systemd OOM outcome")
        raise ValueError("Appliance systemd OOM evidence is not uploadable")

    success = (outcome == "success" and code == 1 and status == 0
               and values["ActiveState"] == "active"
               and values["SubState"] == "exited")
    if controller.get("passed") is True:
        if not success:
            raise ValueError("Passed appliance lacks exact systemd success")
    elif success:
        if (controller.get("stage") != "cleanup"
                or controller.get("failure") != "AtomicControllerFailure"):
            raise ValueError("Failed appliance contradicts systemd success")
    else:
        failure = (
            values["ActiveState"] == "failed"
            and values["SubState"] == "failed"
            and (
                (outcome == "exit-code" and code == 1 and 1 <= status <= 255)
                or (outcome == "signal" and code == 2 and 1 <= status <= 64)
                or (outcome == "core-dump" and code == 3 and 1 <= status <= 64)
                or (outcome == "timeout" and code == 2 and 1 <= status <= 64)
            )
        )
        if not failure:
            raise ValueError("Invalid appliance systemd failure")
    return values


def _validate_producer_result(producer, source, artifact, guest_hash):
    if (set(producer) != PRODUCER_RESULT_KEYS or not _schema_one(producer)
            or any(producer.get(name) is not True for name in (
                "passed", "guest_booted", "graphical_desktop_observed", "artifact_retained"))
            or producer.get("independent_reboot_passed") is not False
            or any(producer.get(name) is not False for name in (
                "os_qualified", "release_qualified", "signature_qualified"))
            or producer.get("source_binding") != source
            or producer.get("artifact") != artifact
            or producer.get("guest_report_sha256") != guest_hash
            or producer.get("command") != provision_qemu_arguments()
            or producer.get("scope") != SCOPE):
        raise ValueError("Appliance producer success receipt changed")
    version = producer.get("qemu_version")
    tools = producer.get("tools")
    if (not isinstance(version, str) or not 0 < len(version) <= 1024
            or not version.startswith("QEMU emulator version ")
            or not isinstance(tools, dict)
            or set(tools) != {"qemu-system-x86_64", "qemu-img"}
            or any(not isinstance(value, str)
                   or re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in tools.values())):
        raise ValueError("Appliance producer tool identity changed")
    _validate_resource_evidence(producer)


def _validate_guest_result(root, guest, source):
    if set(guest) != GUEST_REPORT_KEYS or not _schema_one(guest):
        raise ValueError("Appliance guest report schema changed")
    expected = _expected_guest_contract(root, source, guest.get("nonce"))
    expected_hash = hashlib.sha256(
        (json.dumps(expected, sort_keys=True) + "\n").encode()).hexdigest()
    probe_hash = sha256(root / "image/appliance/verify.py")
    validate_guest_report(guest, expected, probe_hash, expected_hash)
    if guest.get("autologin_sha256") != expected["sddm_config_sha256"]:
        raise ValueError("Appliance guest autologin binding changed")


def _validate_reboot_result(reboot, source, artifact):
    if set(reboot) != REBOOT_RESULT_KEYS or not _schema_one(reboot):
        raise ValueError("Appliance reboot success receipt changed")
    validate_reboot_report(reboot, source, artifact)
    _validate_resource_evidence(reboot)


def validate_retained_evidence(root, expected_expiry=None):
    """Validate the exact small evidence inventory immediately before upload."""
    root = Path(root).resolve()
    evidence = root / ".cache/interactive-appliance-evidence"
    try:
        info = evidence.lstat()
    except OSError as error:
        raise ValueError("Missing appliance evidence directory") from error
    if evidence.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("Unsafe appliance evidence directory")
    entries = {path.name: path for path in evidence.iterdir()}
    result_path = entries.get("result.json")
    if result_path is None:
        raise ValueError("Missing appliance controller result")
    for name, path in entries.items():
        try:
            item = path.lstat()
        except OSError as error:
            raise ValueError("Unreadable appliance evidence file") from error
        maximum = EVIDENCE_FILE_LIMITS.get(name)
        if (maximum is None or path.is_symlink() or not stat.S_ISREG(item.st_mode)
                or item.st_nlink != 1 or item.st_size > maximum):
            raise ValueError("Unsafe appliance evidence file: " + name)
    total = sum(path.stat().st_size for path in entries.values())
    if total > MAX_RETAINED_EVIDENCE_BYTES:
        raise ValueError("Appliance evidence exceeds its aggregate byte ceiling")
    for path in entries.values():
        data = path.read_bytes()
        if any(token in data for token in CREDENTIAL_TOKENS):
            raise ValueError("Credential-like material refused from appliance evidence")

    result = unique_json(result_path.read_bytes())
    if not _schema_one(result):
        raise ValueError("Appliance controller schema changed")
    failure = result.get("passed") is False
    outer_failure = result.get("evidence_kind") == OUTER_FAILURE_KIND
    if outer_failure and not failure:
        raise ValueError("Outer appliance receipt must remain failed")
    if failure:
        if set(entries) != FAILURE_EVIDENCE_FILES:
            _discard_failed_appliance_outputs(root)
            raise ValueError("Failed appliance retained non-controller evidence")
        if not _failure_cleanup_complete(root, result):
            _discard_failed_appliance_outputs(root)
            raise ValueError("Appliance failure cleanup is incomplete")
    checkout = _checkout_binding(root)
    if outer_failure:
        expected_source = {
            "repository": "ThirdKeyAI/symbi-os",
            "commit": checkout["source_commit"],
            "tree": checkout["source_tree"],
        }
        if result.get("source") != expected_source:
            raise ValueError("Outer failure differs from the checkout commit or tree")
        exact = outer_failure_record(root)
        if result != exact:
            raise ValueError("Outer appliance failure receipt changed")
        _systemd_result(entries["systemd-result.txt"], result)
        return total
    source = validate_source_binding(result.get("source_binding"))
    if any(source[name] != value for name, value in checkout.items()):
        raise ValueError("Appliance evidence differs from the checkout commit or tree")
    if failure:
        exact = controller_failure_record(
            result.get("source_binding"), result.get("stage"), result.get("failure"),
            result.get("cleanup"), result.get("resources"), result.get("diagnostics"),
        )
        if result != exact:
            raise ValueError("Appliance failure receipt changed")
        for resource in result["resources"].values():
            _validate_resource_evidence(resource)
        _systemd_result(entries["systemd-result.txt"], result)
        return total

    if set(entries) != SUCCESS_EVIDENCE_FILES:
        raise ValueError("Successful appliance evidence inventory changed")
    success_keys = {
        "schema", "passed", "guest_booted", "graphical_desktop_observed",
        "artifact_retained", "independent_reboot_passed", "os_qualified",
        "release_qualified", "signature_qualified", "source_binding", "artifact",
        "producer_result_sha256", "guest_report_sha256", "reboot_result_sha256",
        "manifest_sha256", "screenshot_sha256", "scope",
    }
    if (set(result) != success_keys
            or any(result.get(name) is not True for name in (
                "passed", "guest_booted", "graphical_desktop_observed",
                "artifact_retained", "independent_reboot_passed"))
            or any(result.get(name) is not False for name in (
                "os_qualified", "release_qualified", "signature_qualified"))
            or result.get("scope") != SCOPE):
        raise ValueError("Appliance controller success receipt changed")
    artifact = result.get("artifact")
    producer = unique_json(entries["producer-result.json"].read_bytes())
    guest = unique_json(entries["guest-report.json"].read_bytes())
    reboot = unique_json(entries["reboot-result.json"].read_bytes())
    hashes = {
        "producer_result_sha256": sha256(entries["producer-result.json"]),
        "guest_report_sha256": sha256(entries["guest-report.json"]),
        "reboot_result_sha256": sha256(entries["reboot-result.json"]),
        "manifest_sha256": sha256(entries["manifest.json"]),
        "screenshot_sha256": sha256(entries["display.ppm"]),
    }
    if any(result.get(name) != value for name, value in hashes.items()):
        raise ValueError("Appliance controller evidence hash changed")
    _validate_guest_result(root, guest, source)
    _validate_producer_result(producer, source, artifact, hashes["guest_report_sha256"])
    _validate_reboot_result(reboot, source, artifact)
    manifest = unique_json(entries["manifest.json"].read_bytes())
    if not _schema_one(manifest):
        raise ValueError("Appliance manifest schema changed")
    expires = _manifest_expiry(expected_expiry)
    if manifest.get("expires_at") != expires.strftime("%Y-%m-%dT%H:%M:%SZ"):
        raise ValueError("Appliance manifest expiry differs from the workflow binding")
    expected_manifest = build_manifest(
        source, artifact, producer, reboot, expires - timedelta(days=RETENTION_DAYS),
    )
    if manifest != expected_manifest:
        raise ValueError("Retained appliance manifest changed")
    screenshot = ppm_observation(entries["display.ppm"])
    if screenshot != {key: reboot["screenshot"][key] for key in screenshot}:
        raise ValueError("Retained appliance screenshot changed")
    _systemd_result(entries["systemd-result.txt"], result)
    return total


def _hash_public_file(path):
    """Hash one public file while refusing credential markers across chunk boundaries."""
    digest = hashlib.sha256()
    tail = b""
    tail_size = max(map(len, CREDENTIAL_TOKENS)) - 1
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            combined = tail + chunk
            if any(token in combined for token in CREDENTIAL_TOKENS):
                raise ValueError("Credential-like material refused from public appliance artifact")
            digest.update(chunk)
            tail = combined[-tail_size:]
    return digest.hexdigest()


def validate_public_artifact(root, expected_expiry=None):
    """Revalidate the exact public download inventory immediately before upload."""
    root = Path(root).resolve()
    validate_retained_evidence(root, expected_expiry)
    evidence = root / ".cache/interactive-appliance-evidence"
    public = root / ".cache/interactive-appliance-artifact"
    try:
        info = public.lstat()
    except OSError as error:
        raise ValueError("Missing public appliance artifact directory") from error
    if public.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("Unsafe public appliance artifact directory")
    entries = {path.name: path for path in public.iterdir()}
    if set(entries) != PUBLIC_ARTIFACT_FILES:
        raise ValueError("Public appliance artifact inventory changed")
    hashes = {}
    for name, path in entries.items():
        item = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
                or not 0 < item.st_size <= PUBLIC_ARTIFACT_LIMITS[name]):
            raise ValueError("Unsafe public appliance artifact file: " + name)
        hashes[name] = _hash_public_file(path)

    controller = unique_json((evidence / "result.json").read_bytes())
    artifact = controller["artifact"]
    qcow = entries[ARTIFACT_NAME]
    actual = dict(artifact)
    actual.update({"bytes": qcow.stat().st_size, "sha256": hashes[ARTIFACT_NAME]})
    if actual != artifact:
        raise ValueError("Public qcow2 differs from retained evidence")
    public_manifest = unique_json(entries["manifest.json"].read_bytes())
    retained_manifest = unique_json((evidence / "manifest.json").read_bytes())
    if (public_manifest != retained_manifest or public_manifest.get("disk") != artifact
            or hashes["manifest.json"] != controller["manifest_sha256"]):
        raise ValueError("Public manifest differs from retained evidence")
    public_screen = ppm_observation(entries["display.ppm"])
    retained_screen = ppm_observation(evidence / "display.ppm")
    if (public_screen != retained_screen
            or hashes["display.ppm"] != controller["screenshot_sha256"]
            or public_manifest.get("reboot", {}).get("screenshot", {}).get("sha256")
            != hashes["display.ppm"]):
        raise ValueError("Public screenshot differs from retained evidence")
    return sum(path.stat().st_size for path in entries.values())


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


def _expected_guest_contract(root, source, nonce):
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("Invalid appliance guest nonce")
    installed = _installed_desktop_bindings(root, source)
    return {
        "schema": 1, "nonce": nonce, "username": "symbi-test",
        "source_binding": source,
        "sddm_config_sha256": hashlib.sha256(SDDM_CONFIGURATION.encode()).hexdigest(),
        "production_files": installed["production_files"],
        "seed_files": installed["seed_files"],
        "desktop_components": {
            "preparation_sha256": installed["preparation_sha256"],
            "files": installed["files"], "packages": installed["packages"],
        },
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
    expected = _expected_guest_contract(root, source, secrets.token_hex(16))
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
              "--memory=4g", "--memory-swap=4g", "--cpus=2", "--pids-limit=64",
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
        expires = _manifest_expiry()
        manifest = build_manifest(
            source, artifact, producer, reboot,
            expires - timedelta(days=RETENTION_DAYS),
        )
        (output / "public/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        _copy_public_evidence(output / "evidence", evidence)
        _copy_public_evidence(reboot_output, evidence)
        os.replace(evidence / "result.json", evidence / "reboot-result.json")
        if sha256(evidence / "display.ppm") != reboot["screenshot"]["sha256"]:
            raise ValueError("Copied display evidence differs from its source-bound report")
        shutil.copyfile(output / "public/manifest.json", evidence / "manifest.json")
        if sha256(evidence / "manifest.json") != sha256(output / "public/manifest.json"):
            raise ValueError("Copied appliance manifest differs from the user artifact")
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
            "producer_result_sha256": sha256(evidence / "producer-result.json"),
            "guest_report_sha256": sha256(evidence / "guest-report.json"),
            "reboot_result_sha256": sha256(evidence / "reboot-result.json"),
            "manifest_sha256": sha256(artifact_output / "manifest.json"),
            "screenshot_sha256": sha256(evidence / "display.ppm"),
            "scope": SCOPE,
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
        resources, diagnostics = {}, {}
        if stage.exists() and not stage.is_symlink():
            for name, output in (
                ("producer", stage / "output"),
                ("reboot", stage / "reboot-output"),
            ):
                try:
                    diagnostic, receipt = _failure_diagnostic(output, name, source)
                except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
                    # Child output is untrusted failure evidence. It may remove
                    # diagnostics, but it must never interrupt cleanup or the
                    # controller's source-bound negative receipt.
                    diagnostic, receipt = None, None
                if receipt is not None:
                    resources[name] = receipt
                if diagnostic is not None:
                    diagnostics[name] = diagnostic
        cleanup = {
            "stage_directory_removed": _remove_local_output(stage),
            "user_artifact_absent": _remove_local_output(artifact_output),
            "screenshot_artifact_absent": _remove_local_output(evidence / "display.ppm"),
            "non_controller_evidence_removed": _prune_failure_evidence(evidence),
        }
        failure = controller_failure_record(
            source, progress["stage"], type(error).__name__, cleanup, resources,
            diagnostics,
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
    root = Path(root).resolve()
    evidence = root / ".cache/interactive-appliance-evidence"
    ready = root / ".cache/interactive-appliance-evidence.ready"
    result_path = evidence / "result.json"
    if not _remove_local_output(ready):
        _discard_failed_appliance_outputs(root)
        return False
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
        _discard_failed_appliance_outputs(root)
        return False
    try:
        exact = controller_failure_record(
            source, result.get("stage"), result.get("failure"),
            result.get("cleanup"), result.get("resources"), result.get("diagnostics"),
        )
    except (TypeError, UnicodeError, ValueError):
        exact = None
    try:
        children = {path.name for path in evidence.iterdir()}
    except OSError:
        children = set()
    if result == exact:
        if children == {"result.json"} and _failure_cleanup_complete(root, result):
            return True
        _discard_failed_appliance_outputs(root)
        return False
    try:
        sanitized = invalidate_appliance_output(root, source)
        final = unique_json(result_path.read_bytes())
        children = {path.name for path in evidence.iterdir()}
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _discard_failed_appliance_outputs(root)
        return False
    if (final == sanitized and children == {"result.json"}
            and _failure_cleanup_complete(root, final)):
        return True
    _discard_failed_appliance_outputs(root)
    return False


def create_outer_failure_evidence(root):
    """Create one content-free receipt when no appliance evidence path was created."""
    root = Path(root).resolve()
    evidence = root / ".cache/interactive-appliance-evidence"
    if not _direct_path_absent(evidence):
        return False
    if not _discard_failed_appliance_outputs(root) or not _direct_path_absent(evidence):
        return False
    try:
        _new_directory(evidence)
        record = outer_failure_record(root)
        if not _failure_cleanup_complete(root, record):
            raise ValueError("Outer appliance cleanup is incomplete")
        _write_controller_record(evidence, record)
        return True
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        _discard_failed_appliance_outputs(root)
        return False


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("Use only the hosted appliance evidence controller")
    if sys.argv[1:] == ["--validate-evidence"]:
        validate_retained_evidence(Path.cwd().resolve())
        return
    if sys.argv[1:] == ["--validate-public-artifact"]:
        validate_public_artifact(Path.cwd().resolve())
        return
    if os.geteuid() != 0:
        raise SystemExit("Use only the hosted failed-appliance sanitizer")
    if sys.argv[1:] == ["--sanitize-failure"]:
        prepared = finalize_failed_appliance_evidence(Path.cwd().resolve())
    elif sys.argv[1:] == ["--create-outer-failure"]:
        prepared = create_outer_failure_evidence(Path.cwd().resolve())
    else:
        raise SystemExit("Use only the hosted failed-appliance sanitizer")
    if not prepared:
        raise SystemExit("No bounded appliance failure receipt was available")


if __name__ == "__main__":
    main()
