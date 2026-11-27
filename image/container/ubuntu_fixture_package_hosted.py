"""Hosted-only producer for an unselected Ubuntu fixture package closure.

The committed contract is intentionally pending discovery.  In that state this
module may authenticate and retain current Ubuntu metadata, but it refuses the
production path before opening a URL or executing a command.  A later review
must replace every null metadata pin with exact byte and SHA-256 identities and
change the state to ``ready`` before a candidate can be produced.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import stat
import subprocess
import time
from urllib.request import Request

from image.container import ubuntu_fixture_inputs as inputs
from image.container import ubuntu_fixture_package_build as build
from image.container import ubuntu_fixture_packages as packages


CONTRACT_NAME = "ubuntu-fixture-package-producer.json"
WORKFLOW = ".github/workflows/ubuntu-fixture-packages.yml"
CONTRACT_FIELDS = {
    "schema", "state", "repository", "workflow", "event", "runner",
    "limits", "timeouts", "retained_inputs", "freshness_policy",
    "metadata_pins", "artifacts", "candidate", "scope",
}
LIMIT_FIELDS = {
    "memory_max", "memory_swap_max", "cpu_max", "pids_max",
    "runtime_seconds",
}
TIMEOUT_FIELDS = {
    "metadata_seconds", "rootfs_seconds", "offline_command_seconds",
    "package_download_seconds",
}
RETAINED_FIELDS = {
    "rootfs_verification", "checksum", "checksum_signature",
    "archive_keyring",
}
PIN_FIELDS = {"suite", "inrelease", "packages_xz"}
PAYLOAD_PIN_FIELDS = {"bytes", "sha256"}
ARTIFACT_FIELDS = {"evidence", "candidate", "retention_days"}
CANDIDATE_FIELDS = {
    "state", "producer_passed", "selected", "qualified",
    "container_qualified", "signature_qualified", "os_qualified",
    "release_qualified",
}
CLAIM_FIELDS = CANDIDATE_FIELDS - {"state"}
COMMAND_FIELDS = {
    "name", "argv", "tool", "launcher", "network", "timeout_seconds",
    "timed_out", "exit_status", "started_at", "finished_at", "duration_ms",
    "stdout", "stderr", "inputs",
}
TOOL_FIELDS = {"path", "bytes", "sha256", "device", "inode"}
RAW_FIELDS = {"path", "bytes", "sha256"}
INPUT_FIELDS = {"name", "bytes", "sha256"}
RESULT_FIELDS = {
    "schema", "mode", "state", "passed", "authoritative", "selected",
    "qualified", "container_qualified", "signature_qualified",
    "os_qualified", "release_qualified", "contract_sha256", "lock_sha256",
    "repository", "run", "verified_at", "rootfs", "metadata", "commands",
    "download", "candidate", "phase_ledger", "scope",
}
RUN_FIELDS = {
    "id", "attempt", "head_sha", "head_tree", "workflow", "event",
}
ROOTFS_RESULT_FIELDS = {
    "archive", "bytes", "sha256", "checksum_sha256",
    "checksum_signature_sha256", "keyring_sha256", "signing_fingerprint",
}
METADATA_RESULT_FIELDS = {
    "suite", "inrelease", "packages_xz", "release", "signature",
}
RESULT_PAYLOAD_FIELDS = {"path", "bytes", "sha256"}
DOWNLOAD_FIELDS = {"count", "bytes", "order_sha256"}
RESULT_CANDIDATE_FIELDS = {"created", "manifest_sha256", "state"}
LEDGER_RECEIPT_FIELDS = {"bytes", "sha256", "phase_count", "terminal_phase"}
SYSTEMD_FALLBACK_FIELDS = {
    "schema", "source", "authoritative", "systemd",
    "measurement_available", "zero_swap", "oom_observed", "oom_auditable",
    "error",
}
SYSTEMD_FALLBACK_SCHEMA = 2
SYSTEMD_RESULT_FIELDS = {
    "LoadState", "ActiveState", "SubState", "Result", "ExecMainCode",
    "ExecMainStatus", "MemoryCurrent", "MemoryPeak", "MemoryMax",
    "MemorySwapCurrent", "MemorySwapPeak", "MemorySwapMax",
    "CPUQuotaPerSecUSec", "CPUQuotaPeriodUSec", "CPUUsageNSec",
    "TasksCurrent", "TasksMax", "RuntimeMaxUSec",
}
CGROUP_FINAL_FIELDS = {
    "schema", "limits", "counters", "zero_swap", "error",
}
CGROUP_FINAL_COUNTERS = {
    "memory.max", "memory.swap.max", "memory.current", "memory.peak",
    "memory.swap.current", "memory.swap.peak", "memory.events", "cpu.max",
    "cpu.stat", "pids.max", "pids.current", "pids.peak",
}
RETENTION_FIELDS = {
    "schema", "mode", "producer_exit_status", "private_work_retained",
    "recursive_path_cleanup_performed", "candidate_present",
    "post_unit_candidate_validated", "selected", "qualified",
}
LEDGER_FIELDS = {
    "schema", "state", "passed", "authoritative", "selected", "qualified",
    "container_qualified", "signature_qualified", "os_qualified",
    "release_qualified", "mode", "contract_sha256", "lock_sha256",
    "repository", "run", "phases", "scope",
}
LEDGER_PHASE_FIELDS = {
    "sequence", "kind", "suite", "commands", "payloads", "diagnostics",
}
LEDGER_PAYLOAD_FIELDS = {"name", "url", "bytes", "sha256"}
LEGACY_PHASE_LEDGER_SCHEMA = 1
PHASE_LEDGER_SCHEMA = 2
LEDGER_SCOPE = (
    "Bounded partial hosted evidence only; never a producer result, candidate, "
    "selection or qualification"
)
LEDGER_PHASE_ORDER = (
    [("checkout", None), ("rootfs-signature", None),
     ("rootfs-download", None)]
    + [
        (kind, source["suite"])
        for source in packages.EXPECTED_SOURCES
        for kind in (
            "inrelease-download", "inrelease-signature",
            "release-validated", "packages-download",
        )
    ]
)
LEDGER_REJECTION_REASONS = {
    "valid-until-rejected", "freshness-rejected", "identity-rejected",
    "content-scope-rejected", "index-inventory-rejected",
    "release-structure-rejected",
}

PENDING_SCOPE = (
    "Manual hosted discovery pending reviewed InRelease and Packages.xz byte "
    "pins; no image consumer, selection or qualification"
)
READY_SCOPE = (
    "Manual hosted producer for a pinned unselected Ubuntu package candidate; "
    "no image consumer, selection or qualification"
)
RESULT_SCOPE = (
    "Hosted Ubuntu package evidence or unselected candidate only; no image "
    "consumer, artifact selection or qualification"
)
EXPECTED_LIMITS = {
    "memory_max": 2 * 1024**3,
    "memory_swap_max": 0,
    "cpu_max": "100000 100000",
    "pids_max": 128,
    "runtime_seconds": 3000,
}
EXPECTED_TIMEOUTS = {
    "metadata_seconds": 300,
    "rootfs_seconds": 600,
    "offline_command_seconds": 600,
    "package_download_seconds": 600,
}
EXPECTED_RETAINED = {
    "rootfs_verification": "image/container/hosted/ubuntu/verified-rootfs.json",
    "checksum": "image/container/hosted/ubuntu/SHA256SUMS",
    "checksum_signature": "image/container/hosted/ubuntu/SHA256SUMS.gpg",
    "archive_keyring": "image/container/hosted/ubuntu/archive.gpg",
}
MAX_COMMAND_OUTPUT = 16 * 1024**2
MAX_TOOL_BYTES = 64 * 1024**2
MAX_PHASE_LEDGER_BYTES = 2 * 1024**2
FETCH_CHUNK = 64 * 1024
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json_sha256(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(raw)


def _iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _strict_positive_int(value, maximum=None):
    return (type(value) is int and value > 0
            and (maximum is None or value <= maximum))


def _load_json(path, maximum=packages.MAX_CONTROL_FILE_BYTES):
    raw = packages.read_bounded_control_file(
        path.parent, path.name, "Ubuntu hosted producer JSON", maximum)
    return packages.unique_json_bytes(raw, maximum)


def validate_contract(root, contract, lock):
    """Validate the exact dormant/ready hosted producer contract."""
    root = Path(root).resolve(strict=True)
    inputs.validate_pending_lock(root, lock)
    require(type(contract) is dict and set(contract) == CONTRACT_FIELDS
            and type(contract.get("schema")) is int and contract["schema"] == 2
            and contract.get("state") in {"pending-discovery", "ready"}
            and contract.get("repository") == packages.REPOSITORY
            and contract.get("workflow") == WORKFLOW
            and contract.get("event") == "workflow_dispatch"
            and contract.get("runner") == "ubuntu-24.04",
            "Ubuntu hosted producer identity or fields changed")
    require(type(contract.get("limits")) is dict
            and set(contract["limits"]) == LIMIT_FIELDS
            and contract["limits"] == EXPECTED_LIMITS
            and type(contract.get("timeouts")) is dict
            and set(contract["timeouts"]) == TIMEOUT_FIELDS
            and contract["timeouts"] == EXPECTED_TIMEOUTS,
            "Ubuntu hosted producer resource or timeout bounds changed")
    require(type(contract.get("retained_inputs")) is dict
            and set(contract["retained_inputs"]) == RETAINED_FIELDS
            and contract["retained_inputs"] == EXPECTED_RETAINED,
            "Ubuntu hosted producer retained input paths changed")
    policies = contract.get("freshness_policy")
    require(type(policies) is list
            and len(policies) == len(packages.EXPECTED_SOURCES),
            "Ubuntu hosted producer freshness policy count changed")
    for policy, source in zip(
            policies, packages.EXPECTED_SOURCES, strict=True):
        build.validate_freshness_policy(policy, source)
    pins = contract.get("metadata_pins")
    require(type(pins) is list
            and len(pins) == len(packages.EXPECTED_SOURCES),
            "Ubuntu hosted producer metadata pin count changed")
    pending = contract["state"] == "pending-discovery"
    for pin, source in zip(pins, packages.EXPECTED_SOURCES, strict=True):
        require(type(pin) is dict and set(pin) == PIN_FIELDS
                and pin.get("suite") == source["suite"],
                "Ubuntu hosted producer metadata pin order changed")
        for name, maximum in (
                ("inrelease", packages.MAX_METADATA_BYTES),
                ("packages_xz", packages.MAX_INDEX_BYTES)):
            payload = pin.get(name)
            require(type(payload) is dict and set(payload) == PAYLOAD_PIN_FIELDS,
                    "Ubuntu hosted producer payload pin fields changed")
            if pending:
                require(payload == {"bytes": None, "sha256": None},
                        "pending Ubuntu metadata contract contains a byte pin")
            else:
                require(_strict_positive_int(payload.get("bytes"), maximum)
                        and packages.exact_hash(payload.get("sha256")),
                        "ready Ubuntu metadata contract has an incomplete pin")
    artifacts = contract.get("artifacts")
    require(type(artifacts) is dict and set(artifacts) == ARTIFACT_FIELDS
            and artifacts == {
                "evidence": "container-ubuntu-fixture-package-evidence",
                "candidate": packages.ARTIFACT_NAME,
                "retention_days": 14,
            }, "Ubuntu hosted producer artifact contract changed")
    candidate = contract.get("candidate")
    require(type(candidate) is dict and set(candidate) == CANDIDATE_FIELDS
            and candidate.get("state") == "candidate-unselected"
            and all(candidate.get(field) is False for field in CLAIM_FIELDS),
            "Ubuntu hosted producer candidate made a claim")
    require(contract.get("scope") == (PENDING_SCOPE if pending else READY_SCOPE),
            "Ubuntu hosted producer scope disagrees with its state")
    return contract


def load_contract(root):
    root = Path(root).resolve(strict=True)
    lock = inputs.load_pending_lock(root)
    contract = packages.unique_json(
        root, "image/container/" + CONTRACT_NAME)
    return validate_contract(root, contract, lock), lock


def validate_mode(contract, mode):
    require(mode in {"discover", "produce"},
            "unknown Ubuntu hosted producer mode")
    expected = "discover" if contract["state"] == "pending-discovery" else "produce"
    require(mode == expected,
            "Ubuntu hosted producer mode is blocked by the metadata pin state")
    return mode


def validate_hosted_environment(contract, mode, environ):
    """Bind the run to one manual GitHub-hosted workflow invocation."""
    validate_mode(contract, mode)
    require(environ.get("GITHUB_ACTIONS") == "true"
            and environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and environ.get("RUNNER_OS") == "Linux"
            and environ.get("RUNNER_ARCH") == "X64"
            and environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environ.get("GITHUB_REPOSITORY")
            == contract["repository"]["full_name"]
            and environ.get("GITHUB_REPOSITORY_ID")
            == str(contract["repository"]["id"]),
            "Ubuntu package producer is not the exact hosted manual workflow")
    sha = environ.get("GITHUB_SHA")
    run_id = environ.get("GITHUB_RUN_ID")
    attempt = environ.get("GITHUB_RUN_ATTEMPT")
    workflow_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    require(packages.exact_hash(sha, 40)
            and isinstance(run_id, str) and run_id.isdigit() and int(run_id) > 0
            and isinstance(attempt, str) and attempt.isdigit()
            and int(attempt) > 0
            and workflow_ref.startswith(
                contract["repository"]["full_name"] + "/" + WORKFLOW + "@"),
            "Ubuntu package producer run identity is malformed")
    return {
        "id": int(run_id),
        "attempt": int(attempt),
        "head_sha": sha,
        "workflow": WORKFLOW,
        "event": "workflow_dispatch",
    }


def validate_retained_inputs(root, contract, lock):
    """Authenticate exact retained keyring/checksum identities before network."""
    retained = contract["retained_inputs"]
    maximums = {
        "rootfs_verification": packages.MAX_CONTROL_FILE_BYTES,
        "checksum": packages.MAX_METADATA_BYTES,
        "checksum_signature": packages.MAX_METADATA_BYTES,
        "archive_keyring": packages.MAX_METADATA_BYTES,
    }
    raw = {
        name: packages.read_bounded_control_file(
            root, path, "Ubuntu retained " + name, maximums[name])
        for name, path in retained.items()
    }
    binding = lock["rootfs"]
    require(sha256_bytes(raw["checksum"]) == binding["checksum"]["sha256"]
            and sha256_bytes(raw["checksum_signature"])
            == binding["checksum"]["signature_sha256"]
            and sha256_bytes(raw["archive_keyring"])
            == binding["keyring"]["sha256"],
            "retained Ubuntu signature input hash changed")
    rows = raw["checksum"].decode("ascii").splitlines()
    require(rows.count(binding["sha256"] + " *" + binding["archive"]) == 1,
            "retained Ubuntu checksum omits the exact Base archive")
    verified = packages.unique_json_bytes(raw["rootfs_verification"])
    expected_fields = {
        "verified_at_utc", "purpose", "archive", "url", "bytes", "sha256",
        "signature_verified", "archive_verified", "signing_fingerprint",
        "keyring", "keyring_sha256", "verification_reference",
        "checksum_file_sha256", "signature_file_sha256", "extracted",
        "container_built",
    }
    require(set(verified) == expected_fields
            and verified.get("archive") == binding["archive"]
            and verified.get("url") == binding["url"]
            and type(verified.get("bytes")) is int
            and verified["bytes"] == binding["bytes"]
            and verified.get("sha256") == binding["sha256"]
            and verified.get("signature_verified") is True
            and verified.get("archive_verified") is True
            and verified.get("signing_fingerprint")
            == binding["checksum"]["signer_fingerprint"]
            and verified.get("keyring_sha256") == binding["keyring"]["sha256"]
            and verified.get("checksum_file_sha256")
            == binding["checksum"]["sha256"]
            and verified.get("signature_file_sha256")
            == binding["checksum"]["signature_sha256"]
            and verified.get("extracted") is False
            and verified.get("container_built") is False,
            "retained Ubuntu rootfs verification record changed")
    return {
        name: {
            "name": name,
            "bytes": len(payload),
            "sha256": sha256_bytes(payload),
        }
        for name, payload in raw.items()
    }


def _safe_evidence_name(value):
    return (type(value) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value) is not None)


def _descriptor_identity(descriptor):
    info = os.fstat(descriptor)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and info.st_gid == 0 and info.st_nlink == 1
            and 0 < info.st_size <= MAX_TOOL_BYTES
            and not (stat.S_IMODE(info.st_mode) & 0o022),
            "Ubuntu producer tool is not an immutable root-owned regular file")
    return info


def _hash_fd(descriptor):
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, FETCH_CHUNK)
        if not block:
            break
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _tool_record(path, descriptor):
    before = _descriptor_identity(descriptor)
    digest = _hash_fd(descriptor)
    after = _descriptor_identity(descriptor)
    require((before.st_dev, before.st_ino, before.st_mode, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns),
            "Ubuntu producer tool changed while hashing")
    return {
        "path": path,
        "bytes": before.st_size,
        "sha256": digest,
        "device": before.st_dev,
        "inode": before.st_ino,
    }


def _read_raw_file(root, relative, maximum=MAX_COMMAND_OUTPUT):
    require(type(relative) is str and relative.startswith("raw/")
            and packages._safe_filename(relative)
            and type(maximum) is int and maximum > 0,
            "Ubuntu producer raw command output path is unsafe")
    root = Path(root).resolve(strict=True)
    parts = PurePosixPath(relative).parts
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = os.open(root, directory_flags)
    leaf = None
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=descriptor)
        before = os.fstat(leaf)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= maximum,
                "Ubuntu producer raw output is not bounded regular data")
        chunks = []
        total = 0
        while True:
            block = os.read(leaf, min(FETCH_CHUNK, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            require(total <= maximum,
                    "Ubuntu producer raw output exceeds its bound")
        raw = b"".join(chunks)
        after = os.fstat(leaf)
        require(len(raw) == before.st_size == after.st_size
                and (before.st_dev, before.st_ino, before.st_mode,
                     before.st_nlink, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_mode,
                    after.st_nlink, after.st_mtime_ns, after.st_ctime_ns),
                "Ubuntu producer raw output changed while reading")
        return raw
    finally:
        if leaf is not None:
            os.close(leaf)
        os.close(descriptor)


class CommandRunner:
    """Run exact held tools and retain bounded stdout/stderr evidence."""

    def __init__(self, evidence, home):
        self.evidence = Path(evidence).resolve(strict=True)
        self.home = Path(home).resolve(strict=True)
        self.raw = self.evidence / "raw"
        self.raw.mkdir(mode=0o700)
        self.results = []

    def run(self, name, argv, timeout, *, networkless=False, inputs_=()):
        require(_safe_evidence_name(name) and type(argv) is list and argv
                and all(type(item) is str and item and "\x00" not in item
                        for item in argv)
                and Path(argv[0]).is_absolute()
                and _strict_positive_int(timeout, 1800),
                "Ubuntu producer command request is malformed")
        tool_fd = os.open(
            argv[0], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        launcher_fd = None
        stdout_path = self.raw / (name + ".stdout")
        stderr_path = self.raw / (name + ".stderr")
        stdout_fd = os.open(
            stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW, 0o600)
        stderr_fd = os.open(
            stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW, 0o600)
        timed_out = False
        started_text = _iso_now()
        started = time.monotonic()
        try:
            tool = _tool_record(argv[0], tool_fd)
            executable = "/proc/self/fd/" + str(tool_fd)
            execution_argv = list(argv)
            launcher = None
            pass_fds = [tool_fd]
            if networkless:
                launcher_path = "/usr/bin/unshare"
                launcher_fd = os.open(
                    launcher_path,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                launcher = _tool_record(launcher_path, launcher_fd)
                execution_argv = [
                    launcher_path, "--net", "--", executable, *argv[1:]
                ]
                executable = "/proc/self/fd/" + str(launcher_fd)
                pass_fds.append(launcher_fd)

            def limit_output():
                resource.setrlimit(
                    resource.RLIMIT_FSIZE,
                    (MAX_COMMAND_OUTPUT, MAX_COMMAND_OUTPUT))

            process = subprocess.Popen(
                execution_argv,
                executable=executable,
                pass_fds=tuple(pass_fds),
                stdin=subprocess.DEVNULL,
                stdout=stdout_fd,
                stderr=stderr_fd,
                cwd=self.home,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(self.home),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                start_new_session=True,
                preexec_fn=limit_output,
            )
            try:
                exit_status = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                exit_status = process.wait()
        finally:
            os.close(stdout_fd)
            os.close(stderr_fd)
            os.close(tool_fd)
            if launcher_fd is not None:
                os.close(launcher_fd)
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = _read_raw_file(self.evidence, "raw/" + stdout_path.name)
        stderr = _read_raw_file(self.evidence, "raw/" + stderr_path.name)
        row = {
            "name": name,
            "argv": argv,
            "tool": tool,
            "launcher": launcher,
            "network": "none" if networkless else "host",
            "timeout_seconds": timeout,
            "timed_out": timed_out,
            "exit_status": exit_status,
            "started_at": started_text,
            "finished_at": _iso_now(),
            "duration_ms": duration_ms,
            "stdout": {
                "path": "raw/" + stdout_path.name,
                "bytes": len(stdout),
                "sha256": sha256_bytes(stdout),
            },
            "stderr": {
                "path": "raw/" + stderr_path.name,
                "bytes": len(stderr),
                "sha256": sha256_bytes(stderr),
            },
            "inputs": list(inputs_),
        }
        validate_command_result(self.evidence, row)
        self.results.append(row)
        return row, stdout, stderr


def validate_command_result(evidence_root, row):
    """Reject caller-forged command provenance or raw-output hashes."""
    require(type(row) is dict and set(row) == COMMAND_FIELDS
            and _safe_evidence_name(row.get("name"))
            and type(row.get("argv")) is list and row["argv"]
            and all(type(item) is str and item for item in row["argv"])
            and row.get("network") in {"host", "none"}
            and _strict_positive_int(row.get("timeout_seconds"), 1800)
            and type(row.get("timed_out")) is bool
            and type(row.get("exit_status")) is int
            and type(row.get("duration_ms")) is int
            and row["duration_ms"] >= 0
            and type(row.get("started_at")) is str
            and type(row.get("finished_at")) is str,
            "Ubuntu producer command evidence fields are malformed")
    for name in ("tool",):
        tool = row.get(name)
        require(type(tool) is dict and set(tool) == TOOL_FIELDS
                and type(tool.get("path")) is str
                and tool["path"] == row["argv"][0]
                and _strict_positive_int(tool.get("bytes"), MAX_TOOL_BYTES)
                and packages.exact_hash(tool.get("sha256"))
                and type(tool.get("device")) is int and tool["device"] >= 0
                and _strict_positive_int(tool.get("inode")),
                "Ubuntu producer tool evidence is malformed")
        descriptor = os.open(
            tool["path"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            require(_tool_record(tool["path"], descriptor) == tool,
                    "Ubuntu producer tool differs from retained evidence")
        finally:
            os.close(descriptor)
    launcher = row.get("launcher")
    if row["network"] == "none":
        require(type(launcher) is dict and set(launcher) == TOOL_FIELDS
                and launcher.get("path") == "/usr/bin/unshare"
                and _strict_positive_int(launcher.get("bytes"), MAX_TOOL_BYTES)
                and packages.exact_hash(launcher.get("sha256"))
                and type(launcher.get("device")) is int
                and _strict_positive_int(launcher.get("inode")),
                "networkless Ubuntu command lacks exact unshare evidence")
        descriptor = os.open(
            launcher["path"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            require(_tool_record(launcher["path"], descriptor) == launcher,
                    "Ubuntu producer launcher differs from retained evidence")
        finally:
            os.close(descriptor)
    else:
        require(launcher is None,
                "networked Ubuntu command has unexpected launcher evidence")
    for name in ("stdout", "stderr"):
        item = row.get(name)
        require(type(item) is dict and set(item) == RAW_FIELDS
                and type(item.get("path")) is str
                and item["path"] == "raw/" + row["name"] + "." + name
                and type(item.get("bytes")) is int
                and 0 <= item["bytes"] <= MAX_COMMAND_OUTPUT
                and packages.exact_hash(item.get("sha256")),
                "Ubuntu producer raw command evidence is malformed")
        raw = _read_raw_file(evidence_root, item["path"])
        require(len(raw) == item["bytes"]
                and sha256_bytes(raw) == item["sha256"],
                "Ubuntu producer raw command output differs from evidence")
    command_inputs = row.get("inputs")
    require(type(command_inputs) is list and len(command_inputs) <= 16,
            "Ubuntu producer command input evidence is malformed")
    names = set()
    for item in command_inputs:
        require(type(item) is dict and set(item) == INPUT_FIELDS
                and _safe_evidence_name(item.get("name"))
                and item["name"] not in names
                and _strict_positive_int(item.get("bytes"), packages.MAX_INDEX_BYTES)
                and packages.exact_hash(item.get("sha256")),
                "Ubuntu producer command input identity is malformed")
        names.add(item["name"])
    return row


@contextmanager
def _deadline(seconds):
    require(_strict_positive_int(seconds, 1800),
            "Ubuntu producer fetch timeout is invalid")
    deadline = time.monotonic() + seconds
    with build._hard_download_deadline(deadline):
        yield deadline


def fetch_exact(url, destination, maximum, timeout, *, expected=None,
                opener=build._OPEN_EXACT_URL):
    """Fetch one no-redirect HTTPS payload with a hard whole-fetch deadline."""
    require(packages._canonical_https(url)
            and type(maximum) is int and maximum > 0
            and (expected is None or (
                type(expected) is dict and set(expected) == PAYLOAD_PIN_FIELDS
                and _strict_positive_int(expected.get("bytes"), maximum)
                and packages.exact_hash(expected.get("sha256")))),
            "Ubuntu producer fetch binding is malformed")
    destination = Path(destination)
    require(destination.is_absolute() and destination.parent.is_dir()
            and not destination.exists()
            and packages._safe_filename(destination.name),
            "Ubuntu producer fetch destination is unsafe")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600)
    written = 0
    digest = hashlib.sha256()
    try:
        with _deadline(timeout) as deadline:
            request = Request(url, headers={
                "User-Agent": "SymbiOS-P0-Ubuntu-closure-producer/1",
                "Accept-Encoding": "identity",
            })
            remaining = deadline - time.monotonic()
            require(remaining > 0, "Ubuntu producer fetch deadline expired")
            with opener(request, timeout=min(build.DOWNLOAD_TIMEOUT_SECONDS,
                                             remaining)) as response:
                length = response.headers.get("Content-Length")
                require(response.status == 200 and response.geturl() == url
                        and type(length) is str and length.isdigit()
                        and 0 < int(length) <= maximum
                        and (expected is None
                             or int(length) == expected["bytes"]),
                        "Ubuntu producer response redirected or changed size")
                while True:
                    block = response.read(FETCH_CHUNK)
                    if not block:
                        break
                    written += len(block)
                    require(written <= int(length)
                            and written <= maximum
                            and time.monotonic() <= deadline,
                            "Ubuntu producer response exceeded its byte or time bound")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        count = os.write(descriptor, view)
                        require(count > 0, "Ubuntu producer payload write stalled")
                        view = view[count:]
        os.fsync(descriptor)
        require(written == int(length),
                "Ubuntu producer response ended before its declared size")
        identity = {"bytes": written, "sha256": digest.hexdigest()}
        if expected is not None:
            require(identity == expected,
                    "Ubuntu producer payload differs from its reviewed pin")
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.getuid() and info.st_gid == os.getgid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size == written,
                "Ubuntu producer payload output identity changed")
        return identity
    finally:
        os.close(descriptor)


def _write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    require(len(raw) <= packages.MAX_METADATA_BYTES,
            "Ubuntu producer JSON output exceeds its bound")
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, "Ubuntu producer JSON write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"bytes": len(raw), "sha256": sha256_bytes(raw)}


def _stable_private_file_identity(info, digest):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "links": info.st_nlink,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "rdevice": info.st_rdev,
        "bytes": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "sha256": digest,
    }


def _same_published_private_file(first, second):
    """Compare one file across a rename, which may legitimately change ctime."""
    if type(first) is not dict or type(second) is not dict:
        return False
    fields = set(first) - {"ctime_ns"}
    return set(first) == set(second) and all(
        first[name] == second[name] for name in fields)


def _private_file_stat_identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_uid, info.st_gid, info.st_rdev, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_private_named_file(directory_fd, name, description, maximum,
                             *, missing_ok=False):
    """Read one direct private file without following or blocking on its type."""
    require(type(directory_fd) is int and directory_fd >= 0
            and _safe_evidence_name(name)
            and type(maximum) is int and maximum > 0
            and type(description) is str and description,
            "Ubuntu private evidence read request is malformed")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ValueError(description + " is missing") from None
    except OSError as error:
        raise ValueError(description + " is unsafe") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid()
                and before.st_gid == os.getegid()
                and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= maximum,
                description + " is not one bounded private regular file")
        remaining = before.st_size
        chunks = []
        digest = hashlib.sha256()
        while remaining:
            block = os.read(descriptor, min(FETCH_CHUNK, remaining))
            require(block, description + " was truncated while reading")
            chunks.append(block)
            digest.update(block)
            remaining -= len(block)
        require(os.read(descriptor, 1) == b"",
                description + " grew while reading")
        after = os.fstat(descriptor)
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise ValueError(description + " name changed while reading") from error
        stable = _private_file_stat_identity(before)
        require(stable == _private_file_stat_identity(after)
                == _private_file_stat_identity(named),
                description + " identity changed while reading")
        raw = b"".join(chunks)
        require(len(raw) == before.st_size,
                description + " byte count changed while reading")
        return raw, _stable_private_file_identity(before, digest.hexdigest())
    finally:
        os.close(descriptor)


def _open_private_evidence_directory(path):
    path = Path(path)
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError("Ubuntu phase-ledger evidence directory is unsafe") \
            from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISDIR(before.st_mode)
                and before.st_uid == os.geteuid()
                and before.st_gid == os.getegid()
                and stat.S_IMODE(before.st_mode) == 0o700,
                "Ubuntu phase-ledger evidence directory is not private")
        named = os.stat(path, follow_symlinks=False)
        stable = lambda info: (
            info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_rdev,
            info.st_mtime_ns, info.st_ctime_ns,
        )
        require(stable(before) == stable(named),
                "Ubuntu phase-ledger evidence directory identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _ledger_payload(name, url, identity):
    require(_safe_evidence_name(name) and type(url) is str
            and url.startswith("https://")
            and type(identity) is dict
            and set(identity) == PAYLOAD_PIN_FIELDS
            and _strict_positive_int(identity.get("bytes"), packages.MAX_INDEX_BYTES)
            and packages.exact_hash(identity.get("sha256")),
            "Ubuntu phase-ledger payload is malformed")
    return {"name": name, "url": url, **identity}


def _renameat2(source_fd, source_name, destination_fd, destination_name, flags):
    require(_safe_evidence_name(source_name)
            and _safe_evidence_name(destination_name)
            and flags in {_RENAME_NOREPLACE, _RENAME_EXCHANGE},
            "Ubuntu phase-ledger rename request is malformed")
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise ValueError(
            "atomic Ubuntu phase-ledger publication is unavailable") from error
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_fd, os.fsencode(source_name), destination_fd,
        os.fsencode(destination_name), flags)
    if result != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise FileExistsError(
                number, "Ubuntu phase-ledger destination already exists",
                destination_name)
        raise OSError(number, "atomic Ubuntu phase-ledger publication failed")


def _validate_release_diagnostics(value):
    fields = {
        "bytes", "sha256", "control_fields_valid", "field_count",
        "date_fields", "valid_until_fields", "sha256_fields",
        "origin_matches", "label_matches", "suite_matches",
        "codename_matches",
    }
    require(type(value) is dict and set(value) == fields
            and _strict_positive_int(value.get("bytes"), packages.MAX_METADATA_BYTES)
            and packages.exact_hash(value.get("sha256"))
            and type(value.get("control_fields_valid")) is bool
            and (value.get("field_count") is None
                 or _strict_positive_int(value["field_count"], 4096))
            and all(type(value.get(name)) is int and 0 <= value[name] <= 4096
                    for name in (
                        "date_fields", "valid_until_fields", "sha256_fields"))
            and all(type(value.get(name)) is bool for name in (
                "origin_matches", "label_matches", "suite_matches",
                "codename_matches")),
            "Ubuntu phase-ledger Release diagnostics are malformed")
    require((value["field_count"] is not None)
            is value["control_fields_valid"],
            "Ubuntu phase-ledger Release diagnostic validity disagrees")
    return value


def _expected_checkout_commands(source_root):
    return {
        "checkout-head": [
            "/usr/bin/git", "-C", str(source_root), "rev-parse", "--verify",
            "HEAD^{commit}",
        ],
        "checkout-tree": [
            "/usr/bin/git", "-C", str(source_root), "rev-parse", "--verify",
            "HEAD^{tree}",
        ],
        "checkout-clean": [
            "/usr/bin/git", "-C", str(source_root), "status",
            "--porcelain=v1", "--untracked-files=all",
        ],
    }


def validate_phase_ledger(value, mode, contract, lock, evidence, source_root,
                          expected_run=None):
    """Validate one strict prefix of the non-authoritative hosted phase ledger."""
    evidence = Path(evidence).resolve(strict=True)
    source_root = Path(source_root).resolve(strict=True)
    require(type(value) is dict and set(value) == LEDGER_FIELDS
            and type(value.get("schema")) is int
            and value["schema"] in {
                LEGACY_PHASE_LEDGER_SCHEMA, PHASE_LEDGER_SCHEMA}
            and value.get("state") == "partial-evidence"
            and value.get("passed") is False
            and value.get("authoritative") is False
            and all(value.get(field) is False for field in (
                "selected", "qualified", "container_qualified",
                "signature_qualified", "os_qualified", "release_qualified"))
            and value.get("mode") == mode
            and value.get("contract_sha256") == canonical_json_sha256(contract)
            and value.get("lock_sha256") == canonical_json_sha256(lock)
            and value.get("repository") == packages.REPOSITORY
            and value.get("scope") == LEDGER_SCOPE,
            "Ubuntu phase ledger fields or authority claims changed")
    run = value.get("run")
    require(type(run) is dict and set(run) == RUN_FIELDS
            and _strict_positive_int(run.get("id"))
            and _strict_positive_int(run.get("attempt"))
            and packages.exact_hash(run.get("head_sha"), 40)
            and packages.exact_hash(run.get("head_tree"), 40)
            and run.get("workflow") == WORKFLOW
            and run.get("event") == "workflow_dispatch"
            and (expected_run is None or run == expected_run),
            "Ubuntu phase ledger run identity changed")
    phases = value.get("phases")
    require(type(phases) is list and len(phases) <= len(LEDGER_PHASE_ORDER),
            "Ubuntu phase ledger is oversized")
    retained = validate_retained_inputs(source_root, contract, lock)
    prior = {}
    for offset, phase in enumerate(phases):
        expected_kind, expected_suite = LEDGER_PHASE_ORDER[offset]
        rejection = (type(phase) is dict
                     and phase.get("kind") == "release-rejected")
        require(type(phase) is dict and set(phase) == LEDGER_PHASE_FIELDS
                and type(phase.get("sequence")) is int
                and phase["sequence"] == offset + 1
                and (phase.get("kind") == expected_kind
                     or (rejection and expected_kind == "release-validated"
                         and offset == len(phases) - 1))
                and phase.get("suite") == expected_suite
                and type(phase.get("commands")) is list
                and len(phase["commands"]) <= 3
                and type(phase.get("payloads")) is list
                and len(phase["payloads"]) <= 1
                and type(phase.get("diagnostics")) is dict,
                "Ubuntu phase ledger order or fields changed")
        command_by_name = {}
        for command in phase["commands"]:
            validate_command_result(evidence, command)
            require(command["name"] not in command_by_name
                    and command["timed_out"] is False
                    and command["exit_status"] == 0,
                    "Ubuntu phase ledger contains a failed or duplicate command")
            command_by_name[command["name"]] = command
        payloads = phase["payloads"]
        for payload in payloads:
            require(type(payload) is dict and set(payload) == LEDGER_PAYLOAD_FIELDS
                    and _safe_evidence_name(payload.get("name"))
                    and type(payload.get("url")) is str
                    and payload["url"].startswith("https://")
                    and _strict_positive_int(
                        payload.get("bytes"), packages.MAX_INDEX_BYTES)
                    and packages.exact_hash(payload.get("sha256")),
                    "Ubuntu phase ledger payload fields changed")

        if rejection:
            source = next(row for row in packages.EXPECTED_SOURCES
                          if row["suite"] == expected_suite)
            download_phase = prior[("inrelease-download", expected_suite)]
            signature_phase = prior[("inrelease-signature", expected_suite)]
            inrelease = download_phase["payloads"][0]
            diagnostics = phase["diagnostics"]
            diagnostics_fields = {
                "reason", "inrelease", "signer_fingerprint"}
            if value["schema"] == PHASE_LEDGER_SCHEMA:
                diagnostics_fields.add("predicate")
            predicate = diagnostics.get("predicate")
            require(command_by_name == {} and payloads == []
                    and type(diagnostics) is dict
                    and set(diagnostics) == diagnostics_fields
                    and type(diagnostics.get("reason")) is str
                    and diagnostics["reason"] in LEDGER_REJECTION_REASONS
                    and ((value["schema"] == LEGACY_PHASE_LEDGER_SCHEMA
                          and predicate is None)
                         or (value["schema"] == PHASE_LEDGER_SCHEMA
                             and ((diagnostics["reason"]
                                   == "index-inventory-rejected"
                                   and type(predicate) is str
                                   and predicate
                                   in build.RELEASE_INVENTORY_PREDICATES)
                                  or (diagnostics["reason"]
                                      != "index-inventory-rejected"
                                      and predicate is None))))
                    and diagnostics.get("inrelease") == {
                        "bytes": inrelease["bytes"],
                        "sha256": inrelease["sha256"],
                    }
                    and diagnostics.get("signer_fingerprint")
                    == source["metadata"]["signer_fingerprint"]
                    == signature_phase["diagnostics"]["signature"][
                        "signing_fingerprint"],
                    "Ubuntu phase ledger Release rejection changed")
            prior[("release-rejected", expected_suite)] = phase
            continue
        if expected_kind == "checkout":
            expected = _expected_checkout_commands(source_root)
            require(set(command_by_name) == set(expected) and payloads == []
                    and phase["diagnostics"] == {
                        "head_sha": run["head_sha"],
                        "head_tree": run["head_tree"],
                        "clean": True,
                    }, "Ubuntu phase ledger checkout binding changed")
            for name, argv in expected.items():
                row = command_by_name[name]
                require(row["argv"] == argv and row["network"] == "host"
                        and row["launcher"] is None and row["inputs"] == []
                        and row["timeout_seconds"]
                        == contract["timeouts"]["metadata_seconds"]
                        and _read_raw_file(evidence, row["stderr"]["path"]) == b"",
                        "Ubuntu phase ledger checkout command changed")
            require(_read_raw_file(
                        evidence, command_by_name["checkout-head"]["stdout"]["path"])
                    == (run["head_sha"] + "\n").encode("ascii")
                    and _read_raw_file(
                        evidence,
                        command_by_name["checkout-tree"]["stdout"]["path"])
                    == (run["head_tree"] + "\n").encode("ascii")
                    and _read_raw_file(
                        evidence,
                        command_by_name["checkout-clean"]["stdout"]["path"])
                    == b"", "Ubuntu phase ledger checkout outputs changed")
        elif expected_kind == "rootfs-signature":
            command = command_by_name.get("rootfs-gpgv")
            expected_inputs = [retained[name] for name in (
                "archive_keyring", "checksum_signature", "checksum")]
            expected_argv = [
                "/usr/bin/gpgv", "--status-fd=1", "--keyring",
                str(source_root / contract["retained_inputs"]["archive_keyring"]),
                str(source_root / contract["retained_inputs"]["checksum_signature"]),
                str(source_root / contract["retained_inputs"]["checksum"]),
            ]
            require(command is not None and len(command_by_name) == 1
                    and command["argv"] == expected_argv
                    and command["inputs"] == expected_inputs
                    and command["network"] == "host"
                    and command["launcher"] is None
                    and command["timeout_seconds"]
                    == contract["timeouts"]["metadata_seconds"]
                    and payloads == [],
                    "Ubuntu phase ledger rootfs signature command changed")
            observed = build.validate_gpgv_status(
                command["exit_status"],
                _read_raw_file(evidence, command["stdout"]["path"]).decode("utf-8"),
                lock["rootfs"]["checksum"]["signer_fingerprint"])
            require(phase["diagnostics"] == observed,
                    "Ubuntu phase ledger rootfs signature diagnostics changed")
        elif expected_kind == "rootfs-download":
            require(command_by_name == {} and len(payloads) == 1
                    and payloads[0] == _ledger_payload(
                        "rootfs", lock["rootfs"]["url"], {
                            "bytes": lock["rootfs"]["bytes"],
                            "sha256": lock["rootfs"]["sha256"],
                        })
                    and phase["diagnostics"] == {},
                    "Ubuntu phase ledger rootfs payload changed")
        else:
            source = next(row for row in packages.EXPECTED_SOURCES
                          if row["suite"] == expected_suite)
            policy = build.expected_freshness_policy(source)
            if expected_kind == "inrelease-download":
                require(command_by_name == {} and len(payloads) == 1
                        and payloads[0]["name"] == "inrelease-" + expected_suite
                        and payloads[0]["url"]
                        == source["metadata"]["inrelease_url"]
                        and payloads[0]["bytes"] <= packages.MAX_METADATA_BYTES
                        and phase["diagnostics"] == {},
                        "Ubuntu phase ledger InRelease payload changed")
                pin = next(row for row in contract["metadata_pins"]
                           if row["suite"] == expected_suite)["inrelease"]
                if contract["state"] == "ready":
                    require({key: payloads[0][key] for key in PAYLOAD_PIN_FIELDS}
                            == pin,
                            "Ubuntu phase ledger InRelease differs from its pin")
            elif expected_kind == "inrelease-signature":
                command = command_by_name.get("inrelease-" + expected_suite)
                prior_download = prior[("inrelease-download", expected_suite)]
                expected_input = {
                    key: prior_download["payloads"][0][key]
                    for key in ("name", "bytes", "sha256")
                }
                require(command is not None and len(command_by_name) == 1
                        and command["inputs"]
                        == [expected_input, retained["archive_keyring"]]
                        and command["network"] == "host"
                        and command["launcher"] is None
                        and command["timeout_seconds"]
                        == contract["timeouts"]["metadata_seconds"]
                        and len(command["argv"]) == 7
                        and command["argv"][:4] == [
                            "/usr/bin/gpgv", "--status-fd=1", "--keyring",
                            str(source_root / contract["retained_inputs"][
                                "archive_keyring"]),
                        ]
                        and command["argv"][4] == "--output"
                        and Path(command["argv"][5]).name
                        == expected_suite + "_Release"
                        and Path(command["argv"][6]).name
                        == expected_suite + "_InRelease"
                        and Path(command["argv"][5]).parent
                        == Path(command["argv"][6]).parent
                        and Path(command["argv"][5]).parent.name
                        == "metadata-" + expected_suite
                        and payloads == [],
                        "Ubuntu phase ledger InRelease command cross-binding changed")
                diagnostics = phase["diagnostics"]
                require(type(diagnostics) is dict
                        and set(diagnostics) == {"signature", "release"},
                        "Ubuntu phase ledger InRelease diagnostics changed")
                observed = build.validate_gpgv_status(
                    command["exit_status"],
                    _read_raw_file(
                        evidence, command["stdout"]["path"]).decode("utf-8"),
                    source["metadata"]["signer_fingerprint"])
                require(diagnostics["signature"] == observed,
                        "Ubuntu phase ledger InRelease signature changed")
                _validate_release_diagnostics(diagnostics["release"])
            elif expected_kind == "release-validated":
                signature_phase = prior[("inrelease-signature", expected_suite)]
                diagnostics = phase["diagnostics"]
                release_diagnostics = signature_phase["diagnostics"]["release"]
                require(command_by_name == {} and payloads == []
                        and type(diagnostics) is dict
                        and set(diagnostics) == {
                            "freshness_policy", "release", "index"}
                        and diagnostics["freshness_policy"] == policy
                        and release_diagnostics["control_fields_valid"] is True
                        and release_diagnostics["date_fields"] == 1
                        and (
                            release_diagnostics["valid_until_fields"] == 0
                            if policy["mode"] == "immutable-release"
                            else release_diagnostics["valid_until_fields"]
                            in (0, 1)
                        )
                        and release_diagnostics["sha256_fields"] == 1
                        and all(release_diagnostics[name] is True for name in (
                            "origin_matches", "label_matches", "suite_matches",
                            "codename_matches"))
                        and diagnostics["release"]
                        == {key: release_diagnostics[key]
                            for key in ("bytes", "sha256")}
                        and type(diagnostics["index"]) is dict
                        and set(diagnostics["index"])
                        == packages.RELEASE_INDEX_FIELDS
                        and diagnostics["index"]["path"]
                        == "main/binary-amd64/Packages.xz"
                        and _strict_positive_int(
                            diagnostics["index"]["bytes"], packages.MAX_INDEX_BYTES)
                        and packages.exact_hash(diagnostics["index"]["sha256"]),
                        "Ubuntu phase ledger validated Release binding changed")
            else:
                validated = prior[("release-validated", expected_suite)]
                identity = validated["diagnostics"]["index"]
                require(command_by_name == {} and len(payloads) == 1
                        and payloads[0] == _ledger_payload(
                            "packages-" + expected_suite, source["packages_url"], {
                                "bytes": identity["bytes"],
                                "sha256": identity["sha256"],
                            })
                        and phase["diagnostics"] == {},
                        "Ubuntu phase ledger Packages payload changed")
                pin = next(row for row in contract["metadata_pins"]
                           if row["suite"] == expected_suite)["packages_xz"]
                if contract["state"] == "ready":
                    require({key: payloads[0][key] for key in PAYLOAD_PIN_FIELDS}
                            == pin,
                            "Ubuntu phase ledger Packages differs from its pin")
        prior[(expected_kind, expected_suite)] = phase
    return value


def _load_phase_ledger_at(directory_fd):
    retained = _read_private_named_file(
        directory_fd, "phase-ledger.json", "Ubuntu phase ledger",
        MAX_PHASE_LEDGER_BYTES)
    raw, identity = retained
    value = packages.unique_json_bytes(raw, MAX_PHASE_LEDGER_BYTES)
    return value, raw, identity


def load_phase_ledger(path):
    """Load one descriptor-anchored, bounded, duplicate-free phase ledger."""
    path = Path(path)
    require(path.name == "phase-ledger.json",
            "Ubuntu phase-ledger path changed")
    directory_fd = _open_private_evidence_directory(path.parent)
    try:
        value, _, _ = _load_phase_ledger_at(directory_fd)
        return value
    finally:
        os.close(directory_fd)


class PhaseLedger:
    """Atomically retain a strict prefix of completed hosted phases."""

    def __init__(self, evidence, mode, contract, lock, run, source_root):
        self.evidence = Path(evidence).resolve(strict=True)
        self.mode = mode
        self.contract = contract
        self.lock = lock
        self.run = dict(run)
        self.source_root = Path(source_root).resolve(strict=True)
        self.published = False
        self.fd = _open_private_evidence_directory(self.evidence)
        self.value = {
            "schema": PHASE_LEDGER_SCHEMA,
            "state": "partial-evidence",
            "passed": False,
            "authoritative": False,
            "selected": False,
            "qualified": False,
            "container_qualified": False,
            "signature_qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "mode": mode,
            "contract_sha256": canonical_json_sha256(contract),
            "lock_sha256": canonical_json_sha256(lock),
            "repository": packages.REPOSITORY,
            "run": self.run,
            "phases": [],
            "scope": LEDGER_SCOPE,
        }
        try:
            self._persist()
        except BaseException:
            self.close()
            raise

    def _named_identity(self, name):
        retained = _read_private_named_file(
            self.fd, name, "Ubuntu phase-ledger named output",
            MAX_PHASE_LEDGER_BYTES, missing_ok=True)
        return None if retained is None else retained[1]

    def _persist(self):
        validate_phase_ledger(
            self.value, self.mode, self.contract, self.lock, self.evidence,
            self.source_root, self.run)
        raw = (json.dumps(self.value, indent=2, sort_keys=True) + "\n").encode()
        require(len(raw) <= MAX_PHASE_LEDGER_BYTES,
                "Ubuntu phase ledger exceeds its byte bound")
        temporary = "phase-ledger.new"
        final = "phase-ledger.json"
        descriptor = None
        temporary_created = False
        temporary_key = None
        temporary_identity = None
        prior_final = self._named_identity(final)
        require((not self.published and prior_final is None)
                or (self.published and prior_final is not None),
                "Ubuntu phase-ledger destination has an unexpected state")
        require(self._named_identity(temporary) is None,
                "Ubuntu phase-ledger temporary name already exists")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            temporary_created = True
            created = os.fstat(descriptor)
            temporary_key = (created.st_dev, created.st_ino)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                require(count > 0, "Ubuntu phase-ledger write stalled")
                view = view[count:]
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.geteuid()
                    and info.st_gid == os.getegid()
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_size == len(raw),
                    "Ubuntu phase-ledger temporary output changed")
            os.close(descriptor)
            descriptor = None
            temporary_identity = self._named_identity(temporary)
            require(temporary_identity is not None
                    and (temporary_identity["device"],
                         temporary_identity["inode"]) == temporary_key
                    and temporary_identity["bytes"] == len(raw)
                    and temporary_identity["sha256"] == sha256_bytes(raw)
                    and self._named_identity(final) == prior_final,
                    "Ubuntu phase-ledger name changed before publication")
            if prior_final is None:
                _renameat2(
                    self.fd, temporary, self.fd, final, _RENAME_NOREPLACE)
                temporary_created = False
            else:
                _renameat2(
                    self.fd, temporary, self.fd, final, _RENAME_EXCHANGE)
                if not _same_published_private_file(
                        self._named_identity(temporary), prior_final):
                    _renameat2(
                        self.fd, temporary, self.fd, final, _RENAME_EXCHANGE)
                    raise ValueError(
                        "Ubuntu phase-ledger destination raced publication")
                os.unlink(temporary, dir_fd=self.fd)
                temporary_created = False
            require(_same_published_private_file(
                        self._named_identity(final), temporary_identity),
                    "Ubuntu phase-ledger destination raced publication")
            os.fsync(self.fd)
            self.published = True
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_created:
                try:
                    info = os.stat(
                        temporary, dir_fd=self.fd, follow_symlinks=False)
                    require(stat.S_ISREG(info.st_mode)
                            and (info.st_dev, info.st_ino) == temporary_key,
                            "Ubuntu phase-ledger temporary output changed")
                    os.unlink(temporary, dir_fd=self.fd)
                except FileNotFoundError:
                    pass
        value, _, identity = _load_phase_ledger_at(self.fd)
        require(value == self.value
                and _same_published_private_file(identity, temporary_identity),
                "Ubuntu phase ledger changed after atomic publication")

    def append(self, kind, suite, commands=(), payloads=(), diagnostics=None):
        expected = LEDGER_PHASE_ORDER[len(self.value["phases"])]
        require((kind, suite) == expected,
                "Ubuntu phase ledger append is out of order")
        self.value["phases"].append({
            "sequence": len(self.value["phases"]) + 1,
            "kind": kind,
            "suite": suite,
            "commands": list(commands),
            "payloads": list(payloads),
            "diagnostics": {} if diagnostics is None else diagnostics,
        })
        self._persist()

    def reject_release(self, suite, inrelease, signer_fingerprint, reason,
                       predicate=None):
        expected = LEDGER_PHASE_ORDER[len(self.value["phases"])]
        require(expected == ("release-validated", suite)
                and type(inrelease) is dict
                and set(inrelease) == PAYLOAD_PIN_FIELDS
                and _strict_positive_int(
                    inrelease.get("bytes"), packages.MAX_METADATA_BYTES)
                and packages.exact_hash(inrelease.get("sha256"))
                and packages.full_fingerprint(signer_fingerprint)
                and type(reason) is str and reason in LEDGER_REJECTION_REASONS
                and ((reason == "index-inventory-rejected"
                      and type(predicate) is str
                      and predicate in build.RELEASE_INVENTORY_PREDICATES)
                     or (reason != "index-inventory-rejected"
                         and predicate is None)),
                "Ubuntu phase-ledger Release rejection is malformed")
        self.value["phases"].append({
            "sequence": len(self.value["phases"]) + 1,
            "kind": "release-rejected",
            "suite": suite,
            "commands": [],
            "payloads": [],
            "diagnostics": {
                "reason": reason,
                "predicate": predicate,
                "inrelease": inrelease,
                "signer_fingerprint": signer_fingerprint,
            },
        })
        self._persist()

    def receipt(self):
        value, raw, _ = _load_phase_ledger_at(self.fd)
        require(value == self.value,
                "Ubuntu phase ledger changed before final receipt")
        terminal = self.value["phases"][-1]["kind"] \
            if self.value["phases"] else None
        return {
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
            "phase_count": len(self.value["phases"]),
            "terminal_phase": terminal,
        }

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def validate_phase_ledger_receipt(receipt, mode, contract, lock, evidence,
                                  source_root, run):
    """Reopen the final ledger and bind its exact bytes to a success receipt."""
    directory_fd = _open_private_evidence_directory(evidence)
    try:
        ledger_value, ledger_raw, _ = _load_phase_ledger_at(directory_fd)
        validate_phase_ledger(
            ledger_value, mode, contract, lock, evidence, source_root, run)
        require(type(receipt) is dict and set(receipt) == LEDGER_RECEIPT_FIELDS
                and receipt == {
                    "bytes": len(ledger_raw),
                    "sha256": sha256_bytes(ledger_raw),
                    "phase_count": len(LEDGER_PHASE_ORDER),
                    "terminal_phase": "packages-download",
                }
                and len(ledger_value["phases"]) == len(LEDGER_PHASE_ORDER)
                and ledger_value["phases"][-1]["kind"] == "packages-download"
                and ledger_value["phases"][-1]["suite"] == "noble-security",
                "Ubuntu producer result phase-ledger receipt changed")
        return ledger_value
    finally:
        os.close(directory_fd)


def systemd_fallback_record(raw):
    """Preserve resource state when the unit cannot run its finally block."""
    require(isinstance(raw, bytes) and len(raw) <= packages.MAX_CONTROL_FILE_BYTES
            and b"\x00" not in raw,
            "Ubuntu producer systemd evidence is malformed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Ubuntu producer systemd evidence is not UTF-8") from error
    rows = {}
    messages = []
    for line in text.splitlines():
        if "=" not in line:
            if line:
                messages.append(line)
            continue
        key, value = line.split("=", 1)
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key) is not None
                and key not in rows,
                "Ubuntu producer systemd evidence has duplicate or unsafe fields")
        rows[key] = value
    zero_values = {"0", "0B"}
    exact_fields = set(rows) == SYSTEMD_RESULT_FIELDS
    measurement_available = exact_fields and rows.get("LoadState") == "loaded"
    oom_auditable = (measurement_available
                     and rows.get("Result") not in {None, "", "[not set]"})
    return {
        "schema": SYSTEMD_FALLBACK_SCHEMA,
        "source": "systemd-fallback",
        "authoritative": False,
        "systemd": rows,
        "measurement_available": measurement_available,
        "zero_swap": (measurement_available
                      and rows.get("MemorySwapMax") in zero_values
                      and rows.get("MemorySwapCurrent") in zero_values
                      and rows.get("MemorySwapPeak") in zero_values),
        "oom_observed": (oom_auditable
                         and rows.get("Result") == "oom-kill"),
        "oom_auditable": oom_auditable,
        "error": (None if measurement_available else
                  "systemd transient unit measurement is unavailable"
                  + (": " + " | ".join(messages) if messages else "")),
    }


def write_systemd_fallback(systemd_path, output_path):
    systemd_path = Path(systemd_path)
    raw = packages.read_bounded_control_file(
        systemd_path.parent, systemd_path.name,
        "Ubuntu producer systemd result", packages.MAX_CONTROL_FILE_BYTES)
    result = systemd_fallback_record(raw)
    require(set(result) == SYSTEMD_FALLBACK_FIELDS,
            "Ubuntu producer fallback resource fields changed")
    _write_json(Path(output_path), result)
    return result


def validate_post_unit_records(cgroup, fallback, cleanup):
    """Require authoritative primary resources and bounded fallback OOM state."""
    require(type(cgroup) is dict and set(cgroup) == CGROUP_FINAL_FIELDS
            and type(cgroup.get("schema")) is int and cgroup["schema"] == 1
            and cgroup.get("limits") == EXPECTED_LIMITS
            and type(cgroup.get("counters")) is dict
            and set(cgroup["counters"]) == CGROUP_FINAL_COUNTERS
            and all(type(value) is str
                    for value in cgroup["counters"].values())
            and cgroup.get("error") is None,
            "Ubuntu producer primary resource evidence is malformed")
    counters = cgroup["counters"]
    require(counters["memory.swap.max"] == "0"
            and counters["memory.swap.current"] == "0"
            and counters["memory.swap.peak"] == "0"
            and cgroup.get("zero_swap") is True,
            "Ubuntu producer primary resource evidence reports swap")
    events = {}
    for line in counters["memory.events"].splitlines():
        fields = line.split()
        require(len(fields) == 2
                and re.fullmatch(r"[a-z][a-z0-9_]*", fields[0]) is not None
                and fields[0] not in events
                and re.fullmatch(r"0|[1-9][0-9]*", fields[1]) is not None,
                "Ubuntu producer primary memory event evidence is malformed")
        events[fields[0]] = int(fields[1])
    require(all(name in events and events[name] == 0 for name in (
                "oom", "oom_kill", "oom_group_kill")),
            "Ubuntu producer primary resource evidence reports OOM")

    require(type(cleanup) is dict and set(cleanup) == RETENTION_FIELDS
            and type(cleanup.get("schema")) is int and cleanup["schema"] == 1
            and cleanup.get("mode") in {"discover", "produce"}
            and type(cleanup.get("producer_exit_status")) is int
            and cleanup["producer_exit_status"] == 0
            and cleanup.get("private_work_retained") is True
            and cleanup.get("recursive_path_cleanup_performed") is False
            and cleanup.get("selected") is False
            and cleanup.get("qualified") is False,
            "Ubuntu producer direct exit or retention evidence is malformed")
    production = cleanup["mode"] == "produce"
    require(cleanup.get("candidate_present") is production
            and cleanup.get("post_unit_candidate_validated") is production,
            "Ubuntu producer post-unit candidate state changed")

    require(type(fallback) is dict and set(fallback) == SYSTEMD_FALLBACK_FIELDS
            and type(fallback.get("schema")) is int
            and fallback["schema"] == SYSTEMD_FALLBACK_SCHEMA
            and fallback.get("source") == "systemd-fallback"
            and fallback.get("authoritative") is False
            and type(fallback.get("systemd")) is dict
            and set(fallback["systemd"]) == SYSTEMD_RESULT_FIELDS
            and all(type(key) is str and type(value) is str
                    for key, value in fallback["systemd"].items())
            and type(fallback.get("measurement_available")) is bool
            and type(fallback.get("zero_swap")) is bool
            and type(fallback.get("oom_observed")) is bool
            and type(fallback.get("oom_auditable")) is bool
            and (fallback.get("error") is None
                 or type(fallback["error"]) is str),
            "Ubuntu producer fallback resource evidence is malformed")
    systemd = fallback["systemd"]
    expected_available = systemd["LoadState"] == "loaded"
    expected_auditable = (expected_available
                          and systemd["Result"] not in {"", "[not set]"})
    expected_zero_swap = (expected_available
                          and all(systemd[name] in {"0", "0B"} for name in (
                              "MemorySwapMax", "MemorySwapCurrent",
                              "MemorySwapPeak")))
    expected_error = (None if expected_available else
                      "systemd transient unit measurement is unavailable")
    require(fallback["measurement_available"] is expected_available
            and fallback["zero_swap"] is expected_zero_swap
            and fallback["oom_observed"]
            is (expected_auditable and systemd["Result"] == "oom-kill")
            and fallback["oom_auditable"] is expected_auditable
            and fallback["error"] == expected_error,
            "Ubuntu producer fallback resource claims changed")
    require(systemd["MemorySwapCurrent"] in {"0", "0B", "[not set]"}
            and systemd["MemorySwapPeak"] in {"0", "0B", "[not set]"}
            and systemd["MemorySwapMax"]
            in {"0", "0B", "[not set]", "infinity"},
            "Ubuntu producer fallback reports nonzero swap")
    if expected_available:
        require(fallback["oom_auditable"] is True
                and fallback["oom_observed"] is False
                and systemd["ActiveState"] == "inactive"
                and systemd["SubState"] == "dead"
                and systemd["Result"] == "success"
                and systemd["ExecMainCode"] == "1"
                and systemd["ExecMainStatus"] == "0",
                "Ubuntu producer loaded fallback reports a failed unit")
    else:
        require(systemd["LoadState"] == "not-found"
                and fallback["oom_auditable"] is False
                and fallback["oom_observed"] is False,
                "Ubuntu producer fallback availability changed")
    return True


def _open_exact_private_directory(path, expected_identity, description):
    require(type(expected_identity) is str
            and re.fullmatch(r"[0-9]+:[0-9]+", expected_identity) is not None,
            description + " identity is malformed")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(descriptor)
    require(f"{info.st_dev}:{info.st_ino}" == expected_identity
            and info.st_uid == os.getuid() and info.st_gid == os.getgid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            description + " identity changed")
    return descriptor


def _write_json_at(directory_fd, name, value):
    require(_safe_evidence_name(name), "Ubuntu producer evidence name is unsafe")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    require(len(raw) <= packages.MAX_CONTROL_FILE_BYTES,
            "Ubuntu producer evidence record exceeds its bound")
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, "Ubuntu producer evidence write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_retention_record(evidence, evidence_identity, output, output_identity,
                           work, work_identity, mode, exit_status, validated):
    """Retain exact private directories without recursive pathname mutation."""
    require(mode in {"discover", "produce"}
            and type(exit_status) is int and exit_status >= 0
            and type(validated) is bool,
            "Ubuntu producer retention state is malformed")
    descriptors = []
    try:
        evidence_fd = _open_exact_private_directory(
            evidence, evidence_identity, "Ubuntu producer evidence directory")
        descriptors.append(evidence_fd)
        output_fd = _open_exact_private_directory(
            output, output_identity, "Ubuntu producer output directory")
        descriptors.append(output_fd)
        work_fd = _open_exact_private_directory(
            work, work_identity, "Ubuntu producer work directory")
        descriptors.append(work_fd)
        try:
            candidate = os.stat(
                "candidate", dir_fd=output_fd, follow_symlinks=False)
            candidate_present = stat.S_ISDIR(candidate.st_mode)
        except FileNotFoundError:
            candidate_present = False
        value = {
            "schema": 1,
            "mode": mode,
            "producer_exit_status": exit_status,
            "private_work_retained": True,
            "recursive_path_cleanup_performed": False,
            "candidate_present": candidate_present,
            "post_unit_candidate_validated": validated,
            "selected": False,
            "qualified": False,
        }
        require(set(value) == RETENTION_FIELDS,
                "Ubuntu producer retention fields changed")
        _write_json_at(evidence_fd, "cleanup.json", value)
        return value
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _copy_private(source, destination):
    raw = source.read_bytes()
    descriptor = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, "Ubuntu producer private copy stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _raw(row, name, evidence):
    return _read_raw_file(evidence, row[name]["path"])


def _require_success(row, description):
    require(row["timed_out"] is False and row["exit_status"] == 0,
            description + " command failed")


def _run_checkout_binding(root, expected_head, runner, timeout):
    """Bind the read-only checkout and its complete tracked/untracked state."""
    values = {}
    for name, revision in (
            ("checkout-head", "HEAD^{commit}"),
            ("checkout-tree", "HEAD^{tree}")):
        argv = [
            "/usr/bin/git", "-C", str(root), "rev-parse", "--verify", revision,
        ]
        row, stdout, stderr = runner.run(name, argv, timeout)
        _require_success(row, "hosted checkout " + name)
        require(stderr == b"" and re.fullmatch(b"[0-9a-f]{40}\\n", stdout),
                "hosted checkout revision output is malformed")
        values[name] = stdout.decode("ascii").strip()
    argv = [
        "/usr/bin/git", "-C", str(root), "status", "--porcelain=v1",
        "--untracked-files=all",
    ]
    row, stdout, stderr = runner.run("checkout-clean", argv, timeout)
    _require_success(row, "hosted checkout clean-state")
    require(stdout == b"" and stderr == b"",
            "hosted checkout differs from its exact committed tree")
    require(values["checkout-head"] == expected_head,
            "hosted checkout HEAD differs from GITHUB_SHA")
    return values["checkout-tree"]


def _run_rootfs(root, lock, contract, work, evidence, runner, retained,
                ledger=None):
    binding = lock["rootfs"]
    keyring = root / contract["retained_inputs"]["archive_keyring"]
    checksum = root / contract["retained_inputs"]["checksum"]
    signature = root / contract["retained_inputs"]["checksum_signature"]
    argv = [
        "/usr/bin/gpgv", "--status-fd=1", "--keyring", str(keyring),
        str(signature), str(checksum),
    ]
    command, stdout, _ = runner.run(
        "rootfs-gpgv", argv, contract["timeouts"]["metadata_seconds"],
        inputs_=[retained[name] for name in (
            "archive_keyring", "checksum_signature", "checksum")],
    )
    _require_success(command, "Ubuntu Base signature")
    signature_record = build.validate_gpgv_status(
        command["exit_status"], stdout.decode("utf-8"),
        binding["checksum"]["signer_fingerprint"])
    if ledger is not None:
        ledger.append(
            "rootfs-signature", None, commands=[command],
            diagnostics=signature_record)
    archive = work / binding["archive"]
    payload = fetch_exact(
        binding["url"], archive, binding["bytes"],
        contract["timeouts"]["rootfs_seconds"],
        expected={"bytes": binding["bytes"], "sha256": binding["sha256"]})
    if ledger is not None:
        ledger.append(
            "rootfs-download", None,
            payloads=[_ledger_payload("rootfs", binding["url"], payload)])
    return archive, {
        "archive": binding["archive"],
        **payload,
        "checksum_sha256": binding["checksum"]["sha256"],
        "checksum_signature_sha256": binding["checksum"]["signature_sha256"],
        "keyring_sha256": binding["keyring"]["sha256"],
        "signing_fingerprint": signature_record["signing_fingerprint"],
    }


def _run_metadata(lock, contract, work, evidence, runner, verified_at,
                  keyring_path, keyring_identity, ledger=None):
    releases = []
    indexes = []
    metadata_result = []
    metadata_inputs = {}
    index_inputs = {}
    for source, pin, policy in zip(
            lock["sources"], contract["metadata_pins"],
            contract["freshness_policy"], strict=True):
        suite = source["suite"]
        directory = work / ("metadata-" + suite)
        directory.mkdir(mode=0o700)
        inrelease_path = directory / (suite + "_InRelease")
        inrelease_expected = None if contract["state"] == "pending-discovery" \
            else pin["inrelease"]
        inrelease = fetch_exact(
            source["metadata"]["inrelease_url"], inrelease_path,
            packages.MAX_METADATA_BYTES,
            contract["timeouts"]["metadata_seconds"],
            expected=inrelease_expected)
        if ledger is not None:
            ledger.append(
                "inrelease-download", suite,
                payloads=[_ledger_payload(
                    "inrelease-" + suite,
                    source["metadata"]["inrelease_url"], inrelease)])
        release_path = directory / (suite + "_Release")
        argv = build.inrelease_verification_command(
            keyring_path, inrelease_path, release_path)
        command, stdout, _ = runner.run(
            "inrelease-" + suite, argv,
            contract["timeouts"]["metadata_seconds"],
            inputs_=({"name": "inrelease-" + suite, **inrelease},
                     keyring_identity),
        )
        _require_success(command, "Ubuntu InRelease signature")
        signature_record = build.validate_gpgv_status(
            command["exit_status"], stdout.decode("utf-8"),
            source["metadata"]["signer_fingerprint"])
        release_raw = packages.read_bounded_control_file(
            directory, release_path.name, "authenticated Ubuntu Release",
            packages.MAX_METADATA_BYTES)
        release_diagnostics = build.signed_release_diagnostics(
            release_raw, source)
        if ledger is not None:
            ledger.append(
                "inrelease-signature", suite, commands=[command],
                diagnostics={
                    "signature": signature_record,
                    "release": release_diagnostics,
                })
        try:
            signed = build.validate_signed_release(
                release_raw, source, verified_at, policy)
        except ValueError as error:
            if ledger is not None:
                ledger.reject_release(
                    suite, inrelease,
                    signature_record["signing_fingerprint"],
                    build.release_rejection_reason(error),
                    build.release_rejection_predicate(error))
            raise
        if contract["state"] == "ready":
            require(inrelease == pin["inrelease"]
                    and signed["index"] == {
                        "path": "main/binary-amd64/Packages.xz",
                        **pin["packages_xz"],
                    }, "authenticated Ubuntu metadata differs from reviewed pins")
        if ledger is not None:
            ledger.append(
                "release-validated", suite,
                diagnostics={
                    "freshness_policy": policy,
                    "release": {
                        "bytes": release_diagnostics["bytes"],
                        "sha256": release_diagnostics["sha256"],
                    },
                    "index": signed["index"],
                })
        index_path = directory / (
            suite + "_main_binary-amd64_Packages.xz")
        index = fetch_exact(
            source["packages_url"], index_path, packages.MAX_INDEX_BYTES,
            contract["timeouts"]["metadata_seconds"],
            expected={
                "bytes": signed["index"]["bytes"],
                "sha256": signed["index"]["sha256"],
            })
        if ledger is not None:
            ledger.append(
                "packages-download", suite,
                payloads=[_ledger_payload(
                    "packages-" + suite, source["packages_url"], index)])
        release_row = build.release_record(
            source, signed, inrelease, signature_record)
        index_row = build.index_record(source, signed["index"])
        releases.append(release_row)
        indexes.append(index_row)
        metadata_inputs[release_row["inrelease"]["filename"]] = inrelease_path
        metadata_inputs[index_row["filename"]] = index_path
        index_inputs[suite] = {
            "path": index_path,
            "binding": signed["index"],
        }
        metadata_result.append({
            "suite": suite,
            "inrelease": {"path": inrelease_path.name, **inrelease},
            "packages_xz": {"path": index_path.name, **index},
            "release": signed,
            "signature": signature_record,
        })
    return releases, indexes, metadata_result, metadata_inputs, index_inputs


def _prepare_offline_tree(work, lock, releases, metadata_inputs,
                          rootfs_status):
    repository = work / "repositories"
    apt_root = work / "apt-root"
    repository.mkdir(mode=0o700)
    apt_root.mkdir(mode=0o700)
    release_by_suite = {row["suite"]: row for row in releases}
    for source in lock["sources"]:
        suite = source["suite"]
        dist = repository / suite / "dists" / suite
        index_dir = dist / "main" / "binary-amd64"
        index_dir.mkdir(parents=True, mode=0o700)
        _copy_private(
            metadata_inputs[release_by_suite[suite]["inrelease"]["filename"]],
            dist / "InRelease")
        _copy_private(
            metadata_inputs[suite + "_main_binary-amd64_Packages.xz"],
            index_dir / "Packages.xz")
    for relative in (
            "etc/apt", "var/lib/apt/lists/partial", "var/cache/apt/archives/partial",
            "var/lib/dpkg/updates", "var/lib/dpkg/info", "var/lib/dpkg/triggers"):
        (apt_root / relative).mkdir(parents=True, mode=0o700)
    status_path = apt_root / "var/lib/dpkg/status"
    descriptor = os.open(
        status_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, rootfs_status)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return repository, apt_root, status_path


def _phase_hash(row):
    return sha256_bytes(
        (row["stdout"]["sha256"] + "\n" + row["stderr"]["sha256"]).encode())


def _validate_production_bindings(manifest, command_by_name, download):
    """Cross-bind raw phase evidence and package totals to the candidate."""
    phases = {
        "apt_update": "apt-update",
        "apt_uri_plan": "apt-uris",
        "apt_simulation": "apt-simulate",
        "dpkg_plan": "dpkg-no-act",
    }
    require(set(phases.values()).issubset(command_by_name),
            "Ubuntu production result omits an offline plan command")
    expected_hashes = {
        manifest_name: _phase_hash(command_by_name[result_name])
        for manifest_name, result_name in phases.items()
    }
    order = manifest["download_order"]
    expected_download = {
        "count": manifest["package_count"],
        "bytes": manifest["package_bytes"],
        "order_sha256": sha256_bytes(
            ("\n".join(order) + "\n").encode("ascii")),
    }
    require(manifest["command_hashes"] == expected_hashes
            and download == expected_download,
            "Ubuntu production result differs from candidate command or download evidence")


def _tool_versions(runner, timeout):
    result = {}
    for key, argv in (
            ("apt_get", ["/usr/bin/apt-get", "--version"]),
            ("dpkg", ["/usr/bin/dpkg", "--version"]),
            ("gpgv", ["/usr/bin/gpgv", "--version"])):
        row, stdout, _ = runner.run("version-" + key, argv, timeout,
                                    networkless=True)
        _require_success(row, key + " version")
        line = stdout.decode("utf-8").splitlines()[0]
        require(line and len(line.encode()) <= 256,
                "Ubuntu producer tool version is malformed")
        result[key] = {"version": line, "sha256": row["tool"]["sha256"]}
    return result


def _produce(root, lock, contract, work, evidence, output, runner,
             verified_at, rootfs_archive, releases, indexes, metadata_inputs,
             index_inputs):
    status, status_binding = build.extract_base_dpkg_status(
        rootfs_archive, lock)
    repository, apt_root, status_path = _prepare_offline_tree(
        work, lock, releases, metadata_inputs, status)
    keyring = root / contract["retained_inputs"]["archive_keyring"]
    commands = build.offline_apt_commands(
        apt_root, repository, keyring, lock["package_request"]["roots"])
    sources_path = apt_root / "etc/apt/sources.list"
    sources_path.write_text(commands["sources_list"], encoding="utf-8")
    os.chmod(sources_path, 0o600)
    command_rows = {}
    for name in ("update", "uris"):
        row, stdout, _ = runner.run(
            "apt-" + name, commands[name],
            contract["timeouts"]["offline_command_seconds"],
            networkless=True)
        _require_success(row, "offline apt " + name)
        command_rows[name] = row
        if name == "uris":
            plan = build.parse_apt_uri_plan(
                stdout, repository, lock["sources"])
    package_rows = build.bind_uri_plan_to_indexes(
        plan, index_inputs, lock["sources"])
    row, simulation, _ = runner.run(
        "apt-simulate", commands["simulate"],
        contract["timeouts"]["offline_command_seconds"], networkless=True)
    _require_success(row, "offline apt simulation")
    build.validate_apt_simulation(simulation, package_rows)
    command_rows["simulate"] = row
    downloads = work / "downloads"
    downloads.mkdir(mode=0o700)
    previous_download_seconds = build.MAX_DOWNLOAD_SECONDS
    build.MAX_DOWNLOAD_SECONDS = contract["timeouts"]["package_download_seconds"]
    try:
        downloaded = build.download_package_plan(plan, package_rows, downloads)
    finally:
        build.MAX_DOWNLOAD_SECONDS = previous_download_seconds
    package_paths = [item["path"] for item in downloaded]
    before_status = sha256_bytes(status_path.read_bytes())
    dpkg_argv = build.offline_dpkg_command(apt_root, package_paths)
    row, _, _ = runner.run(
        "dpkg-no-act", dpkg_argv,
        contract["timeouts"]["offline_command_seconds"], networkless=True)
    _require_success(row, "offline dpkg no-act")
    require(sha256_bytes(status_path.read_bytes()) == before_status,
            "dpkg no-act changed the authenticated base status")
    command_rows["dpkg"] = row
    tools = _tool_versions(
        runner, contract["timeouts"]["offline_command_seconds"])
    package_rows_canonical = sorted(package_rows, key=packages.package_identity)
    command_hashes = {
        "apt_update": _phase_hash(command_rows["update"]),
        "apt_uri_plan": _phase_hash(command_rows["uris"]),
        "apt_simulation": _phase_hash(command_rows["simulate"]),
        "dpkg_plan": _phase_hash(command_rows["dpkg"]),
    }
    manifest = build.candidate_manifest(
        lock, releases, indexes, package_rows_canonical,
        verified_at=verified_at, base_status=status_binding, tools=tools,
        command_hashes=command_hashes,
        download_order=[row["sha256"] for row in package_rows],
    )
    package_inputs = {
        package["filename"]: downloaded[sequence]["path"]
        for sequence, package in enumerate(package_rows)
    }
    candidate = output / "candidate"
    build.write_candidate_output(
        candidate, lock, manifest, metadata_inputs, package_inputs)
    validated = build.validate_candidate_output(candidate, lock)
    require(validated == manifest,
            "published Ubuntu candidate differs from its validated manifest")
    manifest_raw = packages.read_bounded_control_file(
        candidate, "manifest.json", "published Ubuntu candidate manifest",
        packages.MAX_METADATA_BYTES)
    return {
        "count": len(downloaded),
        "bytes": sum(row["bytes"] for row in downloaded),
        "order_sha256": sha256_bytes(
            ("\n".join(row["sha256"] for row in downloaded) + "\n").encode()),
    }, {
        "created": True,
        "manifest_sha256": sha256_bytes(manifest_raw),
        "state": "candidate-unselected",
    }


def _cgroup_path():
    rows = Path("/proc/self/cgroup").read_text().splitlines()
    matches = [row.split("::", 1)[1] for row in rows if row.startswith("0::")]
    require(len(matches) == 1 and matches[0].startswith("/"),
            "Ubuntu producer is not in one cgroup v2 unit")
    return Path("/sys/fs/cgroup") / matches[0].lstrip("/")


def validate_cgroup(contract):
    group = _cgroup_path()
    expected = {
        "memory.max": str(contract["limits"]["memory_max"]),
        "memory.swap.max": str(contract["limits"]["memory_swap_max"]),
        "cpu.max": contract["limits"]["cpu_max"],
        "pids.max": str(contract["limits"]["pids_max"]),
    }
    observed = {name: (group / name).read_text().strip() for name in expected}
    require(observed == expected,
            "Ubuntu producer cgroup differs from the reviewed limits")
    return group, observed


def _write_cgroup_final(group, evidence, limits, error):
    names = (
        "memory.max", "memory.swap.max", "memory.current", "memory.peak",
        "memory.swap.current", "memory.swap.peak", "memory.events", "cpu.max",
        "cpu.stat", "pids.max", "pids.current", "pids.peak",
    )
    counters = {}
    for name in names:
        path = group / name
        if path.exists():
            counters[name] = path.read_text().strip()
    value = {
        "schema": 1,
        "limits": limits,
        "counters": counters,
        "zero_swap": counters.get("memory.swap.current") == "0"
                     and counters.get("memory.swap.peak") == "0",
        "error": error,
    }
    path = evidence / "cgroup-final.json"
    if path.exists():
        path.unlink()
    _write_json(path, value)


def require_clean_resources(group):
    require((group / "memory.swap.current").read_text().strip() == "0"
            and (group / "memory.swap.peak").read_text().strip() == "0",
            "Ubuntu producer used swap")
    events = {}
    for line in (group / "memory.events").read_text().splitlines():
        name, value = line.split()
        events[name] = int(value)
    require(events.get("oom", 0) == 0
            and events.get("oom_kill", 0) == 0
            and events.get("oom_group_kill", 0) == 0,
            "Ubuntu producer encountered an out-of-memory event")


def _result(mode, contract, lock, run, verified_at, rootfs, metadata,
            commands, download, candidate, phase_ledger):
    passed = mode == "produce"
    return {
        "schema": 1,
        "mode": mode,
        "state": ("candidate-unselected" if passed
                  else "discovery-pending-review"),
        "passed": passed,
        "authoritative": False,
        "selected": False,
        "qualified": False,
        "container_qualified": False,
        "signature_qualified": False,
        "os_qualified": False,
        "release_qualified": False,
        "contract_sha256": canonical_json_sha256(contract),
        "lock_sha256": canonical_json_sha256(lock),
        "repository": packages.REPOSITORY,
        "run": run,
        "verified_at": build._iso_time(verified_at),
        "rootfs": rootfs,
        "metadata": metadata,
        "commands": commands,
        "download": download,
        "candidate": candidate,
        "phase_ledger": phase_ledger,
        "scope": RESULT_SCOPE,
    }


def validate_result(result, mode, contract, lock, evidence, source_root,
                    candidate_root=None):
    """Validate the hosted result and every retained command output."""
    require(type(result) is dict and set(result) == RESULT_FIELDS
            and type(result.get("schema")) is int and result["schema"] == 1
            and result.get("mode") == mode
            and result.get("authoritative") is False
            and all(result.get(field) is False for field in (
                "selected", "qualified", "container_qualified",
                "signature_qualified", "os_qualified", "release_qualified"))
            and result.get("contract_sha256") == canonical_json_sha256(contract)
            and result.get("lock_sha256") == canonical_json_sha256(lock)
            and result.get("repository") == packages.REPOSITORY
            and result.get("scope") == RESULT_SCOPE,
            "Ubuntu producer result fields or claims changed")
    production = mode == "produce"
    require(result.get("passed") is production
            and result.get("state") == (
                "candidate-unselected" if production
                else "discovery-pending-review"),
            "Ubuntu producer result state disagrees with its mode")
    source_root = Path(source_root).resolve(strict=True)
    run = result.get("run")
    require(type(run) is dict and set(run) == RUN_FIELDS
            and _strict_positive_int(run.get("id"))
            and _strict_positive_int(run.get("attempt"))
            and packages.exact_hash(run.get("head_sha"), 40)
            and packages.exact_hash(run.get("head_tree"), 40)
            and run.get("workflow") == WORKFLOW
            and run.get("event") == "workflow_dispatch",
            "Ubuntu producer result run identity is malformed")
    receipt = result.get("phase_ledger")
    validate_phase_ledger_receipt(
        receipt, mode, contract, lock, evidence, source_root, run)
    rootfs = result.get("rootfs")
    require(type(rootfs) is dict and set(rootfs) == ROOTFS_RESULT_FIELDS
            and rootfs.get("archive") == lock["rootfs"]["archive"]
            and type(rootfs.get("bytes")) is int
            and rootfs["bytes"] == lock["rootfs"]["bytes"]
            and rootfs.get("sha256") == lock["rootfs"]["sha256"]
            and rootfs.get("checksum_sha256")
            == lock["rootfs"]["checksum"]["sha256"]
            and rootfs.get("checksum_signature_sha256")
            == lock["rootfs"]["checksum"]["signature_sha256"]
            and rootfs.get("keyring_sha256") == lock["rootfs"]["keyring"]["sha256"]
            and rootfs.get("signing_fingerprint")
            == lock["rootfs"]["checksum"]["signer_fingerprint"],
            "Ubuntu producer result rootfs binding changed")
    metadata = result.get("metadata")
    require(type(metadata) is list
            and len(metadata) == len(packages.EXPECTED_SOURCES),
            "Ubuntu producer result metadata count changed")
    for row, source in zip(metadata, packages.EXPECTED_SOURCES, strict=True):
        require(type(row) is dict and set(row) == METADATA_RESULT_FIELDS
                and row.get("suite") == source["suite"]
                and type(row.get("inrelease")) is dict
                and set(row["inrelease"]) == RESULT_PAYLOAD_FIELDS
                and type(row.get("packages_xz")) is dict
                and set(row["packages_xz"]) == RESULT_PAYLOAD_FIELDS
                and type(row.get("release")) is dict
                and row["release"].get("suite") == source["suite"]
                and type(row.get("signature")) is dict
                and row["signature"].get("signing_fingerprint")
                == source["metadata"]["signer_fingerprint"],
                "Ubuntu producer result metadata binding changed")
    command_rows = result.get("commands")
    require(type(command_rows) is list and command_rows,
            "Ubuntu producer result lacks command evidence")
    command_by_name = {}
    for row in command_rows:
        validate_command_result(evidence, row)
        require(row["name"] not in command_by_name
                and row["timed_out"] is False and row["exit_status"] == 0,
                "Ubuntu producer result contains failed or duplicate commands")
        command_by_name[row["name"]] = row
    require("rootfs-gpgv" in command_by_name
            and {"inrelease-" + source["suite"]
                 for source in packages.EXPECTED_SOURCES}.issubset(command_by_name),
            "Ubuntu producer result omits signature commands")
    checkout_commands = {
        "checkout-head": [
            "/usr/bin/git", "-C", str(source_root), "rev-parse", "--verify",
            "HEAD^{commit}",
        ],
        "checkout-tree": [
            "/usr/bin/git", "-C", str(source_root), "rev-parse", "--verify",
            "HEAD^{tree}",
        ],
        "checkout-clean": [
            "/usr/bin/git", "-C", str(source_root), "status", "--porcelain=v1",
            "--untracked-files=all",
        ],
    }
    require(set(checkout_commands).issubset(command_by_name),
            "Ubuntu producer result omits checkout binding commands")
    for name, argv in checkout_commands.items():
        row = command_by_name[name]
        require(row["argv"] == argv and row["network"] == "host"
                and row["launcher"] is None and row["inputs"] == [],
                "Ubuntu producer checkout command binding changed")
    require(_read_raw_file(
                evidence, command_by_name["checkout-head"]["stdout"]["path"])
            == (run["head_sha"] + "\n").encode("ascii")
            and _read_raw_file(
                evidence,
                command_by_name["checkout-tree"]["stdout"]["path"])
            == (run["head_tree"] + "\n").encode("ascii")
            and _read_raw_file(
                evidence,
                command_by_name["checkout-clean"]["stdout"]["path"])
            == b""
            and all(_read_raw_file(evidence, command_by_name[name]["stderr"]["path"])
                    == b"" for name in checkout_commands),
            "Ubuntu producer checkout evidence differs from the run identity")
    download = result.get("download")
    candidate = result.get("candidate")
    require(type(download) is dict and set(download) == DOWNLOAD_FIELDS
            and type(candidate) is dict
            and set(candidate) == RESULT_CANDIDATE_FIELDS,
            "Ubuntu producer result candidate fields changed")
    if production:
        require(_strict_positive_int(download.get("count"), packages.MAX_PACKAGE_COUNT)
                and _strict_positive_int(download.get("bytes"), packages.MAX_CLOSURE_BYTES)
                and packages.exact_hash(download.get("order_sha256"))
                and candidate == {
                    "created": True,
                    "manifest_sha256": candidate["manifest_sha256"],
                    "state": "candidate-unselected",
                }
                and packages.exact_hash(candidate["manifest_sha256"])
                and candidate_root is not None,
                "Ubuntu production result lacks a bounded unselected candidate")
        manifest = build.validate_candidate_output(candidate_root, lock)
        raw = packages.read_bounded_control_file(
            candidate_root, "manifest.json", "Ubuntu candidate manifest",
            packages.MAX_METADATA_BYTES)
        require(manifest["state"] == "candidate-unselected"
                and manifest["producer_passed"] is False
                and sha256_bytes(raw) == candidate["manifest_sha256"],
                "Ubuntu production candidate is not the exact unselected output")
        _validate_production_bindings(manifest, command_by_name, download)
    else:
        require(download == {"count": 0, "bytes": 0, "order_sha256": None}
                and candidate == {
                    "created": False, "manifest_sha256": None,
                    "state": "candidate-unselected",
                }, "Ubuntu discovery created a package candidate")
    return result


def run(root, mode, work, evidence, output, environ=None):
    root = Path(root).resolve(strict=True)
    work = Path(work).resolve(strict=True)
    evidence = Path(evidence).resolve(strict=True)
    output = Path(output).resolve(strict=True)
    environ = os.environ if environ is None else environ
    contract, lock = load_contract(root)
    # This check is intentionally before cgroup inspection, commands and URLs.
    run_identity = validate_hosted_environment(contract, mode, environ)
    group, _ = validate_cgroup(contract)
    runner = CommandRunner(evidence, work)
    error = None
    ledger = None
    try:
        run_identity["head_tree"] = _run_checkout_binding(
            root, run_identity["head_sha"], runner,
            contract["timeouts"]["metadata_seconds"])
        ledger = PhaseLedger(
            evidence, mode, contract, lock, run_identity, root)
        ledger.append(
            "checkout", None, commands=runner.results[-3:],
            diagnostics={
                "head_sha": run_identity["head_sha"],
                "head_tree": run_identity["head_tree"],
                "clean": True,
            })
        retained = validate_retained_inputs(root, contract, lock)
        verified_at = datetime.now(timezone.utc).replace(microsecond=0)
        rootfs_archive, rootfs_result = _run_rootfs(
            root, lock, contract, work, evidence, runner, retained, ledger)
        releases, indexes, metadata_result, metadata_inputs, index_inputs = \
            _run_metadata(
                lock, contract, work, evidence, runner, verified_at,
                root / contract["retained_inputs"]["archive_keyring"],
                retained["archive_keyring"], ledger)
        if mode == "produce":
            download, candidate = _produce(
                root, lock, contract, work, evidence, output, runner,
                verified_at, rootfs_archive, releases, indexes,
                metadata_inputs, index_inputs)
        else:
            download = {"count": 0, "bytes": 0, "order_sha256": None}
            candidate = {
                "created": False, "manifest_sha256": None,
                "state": "candidate-unselected",
            }
        require_clean_resources(group)
        result = _result(
            mode, contract, lock, run_identity, verified_at, rootfs_result,
            metadata_result, runner.results, download, candidate,
            ledger.receipt())
        validate_result(
            result, mode, contract, lock, evidence, root,
            output / "candidate" if mode == "produce" else None)
        _write_json(evidence / "producer-result.json", result)
        if mode == "discover":
            discovery = {
                "schema": 1,
                "state": "pending-review",
                "authoritative": False,
                "metadata_pins": [
                    {
                        "suite": row["suite"],
                        "inrelease": {
                            "bytes": row["inrelease"]["bytes"],
                            "sha256": row["inrelease"]["sha256"],
                        },
                        "packages_xz": {
                            "bytes": row["packages_xz"]["bytes"],
                            "sha256": row["packages_xz"]["sha256"],
                        },
                    }
                    for row in metadata_result
                ],
                "phase_ledger": result["phase_ledger"],
                "scope": "Authenticated current metadata for review; not a pin",
            }
            _write_json(evidence / "discovery.json", discovery)
        return result
    except Exception as caught:
        error = type(caught).__name__ + ": " + str(caught)
        raise
    finally:
        if ledger is not None:
            ledger.close()
        _write_cgroup_final(group, evidence, contract["limits"], error)


def validate_output(root, candidate, evidence):
    root = Path(root).resolve(strict=True)
    candidate = Path(candidate).resolve(strict=True)
    evidence = Path(evidence).resolve(strict=True)
    contract, lock = load_contract(root)
    require(contract["state"] == "ready",
            "pending Ubuntu contract cannot validate a production output")
    result = _load_json(evidence / "producer-result.json",
                        packages.MAX_METADATA_BYTES)
    return validate_result(
        result, "produce", contract, lock, evidence, root, candidate)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the hosted unselected Ubuntu package producer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    execute = subparsers.add_parser("run")
    execute.add_argument("--root", type=Path, required=True)
    execute.add_argument("--mode", choices=("discover", "produce"), required=True)
    execute.add_argument("--work", type=Path, required=True)
    execute.add_argument("--evidence", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate-output")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument("--candidate", type=Path, required=True)
    validate.add_argument("--evidence", type=Path, required=True)
    fallback = subparsers.add_parser("resource-fallback")
    fallback.add_argument("--systemd", type=Path, required=True)
    fallback.add_argument("--output", type=Path, required=True)
    retention = subparsers.add_parser("retention-record")
    retention.add_argument("--evidence", type=Path, required=True)
    retention.add_argument("--evidence-identity", required=True)
    retention.add_argument("--output", type=Path, required=True)
    retention.add_argument("--output-identity", required=True)
    retention.add_argument("--work", type=Path, required=True)
    retention.add_argument("--work-identity", required=True)
    retention.add_argument("--mode", choices=("discover", "produce"), required=True)
    retention.add_argument("--exit-status", type=int, required=True)
    retention.add_argument("--validated", choices=("true", "false"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run(
                args.root, args.mode, args.work, args.evidence, args.output)
        elif args.command == "validate-output":
            result = validate_output(args.root, args.candidate, args.evidence)
        elif args.command == "resource-fallback":
            result = write_systemd_fallback(args.systemd, args.output)
        else:
            result = write_retention_record(
                args.evidence, args.evidence_identity, args.output,
                args.output_identity, args.work, args.work_identity, args.mode,
                args.exit_status, args.validated == "true")
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError) as error:
        parser.exit(1, "Ubuntu package producer rejected: " + str(error) + "\n")
    if args.command == "resource-fallback":
        print(json.dumps({
            "source": result["source"],
            "measurement_available": result["measurement_available"],
            "zero_swap": result["zero_swap"],
            "oom_observed": result["oom_observed"],
        }, sort_keys=True))
    elif args.command == "retention-record":
        print(json.dumps({
            "private_work_retained": result["private_work_retained"],
            "recursive_path_cleanup_performed": False,
            "candidate_present": result["candidate_present"],
        }, sort_keys=True))
    else:
        print(json.dumps({
            "state": result["state"],
            "passed": result["passed"],
            "selected": False,
            "qualified": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
