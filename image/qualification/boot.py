#!/usr/bin/env python3
"""Boot the installed Atomic disk for one bounded offline Landlock qualification."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import socket
import stat
import struct
import subprocess
import time
import zlib

if __package__:
    from .symbi_mountinfo import (canonical_major_minor,
                                  validate_mount_observation)
else:
    from symbi_mountinfo import (canonical_major_minor,
                                 validate_mount_observation)


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 12 * 1024 * 1024
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_PROGRESS_BYTES = 1024 * 1024
MAX_PROGRESS_SAMPLE_BYTES = 8192
PROGRESS_INTERVAL_SECONDS = 30
MAX_QMP_MESSAGE_BYTES = 16384
QMP_TIMEOUT_SECONDS = 2
QMP_SOCKET_MODE = 0o700
QMP_CREDENTIALS = struct.Struct("=iII")
QMP_STATES = frozenset({
    "colo", "debug", "finish-migrate", "guest-panicked", "inmigrate",
    "internal-error", "io-error", "paused", "postmigrate", "preconfig",
    "prelaunch", "restore-vm", "running", "save-vm", "shutdown",
    "suspended", "watchdog",
})


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate qualification report key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("qualification report must be a JSON object")
    return result


def _qmp_message(stream):
    raw = stream.readline(MAX_QMP_MESSAGE_BYTES + 1)
    if (not isinstance(raw, bytes) or not raw or len(raw) > MAX_QMP_MESSAGE_BYTES
            or not raw.endswith(b"\n")):
        raise ValueError("missing or oversized QMP response")
    return unique_json(raw)


def _exact_keys(value, keys, description):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError("unexpected " + description + " schema")


def _validate_qmp_greeting(greeting):
    _exact_keys(greeting, {"QMP"}, "QMP greeting")
    qmp = greeting["QMP"]
    _exact_keys(qmp, {"version", "capabilities"}, "QMP greeting")
    version = qmp["version"]
    _exact_keys(version, {"qemu", "package"}, "QMP version")
    qemu = version["qemu"]
    _exact_keys(qemu, {"major", "minor", "micro"}, "QMP version")
    if (any(type(qemu[name]) is not int or not 0 <= qemu[name] <= 2**31 - 1
            for name in ("major", "minor", "micro"))
            or not isinstance(version["package"], str)
            or len(version["package"].encode("utf-8")) > 1024
            or not isinstance(qmp["capabilities"], list)
            or any(not isinstance(item, str) or not item or len(item.encode("utf-8")) > 128
                   for item in qmp["capabilities"])
            or len(qmp["capabilities"]) != len(set(qmp["capabilities"]))):
        raise ValueError("invalid QMP greeting values")


def _qmp_call(stream, name, request_id):
    raw = (json.dumps({"execute": name, "id": request_id},
                      separators=(",", ":")) + "\n").encode()
    if len(raw) > 1024:
        raise ValueError("oversized QMP request")
    stream.write(raw)
    stream.flush()
    response = _qmp_message(stream)
    _exact_keys(response, {"return", "id"}, "QMP response")
    if response["id"] != request_id:
        raise ValueError("unexpected QMP response id")
    return response["return"]


def qmp_request(stream, name, stable=lambda: None):
    """Perform one strict handshake and one allowed, bounded QMP operation."""
    if name not in {"query-status", "quit"}:
        raise ValueError("unexpected QMP operation")
    _validate_qmp_greeting(_qmp_message(stream))
    capabilities = _qmp_call(
        stream, "qmp_capabilities", "symbi-qmp-capabilities")
    if capabilities != {}:
        raise ValueError("unexpected QMP capabilities response")
    stable()
    result = _qmp_call(stream, name, "symbi-" + name)
    if name == "quit":
        if result != {}:
            raise ValueError("unexpected QMP quit response")
        return result
    _exact_keys(result, {"running", "singlestep", "status"},
                "QMP query-status response")
    if (type(result["running"]) is not bool
            or type(result["singlestep"]) is not bool
            or not isinstance(result["status"], str)
            or result["status"] not in QMP_STATES
            or result["running"] is not (result["status"] == "running")):
        raise ValueError("invalid QMP query-status values")
    return result


def path_identity(info):
    """Return the complete identity used for one private cleanup leaf."""
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink)


def validate_socket_info(info, expected_uid, expected_gid, expected=None):
    identity = path_identity(info)
    if (not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != QMP_SOCKET_MODE
            or info.st_uid != expected_uid or info.st_gid != expected_gid
            or info.st_nlink != 1 or (expected is not None and identity != expected)):
        raise ValueError("unsafe or replaced QMP control socket")
    return identity


def _process_starttime(raw, pid):
    if not isinstance(raw, str) or not raw.startswith(str(pid) + " ("):
        raise ValueError("invalid QEMU process stat")
    end = raw.rfind(")")
    fields = raw[end + 2:].split() if end >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError("invalid QEMU process start time")
    return int(fields[19])


def _read_process_state(pid, executable):
    process = Path("/proc") / str(pid)
    starttime = _process_starttime(_bounded_text(process / "stat", 4096), pid)
    status = {key: value.strip() for key, value in
              (line.split(":", 1) for line in
               _bounded_text(process / "status", 65536).splitlines() if ":" in line)}
    try:
        uids = [int(value) for value in status["Uid"].split()]
        gids = [int(value) for value in status["Gid"].split()]
    except (KeyError, ValueError) as error:
        raise ValueError("invalid QEMU process credentials") from error
    if len(uids) != 4 or len(gids) != 4 or len(set(uids)) != 1 or len(set(gids)) != 1:
        raise ValueError("QEMU process credentials changed")
    observed_executable = (process / "exe").stat()
    expected_executable = Path(executable).stat()
    if ((observed_executable.st_dev, observed_executable.st_ino)
            != (expected_executable.st_dev, expected_executable.st_ino)):
        raise ValueError("QEMU executable identity changed")
    return {"pid": pid, "starttime": starttime,
            "executable_device": observed_executable.st_dev,
            "executable_inode": observed_executable.st_ino,
            "uid": uids[0], "gid": gids[0]}


def validate_process_state(identity, observed):
    keys = {"pid", "starttime", "executable_device", "executable_inode", "uid", "gid"}
    if (not isinstance(identity, dict) or not isinstance(observed, dict)
            or set(observed) != keys
            or any(observed.get(key) != identity.get(key) for key in keys)):
        raise ValueError("QEMU process identity changed")


def capture_process_identity(child, executable):
    if (type(child.pid) is not int or child.pid <= 1 or child.poll() is not None
            or not Path(executable).is_absolute()):
        raise ValueError("QEMU did not remain live for identity capture")
    identity = _read_process_state(child.pid, executable)
    if identity["uid"] != os.geteuid() or identity["gid"] != os.getegid():
        raise ValueError("QEMU process owner changed")
    identity.update(executable=str(executable), pidfd=None)
    opener = getattr(os, "pidfd_open", None)
    try:
        if opener is not None:
            identity["pidfd"] = opener(child.pid, 0)
        validate_process_state(identity, _read_process_state(child.pid, executable))
        if child.poll() is not None:
            raise ValueError("QEMU exited during identity capture")
    except Exception:
        if identity["pidfd"] is not None:
            os.close(identity["pidfd"])
        raise
    return identity


def verify_process_identity(identity, reader=_read_process_state):
    validate_process_state(
        identity, reader(identity["pid"], identity["executable"]))


def validate_peer_credentials(raw, identity):
    if not isinstance(raw, bytes) or len(raw) != QMP_CREDENTIALS.size:
        raise ValueError("invalid QMP peer credentials")
    pid, uid, gid = QMP_CREDENTIALS.unpack(raw)
    if (pid, uid, gid) != (identity["pid"], identity["uid"], identity["gid"]):
        raise ValueError("QMP peer is not the launched QEMU process")
    return {"pid": pid, "uid": uid, "gid": gid}


def create_qmp_control(path, process):
    path = Path(path)
    parent = path.parent.lstat()
    if (not path.is_absolute() or path.name != "qmp.sock"
            or not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != process["uid"] or parent.st_gid != process["gid"]):
        raise ValueError("QMP path is not the exact private output leaf")
    return {"path": path, "directory_identity": path_identity(parent),
            "socket_identity": None, "process": process}


def _control_socket_info(control, expected=None):
    path = control["path"]
    if path_identity(path.parent.lstat()) != control["directory_identity"]:
        raise ValueError("QMP private directory identity changed")
    return validate_socket_info(
        path.lstat(), control["process"]["uid"], control["process"]["gid"],
        expected if expected is not None else control["socket_identity"])


def qmp_command(control, name):
    """Issue one strict operation to the exact launched QEMU Unix peer."""
    if name not in {"query-status", "quit"}:
        raise ValueError("unexpected QMP operation")
    verify_process_identity(control["process"])
    before = _control_socket_info(control)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(QMP_TIMEOUT_SECONDS)
        channel.connect(str(control["path"]))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError("QMP peer credentials are unavailable")
        validate_peer_credentials(
            channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                               QMP_CREDENTIALS.size),
            control["process"],
        )
        if _control_socket_info(control, before) != before:
            raise ValueError("QMP control socket identity changed")
        control["socket_identity"] = before

        def stable():
            verify_process_identity(control["process"])
            if _control_socket_info(control, before) != before:
                raise ValueError("QMP control socket identity changed")

        with channel.makefile("rwb") as stream:
            result = qmp_request(stream, name, stable)
        if name == "query-status":
            stable()
        return result


def _cleanup_error(error):
    return (type(error).__name__ + ": " + str(error))[:512]


def wait_for_exact_exit(child, identity, timeout):
    """Prove exit of the captured direct child, using its pidfd when available."""
    if identity is None or child.pid != identity.get("pid"):
        return False
    returncode = child.poll()
    if returncode is None:
        verify_process_identity(identity)
        pidfd = identity.get("pidfd")
        if pidfd is not None and not select.select([pidfd], [], [], timeout)[0]:
            return False
        try:
            returncode = child.wait(timeout=timeout if pidfd is None else 0.1)
        except subprocess.TimeoutExpired:
            return False
    if type(returncode) is not int:
        return False
    pidfd = identity.get("pidfd")
    return pidfd is None or bool(select.select([pidfd], [], [], 0)[0])


def stop_child(child, identity=None, control=None, request=qmp_command,
               prove_exit=wait_for_exact_exit, verify=verify_process_identity):
    """Stop only the captured QEMU child and prove its exit before cleanup."""
    result = {"attempted": False, "qmp_quit": False, "terminated": False,
              "killed": False, "exit_proven": False, "errors": []}
    if child is None:
        result["exit_proven"] = True
        return result
    if identity is None or child.pid != identity.get("pid"):
        result["errors"].append("ValueError: missing exact QEMU process identity")
        return result
    try:
        if prove_exit(child, identity, 0):
            result["exit_proven"] = True
            return result
        verify(identity)
    except Exception as error:
        result["errors"].append(_cleanup_error(error))
        return result
    result["attempted"] = True
    if control is not None:
        try:
            request(control, "quit")
            result["qmp_quit"] = True
        except Exception as error:
            result["errors"].append(_cleanup_error(error))
        else:
            try:
                if prove_exit(child, identity, 10):
                    result["exit_proven"] = True
                    return result
            except Exception as error:
                result["errors"].append(_cleanup_error(error))
    try:
        verify(identity)
        child.terminate()
        result["terminated"] = True
    except (OSError, ValueError) as error:
        result["errors"].append(_cleanup_error(error))
    else:
        try:
            if prove_exit(child, identity, 10):
                result["exit_proven"] = True
                return result
        except Exception as error:
            result["errors"].append(_cleanup_error(error))
    try:
        verify(identity)
        child.kill()
        result["killed"] = True
    except (OSError, ValueError) as error:
        result["errors"].append(_cleanup_error(error))
    else:
        try:
            if prove_exit(child, identity, 10):
                result["exit_proven"] = True
                return result
        except Exception as error:
            result["errors"].append(_cleanup_error(error))
    try:
        result["exit_proven"] = prove_exit(child, identity, 0)
    except Exception as error:
        result["errors"].append(_cleanup_error(error))
    return result


def discard_control_socket(path, identity=None, exit_proven=False):
    """Remove the pinned QMP leaf only after exact QEMU exit was proven."""
    path = Path(path)
    result = {"attempted": False, "removed": False, "errors": []}
    if not exit_proven:
        result["errors"].append("ValueError: exact QEMU exit not proven")
        return result
    try:
        info = path.lstat()
    except FileNotFoundError:
        result["removed"] = True
        return result
    result["attempted"] = True
    try:
        if identity is None:
            raise ValueError("QMP socket identity was not bound to its peer")
        validate_socket_info(info, identity[4], identity[5], identity)
        validate_socket_info(path.lstat(), identity[4], identity[5], identity)
        path.unlink()
        if path.exists() or path.is_symlink():
            raise ValueError("QMP control socket remains after discard")
        result["removed"] = True
    except (OSError, ValueError) as error:
        result["errors"].append(_cleanup_error(error))
    return result


def write_progress_sample(stream, sample):
    """Append one small JSON progress record within the fixed evidence ceiling."""
    if not isinstance(sample, dict):
        raise ValueError("invalid progress sample")
    raw = (json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if (len(raw) > MAX_PROGRESS_SAMPLE_BYTES
            or stream.tell() + len(raw) > MAX_PROGRESS_BYTES):
        raise ValueError("qualification progress evidence exceeded its bound")
    stream.write(raw)
    stream.flush()


def _bounded_text(path, maximum):
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("oversized progress input")
    return raw.decode("utf-8", errors="strict").strip()


def progress_snapshot(child, control, output, group, started, sample):
    """Capture fixed process, cgroup, output and QMP liveness fields."""
    snapshot = {"schema": 1, "sample": sample,
                "elapsed_seconds": int(max(0, time.monotonic() - started)),
                "outputs": {}}
    for name in ("qemu.log", "serial.log", "report.json", "guest.qcow2"):
        path = Path(output) / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        snapshot["outputs"][name] = info.st_size if stat.S_ISREG(info.st_mode) else None
    process = Path("/proc") / str(child.pid)
    try:
        raw = _bounded_text(process / "status", 65536)
        fields = {key: value.strip() for key, value in
                  (line.split(":", 1) for line in raw.splitlines() if ":" in line)}
        snapshot["qemu"] = {key: fields[key] for key in
                            ("State", "Threads", "VmPeak", "VmSize", "VmRSS")
                            if key in fields}
        snapshot["qemu"]["pid"] = child.pid
        snapshot["qemu"]["returncode"] = child.poll()
    except (OSError, UnicodeError, ValueError) as error:
        snapshot["qemu"] = {"error": _cleanup_error(error)}
    else:
        try:
            snapshot["qemu"]["wchan"] = _bounded_text(process / "wchan", 256)
        except (OSError, UnicodeError, ValueError) as error:
            snapshot["qemu"]["wchan_error"] = _cleanup_error(error)
    try:
        snapshot["qmp"] = qmp_command(control, "query-status")
    except (OSError, TimeoutError, ValueError) as error:
        snapshot["qmp"] = {"error": _cleanup_error(error)}
    snapshot["cgroup"] = {}
    for name, maximum in (("memory.current", 128), ("memory.peak", 128),
                          ("memory.events", 4096), ("memory.pressure", 4096),
                          ("cpu.stat", 4096), ("pids.current", 128)):
        try:
            snapshot["cgroup"][name] = _bounded_text(Path(group) / name, maximum)
        except (OSError, UnicodeError, ValueError) as error:
            snapshot["cgroup"][name] = _cleanup_error(error)
    return snapshot


def discard_overlay(path, identity=None, exit_proven=False):
    """Remove the pinned overlay only after exact QEMU exit was proven."""
    path = Path(path)
    result = {"attempted": False, "removed": False, "errors": []}
    if not exit_proven:
        result["errors"].append("ValueError: exact QEMU exit not proven")
        return result
    try:
        info = path.lstat()
    except FileNotFoundError:
        result["removed"] = True
        return result
    result["attempted"] = True
    try:
        if (identity is None or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_gid != os.getegid()
                or info.st_nlink != 1 or path_identity(info) != identity
                or path_identity(path.lstat()) != identity):
            raise ValueError("qualification overlay identity changed before discard")
        path.unlink()
        if path.exists() or path.is_symlink():
            raise ValueError("qualification overlay remains after discard")
        result["removed"] = True
    except (OSError, ValueError) as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    return result


def firmware_arguments(directory):
    if directory != Path("/inputs"):
        raise ValueError("fixed read-only firmware input mount required")
    files = [
        ("fstab.extra", "fstab.extra"),
        ("systemd.extra-unit.m.service", "m.service"),
        ("systemd.extra-unit.p.service", "p.service"),
        ("systemd.extra-unit.q.service", "q.service"),
        ("systemd.extra-unit.l.service", "l.service"),
        ("symbi-status-server.py", "status_server.py"),
        ("symbi-landlock.py", "landlock.py"),
        ("vertical_slice.py", "vertical_slice.py"),
        ("symbi-runner.py", "guest.py"),
        ("symbi-prepare.py", "prepare.py"),
        ("symbi-source-mount.py", "source_mount.py"),
        ("symbi_mountinfo.py", "symbi_mountinfo.py"),
        ("symbi-expected.json", "expected.json"),
        ("symbi-sysusers.conf", "sysusers.conf"),
    ]
    result = []
    for name, filename in files:
        name = "opt/io.systemd.credentials/" + name
        if len(name.encode("ascii")) >= 56:
            raise ValueError("QEMU firmware name is too long")
        result += ["-fw_cfg", f"name={name},file={directory / filename}"]
    return result


def overlay_command(inputs=Path("/inputs"), output=Path("/output")):
    if inputs != Path("/inputs") or output != Path("/output"):
        raise ValueError("fixed overlay mounts required")
    return ["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
            "-b", "/inputs/atomic.raw", "/output/guest.qcow2"]


def qemu_command(inputs=Path("/inputs"), output=Path("/output")):
    if inputs != Path("/inputs") or output != Path("/output"):
        raise ValueError("fixed QEMU mounts required")
    return [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=single", "-cpu", "max", "-m", "2048M", "-smp", "1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Landlock-Probe",
        "-drive", "file=/output/guest.qcow2,format=qcow2,if=virtio",
        "-drive", "file=/inputs/source.raw,format=raw,if=none,"
                  "id=symbi-qualification-source,readonly=on",
        "-device", "virtio-blk-pci,drive=symbi-qualification-source,serial=SYMBIQUAL",
        "-device", "virtio-rng-pci", "-device", "virtio-serial-pci",
        "-chardev", "file,id=report,path=/output/report.json",
        "-device", "virtserialport,chardev=report,name=org.symbi.qualification",
        "-qmp", "unix:/output/qmp.sock,server=on,wait=off",
        "-serial", "file:/output/serial.log", "-monitor", "none", "-display", "none",
        *firmware_arguments(inputs),
    ]


def validate_source_device(report, expected):
    """Bind guest block evidence to the authenticated source-disk identity."""
    try:
        observed = report["source_device"]
        source = expected["source_disk"]
    except (KeyError, TypeError) as error:
        raise ValueError("qualification source-device evidence is missing") from error
    required = {"path", "major_minor", "TYPE", "LABEL", "UUID"}
    if (not isinstance(observed, dict) or not isinstance(source, dict)
            or set(observed) != required
            or re.fullmatch(r"/dev/vd[a-z]{1,3}", observed.get("path", "")) is None
            or not canonical_major_minor(observed.get("major_minor"))
            or observed.get("TYPE") != source.get("filesystem")
            or observed.get("LABEL") != source.get("label")
            or observed.get("UUID") != source.get("uuid")):
        raise ValueError("qualification source-device evidence differs")
    validate_mount_observation(
        report.get("source_mount_observation"),
        mountpoint="/run/symbi-qualification/source",
        source=observed["path"], major_minor=observed["major_minor"])


def _safe_artifact_name(name):
    if not isinstance(name, str) or not name or len(name.encode()) > 240:
        raise ValueError("invalid public report name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe public report path")
    if "private-actions" in path.parts or any(part.lower().endswith((".pem", ".key", ".p12")) for part in path.parts):
        raise ValueError("private qualification material cannot be retained")
    allowed = {"bootc-before.json", "bootc-after.json", "platform.json", "platform.log",
               "release-driver.log", "vertical-slice.json", "release"}
    if path.parts[0] not in allowed:
        raise ValueError("unexpected public report path")
    return path


def _bounded_decompress(encoded, compressed_bytes, expected_bytes):
    if (not isinstance(encoded, str) or not isinstance(compressed_bytes, int)
            or not isinstance(expected_bytes, int) or not 0 <= compressed_bytes <= MAX_ARTIFACT_BYTES
            or not 0 <= expected_bytes <= MAX_ARTIFACT_BYTES):
        raise ValueError("invalid artifact size")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid artifact encoding") from error
    if len(compressed) != compressed_bytes:
        raise ValueError("compressed artifact size changed")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("unbounded or malformed compressed artifact")
    raw += decoder.flush(MAX_ARTIFACT_BYTES + 1 - len(raw))
    if len(raw) != expected_bytes:
        raise ValueError("expanded artifact size changed")
    return raw


def validate_guest_report(report, expected, expected_hash, runner_hash, driver_hash,
                          validator_hash):
    required = {
        "schema": 1, "passed": True, "qualified": True, "guest_booted": True,
        "os_qualified": False, "release_qualified": False,
        "product": "Symbi-Hosted-Landlock-Probe", "nonce": expected["nonce"],
        "expected_sha256": expected_hash, "runner_sha256": runner_hash,
        "driver_sha256": driver_hash, "validator_sha256": validator_hash,
        "source_revision": expected["source_revision"],
        "source_manifest_sha256": expected["source_manifest_sha256"],
        "binary_sha256": expected["binary_sha256"], "image_ref": expected["image_ref"],
    }
    if any(report.get(key) != value for key, value in required.items()):
        raise ValueError("unbound, incomplete or falsely qualified guest report")
    validate_source_device(report, expected)
    minimum = expected.get("minimum_landlock_abi", 6)
    if type(report.get("landlock_abi")) is not int or report["landlock_abi"] < minimum:
        raise ValueError("Landlock ABI does not meet the selected minimum")
    summary = report.get("summary")
    artifacts = report.get("artifacts")
    if (not isinstance(summary, dict) or summary.get("passed") is not True
            or summary.get("qualified") is not True or not isinstance(artifacts, dict)
            or not isinstance(summary.get("public_reports"), dict)
            or set(artifacts) != set(summary["public_reports"])):
        raise ValueError("public report allowlist differs from the qualified summary")
    if not artifacts:
        raise ValueError("qualification retained no public reports")
    expanded = {}
    total = 0
    for name, item in artifacts.items():
        path = _safe_artifact_name(name)
        if not isinstance(item, dict) or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")):
            raise ValueError("invalid public artifact metadata")
        raw = _bounded_decompress(item.get("zlib_base64"), item.get("zlib_bytes"), item.get("bytes"))
        total += len(raw)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise ValueError("total public qualification evidence exceeded its bound")
        observed = hashlib.sha256(raw).hexdigest()
        if observed != item["sha256"] or observed != summary["public_reports"].get(name):
            raise ValueError("public report bytes differ from the qualified summary")
        expanded[str(path)] = raw
    return expanded


def main():
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use the unprivileged disposable hosted QEMU container")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    process = {key: value.strip() for key, value in
               (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    if (limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                   "cpu.max": "200000 100000", "pids.max": "64"}
            or process["CapEff"] != "0000000000000000" or process["NoNewPrivs"] != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or not os.statvfs("/inputs/atomic.raw").f_flag & os.ST_RDONLY
            or not os.statvfs("/inputs/source.raw").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("qualification QEMU container isolation changed")
    inputs, output = Path("/inputs"), Path("/output")
    expected_raw = (inputs / "expected.json").read_bytes()
    if len(expected_raw) > 128 * 1024:
        raise ValueError("oversized qualification expectation")
    expected = unique_json(expected_raw)
    source_disk = expected.get("source_disk", {})
    if ((inputs / "source.raw").stat().st_size != source_disk.get("bytes")
            or sha256(inputs / "source.raw") != source_disk.get("sha256")):
        raise ValueError("authenticated source disk changed")
    hashes = {name: sha256(inputs / name) for name in
              ("guest.py", "landlock.py", "vertical_slice.py", "expected.json")}
    record = {"schema": 1, "passed": False, "guest_booted": False,
              "qualification_qualified": False, "os_qualified": False,
              "release_qualified": False, "limits": limits, "inputs": hashes,
              "source_disk": source_disk,
              "scope": "Offline Landlock qualification on the exact installed development image"}
    child = None
    process_identity = None
    qmp_control = None
    overlay = output / "guest.qcow2"
    overlay_identity = None
    qmp_path = output / "qmp.sock"
    try:
        with (output / "prepare-overlay.log").open("x") as log:
            subprocess.run(overlay_command(inputs, output), stdin=subprocess.DEVNULL,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
        overlay_identity = path_identity(overlay.stat())
        record["overlay"] = {"path": str(overlay), "backing": "/inputs/atomic.raw",
                             "format": "qcow2"}
        command = qemu_command(inputs, output)
        record["command"] = command
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        started = time.monotonic()
        with (output / "qemu.log").open("x") as log, \
                (output / "progress.jsonl").open("xb") as progress:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                          "HOME": "/output", "TMPDIR": "/output"},
                                     umask=0o077)
            process_identity = capture_process_identity(child, command[0])
            qmp_control = create_qmp_control(qmp_path, process_identity)
            record["qemu_process"] = {
                key: process_identity[key] for key in
                ("pid", "starttime", "executable_device", "executable_inode",
                 "uid", "gid", "executable")
            }
            record["qemu_process"]["pidfd"] = process_identity["pidfd"] is not None
            next_progress = started
            progress_samples = 0
            while child.poll() is None:
                for name, maximum in (("serial.log", 2 * 1024 * 1024),
                                      ("qemu.log", 1024 * 1024),
                                      ("report.json", MAX_REPORT_BYTES)):
                    path = output / name
                    if path.exists() and path.stat().st_size > maximum:
                        raise ValueError("guest output exceeded its bound: " + name)
                now = time.monotonic()
                if now >= next_progress:
                    write_progress_sample(
                        progress,
                        progress_snapshot(
                            child, qmp_control, output, group, started, progress_samples),
                    )
                    progress_samples += 1
                    next_progress += PROGRESS_INTERVAL_SECONDS
                if time.monotonic() - started >= 5700:
                    raise TimeoutError("Landlock guest did not report and power off within 95 minutes")
                time.sleep(0.5)
            write_progress_sample(
                progress,
                progress_snapshot(
                    child, qmp_control, output, group, started, progress_samples),
            )
        record["exit_code"] = child.returncode
        record["elapsed_seconds"] = time.monotonic() - started
        if child.returncode != 0:
            raise RuntimeError("qualification QEMU failed; inspect original logs")
        path = output / "report.json"
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT_BYTES:
            raise ValueError("missing bounded guest qualification report")
        report = unique_json(path.read_bytes())
        files = validate_guest_report(report, expected, hashes["expected.json"],
                                      hashes["guest.py"], hashes["landlock.py"],
                                      hashes["vertical_slice.py"])
        evidence = output / "evidence"
        evidence.mkdir(mode=0o700)
        for name, raw in files.items():
            target = evidence / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
        (evidence / "summary.json").write_text(json.dumps(report["summary"], indent=2) + "\n")
        if sha256(inputs / "source.raw") != source_disk["sha256"]:
            raise ValueError("read-only source disk changed during qualification")
        if path_identity(overlay.stat()) != overlay_identity:
            raise ValueError("qualification overlay identity changed")
        record.update(passed=True, guest_booted=True, qualification_qualified=True,
                      source_revision=report["source_revision"],
                      binary_sha256=report["binary_sha256"], landlock_abi=report["landlock_abi"],
                      public_reports=report["summary"]["public_reports"])
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        cleanup = stop_child(child, process_identity, qmp_control)
        record["child_cleanup"] = cleanup
        if cleanup["attempted"]:
            record["passed"] = False
        socket_identity = (qmp_control or {}).get("socket_identity")
        qmp_cleanup = discard_control_socket(
            qmp_path, socket_identity, cleanup["exit_proven"])
        record["qmp_cleanup"] = qmp_cleanup
        if not qmp_cleanup["removed"] or qmp_cleanup["errors"]:
            record["passed"] = False
        overlay_cleanup = discard_overlay(
            overlay, overlay_identity, cleanup["exit_proven"])
        record["overlay_cleanup"] = overlay_cleanup
        if not overlay_cleanup["removed"] or overlay_cleanup["errors"]:
            record["passed"] = False
        if process_identity is not None and process_identity["pidfd"] is not None:
            try:
                os.close(process_identity["pidfd"])
                process_identity["pidfd"] = None
            except OSError as error:
                record["pidfd_cleanup_error"] = _cleanup_error(error)
                record["passed"] = False
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                    for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(line.split() for line in record["cgroup_final"]["memory.events"].splitlines())
        if any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill")):
            record["passed"] = False
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    if not record["passed"]:
        raise RuntimeError("hosted Landlock qualification resource controls failed")


if __name__ == "__main__":
    main()
