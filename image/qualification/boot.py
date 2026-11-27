#!/usr/bin/env python3
"""Boot the installed Atomic disk for one bounded offline Landlock qualification."""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import signal
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
MAX_QMP_MESSAGES_PER_CALL = 8
QMP_TIMEOUT_SECONDS = 2
QMP_SOCKET_MODE = 0o700
QMP_CREDENTIALS = struct.Struct("=iII")
MAX_PROCESS_CMDLINE_BYTES = 64 * 1024
MAX_PROCESS_CGROUP_BYTES = 4096
QMP_STATES = frozenset({
    "colo", "debug", "finish-migrate", "guest-panicked", "inmigrate",
    "internal-error", "io-error", "paused", "postmigrate", "preconfig",
    "prelaunch", "restore-vm", "running", "save-vm", "shutdown",
    "suspended", "watchdog",
})
QMP_ROOT_DRIVE = "symbi-atomic-root"
QMP_ROOT_DEVICE = "symbi-atomic-root-device"
QMP_SOURCE_DRIVE = "symbi-qualification-source"
QMP_SOURCE_DEVICE = "symbi-qualification-source-device"
QMP_TOPOLOGY = {
    "schema": 1,
    "strict_boot": True,
    "root": {
        "drive": QMP_ROOT_DRIVE,
        "device": QMP_ROOT_DEVICE,
        "file": "/output/guest.qcow2",
        "format": "qcow2",
        "backing_file": "/inputs/atomic.raw",
        "read_only": False,
        "bootindex": 1,
    },
    "source": {
        "drive": QMP_SOURCE_DRIVE,
        "device": QMP_SOURCE_DEVICE,
        "file": "/inputs/source.raw",
        "format": "raw",
        "backing_file": None,
        "read_only": True,
        "bootindex": -1,
    },
}
QMP_PREDICATE_RESULTS = frozenset({"pass", "fail", "blocked"})
QMP_INVENTORY_PREDICATES = frozenset({
    "is_list", "count", "rows_are_objects", "device_fields_are_strings",
    "devices_unique", "only_expected_devices", "exact_devices",
})
QMP_DEVICE_PREDICATES = frozenset({
    "drive", "qdev", "inserted", "file", "format", "read_only_type",
    "read_only", "backing_file", "bootindex_type", "bootindex",
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

    def reject_constant(value):
        raise ValueError("non-RFC JSON constant: " + value)

    result = json.loads(raw, object_pairs_hook=unique,
                        parse_constant=reject_constant)
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


def _validate_qmp_event(message):
    keys = set(message) if isinstance(message, dict) else set()
    if keys not in ({"event", "timestamp"},
                    {"event", "data", "timestamp"}):
        raise ValueError("unexpected QMP event schema")
    timestamp = message["timestamp"]
    _exact_keys(timestamp, {"seconds", "microseconds"},
                "QMP event timestamp")
    if (not isinstance(message["event"], str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}",
                            message["event"]) is None
            or ("data" in message and not isinstance(message["data"], dict))
            or type(timestamp["seconds"]) is not int
            or not 0 <= timestamp["seconds"] <= 2**63 - 1
            or type(timestamp["microseconds"]) is not int
            or not 0 <= timestamp["microseconds"] <= 999999):
        raise ValueError("invalid QMP event values")


def _qmp_call(stream, name, request_id, allow_events=False, arguments=None):
    request = {"execute": name, "id": request_id}
    if arguments is not None:
        if not isinstance(arguments, dict):
            raise ValueError("invalid QMP request arguments")
        request["arguments"] = arguments
    raw = (json.dumps(request,
                      separators=(",", ":")) + "\n").encode()
    if len(raw) > 1024:
        raise ValueError("oversized QMP request")
    stream.write(raw)
    stream.flush()
    for _ in range(MAX_QMP_MESSAGES_PER_CALL):
        response = _qmp_message(stream)
        if allow_events and isinstance(response, dict) and "event" in response:
            _validate_qmp_event(response)
            continue
        _exact_keys(response, {"return", "id"}, "QMP response")
        if response["id"] != request_id:
            raise ValueError("unexpected QMP response id")
        return response["return"]
    raise ValueError("too many QMP events before response")


def _exact_fixed_record(observed, expected):
    if type(observed) is not type(expected):
        raise ValueError("QMP block topology record differs")
    if isinstance(expected, dict):
        if set(observed) != set(expected):
            raise ValueError("QMP block topology record differs")
        for key in expected:
            _exact_fixed_record(observed[key], expected[key])
    elif observed != expected:
        raise ValueError("QMP block topology record differs")


def _predicate(value, available=True):
    if not available:
        return "blocked"
    return "pass" if value else "fail"


def _qmp_device_predicates(rows, devices_valid, drive, qdev, filename,
                           driver, read_only, backing, bootindex,
                           expected_bootindex):
    matches = ([row for row in rows if row.get("device") == drive]
               if devices_valid else [])
    row_available = devices_valid and len(matches) == 1
    row = matches[0] if row_available else None
    inserted = row.get("inserted") if row_available else None
    inserted_valid = row_available and isinstance(inserted, dict)
    read_only_value = inserted.get("ro") if inserted_valid else None
    read_only_valid = inserted_valid and type(read_only_value) is bool
    bootindex_valid = type(bootindex) is int
    return {
        "drive": _predicate(len(matches) == 1, devices_valid),
        "qdev": _predicate(
            row.get("qdev") == qdev if row_available else False,
            row_available),
        "inserted": _predicate(inserted_valid, row_available),
        "file": _predicate(
            inserted.get("file") == filename if inserted_valid else False,
            inserted_valid),
        "format": _predicate(
            inserted.get("drv") == driver if inserted_valid else False,
            inserted_valid),
        "read_only_type": _predicate(read_only_valid, inserted_valid),
        "read_only": _predicate(read_only_value is read_only, read_only_valid),
        "backing_file": _predicate(
            inserted.get("backing_file") == backing
            if inserted_valid else False, inserted_valid),
        "bootindex_type": _predicate(bootindex_valid),
        "bootindex": _predicate(
            bootindex == expected_bootindex, bootindex_valid),
    }


def qmp_topology_observation(blocks, root_bootindex, source_bootindex):
    """Return only fixed predicate outcomes for one live QMP observation."""
    is_list = type(blocks) is list
    rows = blocks if is_list else []
    rows_valid = is_list and all(isinstance(row, dict) for row in rows)
    devices_valid = (rows_valid
                     and all(type(row.get("device")) is str for row in rows))
    devices = [row["device"] for row in rows] if devices_valid else []
    expected_devices = {QMP_ROOT_DRIVE, QMP_SOURCE_DRIVE}
    inventory = {
        "is_list": _predicate(is_list),
        "count": _predicate(len(rows) == 2, is_list),
        "rows_are_objects": _predicate(rows_valid, is_list),
        "device_fields_are_strings": _predicate(devices_valid, rows_valid),
        "devices_unique": _predicate(
            len(set(devices)) == len(devices), devices_valid),
        "only_expected_devices": _predicate(
            all(device in expected_devices for device in devices),
            devices_valid),
        "exact_devices": _predicate(
            len(devices) == 2 and set(devices) == expected_devices,
            devices_valid),
    }
    return {
        "schema": 1,
        "inventory": inventory,
        "root": _qmp_device_predicates(
            rows, devices_valid, QMP_ROOT_DRIVE, QMP_ROOT_DEVICE,
            "/output/guest.qcow2", "qcow2", False, "/inputs/atomic.raw",
            root_bootindex, 1),
        "source": _qmp_device_predicates(
            rows, devices_valid, QMP_SOURCE_DRIVE, QMP_SOURCE_DEVICE,
            "/inputs/source.raw", "raw", True, None,
            source_bootindex, -1),
    }


def validate_qmp_topology_observation(record):
    """Require the fixed content-free failure-observation schema."""
    if (type(record) is not dict
            or set(record) != {"schema", "inventory", "root", "source"}
            or type(record.get("schema")) is not int
            or record["schema"] != 1):
        raise ValueError("invalid QMP topology observation")
    result = {"schema": 1}
    for name, predicates in (("inventory", QMP_INVENTORY_PREDICATES),
                             ("root", QMP_DEVICE_PREDICATES),
                             ("source", QMP_DEVICE_PREDICATES)):
        section = record.get(name)
        if (type(section) is not dict or set(section) != predicates
                or any(type(value) is not str
                       or value not in QMP_PREDICATE_RESULTS
                       for value in section.values())):
            raise ValueError("invalid QMP topology observation")
        result[name] = {key: section[key] for key in sorted(predicates)}
    return result


def _qmp_topology_failure(message, observation):
    error = ValueError(message)
    error.qmp_topology_observation = validate_qmp_topology_observation(
        observation)
    return error


def retain_qmp_topology_failure(record, error):
    """Copy one validated predicate-only topology diagnostic into the result."""
    if type(record) is not dict:
        raise ValueError("invalid qualification result record")
    observation = getattr(error, "qmp_topology_observation", None)
    if observation is None:
        return False
    if "block_topology_observation" in record:
        raise ValueError("duplicate QMP topology observation")
    record["block_topology_observation"] = (
        validate_qmp_topology_observation(observation))
    return True


def validate_qmp_topology_record(record):
    """Require the fixed content-free topology summary at every trust boundary."""
    _exact_fixed_record(record, QMP_TOPOLOGY)
    return record


def validate_qmp_block_topology(blocks, root_bootindex, source_bootindex):
    """Bind live QMP block nodes and boot indexes to the fixed launch argv."""
    observation = qmp_topology_observation(
        blocks, root_bootindex, source_bootindex)
    if type(blocks) is not list or len(blocks) != 2:
        raise _qmp_topology_failure(
            "unexpected QMP block device inventory", observation)
    indexed = {}
    for block in blocks:
        if not isinstance(block, dict) or type(block.get("device")) is not str:
            raise _qmp_topology_failure(
                "invalid QMP block device", observation)
        if block["device"] in indexed:
            raise _qmp_topology_failure(
                "duplicate QMP block device", observation)
        indexed[block["device"]] = block
    if set(indexed) != {QMP_ROOT_DRIVE, QMP_SOURCE_DRIVE}:
        raise _qmp_topology_failure(
            "unexpected QMP block device inventory", observation)

    for drive, device, filename, driver, read_only, backing in (
        (QMP_ROOT_DRIVE, QMP_ROOT_DEVICE, "/output/guest.qcow2",
         "qcow2", False, "/inputs/atomic.raw"),
        (QMP_SOURCE_DRIVE, QMP_SOURCE_DEVICE, "/inputs/source.raw",
         "raw", True, None),
    ):
        block = indexed[drive]
        inserted = block.get("inserted")
        if (block.get("qdev") != device or not isinstance(inserted, dict)
                or inserted.get("file") != filename
                or inserted.get("drv") != driver
                or type(inserted.get("ro")) is not bool
                or inserted["ro"] is not read_only
                or inserted.get("backing_file") != backing):
            raise _qmp_topology_failure(
                "QMP block device mapping differs", observation)
    if (type(root_bootindex) is not int or root_bootindex != 1
            or type(source_bootindex) is not int or source_bootindex != -1):
        raise _qmp_topology_failure(
            "QMP firmware boot indexes differ", observation)
    return {key: (dict(value) if isinstance(value, dict) else value)
            for key, value in QMP_TOPOLOGY.items()}


def qmp_request(stream, name, stable=lambda: None):
    """Perform one strict handshake and one allowed, bounded QMP operation."""
    if name not in {"query-status", "query-block-topology", "quit"}:
        raise ValueError("unexpected QMP operation")
    _validate_qmp_greeting(_qmp_message(stream))
    capabilities = _qmp_call(
        stream, "qmp_capabilities", "symbi-qmp-capabilities")
    if capabilities != {}:
        raise ValueError("unexpected QMP capabilities response")
    stable()
    if name == "query-block-topology":
        blocks = _qmp_call(
            stream, "query-block", "symbi-query-block", allow_events=True)
        stable()
        root_bootindex = _qmp_call(
            stream, "qom-get", "symbi-root-bootindex", allow_events=True,
            arguments={"path": "/machine/peripheral/" + QMP_ROOT_DEVICE,
                       "property": "bootindex"})
        stable()
        source_bootindex = _qmp_call(
            stream, "qom-get", "symbi-source-bootindex", allow_events=True,
            arguments={"path": "/machine/peripheral/" + QMP_SOURCE_DEVICE,
                       "property": "bootindex"})
        stable()
        return validate_qmp_block_topology(
            blocks, root_bootindex, source_bootindex)
    result = _qmp_call(stream, name, "symbi-" + name, allow_events=True)
    if name == "quit":
        if result != {}:
            raise ValueError("unexpected QMP quit response")
        return result
    keys = set(result) if isinstance(result, dict) else set()
    if keys not in ({"running", "status"},
                    {"running", "singlestep", "status"}):
        raise ValueError("unexpected QMP query-status response schema")
    if (type(result["running"]) is not bool
            or ("singlestep" in result
                and type(result["singlestep"]) is not bool)
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


def _process_cgroup(raw):
    if not isinstance(raw, str):
        raise ValueError("invalid QEMU process cgroup")
    lines = raw.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/") or "\x00" in lines[0]:
        raise ValueError("invalid QEMU process cgroup")
    path = PurePosixPath(lines[0][3:])
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ValueError("invalid QEMU process cgroup")
    return lines[0]


def _command_identity(command):
    if (not isinstance(command, (list, tuple)) or not command or len(command) > 256
            or any(type(value) is not str or "\x00" in value for value in command)
            or not Path(command[0]).is_absolute()):
        raise ValueError("invalid QEMU launch command")
    raw = b"\0".join(os.fsencode(value) for value in command) + b"\0"
    if len(raw) > MAX_PROCESS_CMDLINE_BYTES:
        raise ValueError("oversized QEMU launch command")
    return {"cmdline_sha256": hashlib.sha256(raw).hexdigest(),
            "cmdline_bytes": len(raw)}


def prepare_process_identity(command, cgroup):
    """Bind the exact absolute executable and argv before direct Popen."""
    command_identity = _command_identity(command)
    executable = Path(command[0])
    info = executable.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("QEMU executable is not a regular file")
    return {"executable": str(executable),
            "executable_device": info.st_dev,
            "executable_inode": info.st_ino,
            **command_identity, "cgroup": _process_cgroup(cgroup)}


def _validate_launch_identity(identity):
    keys = {"executable", "executable_device", "executable_inode",
            "cmdline_sha256", "cmdline_bytes", "cgroup"}
    if (not isinstance(identity, dict) or not keys.issubset(identity)
            or not isinstance(identity["executable"], str)
            or not Path(identity["executable"]).is_absolute()
            or type(identity["executable_device"]) is not int
            or type(identity["executable_inode"]) is not int
            or not re.fullmatch(r"[0-9a-f]{64}", identity["cmdline_sha256"])
            or type(identity["cmdline_bytes"]) is not int
            or not 0 < identity["cmdline_bytes"] <= MAX_PROCESS_CMDLINE_BYTES
            or _process_cgroup(identity["cgroup"]) != identity["cgroup"]):
        raise ValueError("invalid QEMU launch identity")
    info = Path(identity["executable"]).stat()
    if (not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) !=
               (identity["executable_device"], identity["executable_inode"])):
        raise ValueError("QEMU executable identity changed")


def _verify_process_executable(process, identity):
    try:
        observed = (process / "exe").stat()
    except OSError as error:
        if error.errno == errno.EACCES:
            return False
        raise
    if (not stat.S_ISREG(observed.st_mode)
            or (observed.st_dev, observed.st_ino) !=
               (identity["executable_device"], identity["executable_inode"])):
        raise ValueError("QEMU executable identity changed")
    return True


def _read_process_state(pid, identity):
    process = Path("/proc") / str(pid)
    starttime = _process_starttime(_bounded_text(process / "stat", 4096), pid)
    status = {key: value.strip() for key, value in
              (line.split(":", 1) for line in
               _bounded_text(process / "status", 65536).splitlines() if ":" in line)}
    try:
        uids = [int(value) for value in status["Uid"].split()]
        gids = [int(value) for value in status["Gid"].split()]
        ppid = int(status["PPid"])
    except (KeyError, ValueError) as error:
        raise ValueError("invalid QEMU process credentials") from error
    if len(uids) != 4 or len(gids) != 4 or len(set(uids)) != 1 or len(set(gids)) != 1:
        raise ValueError("QEMU process credentials changed")
    cmdline = _bounded_bytes(process / "cmdline", MAX_PROCESS_CMDLINE_BYTES)
    cgroup = _process_cgroup(
        _bounded_text(process / "cgroup", MAX_PROCESS_CGROUP_BYTES))
    return {"pid": pid, "ppid": ppid, "starttime": starttime,
            "cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
            "cmdline_bytes": len(cmdline), "cgroup": cgroup,
            "uid": uids[0], "gid": gids[0],
            "proc_exe_verified": _verify_process_executable(process, identity)}


def validate_process_state(identity, observed):
    keys = {"pid", "ppid", "starttime", "cmdline_sha256", "cmdline_bytes",
            "cgroup", "uid", "gid"}
    if (not isinstance(identity, dict) or not isinstance(observed, dict)
            or set(observed) != keys | {"proc_exe_verified"}
            or type(identity.get("proc_exe_verified")) is not bool
            or type(observed["proc_exe_verified"]) is not bool
            or any(observed.get(key) != identity.get(key) for key in keys)
            or (identity["proc_exe_verified"]
                and not observed["proc_exe_verified"])):
        raise ValueError("QEMU process identity changed")


def _pidfd_controls():
    opener = getattr(os, "pidfd_open", None)
    sender = getattr(signal, "pidfd_send_signal", None)
    if (not callable(opener) or not callable(sender)
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise ValueError("required QEMU pidfd controls are unavailable")
    return opener, sender


def _pidfd_exited(identity, timeout):
    pidfd = identity.get("pidfd") if isinstance(identity, dict) else None
    if type(pidfd) is not int or pidfd < 0:
        raise ValueError("QEMU pidfd is unavailable")
    try:
        return bool(select.select([pidfd], [], [], timeout)[0])
    except (OSError, ValueError) as error:
        raise ValueError("QEMU pidfd is invalid") from error


def _require_live_pidfd(identity):
    if _pidfd_exited(identity, 0):
        raise ValueError("exact QEMU process exited")


def capture_process_identity(child, prepared, reader=_read_process_state):
    if (type(child.pid) is not int or child.pid <= 1
            or not isinstance(prepared, dict)):
        raise ValueError("QEMU did not remain live for identity capture")
    opener, _ = _pidfd_controls()
    identity = {**prepared, "pid": child.pid, "pidfd": None}
    try:
        identity["pidfd"] = opener(child.pid, 0)
        _require_live_pidfd(identity)
        _validate_launch_identity(prepared)
        launched = _command_identity(child.args)
        if launched != {key: prepared[key] for key in launched}:
            raise ValueError("QEMU Popen command identity changed")
        observed = reader(child.pid, identity)
        identity.update(ppid=observed["ppid"], starttime=observed["starttime"],
                        uid=observed["uid"], gid=observed["gid"],
                        proc_exe_verified=observed["proc_exe_verified"])
        if (identity["ppid"] != os.getpid()
                or identity["uid"] != os.geteuid()
                or identity["gid"] != os.getegid()):
            raise ValueError("QEMU direct-child identity changed")
        validate_process_state(identity, observed)
        observed = reader(child.pid, identity)
        validate_process_state(identity, observed)
        if observed["proc_exe_verified"]:
            identity["proc_exe_verified"] = True
        _require_live_pidfd(identity)
        if child.poll() is not None:
            raise ValueError("QEMU exited during identity capture")
    except Exception:
        if type(identity["pidfd"]) is int and identity["pidfd"] >= 0:
            try:
                os.close(identity["pidfd"])
            except OSError:
                pass
        raise
    return identity


def verify_process_identity(identity, reader=_read_process_state):
    _require_live_pidfd(identity)
    _validate_launch_identity(identity)
    observed = reader(identity["pid"], identity)
    validate_process_state(identity, observed)
    if observed["proc_exe_verified"]:
        identity["proc_exe_verified"] = True
    _require_live_pidfd(identity)


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
    if name not in {"query-status", "query-block-topology", "quit"}:
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
        if name in {"query-status", "query-block-topology"}:
            stable()
        return result


def observe_qmp_topology(control, timeout=30, clock=time.monotonic,
                         sleep=time.sleep, request=qmp_command):
    """Wait only for the private QMP socket, then bind the live block topology."""
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise ValueError("invalid QMP topology deadline")
    started = clock()
    while True:
        try:
            return validate_qmp_topology_record(
                request(control, "query-block-topology"))
        except OSError as error:
            startup_error = error.errno == errno.ECONNREFUSED
            if error.errno == errno.ENOENT:
                try:
                    control["path"].lstat()
                except FileNotFoundError:
                    startup_error = True
            if not startup_error:
                raise
            if clock() - started >= timeout:
                raise TimeoutError(
                    "QMP block topology was not observable within 30 seconds") from error
            sleep(0.1)


def _cleanup_error(error):
    return (type(error).__name__ + ": " + str(error))[:512]


def wait_for_exact_exit(child, identity, timeout):
    """Prove exit of the captured direct child through its mandatory pidfd."""
    if identity is None or child.pid != identity.get("pid"):
        return False
    _pidfd_controls()
    returncode = child.poll()
    if returncode is None:
        try:
            verify_process_identity(identity)
        except Exception:
            returncode = child.poll()
            if _pidfd_exited(identity, timeout):
                if returncode is None:
                    try:
                        returncode = child.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
                if type(returncode) is int:
                    return True
            raise
        if not _pidfd_exited(identity, timeout):
            return False
        try:
            returncode = child.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            return False
    if type(returncode) is not int:
        return False
    return _pidfd_exited(identity, 0)


def _send_pidfd_signal(identity, number):
    """Signal only the exact task referenced by the captured pidfd."""
    _, sender = _pidfd_controls()
    _require_live_pidfd(identity)
    sender(identity["pidfd"], number, None, 0)


def stop_child(child, identity=None, control=None, request=qmp_command,
               prove_exit=wait_for_exact_exit, verify=verify_process_identity,
               send_signal=_send_pidfd_signal):
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
        # QEMU may close QMP after accepting quit but before returning its
        # response.  In either case only pidfd readiness plus the direct
        # Popen return code authorizes private-leaf cleanup.
        try:
            if prove_exit(child, identity, 10):
                result["exit_proven"] = True
                return result
        except Exception as error:
            result["errors"].append(_cleanup_error(error))
    try:
        verify(identity)
        send_signal(identity, signal.SIGTERM)
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
        send_signal(identity, signal.SIGKILL)
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
    raw = _bounded_bytes(path, maximum)
    return raw.decode("utf-8", errors="strict").strip()


def _bounded_bytes(path, maximum):
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("oversized progress input")
    return raw


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
        "-accel", "tcg,thread=multi", "-cpu", "max", "-m", "2048M",
        "-smp", "cpus=2,sockets=1,cores=2,threads=1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-boot", "strict=on",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Landlock-Probe",
        "-drive", "file=/output/guest.qcow2,format=qcow2,if=none,"
                  "id=symbi-atomic-root",
        "-device", "virtio-blk-pci,drive=symbi-atomic-root,"
                   "id=symbi-atomic-root-device,serial=SYMBIROOT,bootindex=1",
        "-drive", "file=/inputs/source.raw,format=raw,if=none,"
                  "id=symbi-qualification-source,readonly=on",
        "-device", "virtio-blk-pci,drive=symbi-qualification-source,"
                   "id=symbi-qualification-source-device,serial=SYMBIQUAL",
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
    self_cgroup = _process_cgroup(
        _bounded_text("/proc/self/cgroup", MAX_PROCESS_CGROUP_BYTES))
    group = (Path("/sys/fs/cgroup") /
             Path(self_cgroup.split("::", 1)[1]).relative_to("/"))
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
            prepared_process = prepare_process_identity(command, self_cgroup)
            _pidfd_controls()
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                          "HOME": "/output", "TMPDIR": "/output"},
                                     umask=0o077)
            process_identity = capture_process_identity(child, prepared_process)
            qmp_control = create_qmp_control(qmp_path, process_identity)
            record["qemu_process"] = {
                key: process_identity[key] for key in
                ("pid", "ppid", "starttime", "executable_device", "executable_inode",
                 "uid", "gid", "executable", "cmdline_sha256", "cmdline_bytes",
                 "cgroup", "proc_exe_verified")
            }
            record["qemu_process"]["pidfd"] = True
            record["block_topology"] = observe_qmp_topology(qmp_control)
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
        retain_qmp_topology_failure(record, error)
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
