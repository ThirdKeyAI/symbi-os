"""Exercise one phase of an offline signed bootc switch and rollback."""
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SOURCE = Path("/run/symbi-update/source")
SOURCE_SERIAL = "SYMBIUPDATE"
SOURCE_SERIAL_BYTES = b"SYMBIUPDATE"
SOURCE_DEVICE_TIMEOUT_SECONDS = 30
SYS_BLOCK = Path("/sys/class/block")
DEV_ROOT = Path("/dev")
MOUNTINFO = Path("/proc/self/mountinfo")
MOUNTINFO_MAX_BYTES = 256 * 1024
MOUNTINFO_MAX_LINES = 4096
MOUNTINFO_MAX_LINE_BYTES = 8192
FDINFO = Path("/proc/self/fdinfo")
FDINFO_MAX_BYTES = 4096
FDINFO_MAX_LINES = 64
FDINFO_MAX_LINE_BYTES = 512
NEGATIVE_SOURCE = Path("/run/symbi-update-negative/source")
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
POSITIVE_OVERLAY_CASE = "valid-signature"
UPDATE_COMMAND_TIMEOUT_SECONDS = 1200
STATE = Path("/var/lib/symbi-update-test/phase")
CHANNEL = Path("/dev/virtio-ports/org.symbi.update")
STATUS_OUTPUT = Path("/run/symbi-atomic-status.json")
STATUS_UNIT = "s.service"
STATUS_PROPERTIES = (
    "Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"
)
STATUS_SERVICE = {
    "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
    "ActiveState": "active", "SubState": "exited",
}
BOOTC_CONTEXT = "system_u:system_r:install_t:s0"
BOOTC_RUNCON = Path("/usr/bin/runcon")
BOOTC_RUNCON_LABEL = "system_u:object_r:bin_t:s0"
BOOTC_SOURCE = Path("/usr/bin/bootc")
BOOTC_LABEL_REFERENCE = Path("/usr/bin/ostree")
BOOTC_PROBE_COMMAND = [str(BOOTC_RUNCON), BOOTC_CONTEXT,
                       str(BOOTC_SOURCE), "--version"]
BOOTC_OPERATIONS = {
    "negative": ["switch", "--transport", "dir",
                 "--enforce-container-sigpolicy", str(NEGATIVE_SOURCE)],
    "positive": ["switch", "--transport", "dir",
                 "--enforce-container-sigpolicy", str(SOURCE)],
    "rollback": ["rollback"],
}


def write_channel(raw, channel=CHANNEL):
    """Write one bounded report completely before the service can power off."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 128 * 1024:
        raise ValueError("invalid update guest report payload")
    channel = Path(channel)
    deadline = time.monotonic() + 15
    while not channel.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    with channel.open("wb", buffering=0) as output:
        offset = 0
        while offset < len(raw):
            written = output.write(raw[offset:])
            if type(written) is not int or not 0 < written <= len(raw) - offset:
                raise RuntimeError("guest report channel stopped accepting data")
            offset += written


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def exact_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)


def service_properties(raw):
    """Parse the exact bounded systemd result needed by a fixed unit."""
    if (not isinstance(raw, str) or not raw.endswith("\n")
            or not 0 < len(raw.encode()) <= 4096):
        raise ValueError("invalid fixed service property output")
    properties = {}
    for line in raw.splitlines():
        if "=" not in line:
            raise ValueError("malformed fixed service property output")
        key, value = line.split("=", 1)
        if (key not in STATUS_PROPERTIES.split(",") or key in properties
                or not value or len(value) > 128):
            raise ValueError("ambiguous fixed service property output")
        properties[key] = value
    if set(properties) != set(STATUS_PROPERTIES.split(",")):
        raise ValueError("incomplete fixed service property output")
    return properties


def _unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate bootc status key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("bootc status is not an object")
    return value


def fixed_bootc_status(run, observations, status_path=STATUS_OUTPUT):
    """Restart the fixed direct collector and read only its fresh output."""
    if not isinstance(observations, list) or not Path(status_path).is_absolute():
        raise ValueError("invalid fixed status observation target")
    status_path = Path(status_path)
    parent = os.open(status_path.parent,
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        directory = os.fstat(parent)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or directory.st_gid != 0
                or directory.st_mode & 0o022):
            raise ValueError("status parent is not root controlled")
        try:
            stale = os.open(status_path.name,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=parent)
        except FileNotFoundError:
            pass
        else:
            try:
                info = os.fstat(stale)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                        or info.st_gid != 0
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError("stale status output is not private and root owned")
            finally:
                os.close(stale)
            os.unlink(status_path.name, dir_fd=parent)
        run(["/usr/bin/systemctl", "restart", STATUS_UNIT], timeout=120)
        raw_properties = run([
            "/usr/bin/systemctl", "show", STATUS_UNIT,
            "--property=" + STATUS_PROPERTIES,
        ])
        properties = service_properties(raw_properties)
        if properties != STATUS_SERVICE:
            raise ValueError("fixed bootc status collector did not complete")
        output = os.open(status_path.name,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
        with os.fdopen(output, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_gid != 0
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                    or not 0 < before.st_size <= 128 * 1024):
                raise ValueError("status output is not one bounded private root file")
            raw = stream.read(128 * 1024 + 1)
            after = os.fstat(stream.fileno())
            identity = lambda info: (
                info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            )
            if len(raw) != before.st_size or identity(before) != identity(after):
                raise ValueError("status output changed during observation")
    finally:
        os.close(parent)
    observation = {
        "sequence": len(observations) + 1,
        "unit": STATUS_UNIT,
        "service": properties,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    observations.append(observation)
    return _unique_json(raw)


def _fd_digest(fd):
    with os.fdopen(os.dup(fd), "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _stable_regular(fd, *, uid=0, gid=0, mode=None):
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
            or before.st_gid != gid
            or not 0 < before.st_size <= 256 * 1024 * 1024
            or (mode is not None and stat.S_IMODE(before.st_mode) != mode)):
        raise ValueError("fixed bootc input controls changed")
    digest = _fd_digest(fd)
    after = os.fstat(fd)
    identity = lambda info: (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise ValueError("fixed bootc input changed during observation")
    return before, digest


def _bootc_file_observation(source_path=None, label_reference=None,
                            runcon_path=None):
    source_path = BOOTC_SOURCE if source_path is None else Path(source_path)
    label_reference = (BOOTC_LABEL_REFERENCE if label_reference is None
                       else Path(label_reference))
    runcon_path = BOOTC_RUNCON if runcon_path is None else Path(runcon_path)
    if (not source_path.is_absolute() or not label_reference.is_absolute()
            or not runcon_path.is_absolute()):
        raise ValueError("fixed bootc input paths must be absolute")
    source = reference = runcon = None
    try:
        source = os.open(source_path,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        reference = os.open(label_reference,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        runcon = os.open(runcon_path,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        _, source_hash = _stable_regular(source, mode=0o755)
        _, reference_hash = _stable_regular(reference, mode=0o755)
        _, runcon_hash = _stable_regular(runcon, mode=0o755)

        def normalized_label(descriptor):
            value = os.getxattr(descriptor, "security.selinux")
            if value.endswith(b"\0"):
                value = value[:-1]
            if not value or b"\0" in value:
                raise ValueError("invalid SELinux file label")
            return value
        runcon_label = normalized_label(runcon).decode("ascii")
        if runcon_label != BOOTC_RUNCON_LABEL:
            raise ValueError("runcon does not carry the fixed generic executable label")
        label = normalized_label(source)
        reference_label = normalized_label(reference)
        if label != reference_label:
            raise ValueError("bootc SELinux label differs from ostree")
        label_text = label.decode("ascii")
        if re.fullmatch(r"[^:\x00]+:object_r:install_exec_t:[^\x00]+", label_text) is None:
            raise ValueError("bootc does not carry install_exec_t")
        return {
            "runcon": str(runcon_path),
            "runcon_sha256": runcon_hash,
            "runcon_selinux_label": runcon_label,
            "source": str(source_path),
            "label_reference": str(label_reference),
            "source_sha256": source_hash,
            "label_reference_sha256": reference_hash,
            "selinux_label": label_text,
            "mode": "0755",
        }
    finally:
        for fd in (runcon, reference, source):
            if fd is not None:
                os.close(fd)


def fixed_bootc_transition(run):
    """Bind the successful nonmutating transition probe and executable inputs."""
    properties = service_properties(run([
        "/usr/bin/systemctl", "show", "b.service",
        "--property=" + STATUS_PROPERTIES,
    ]))
    if properties != STATUS_SERVICE:
        raise ValueError("fixed bootc transition probe did not complete")
    return {
        "unit": "b.service", "service": properties,
        "context": BOOTC_CONTEXT,
        "probe_command": BOOTC_PROBE_COMMAND,
        "scope": "Explicit transition availability only; no update qualification",
        **_bootc_file_observation(),
    }


def fixed_bootc_operation(run, record, operation, *, expected_success, timeout):
    """Run one exact mutation through runcon after revalidating fixed inputs."""
    if (operation not in BOOTC_OPERATIONS or type(expected_success) is not bool
            or type(timeout) is not int
            or not 1 <= timeout <= UPDATE_COMMAND_TIMEOUT_SECONDS
            or not isinstance(record.get("bootc_transition"), dict)):
        raise ValueError("invalid fixed bootc operation")
    current = _bootc_file_observation()
    retained = {key: record["bootc_transition"].get(key) for key in current}
    if current != retained:
        raise ValueError("fixed bootc input changed before use")
    command = [str(BOOTC_RUNCON), BOOTC_CONTEXT, str(BOOTC_SOURCE),
               *BOOTC_OPERATIONS[operation]]
    result = run(command, timeout=timeout, check=False, return_result=True)
    if _bootc_file_observation() != current:
        raise ValueError("fixed bootc input changed during use")
    observation = {
        "name": operation,
        "command": command,
        "exit_code": result.returncode,
        "stderr": result.stderr,
        "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
    }
    record["bootc_operation"] = observation
    if expected_success:
        if result.returncode != 0:
            raise ValueError("fixed bootc operation failed")
    elif result.returncode == 0 or "signature" not in result.stderr.lower():
        raise ValueError("bootc did not retain a native signature rejection")
    return observation


def validate_source_identity(raw, expected):
    """Require the mounted update filesystem's exact generated identity."""
    if (not isinstance(raw, str) or not isinstance(expected, dict)
            or expected.get("filesystem") != "ext4"
            or expected.get("label") != "SYMBIUPDATE"
            or re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                            expected.get("uuid", "")) is None):
        raise ValueError("invalid expected update filesystem identity")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 32:
        raise ValueError("invalid update filesystem identity output")
    fields = {}
    for line in lines:
        if "=" not in line:
            raise ValueError("malformed update filesystem identity output")
        key, value = line.split("=", 1)
        if (re.fullmatch(r"[A-Z0-9_]+", key) is None or not value
                or key in fields or len(key) > 64 or len(value) > 4096):
            raise ValueError("ambiguous update filesystem identity output")
        fields[key] = value
    selected = {name: fields.get(name) for name in ("TYPE", "LABEL", "UUID")}
    required = {"TYPE": expected["filesystem"], "LABEL": expected["label"],
                "UUID": expected["uuid"]}
    if selected != required:
        raise ValueError("update filesystem identity differs")
    return selected


_MOUNTINFO_ESCAPES = {
    "040": " ",
    "011": "\t",
    "012": "\n",
    "134": "\\",
}


def _decode_mountinfo_field(value):
    """Decode only the four escapes emitted by procfs mountinfo."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 4096
            or "\x00" in value or "\r" in value or "\n" in value):
        raise ValueError("invalid mountinfo field")
    decoded = []
    offset = 0
    while offset < len(value):
        if value[offset] != "\\":
            decoded.append(value[offset])
            offset += 1
            continue
        code = value[offset + 1:offset + 4]
        if len(code) != 3 or code not in _MOUNTINFO_ESCAPES:
            raise ValueError("invalid mountinfo escape")
        decoded.append(_MOUNTINFO_ESCAPES[code])
        offset += 4
    result = "".join(decoded)
    if "\x00" in result:
        raise ValueError("invalid decoded mountinfo field")
    return result


def _mountinfo_options(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 4096
            or "\x00" in value or any(character.isspace() for character in value)):
        raise ValueError("invalid mountinfo options")
    options = value.split(",")
    if (not 1 <= len(options) <= 128
            or any(not option or len(option) > 4096 for option in options)):
        raise ValueError("ambiguous mountinfo options")
    return options


def mount_observation(raw, mountpoint, visible_mount_id):
    """Select the kernel row named by an opened directory's visible mount ID."""
    mountpoint = Path(mountpoint)
    if (not mountpoint.is_absolute() or not isinstance(raw, str)
            or type(visible_mount_id) is not int or not 1 <= visible_mount_id <= 9999999999):
        raise ValueError("invalid visible mount observation input")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("invalid mountinfo encoding") from error
    if (not 0 < len(encoded) <= MOUNTINFO_MAX_BYTES or not raw.endswith("\n")
            or "\x00" in raw or "\r" in raw):
        raise ValueError("invalid or oversized mountinfo")
    lines = raw[:-1].split("\n")
    if not 1 <= len(lines) <= MOUNTINFO_MAX_LINES:
        raise ValueError("invalid mountinfo line count")
    matches = []
    for line in lines:
        if (not line or len(line.encode("utf-8")) > MOUNTINFO_MAX_LINE_BYTES
                or "\t" in line):
            raise ValueError("invalid mountinfo line")
        fields = line.split(" ")
        if (not 10 <= len(fields) <= 128 or any(not field for field in fields)
                or len([field for field in fields if field == "-"]) != 1):
            raise ValueError("malformed mountinfo line")
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4:
            raise ValueError("malformed mountinfo separator")
        if (re.fullmatch(r"(0|[1-9][0-9]{0,9})", fields[0]) is None
                or re.fullmatch(r"(0|[1-9][0-9]{0,9})", fields[1]) is None
                or re.fullmatch(r"(0|[1-9][0-9]{0,6}):(0|[1-9][0-9]{0,6})",
                                fields[2]) is None
                or re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}",
                                fields[separator + 1]) is None
                or any(len(field) > 4096 for field in fields[6:separator])):
            raise ValueError("invalid mountinfo identity")
        root = _decode_mountinfo_field(fields[3])
        observed_mountpoint = _decode_mountinfo_field(fields[4])
        source = _decode_mountinfo_field(fields[separator + 2])
        options = _mountinfo_options(fields[5])
        super_options = _mountinfo_options(fields[separator + 3])
        if observed_mountpoint == str(mountpoint):
            matches.append({
                "mount_id": int(fields[0]),
                "mountpoint": observed_mountpoint,
                "root": root,
                "fstype": fields[separator + 1],
                "source": source,
                "major_minor": fields[2],
                "options": options,
                "super_options": super_options,
            })
    selected = [entry for entry in matches if entry["mount_id"] == visible_mount_id]
    observation = {
        "mountinfo_sha256": hashlib.sha256(encoded).hexdigest(),
        "path_match_count": len(matches),
        "selected_match_count": len(selected),
        "visible_mount_id": visible_mount_id,
        "selected_mount_id": visible_mount_id if selected else None,
    }
    if len(selected) == 1:
        selected_entry = dict(selected[0])
        observation["selected_mount_id"] = selected_entry.pop("mount_id")
        observation.update(selected_entry)
    return observation


def source_mount_observation(raw, visible_mount_id, mountpoint=SOURCE.parent):
    """Observe only the fixed update mountpoint selected by its open descriptor."""
    if Path(mountpoint) != SOURCE.parent:
        raise ValueError("fixed update mountpoint required")
    return mount_observation(raw, mountpoint, visible_mount_id)


def validate_source_mount(observation, source_device, device_number):
    """Bind one mountinfo entry to the exact direct block node and controls."""
    required = {"mountinfo_sha256", "path_match_count", "selected_match_count",
                "visible_mount_id", "selected_mount_id", "mountpoint", "root",
                "fstype", "source", "major_minor", "options", "super_options"}
    source_device = Path(source_device)
    if (not isinstance(observation, dict) or set(observation) != required
            or type(observation.get("path_match_count")) is not int
            or observation.get("path_match_count") < 1
            or observation.get("selected_match_count") != 1
            or observation.get("visible_mount_id") != observation.get("selected_mount_id")
            or re.fullmatch(r"[a-f0-9]{64}",
                            observation.get("mountinfo_sha256", "")) is None
            or not isinstance(device_number, tuple) or len(device_number) != 2
            or any(type(value) is not int or not 0 <= value <= 9999999
                   for value in device_number)
            or re.fullmatch(r"/dev/vd[a-z]{1,3}", str(source_device)) is None):
        raise ValueError("ambiguous update source mount observation")
    options = observation.get("options")
    super_options = observation.get("super_options")
    if (not isinstance(options, list) or not isinstance(super_options, list)
            or len(options) != len(set(options))
            or len(super_options) != len(set(super_options))
            or any(not isinstance(value, str) or not value or len(value) > 4096
                   for value in options + super_options)
            or observation.get("mountpoint") != str(SOURCE.parent)
            or observation.get("root") != "/"
            or observation.get("fstype") != "ext4"
            or observation.get("source") != str(source_device)
            or observation.get("major_minor") != f"{device_number[0]}:{device_number[1]}"
            or "rw" in options
            or not {"ro", "nosuid", "nodev", "noexec"}.issubset(set(options))):
        raise ValueError("update source mount controls changed")
    return observation


def parse_visible_mount_id(raw):
    """Parse one canonical mnt_id from a bounded procfs fdinfo record."""
    if not isinstance(raw, str):
        raise ValueError("invalid fdinfo input")
    try:
        encoded = raw.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("invalid fdinfo encoding") from error
    if (not 0 < len(encoded) <= FDINFO_MAX_BYTES or not raw.endswith("\n")
            or "\x00" in raw or "\r" in raw):
        raise ValueError("invalid or oversized fdinfo")
    lines = raw[:-1].split("\n")
    if not 1 <= len(lines) <= FDINFO_MAX_LINES:
        raise ValueError("invalid fdinfo line count")
    mount_ids = []
    for line in lines:
        if (not line or len(line.encode("ascii")) > FDINFO_MAX_LINE_BYTES
                or ":" not in line):
            raise ValueError("malformed fdinfo line")
        key, value = line.split(":", 1)
        if re.fullmatch(r"[a-z_]{1,64}", key) is None or len(value) > 4096:
            raise ValueError("invalid fdinfo field")
        if key == "mnt_id":
            match = re.fullmatch(r"[\t ]+(0|[1-9][0-9]{0,9})", value)
            if match is None:
                raise ValueError("invalid fdinfo mount ID")
            mount_ids.append(int(match.group(1)))
    if len(mount_ids) != 1 or mount_ids[0] < 1:
        raise ValueError("ambiguous fdinfo mount ID")
    return mount_ids[0]


def read_visible_mount_id(descriptor):
    """Read the fixed procfs fdinfo record for one still-open descriptor."""
    if type(descriptor) is not int or descriptor < 0:
        raise ValueError("invalid visible mount descriptor")
    path = FDINFO / str(descriptor)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fdinfo = os.open(path, flags)
    try:
        chunks = []
        total = 0
        while total <= FDINFO_MAX_BYTES:
            chunk = os.read(fdinfo, min(4096, FDINFO_MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fdinfo)
    if total > FDINFO_MAX_BYTES:
        raise ValueError("oversized fdinfo")
    try:
        raw = b"".join(chunks).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("invalid fdinfo encoding") from error
    return parse_visible_mount_id(raw)


def observe_visible_source_mount(*, opener=None, descriptor_stat=None,
                                 path_lstat=None, closer=None,
                                 fdinfo_reader=None, mountinfo_reader=None):
    """Open the fixed path and select the row the kernel exposes through that fd."""
    opener = os.open if opener is None else opener
    descriptor_stat = os.fstat if descriptor_stat is None else descriptor_stat
    path_lstat = os.lstat if path_lstat is None else path_lstat
    closer = os.close if closer is None else closer
    fdinfo_reader = read_visible_mount_id if fdinfo_reader is None else fdinfo_reader
    mountinfo_reader = read_mountinfo if mountinfo_reader is None else mountinfo_reader
    required_flags = (getattr(os, "O_PATH", 0) | os.O_DIRECTORY | os.O_CLOEXEC
                      | getattr(os, "O_NOFOLLOW", 0))
    if not getattr(os, "O_PATH", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("kernel path-only no-follow open is unavailable")
    descriptor = opener(SOURCE.parent, required_flags)
    try:
        opened = descriptor_stat(descriptor)
        before = path_lstat(SOURCE.parent)
        identity = lambda info: (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        if (not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(before.st_mode)
                or identity(opened) != identity(before)):
            raise ValueError("visible update mount path differs from its descriptor")
        visible_mount_id = fdinfo_reader(descriptor)
        observation = source_mount_observation(mountinfo_reader(), visible_mount_id)
        after = path_lstat(SOURCE.parent)
        if not stat.S_ISDIR(after.st_mode) or identity(after) != identity(opened):
            raise ValueError("visible update mount path changed during observation")
        return observation
    finally:
        closer(descriptor)


def validate_mounted_device(source_device, mountpoint, *, device_lstat=None,
                            mount_stat=None, is_mount=None):
    """Require the mounted directory and direct block node to share a device ID."""
    source_device, mountpoint = Path(source_device), Path(mountpoint)
    if (re.fullmatch(r"/dev/vd[a-z]{1,3}", str(source_device)) is None
            or mountpoint != SOURCE.parent):
        raise ValueError("fixed update source device and mountpoint required")
    device_lstat = os.lstat if device_lstat is None else device_lstat
    mount_stat = os.stat if mount_stat is None else mount_stat
    is_mount = os.path.ismount if is_mount is None else is_mount
    device = device_lstat(source_device)
    mounted = mount_stat(mountpoint)
    if (not stat.S_ISBLK(device.st_mode) or not stat.S_ISDIR(mounted.st_mode)
            or not is_mount(mountpoint)):
        raise ValueError("update source is not a direct block-device mount")
    device_number = (os.major(device.st_rdev), os.minor(device.st_rdev))
    mounted_number = (os.major(mounted.st_dev), os.minor(mounted.st_dev))
    if mounted_number != device_number:
        raise ValueError("mounted update source device number differs")
    return device_number


def read_mountinfo(path=MOUNTINFO):
    """Read the current mount namespace table with a hard byte ceiling."""
    if Path(path) != MOUNTINFO:
        raise ValueError("fixed mountinfo path required")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        chunks = []
        total = 0
        while total <= MOUNTINFO_MAX_BYTES:
            chunk = os.read(descriptor, min(65536, MOUNTINFO_MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    if total > MOUNTINFO_MAX_BYTES:
        raise ValueError("oversized mountinfo")
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("invalid mountinfo encoding") from error


def _sysfs_bytes(path, limit):
    """Read one bounded sysfs attribute without following its final component."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        return os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)


def _sysfs_value(path):
    """Read one small ASCII sysfs line."""
    raw = _sysfs_bytes(path, 128)
    if raw is None:
        return None
    if len(raw) > 128 or b"\x00" in raw or b"\r" in raw:
        raise ValueError("invalid block-device sysfs attribute")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw:
        raise ValueError("invalid block-device sysfs attribute")
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("invalid block-device sysfs attribute") from error
    if not value:
        raise ValueError("empty block-device sysfs attribute")
    return value


def _block_serial(path):
    """Read only enough bytes to compare the kernel's exact virtio serial."""
    return _sysfs_bytes(path, len(SOURCE_SERIAL_BYTES))


def discover_source_device(sys_block=SYS_BLOCK, dev_root=DEV_ROOT, device_lstat=None):
    """Find one virtio disk by exact kernel serial and bind its device node."""
    sys_block, dev_root = Path(sys_block), Path(dev_root)
    device_lstat = os.lstat if device_lstat is None else device_lstat
    entries = list(sys_block.iterdir())
    names = sorted(path.name for path in entries)
    if (not names or len(names) > 64
            or len(names) != len(set(names))
            or any(re.fullmatch(r"[A-Za-z0-9_.!-]{1,128}", name) is None
                   for name in names)):
        raise ValueError("invalid block-device inventory")
    matches = []
    for name in names:
        if re.fullmatch(r"vd[a-z]{1,3}", name) is None:
            continue
        entry = sys_block / name
        if _block_serial(entry / "serial") == SOURCE_SERIAL_BYTES:
            matches.append(name)
    if len(matches) > 1:
        raise ValueError("ambiguous update source virtio serial")
    if not matches:
        return None, names
    name = matches[0]
    major_minor = _sysfs_value(sys_block / name / "dev")
    if major_minor is None:
        return None, names
    match = re.fullmatch(r"(0|[1-9][0-9]{0,6}):(0|[1-9][0-9]{0,6})",
                         major_minor)
    if match is None:
        raise ValueError("invalid update source device number")
    major, minor = int(match[1]), int(match[2])
    device = dev_root / name
    try:
        info = device_lstat(device)
    except FileNotFoundError:
        return None, names
    if (not stat.S_ISBLK(info.st_mode)
            or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (major, minor)):
        raise ValueError("update source device node differs from sysfs")
    return device, names


def wait_for_source_device(*, scan=None, clock=None, sleeper=None,
                           timeout=SOURCE_DEVICE_TIMEOUT_SECONDS):
    """Poll the kernel block inventory for a bounded time without udev state."""
    if type(timeout) is not int or not 1 <= timeout <= SOURCE_DEVICE_TIMEOUT_SECONDS:
        raise ValueError("invalid update source discovery timeout")
    scan = discover_source_device if scan is None else scan
    clock = time.monotonic if clock is None else clock
    sleeper = time.sleep if sleeper is None else sleeper
    deadline = clock() + timeout
    first_scan = True
    while True:
        if not first_scan and clock() >= deadline:
            raise ValueError("fixed update source virtio serial is absent")
        first_scan = False
        device, inventory = scan()
        if device is not None:
            return device, inventory
        remaining = deadline - clock()
        if remaining <= 0:
            raise ValueError("fixed update source virtio serial is absent")
        sleeper(min(0.25, remaining))


def image_digest(entry, expected):
    """Return an exact, policy-authenticated boot entry digest."""
    if not isinstance(entry, dict) or entry.get("incompatible") is not False:
        raise ValueError("missing compatible bootc deployment")
    image = entry.get("image")
    reference = image.get("image", {}) if isinstance(image, dict) else {}
    if (image.get("imageDigest") != expected or image.get("architecture") != "amd64"
            or reference.get("signature") != "containerPolicy"
            or not isinstance(reference.get("transport"), str)
            or not isinstance(reference.get("image"), str)):
        raise ValueError("bootc deployment lost its exact digest or signature policy")
    return image["imageDigest"]


def phase_status(status, booted, *, staged=None, rollback=None, rollback_queued=False):
    try:
        if (status.get("apiVersion") != "org.containers.bootc/v1"
                or status.get("kind") != "BootcHost"
                or status["status"].get("type") != "bootcHost"
                or status["status"].get("rollbackQueued", False) is not rollback_queued):
            raise ValueError("unexpected bootc host state")
        observed = {"booted": image_digest(status["status"].get("booted"), booted)}
        for name, expected in (("staged", staged), ("rollback", rollback)):
            entry = status["status"].get(name)
            if expected is None:
                if entry is not None:
                    raise ValueError("unexpected " + name + " deployment")
            else:
                observed[name] = image_digest(entry, expected)
        return observed
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed bootc status") from error


def deployment_snapshot(status, booted):
    """Capture the configured default and every deployment slot after validation."""
    phase_status(status, booted)
    try:
        default = status["spec"]["image"]
        active = status["status"]["booted"]
        reference = active["image"]["image"]
        if (not isinstance(default, dict) or default != reference
                or default.get("signature") != "containerPolicy"):
            raise ValueError("bootc configured default differs from the booted signed image")
        # The JSON round trip rejects non-serializable values and detaches the
        # comparison from the caller's mutable status object.
        return json.loads(json.dumps({
            "default": default,
            "booted": active,
            "staged": status["status"].get("staged"),
            "rollback": status["status"].get("rollback"),
            "rollback_queued": status["status"].get("rollbackQueued", False),
        }, sort_keys=True))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed bootc deployment snapshot") from error


def staged_deployment_snapshot(status, booted, staged):
    """Capture an exact successful switch without accepting unrelated state."""
    phase_status(status, booted, staged=staged)
    try:
        default = status["spec"]["image"]
        active = status["status"]["booted"]
        pending = status["status"]["staged"]
        reference = pending["image"]["image"]
        if (not isinstance(default, dict) or default != reference
                or default.get("signature") != "containerPolicy"
                or default.get("transport") != "dir"):
            raise ValueError("bootc configured default differs from the staged signed image")
        return json.loads(json.dumps({
            "default": default,
            "booted": active,
            "staged": pending,
            "rollback": status["status"].get("rollback"),
            "rollback_queued": status["status"].get("rollbackQueued", False),
        }, sort_keys=True))
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("malformed staged bootc deployment snapshot") from error


def write_state(value):
    if value not in ("updated", "rolled-back"):
        raise ValueError("invalid update phase state")
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE.with_name("phase.new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, (value + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, STATE)
    directory = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Hosted-Update-Probe"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 3):
        raise SystemExit("Use only the disposable hosted update guest")
    expected_path, policy_path = map(Path, sys.argv[1:])
    if expected_path.stat().st_size > 128 * 1024 or policy_path.stat().st_size > 128 * 1024:
        raise ValueError("oversized update credential")
    expected = json.loads(expected_path.read_bytes())
    old, new = expected["old_digest"], expected["new_digest"]
    source_expected = expected.get("source_disk")
    if (not exact_digest(old) or not exact_digest(new) or old == new
            or not re.fullmatch(r"[a-f0-9]{32}", expected["nonce"])
            or not isinstance(source_expected, dict)
            or source_expected.get("serial") != SOURCE_SERIAL):
        raise ValueError("invalid update expectation")
    record = {"schema": 1, "passed": False, "guest_booted": True,
              "release_qualified": False, "product": product,
              "nonce": expected["nonce"], "expected_sha256": sha256(expected_path),
              "runner_sha256": sha256(Path(__file__)), "commands": [],
              "status_observations": [],
              "scope": "Offline ephemeral fixture-signed update and rollback only"}

    def run(command, *, timeout=120, check=True, return_result=False):
        if (type(timeout) is not int or not 1 <= timeout <= UPDATE_COMMAND_TIMEOUT_SECONDS
                or type(check) is not bool or type(return_result) is not bool):
            raise ValueError("invalid update command timeout")
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, text=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        if len(result.stdout.encode()) > 256 * 1024 or len(result.stderr.encode()) > 128 * 1024:
            raise ValueError("update command output exceeded its bound")
        record["commands"].append({"command": command, "exit_code": result.returncode,
                                   "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                                   "stderr": result.stderr})
        if check:
            result.check_returncode()
        return result if return_result else result.stdout

    try:
        if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
            raise ValueError("update guest gained a network interface")
        if run(["/usr/sbin/getenforce"]).strip() != "Enforcing":
            raise ValueError("SELinux is not enforcing")
        record["bootc_transition"] = fixed_bootc_transition(run)
        observed_devices = []

        def scan_source():
            device, inventory = discover_source_device()
            observed_devices[:] = inventory
            return device, inventory

        try:
            source_device, block_devices = wait_for_source_device(scan=scan_source)
        except ValueError:
            if observed_devices:
                record["block_devices"] = observed_devices
            raise
        record["block_devices"] = block_devices
        identity = validate_source_identity(
            run(["/usr/sbin/blkid", "-p", "-o", "export", str(source_device)]),
            source_expected)
        mountpoint = SOURCE.parent.lstat()
        if (not stat.S_ISDIR(mountpoint.st_mode) or stat.S_IMODE(mountpoint.st_mode) != 0o700
                or mountpoint.st_uid != 0 or mountpoint.st_gid != 0
                or mountpoint.st_nlink != 2 or os.path.ismount(SOURCE.parent)):
            raise ValueError("update runtime mount point controls changed")
        with os.scandir(SOURCE.parent) as entries:
            if next(entries, None) is not None:
                raise ValueError("update runtime mount point is not empty")
        run(["/usr/bin/mount", "-t", "ext4", "-o", "ro,nosuid,nodev,noexec",
             str(source_device), str(SOURCE.parent)])
        if not os.statvfs(SOURCE).f_flag & os.ST_RDONLY:
            raise ValueError("update source is writable")
        observation = observe_visible_source_mount()
        record["source_mount_observation"] = observation
        device_number = validate_mounted_device(source_device, SOURCE.parent)
        validate_source_mount(observation, source_device, device_number)
        record["source_device"] = {"path": str(source_device),
                                   "serial": SOURCE_SERIAL, **identity}
        manifest = SOURCE / "manifest.json"
        signature = SOURCE / "signature-1"
        for path in (manifest, signature):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("update source contains a linked or special control file")
        if (sha256(manifest) != new.removeprefix("sha256:")
                or sha256(signature) != expected["signature_sha256"]
                or sha256(policy_path) != expected["policy_sha256"]
                or sha256(Path("/etc/containers/policy.json")) != expected["original_policy_sha256"]):
            raise ValueError("authenticated update input changed")
        raw_status = lambda: fixed_bootc_status(run, record["status_observations"])
        positive = expected.get("same_path_positive_control")
        negative = expected.get("negative_control")
        if positive is not None or negative is not None:
            if positive is not None and negative is not None:
                raise ValueError("conflicting disposable update controls")
            is_positive = positive is not None
            control = positive if is_positive else negative
            if (not isinstance(control, dict) or STATE.exists()
                    or control.get("source") != str(NEGATIVE_SOURCE)
                    or (is_positive and (set(control) != {"case", "source"}
                                         or control.get("case") != POSITIVE_OVERLAY_CASE))
                    or (not is_positive
                        and (set(control) != {"case", "source", "signature"}
                             or control.get("case") not in NEGATIVE_CASES))):
                raise ValueError("invalid or persistent disposable update control")
            case = control["case"]
            before = deployment_snapshot(raw_status(), old)
            before_hash = hashlib.sha256(json.dumps(
                before, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            root = NEGATIVE_SOURCE.parent
            if root.exists() or root.is_symlink():
                raise ValueError("negative update overlay already exists")
            for path in (root / "upper", root / "work", NEGATIVE_SOURCE):
                path.mkdir(mode=0o700, parents=True, exist_ok=False)
            run(["/usr/bin/mount", "-t", "overlay", "overlay", "-o",
                 "lowerdir=" + str(SOURCE) + ",upperdir=" + str(root / "upper")
                 + ",workdir=" + str(root / "work") + ",nosuid,nodev,noexec",
                 str(NEGATIVE_SOURCE)])
            overlay_signature = NEGATIVE_SOURCE / "signature-1"
            signature_control = None
            if not is_positive:
                overlay_signature.unlink()
                signature_control = negative["signature"]
                if case == "unsigned":
                    if signature_control is not None:
                        raise ValueError("unsigned control unexpectedly supplies a signature")
                else:
                    if (not isinstance(signature_control, dict)
                            or set(signature_control) != {"base64", "sha256"}
                            or not re.fullmatch(r"[a-f0-9]{64}", signature_control.get("sha256", ""))):
                        raise ValueError("invalid negative source signature control")
                    try:
                        payload = base64.b64decode(signature_control["base64"], validate=True)
                    except (binascii.Error, ValueError, TypeError) as error:
                        raise ValueError("invalid negative source signature encoding") from error
                    if (not 0 < len(payload) <= 65536
                            or hashlib.sha256(payload).hexdigest() != signature_control["sha256"]
                            or signature_control["sha256"] == expected["signature_sha256"]):
                        raise ValueError("negative source signature identity changed")
                    descriptor = os.open(overlay_signature, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
                    try:
                        remaining = memoryview(payload)
                        while remaining:
                            written = os.write(descriptor, remaining)
                            if written <= 0:
                                raise OSError("short negative signature write")
                            remaining = remaining[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            run(["/usr/bin/mount", "-o", "remount,ro,nosuid,nodev,noexec",
                 str(NEGATIVE_SOURCE)])
            if (not os.statvfs(NEGATIVE_SOURCE).f_flag & os.ST_RDONLY
                    or sha256(NEGATIVE_SOURCE / "manifest.json") != new.removeprefix("sha256:")):
                raise ValueError("negative update source is writable or changed its manifest")
            if is_positive:
                if sha256(overlay_signature) != expected["signature_sha256"]:
                    raise ValueError("valid overlay signature changed after remount")
            elif case == "unsigned":
                if overlay_signature.exists() or overlay_signature.is_symlink():
                    raise ValueError("unsigned update source retained a signature")
            elif sha256(overlay_signature) != signature_control["sha256"]:
                raise ValueError("negative update signature changed after overlay remount")
            run(["/usr/bin/mount", "--bind", str(policy_path), "/etc/containers/policy.json"])
            run(["/usr/bin/mount", "-o", "remount,bind,ro", "/etc/containers/policy.json"])
            if sha256(Path("/etc/containers/policy.json")) != expected["policy_sha256"]:
                raise ValueError("guest update policy bind changed")
            operation = fixed_bootc_operation(
                run, record, "negative", expected_success=is_positive,
                timeout=UPDATE_COMMAND_TIMEOUT_SECONDS)
            switch_exit = operation["exit_code"]
            if is_positive:
                after = staged_deployment_snapshot(raw_status(), old, new)
                after_hash = hashlib.sha256(json.dumps(
                    after, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if (switch_exit != 0 or before_hash == after_hash or before == after
                        or before["booted"] != after["booted"]
                        or before["default"] == after["default"]
                        or before["staged"] is not None or after["staged"] is None):
                    raise ValueError("valid overlay switch did not stage only the signed update")
                record["same_path_positive_control"] = {
                    "case": case, "switch_accepted": True, "switch_exit_code": switch_exit,
                    "booted_unchanged": True, "deployment_staged": True,
                    "default_changed": True, "staged_digest": new,
                    "state_before_sha256": before_hash, "state_after_sha256": after_hash,
                    "source": str(NEGATIVE_SOURCE), "source_readonly": True,
                }
            else:
                after = deployment_snapshot(raw_status(), old)
                after_hash = hashlib.sha256(json.dumps(
                    after, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if switch_exit == 0 or before != after or before_hash != after_hash:
                    raise ValueError("rejected update changed the bootc default or deployments")
                record["negative_control"] = {
                    "case": case, "switch_rejected": True, "switch_exit_code": switch_exit,
                    "deployment_unchanged": True, "default_unchanged": True,
                    "state_sha256": before_hash, "source": str(NEGATIVE_SOURCE),
                    "source_readonly": True,
                }
            record["source_mounted_readonly"] = True
            record["passed"] = True
            state = None
        else:
            state = STATE.read_text().strip() if STATE.exists() else "installed"
        if state == "installed":
            phase_status(raw_status(), old)
            run(["/usr/bin/mount", "--bind", str(policy_path), "/etc/containers/policy.json"])
            run(["/usr/bin/mount", "-o", "remount,bind,ro", "/etc/containers/policy.json"])
            if sha256(Path("/etc/containers/policy.json")) != expected["policy_sha256"]:
                raise ValueError("guest update policy bind changed")
            fixed_bootc_operation(
                run, record, "positive", expected_success=True,
                timeout=UPDATE_COMMAND_TIMEOUT_SECONDS)
            phase_status(raw_status(), old, staged=new)
            write_state("updated")
            record["phase"] = {"name": "installed", "booted_digest": old,
                               "operation": "signed-update-staged", "staged_digest": new}
        elif state == "updated":
            phase_status(raw_status(), new, rollback=old)
            fixed_bootc_operation(
                run, record, "rollback", expected_success=True, timeout=300)
            phase_status(raw_status(), new, rollback=old, rollback_queued=True)
            write_state("rolled-back")
            record["phase"] = {"name": "updated", "booted_digest": new,
                               "operation": "rollback-queued", "rollback_digest": old}
        elif state == "rolled-back":
            phase_status(raw_status(), old, rollback=new)
            record["phase"] = {"name": "rolled-back", "booted_digest": old,
                               "rollback_from_digest": new}
        elif state is not None:
            raise ValueError("unknown persistent update phase")
        if state is not None:
            record["source_mounted_readonly"] = True
            record["passed"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    if len(raw) > 128 * 1024:
        raise ValueError("update guest report exceeds its bound")
    write_channel(raw)
    if not record["passed"]:
        raise RuntimeError("update guest phase failed")


if __name__ == "__main__":
    main()
