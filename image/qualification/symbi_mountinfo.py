#!/usr/bin/env python3
"""Bounded selection of the kernel mountinfo entry visible at a fixed path."""
import hashlib
import os
from pathlib import Path
import re
import stat


MAX_MOUNTINFO_BYTES = 1024 * 1024
MAX_MOUNTINFO_LINES = 4096
MAX_MOUNTINFO_LINE_BYTES = 8192
MOUNTINFO = Path("/proc/self/mountinfo")
FDINFO = Path("/proc/self/fdinfo")
MAX_FDINFO_BYTES = 4096
MAX_FDINFO_LINES = 64
MAX_FDINFO_LINE_BYTES = 512
_ESCAPES = {
    b"040": b" ",
    b"011": b"\t",
    b"012": b"\n",
    b"134": b"\\",
}


def read_mountinfo(path=MOUNTINFO):
    """Read one bounded mountinfo snapshot without accepting truncation."""
    if Path(path) != MOUNTINFO or not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("fixed no-follow mountinfo path required")
    descriptor = os.open(MOUNTINFO, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks = []
        total = 0
        while total <= MAX_MOUNTINFO_BYTES:
            chunk = os.read(
                descriptor, min(65536, MAX_MOUNTINFO_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if not raw or len(raw) > MAX_MOUNTINFO_BYTES:
        raise ValueError("kernel mountinfo is empty or exceeded its bound")
    return raw


def _decode_field(value):
    if not isinstance(value, bytes) or not value or b"\0" in value:
        raise ValueError("invalid kernel mountinfo field")
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] != 0x5C:
            decoded.append(value[index])
            index += 1
            continue
        escape = value[index + 1:index + 4]
        if len(escape) != 3 or escape not in _ESCAPES:
            raise ValueError("invalid kernel mountinfo escape")
        decoded.extend(_ESCAPES[escape])
        index += 4
    return bytes(decoded)


def _ascii_field(value, name):
    try:
        return _decode_field(value).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII kernel mountinfo " + name) from error


def _options(value, name):
    text = _ascii_field(value, name)
    options = text.split(",")
    if (not options or any(not item or re.fullmatch(r"[A-Za-z0-9_.:=+-]{1,256}", item) is None
                           for item in options)
            or len(set(options)) != len(options)):
        raise ValueError("invalid kernel mountinfo " + name)
    return sorted(options)


def canonical_major_minor(value):
    """Return whether one device number uses the shared bounded spelling."""
    return (isinstance(value, str)
            and re.fullmatch(r"(?:0|[1-9][0-9]{0,6}):(?:0|[1-9][0-9]{0,6})",
                             value) is not None)


def observe_mountinfo(raw, mountpoint, visible_mount_id):
    """Select the mountinfo row named by an opened directory's mount ID."""
    if not isinstance(mountpoint, str) or not mountpoint.startswith("/"):
        raise ValueError("invalid expected mount point")
    if type(visible_mount_id) is not int or not 1 <= visible_mount_id <= 9999999999:
        raise ValueError("invalid visible mount ID")
    try:
        target = mountpoint.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("non-ASCII expected mount point") from error
    if not 1 <= len(target) <= 4096:
        raise ValueError("invalid expected mount point")
    if isinstance(raw, str):
        try:
            raw = raw.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("non-ASCII kernel mountinfo input") from error
    if (not isinstance(raw, bytes) or not raw or len(raw) > MAX_MOUNTINFO_BYTES
            or not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw):
        raise ValueError("kernel mountinfo is empty, unsafe or exceeded its bound")
    lines = raw[:-1].split(b"\n")
    if not 1 <= len(lines) <= MAX_MOUNTINFO_LINES:
        raise ValueError("kernel mountinfo line count exceeded its bound")
    matches = []
    for line in lines:
        if not line or len(line) > MAX_MOUNTINFO_LINE_BYTES:
            raise ValueError("invalid kernel mountinfo line")
        fields = line.split(b" ")
        if not 10 <= len(fields) <= 128 or any(not field for field in fields):
            raise ValueError("malformed kernel mountinfo line")
        decoded_mountpoint = _decode_field(fields[4])
        if decoded_mountpoint != target:
            continue
        mount_id = _ascii_field(fields[0], "mount ID")
        if re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", mount_id) is None:
            raise ValueError("invalid kernel mountinfo mount ID")
        separators = [index for index in range(6, len(fields)) if fields[index] == b"-"]
        if len(separators) != 1:
            raise ValueError("ambiguous kernel mountinfo separator")
        separator = separators[0]
        if separator < 6 or len(fields) != separator + 4:
            raise ValueError("incomplete kernel mountinfo entry")
        parent_id = _ascii_field(fields[1], "parent ID")
        if (re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", parent_id) is None
                or any(re.fullmatch(rb"[A-Za-z0-9_.:=+-]{1,256}", field) is None
                       for field in fields[6:separator])):
            raise ValueError("invalid kernel mountinfo identity")
        major_minor = _ascii_field(fields[2], "device number")
        if not canonical_major_minor(major_minor):
            raise ValueError("invalid kernel mountinfo device number")
        matches.append({
            "mount_id": int(mount_id),
            "mountpoint": decoded_mountpoint.decode("ascii"),
            "root": _ascii_field(fields[3], "root"),
            "fstype": _ascii_field(fields[separator + 1], "filesystem"),
            "source": _ascii_field(fields[separator + 2], "source"),
            "major_minor": major_minor,
            "options": _options(fields[5], "mount options"),
            "super_options": _options(fields[separator + 3], "superblock options"),
        })
    selected = [entry for entry in matches if entry["mount_id"] == visible_mount_id]
    observation = {
        "mountinfo_sha256": hashlib.sha256(raw).hexdigest(),
        "path_match_count": len(matches),
        "selected_match_count": len(selected),
        "visible_mount_id": visible_mount_id,
        "selected_mount_id": visible_mount_id if selected else None,
    }
    if len(selected) == 1:
        entry = dict(selected[0])
        observation["selected_mount_id"] = entry.pop("mount_id")
        observation.update(entry)
    return observation


def parse_visible_mount_id(raw):
    """Parse one canonical mnt_id from a bounded procfs fdinfo record."""
    if (not isinstance(raw, bytes) or not raw or len(raw) > MAX_FDINFO_BYTES
            or not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw):
        raise ValueError("invalid or oversized fdinfo")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII fdinfo") from error
    lines = text[:-1].split("\n")
    if not 1 <= len(lines) <= MAX_FDINFO_LINES:
        raise ValueError("invalid fdinfo line count")
    mount_ids = []
    for line in lines:
        if (not line or len(line.encode("ascii")) > MAX_FDINFO_LINE_BYTES
                or ":" not in line):
            raise ValueError("malformed fdinfo line")
        key, value = line.split(":", 1)
        if (re.fullmatch(r"[a-z_]{1,64}", key) is None
                or not value or len(value) > 4096):
            raise ValueError("invalid fdinfo field")
        if key == "mnt_id":
            match = re.fullmatch(r"[\t ]+(?:0|[1-9][0-9]{0,9})", value)
            if match is None:
                raise ValueError("invalid fdinfo mount ID")
            mount_ids.append(int(value.strip()))
    if len(mount_ids) != 1 or mount_ids[0] < 1:
        raise ValueError("ambiguous fdinfo mount ID")
    return mount_ids[0]


def read_visible_mount_id(descriptor):
    """Read bounded fdinfo for one still-open directory descriptor."""
    if type(descriptor) is not int or descriptor < 0:
        raise ValueError("invalid visible mount descriptor")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("kernel no-follow open is unavailable")
    fdinfo = os.open(FDINFO / str(descriptor), flags | os.O_NOFOLLOW)
    try:
        chunks = []
        total = 0
        while total <= MAX_FDINFO_BYTES:
            chunk = os.read(fdinfo, min(4096, MAX_FDINFO_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fdinfo)
    if total > MAX_FDINFO_BYTES:
        raise ValueError("oversized fdinfo")
    return parse_visible_mount_id(b"".join(chunks))


def observe_visible_mount(mountpoint, *, opener=None, descriptor_stat=None,
                          path_lstat=None, closer=None, fdinfo_reader=None,
                          mountinfo_reader=None):
    """Open one fixed path and select the mount row visible through that fd."""
    mountpoint = Path(mountpoint)
    if not mountpoint.is_absolute():
        raise ValueError("absolute visible mountpoint required")
    opener = os.open if opener is None else opener
    descriptor_stat = os.fstat if descriptor_stat is None else descriptor_stat
    path_lstat = os.lstat if path_lstat is None else path_lstat
    closer = os.close if closer is None else closer
    fdinfo_reader = read_visible_mount_id if fdinfo_reader is None else fdinfo_reader
    mountinfo_reader = read_mountinfo if mountinfo_reader is None else mountinfo_reader
    if not getattr(os, "O_PATH", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("kernel path-only no-follow open is unavailable")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = opener(mountpoint, flags)
    try:
        opened = descriptor_stat(descriptor)
        before = path_lstat(mountpoint)
        identity = lambda info: (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        if (not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(before.st_mode)
                or identity(opened) != identity(before)):
            raise ValueError("visible mount path differs from its descriptor")
        visible_mount_id = fdinfo_reader(descriptor)
        observation = observe_mountinfo(
            mountinfo_reader(), str(mountpoint), visible_mount_id)
        after = path_lstat(mountpoint)
        if not stat.S_ISDIR(after.st_mode) or identity(after) != identity(opened):
            raise ValueError("visible mount path changed during observation")
        return observation
    finally:
        closer(descriptor)


def validate_mount_observation(observed, *, mountpoint, source, major_minor):
    """Bind an observation to the exact read-only source mount."""
    required = {"mountpoint", "root", "fstype", "source", "major_minor",
                "options", "super_options", "mountinfo_sha256",
                "path_match_count", "selected_match_count", "visible_mount_id",
                "selected_mount_id"}
    options = observed.get("options") if isinstance(observed, dict) else None
    super_options = (observed.get("super_options")
                     if isinstance(observed, dict) else None)
    valid_options = lambda values: (
        isinstance(values, list) and 1 <= len(values) <= 128
        and all(isinstance(item, str)
                and re.fullmatch(r"[A-Za-z0-9_.:=+-]{1,256}", item) is not None
                for item in values)
        and len(values) == len(set(values)) and values == sorted(values))
    if (not isinstance(observed, dict) or set(observed) != required
            or type(observed.get("path_match_count")) is not int
            or not 1 <= observed.get("path_match_count") <= MAX_MOUNTINFO_LINES
            or type(observed.get("selected_match_count")) is not int
            or observed.get("selected_match_count") != 1
            or type(observed.get("visible_mount_id")) is not int
            or not 1 <= observed.get("visible_mount_id") <= 9999999999
            or type(observed.get("selected_mount_id")) is not int
            or observed.get("visible_mount_id") != observed.get("selected_mount_id")
            or observed.get("mountpoint") != mountpoint
            or observed.get("root") != "/"
            or observed.get("fstype") != "ext4"
            or observed.get("source") != source
            or observed.get("major_minor") != major_minor
            or not canonical_major_minor(observed.get("major_minor"))
            or not canonical_major_minor(major_minor)
            or not valid_options(options) or "rw" in options
            or not {"ro", "nosuid", "nodev", "noexec"}.issubset(options)
            or not valid_options(super_options)
            or not isinstance(observed.get("mountinfo_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", observed["mountinfo_sha256"]) is None):
        raise ValueError("qualification source mount controls changed")
    return observed
