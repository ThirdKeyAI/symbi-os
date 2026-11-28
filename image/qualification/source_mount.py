#!/usr/bin/env python3
"""Verify one main-namespace qualification mount through a fixed block identity."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

if __package__:
    from .symbi_mountinfo import (canonical_major_minor, observe_visible_mount,
                                  validate_mount_observation)
else:
    from symbi_mountinfo import (canonical_major_minor, observe_visible_mount,
                                 validate_mount_observation)


RUNTIME = Path("/run/symbi-qualification")
SOURCE = RUNTIME / "source"
SOURCE_DEVICE = Path("/dev/disk/by-id/virtio-SYMBIQUAL")
SOURCE_RECORD = RUNTIME / "source-device.json"
UDEV_RULE = Path("/usr/lib/udev/rules.d/61-symbi-qualification-source.rules")
SOURCE_SERIAL = "SYMBIQUAL"
ROOT_SERIAL = "SYMBIROOT"
EXPECTED_UDEV_RULE = (
    'ACTION=="add|change", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", '
    'ATTRS{serial}=="SYMBIQUAL", DRIVERS=="virtio_blk", '
    'SYMLINK+="disk/by-id/virtio-SYMBIQUAL"\n')
MAX_BLOCK_DEVICES = 64


def validate_udev_rule(raw):
    """Accept only the image-owned exact source-serial rule."""
    if raw != EXPECTED_UDEV_RULE:
        raise ValueError("qualification source-device udev rule differs")
    return raw


def validate_installed_udev_rule(path=UDEV_RULE):
    """Require one root-owned regular rule with the reviewed exact bytes."""
    path = Path(path)
    descriptor = None
    try:
        if not getattr(os, "O_NOFOLLOW", 0):
            raise ValueError("kernel no-follow open is unavailable")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        chunks = []
        total = 0
        while total <= 1024:
            chunk = os.read(descriptor, min(256, 1025 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > 1024:
            raise ValueError("qualification source-device udev rule is oversized")
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as error:
        raise ValueError("qualification source-device udev rule is absent") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns)
    if (identity(before) != identity(after) or not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0 or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o644 or before.st_size != len(raw)):
        raise ValueError("qualification source-device udev rule is unsafe")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("qualification source-device udev rule is non-ASCII") from error
    return validate_udev_rule(text)


def _bounded_sysfs_text(path, maximum=128):
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    if (not raw or len(raw) > maximum or b"\0" in raw or b"\r" in raw
            or raw.count(b"\n") > 1 or (b"\n" in raw and not raw.endswith(b"\n"))):
        raise ValueError("invalid qualification block sysfs value")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII qualification block sysfs value") from error
    if not value:
        raise ValueError("empty qualification block sysfs value")
    return value


def _sysfs_link_name(path):
    path = Path(path)
    try:
        if not path.is_symlink():
            return None
        return path.resolve(strict=True).name
    except OSError:
        return None


def observe_block_inventory(sys_block=Path("/sys/class/block"), dev_root=Path("/dev")):
    """Observe bounded whole-disk identities without selecting by kernel order."""
    sys_block = Path(sys_block)
    dev_root = Path(dev_root)
    entries = sorted(sys_block.iterdir(), key=lambda item: item.name)
    if (not entries or len(entries) > MAX_BLOCK_DEVICES
            or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.!-]{0,127}", item.name) is None
                   for item in entries)):
        raise ValueError("invalid qualification block-device inventory")
    rows = []
    for entry in entries:
        # virtio_blk exposes the disk serial on the device bound to the
        # virtio_blk driver, which is the block event device's parent.
        serial = _bounded_sysfs_text(entry / "device/serial")
        if serial is None:
            continue
        major_minor = _bounded_sysfs_text(entry / "dev", 32)
        read_only = _bounded_sysfs_text(entry / "ro", 2)
        node = dev_root / entry.name
        try:
            node_info = node.lstat()
        except OSError:
            node_info = None
        node_block = node_info is not None and stat.S_ISBLK(node_info.st_mode)
        node_major_minor = (f"{os.major(node_info.st_rdev)}:{os.minor(node_info.st_rdev)}"
                            if node_block else None)
        rows.append({
            "name": entry.name,
            "path": str(node),
            "serial": serial,
            "major_minor": major_minor,
            "node_major_minor": node_major_minor,
            "read_only": {"0": False, "1": True}.get(read_only),
            "whole_disk": not (entry / "partition").exists(),
            "subsystem": _sysfs_link_name(entry / "device/subsystem"),
            "driver": _sysfs_link_name(entry / "device/driver"),
            "node_block": node_block,
            "node_uid": node_info.st_uid if node_info is not None else None,
            "node_nlink": node_info.st_nlink if node_info is not None else None,
        })
    return rows


def observe_source_link(path=SOURCE_DEVICE):
    """Capture one direct root-owned udev symlink without accepting aliases."""
    path = Path(path)
    try:
        before = path.lstat()
        target = os.readlink(path)
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError as error:
        raise ValueError("fixed qualification source block-device link is absent") from error
    identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                             info.st_nlink, stat.S_IFMT(info.st_mode), info.st_ctime_ns)
    if identity(before) != identity(after):
        raise ValueError("fixed qualification source block-device link changed")
    return {
        "is_symlink": stat.S_ISLNK(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "nlink": before.st_nlink,
        "target": target,
        "resolved": str(resolved),
    }


def validate_block_identity(inventory, link):
    """Bind the exact source serial and udev link to a distinct virtio disk."""
    row_keys = {"name", "path", "serial", "major_minor", "node_major_minor",
                "read_only", "whole_disk", "subsystem", "driver", "node_block",
                "node_uid", "node_nlink"}
    link_keys = {"is_symlink", "uid", "gid", "nlink", "target", "resolved"}
    if (not isinstance(inventory, list) or not 1 <= len(inventory) <= MAX_BLOCK_DEVICES
            or not isinstance(link, dict) or set(link) != link_keys):
        raise ValueError("invalid qualification block identity evidence")
    for row in inventory:
        if (not isinstance(row, dict) or set(row) != row_keys
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.!-]{0,127}",
                                row.get("name", "")) is None
                or row.get("path") != "/dev/" + row["name"]
                or not isinstance(row.get("serial"), str)
                or re.fullmatch(r"[\x21-\x7e]{1,128}", row["serial"]) is None
                or not canonical_major_minor(row.get("major_minor"))
                or (row.get("node_major_minor") is not None
                    and not canonical_major_minor(row["node_major_minor"]))
                or type(row.get("read_only")) not in (bool, type(None))
                or type(row.get("whole_disk")) is not bool
                or type(row.get("node_block")) is not bool
                or type(row.get("node_uid")) not in (int, type(None))
                or type(row.get("node_nlink")) not in (int, type(None))
                or row.get("subsystem") not in (None, "virtio")
                or row.get("driver") not in (None, "virtio_blk")):
            raise ValueError("invalid qualification block inventory row")
    if (len({row["name"] for row in inventory}) != len(inventory)
            or len({row["path"] for row in inventory}) != len(inventory)
            or len({row["major_minor"] for row in inventory}) != len(inventory)):
        raise ValueError("ambiguous qualification block inventory")
    sources = [row for row in inventory if row["serial"] == SOURCE_SERIAL]
    roots = [row for row in inventory if row["serial"] == ROOT_SERIAL]
    if len(sources) != 1 or len(roots) != 1:
        raise ValueError("qualification source or root serial is absent or ambiguous")
    source = sources[0]
    root = roots[0]
    valid_disk = lambda row: (
        row["whole_disk"] is True and row["subsystem"] == "virtio"
        and row["driver"] == "virtio_blk" and row["node_block"] is True
        and row["node_uid"] == 0 and row["node_nlink"] == 1
        and row["node_major_minor"] == row["major_minor"])
    if (not valid_disk(source) or not valid_disk(root)
            or source["read_only"] is not True or root["read_only"] is not False
            or source["path"] == root["path"]
            or source["major_minor"] == root["major_minor"]):
        raise ValueError("qualification source is not one distinct read-only virtio disk")
    if (link.get("is_symlink") is not True or link.get("uid") != 0
            or link.get("gid") != 0 or link.get("nlink") != 1
            or link.get("target") != "../../" + source["name"]
            or link.get("resolved") != source["path"]):
        raise ValueError("qualification source udev link does not bind the source serial")
    return {
        "link": str(SOURCE_DEVICE),
        "link_target": link["target"],
        "path": source["path"],
        "sysfs_name": source["name"],
        "serial": source["serial"],
        "major_minor": source["major_minor"],
        "read_only": source["read_only"],
        "transport_subsystem": source["subsystem"],
        "transport_driver": source["driver"],
        "root_path": root["path"],
        "root_sysfs_name": root["name"],
        "root_serial": root["serial"],
        "root_major_minor": root["major_minor"],
        "root_read_only": root["read_only"],
        "root_transport_subsystem": root["subsystem"],
        "root_transport_driver": root["driver"],
    }


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate qualification expectation key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("qualification expectation must be an object")
    return result


def validate_source_identity(raw, expected):
    """Require the generated filesystem's exact type, label and UUID."""
    if (not isinstance(raw, str) or not isinstance(expected, dict)
            or expected.get("filesystem") != "ext4"
            or expected.get("label") != "SYMBIQUAL"
            or re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                            expected.get("uuid", "")) is None):
        raise ValueError("invalid expected qualification filesystem identity")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 32:
        raise ValueError("invalid qualification filesystem identity output")
    fields = {}
    for line in lines:
        if "=" not in line:
            raise ValueError("malformed qualification filesystem identity output")
        key, value = line.split("=", 1)
        if (re.fullmatch(r"[A-Z0-9_]+", key) is None or not value
                or key in fields or len(key) > 64 or len(value) > 4096):
            raise ValueError("ambiguous qualification filesystem identity output")
        fields[key] = value
    selected = {name: fields.get(name) for name in ("TYPE", "LABEL", "UUID")}
    required = {"TYPE": expected["filesystem"], "LABEL": expected["label"],
                "UUID": expected["uuid"]}
    if selected != required:
        raise ValueError("qualification filesystem identity differs")
    return selected


def run(command, *, timeout, check=True):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=timeout,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if len(result.stdout.encode()) > 32 * 1024 or len(result.stderr.encode()) > 32 * 1024:
        raise ValueError("qualification mount command output exceeded its bound")
    if check:
        result.check_returncode()
    return result


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 2 or Path("/run/.containerenv").exists()
            or Path("/sys/class/dmi/id/product_name").read_text().strip()
            != "Symbi-Hosted-Landlock-Probe"):
        raise SystemExit("Use only the disposable hosted qualification mount service")
    expected_path = Path(sys.argv[1])
    raw = expected_path.read_bytes()
    if len(raw) > 128 * 1024:
        raise ValueError("oversized qualification expectation")
    expected = unique_json(raw)
    source_expected = expected.get("source_disk")
    if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
        raise ValueError("qualification mount service gained a network interface")
    validate_installed_udev_rule()
    settled = run(["/usr/bin/udevadm", "settle", "--timeout=30",
                   "--exit-if-exists=" + str(SOURCE_DEVICE)], timeout=40, check=False)
    if settled.returncode != 0:
        block_devices = sorted(path.name for path in Path("/sys/class/block").iterdir())
        raise ValueError("fixed qualification source block-device link is absent; observed "
                         + ",".join(block_devices[:MAX_BLOCK_DEVICES]))
    block_identity = validate_block_identity(
        observe_block_inventory(), observe_source_link())
    identity = validate_source_identity(
        run(["/usr/sbin/blkid", "-p", "-o", "export", block_identity["path"]],
            timeout=30).stdout,
        source_expected)
    runtime = RUNTIME.lstat()
    if (not stat.S_ISDIR(runtime.st_mode) or runtime.st_uid != 0 or runtime.st_gid != 0
            or stat.S_IMODE(runtime.st_mode) != 0o755):
        raise ValueError("qualification runtime directory controls changed")
    if SOURCE_RECORD.exists() or SOURCE_RECORD.is_symlink():
        raise ValueError("qualification source-device record must be new")
    mountpoint = SOURCE.lstat()
    if (not stat.S_ISDIR(mountpoint.st_mode) or mountpoint.st_uid != 0
            or mountpoint.st_gid != 0 or mountpoint.st_mode & 0o022
            or not os.path.ismount(SOURCE)):
        raise ValueError("qualification source mount point controls changed")
    observation = observe_visible_mount(SOURCE)
    print(json.dumps({"source_mount_observation": observation}, sort_keys=True), flush=True)
    validate_mount_observation(observation, mountpoint=str(SOURCE),
                               source=block_identity["path"],
                               major_minor=block_identity["major_minor"])
    if (f"{os.major(mountpoint.st_dev)}:{os.minor(mountpoint.st_dev)}"
            != block_identity["major_minor"]):
        raise ValueError("qualification source mount device changed")
    flags = os.statvfs(SOURCE).f_flag
    required_flags = os.ST_RDONLY | os.ST_NOSUID
    for name in ("ST_NODEV", "ST_NOEXEC"):
        required_flags |= getattr(os, name, 0)
    if flags & required_flags != required_flags:
        raise ValueError("qualification source mount controls changed")
    record = {**block_identity, **identity}
    temporary = RUNTIME / "source-device.new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, SOURCE_RECORD)
    directory = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


if __name__ == "__main__":
    main()
