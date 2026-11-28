#!/usr/bin/python3
"""Emit one bounded, diagnostic-only view of the hosted source disk.

This helper never selects a block device, creates a link, mounts a filesystem,
or changes qualification state.  Its single JSON line is retained through the
existing serial-console evidence path when the fixed udev link is absent.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


PREFIX = "SYMBI_SOURCE_DIAGNOSTIC="
PRODUCT = "Symbi-Hosted-Landlock-Probe"
SOURCE_LINK = Path("/dev/disk/by-id/virtio-SYMBIQUAL")
RULE = Path("/usr/lib/udev/rules.d/61-symbi-qualification-source.rules")
EXPECTED_RULE = (
    'ACTION=="add|change", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", '
    'ATTRS{serial}=="SYMBIQUAL", DRIVERS=="virtio_blk", '
    'SYMLINK+="disk/by-id/virtio-SYMBIQUAL"\n'
).encode("ascii")
MAX_BLOCK_ENTRIES = 64
MAX_WHOLE_DISKS = 8
MAX_SYSFS_BYTES = 4096
MAX_UDEV_BYTES = 16 * 1024
MAX_RECORD_BYTES = 32 * 1024
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.!-]{0,127}")
SAFE_KEY = re.compile(r"[A-Z0-9_]{1,128}")
MAJOR_MINOR = re.compile(r"(?:0|[1-9][0-9]{0,7}):(?:0|[1-9][0-9]{0,7})")


def _bounded_bytes(path, maximum, *, optional=False):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(maximum + 1)
    except FileNotFoundError:
        if optional:
            return None
        raise
    if len(raw) > maximum:
        raise ValueError("diagnostic input exceeded its bound")
    return raw


def _bounded_text(path, maximum=MAX_SYSFS_BYTES, *, optional=False):
    raw = _bounded_bytes(path, maximum, optional=optional)
    if raw is None:
        return None
    if b"\0" in raw or b"\r" in raw or raw.count(b"\n") > 1 \
            or (b"\n" in raw and not raw.endswith(b"\n")):
        raise ValueError("invalid diagnostic sysfs value")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    value = raw.decode("ascii")
    if not value or any(ord(character) < 0x20 or ord(character) > 0x7e
                        for character in value):
        raise ValueError("invalid diagnostic sysfs text")
    return value


def _link_name(path):
    path = Path(path)
    try:
        return path.resolve(strict=True).name if path.is_symlink() else None
    except OSError:
        return None


def _properties(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_UDEV_BYTES or b"\0" in raw:
        raise ValueError("invalid bounded udev properties")
    result = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if "=" not in line:
            raise ValueError("malformed udev property")
        key, value = line.split("=", 1)
        if (SAFE_KEY.fullmatch(key) is None or key in result or not value
                or len(value.encode()) > 4096
                or any(ord(character) < 0x20 and character != "\t"
                       for character in value)):
            raise ValueError("invalid udev property")
        result[key] = value
    if len(result) > 128:
        raise ValueError("too many udev properties")
    return {key: result[key] for key in sorted(result)}


def _udev_properties(sysfs_path, runner=subprocess.run):
    command = ["/usr/bin/udevadm", "info", "--query=property",
               "--path=" + str(sysfs_path)]
    completed = runner(
        command, stdin=subprocess.DEVNULL, capture_output=True, timeout=0.5,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    stdout = completed.stdout
    stderr = completed.stderr
    if (not isinstance(stdout, bytes) or not isinstance(stderr, bytes)
            or len(stdout) > MAX_UDEV_BYTES or len(stderr) > 4096):
        raise ValueError("udev diagnostic output exceeded its bound")
    return {
        "returncode": completed.returncode,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "properties": _properties(stdout) if completed.returncode == 0 else {},
    }


def _uevent(path):
    raw = _bounded_bytes(path, MAX_SYSFS_BYTES)
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "properties": _properties(raw),
    }


def observe_whole_disks(sys_block=Path("/sys/class/block"), runner=subprocess.run):
    """Record bounded whole-disk state without selecting a source device."""
    entries = sorted(Path(sys_block).iterdir(), key=lambda path: path.name)
    if (not entries or len(entries) > MAX_BLOCK_ENTRIES
            or any(SAFE_NAME.fullmatch(path.name) is None for path in entries)):
        raise ValueError("invalid diagnostic block inventory")
    disks = [entry for entry in entries if not (entry / "partition").exists()]
    if not 1 <= len(disks) <= MAX_WHOLE_DISKS:
        raise ValueError("invalid diagnostic whole-disk inventory")
    rows = []
    for entry in disks:
        major_minor = _bounded_text(entry / "dev", 32)
        read_only = _bounded_text(entry / "ro", 2)
        if MAJOR_MINOR.fullmatch(major_minor) is None or read_only not in ("0", "1"):
            raise ValueError("invalid diagnostic block identity")
        resolved = str(entry.resolve(strict=True))
        if (len(resolved.encode()) > 4096 or not resolved.startswith("/")
                or any(ord(character) < 0x20 for character in resolved)):
            raise ValueError("invalid diagnostic sysfs path")
        rows.append({
            "name": entry.name,
            "major_minor": major_minor,
            "read_only": read_only == "1",
            "sysfs_path": resolved,
            "event_serial": _bounded_text(entry / "serial", optional=True),
            "parent_serial": _bounded_text(entry / "device/serial", optional=True),
            "transport_subsystem": _link_name(entry / "device/subsystem"),
            "transport_driver": _link_name(entry / "device/driver"),
            "uevent": _uevent(entry / "uevent"),
            "udev": _udev_properties(entry, runner),
        })
    return rows


def observe_rule(path=RULE):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        return {
            "path": str(path), "exists": False, "regular": False,
            "root_owned": False, "mode": None, "bytes": None, "sha256": None,
            "expected_sha256": hashlib.sha256(EXPECTED_RULE).hexdigest(),
            "exact_match": False,
        }
    regular = stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw = _bounded_bytes(path, 1024) if regular else b""
    return {
        "path": str(path), "exists": True, "regular": regular,
        "root_owned": info.st_uid == 0 and info.st_gid == 0,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "expected_sha256": hashlib.sha256(EXPECTED_RULE).hexdigest(),
        "exact_match": (regular and info.st_uid == 0 and info.st_gid == 0
                        and stat.S_IMODE(info.st_mode) == 0o644
                        and raw == EXPECTED_RULE),
    }


def observe_link(path=SOURCE_LINK):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "is_symlink": False, "uid": None, "gid": None,
                "nlink": None, "target": None, "resolved": None}
    target = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
    try:
        resolved = str(path.resolve(strict=True)) if target is not None else None
    except OSError:
        resolved = None
    for value in (target, resolved):
        if value is not None and (len(value.encode()) > 4096
                                  or any(ord(character) < 0x20 for character in value)):
            raise ValueError("invalid diagnostic source link")
    return {"exists": True, "is_symlink": stat.S_ISLNK(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid, "nlink": info.st_nlink,
            "target": target, "resolved": resolved}


def settle(runner=subprocess.run, clock=time.monotonic):
    command = ["/usr/bin/udevadm", "settle", "--timeout=10",
               "--exit-if-exists=" + str(SOURCE_LINK)]
    started = clock()
    completed = runner(
        command, stdin=subprocess.DEVNULL, capture_output=True, timeout=12,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    elapsed_ms = int(max(0, clock() - started) * 1000)
    if (not isinstance(completed.stdout, bytes) or not isinstance(completed.stderr, bytes)
            or len(completed.stdout) > 4096 or len(completed.stderr) > 4096
            or elapsed_ms > 12_000):
        raise ValueError("invalid bounded udev settle result")
    return {
        "timeout_seconds": 10, "returncode": completed.returncode,
        "elapsed_ms": elapsed_ms,
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def diagnosis(disks, rule, before, after):
    """Classify observations only; never convert a candidate into a selector."""
    read_only = [row for row in disks if row["read_only"] is True]
    serial = [row for row in read_only if row["parent_serial"] == "SYMBIQUAL"]
    pair = [row for row in serial if row["transport_subsystem"] == "virtio"
            and row["transport_driver"] == "virtio_blk"]
    fixed_link = str(SOURCE_LINK)
    database_link = any(fixed_link in row["udev"]["properties"].get("DEVLINKS", "").split()
                        for row in read_only)
    return {
        "read_only_whole_disk_count": len(read_only),
        "source_serial_on_read_only_disk": bool(serial),
        "source_serial_driver_pair_count": len(pair),
        "source_serial_driver_match": bool(pair),
        "installed_rule_exact": rule["exact_match"] is True,
        "udev_database_has_fixed_link": database_link,
        "filesystem_link_before_settle": before["exists"] is True,
        "filesystem_link_after_settle": after["exists"] is True,
        "filesystem_link_appeared_during_settle": (
            before["exists"] is False and after["exists"] is True),
    }


def build_record(*, disks, rule, before, after, settled):
    return {
        "schema": 1, "purpose": "diagnostic-only", "qualified": False,
        "selector_applied": False, "product": PRODUCT,
        "source_link_path": str(SOURCE_LINK), "whole_disks": disks,
        "rule": rule, "link_before_settle": before,
        "link_after_settle": after, "settle": settled,
        "diagnosis": diagnosis(disks, rule, before, after),
    }


def emit(record):
    raw = (PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":"))
           + "\n").encode("utf-8")
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("source diagnostic record exceeded its bound")
    offset = 0
    while offset < len(raw):
        written = os.write(1, raw[offset:])
        if not written:
            raise RuntimeError("source diagnostic output stopped accepting bytes")
        offset += written


def main():
    try:
        product = _bounded_text("/sys/class/dmi/id/product_name", 128)
        if (os.geteuid() != 0 or Path("/run/.containerenv").exists()
                or product != PRODUCT):
            raise ValueError("source diagnostic is restricted to the hosted probe")
        rule = observe_rule()
        before = observe_link()
        settled = settle()
        disks = observe_whole_disks()
        after = observe_link()
        record = build_record(disks=disks, rule=rule, before=before, after=after,
                              settled=settled)
    except Exception as error:
        record = {
            "schema": 1, "purpose": "diagnostic-only", "qualified": False,
            "selector_applied": False, "product": PRODUCT,
            "diagnostic_error": (type(error).__name__ + ": " + str(error))[:512],
        }
    try:
        emit(record)
    except Exception as error:
        emit({
            "schema": 1, "purpose": "diagnostic-only", "qualified": False,
            "selector_applied": False, "product": PRODUCT,
            "diagnostic_error": (type(error).__name__ + ": " + str(error))[:512],
        })


if __name__ == "__main__":
    main()
