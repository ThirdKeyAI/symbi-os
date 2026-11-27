#!/usr/bin/env python3
"""Verify one main-namespace qualification mount through a fixed block identity."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


RUNTIME = Path("/run/symbi-qualification")
SOURCE = RUNTIME / "source"
SOURCE_DEVICE = Path("/dev/disk/by-id/virtio-SYMBIQUAL")
SOURCE_RECORD = RUNTIME / "source-device.json"


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
    settled = run(["/usr/bin/udevadm", "settle", "--timeout=30",
                   "--exit-if-exists=" + str(SOURCE_DEVICE)], timeout=40, check=False)
    block_devices = sorted(path.name for path in Path("/sys/class/block").iterdir())
    if (not block_devices or len(block_devices) > 64
            or any(re.fullmatch(r"[A-Za-z0-9_.!-]{1,128}", name) is None
                   for name in block_devices)):
        raise ValueError("invalid qualification block-device inventory")
    if settled.returncode != 0 or not SOURCE_DEVICE.is_symlink():
        raise ValueError("fixed qualification source block-device link is absent; observed "
                         + ",".join(block_devices))
    source_device = SOURCE_DEVICE.resolve(strict=True)
    if (re.fullmatch(r"/dev/vd[a-z]{1,3}", str(source_device)) is None
            or not stat.S_ISBLK(source_device.stat().st_mode)):
        raise ValueError("fixed qualification source is not a virtio block device")
    identity = validate_source_identity(
        run(["/usr/sbin/blkid", "-p", "-o", "export", str(SOURCE_DEVICE)],
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
    flags = os.statvfs(SOURCE).f_flag
    required_flags = os.ST_RDONLY | os.ST_NOSUID
    for name in ("ST_NODEV", "ST_NOEXEC"):
        required_flags |= getattr(os, name, 0)
    mounted = run(["/usr/bin/findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS",
                   "--target", str(SOURCE)], timeout=15).stdout.split()
    mounted_source = mounted[0].split("[", 1)[0] if mounted else ""
    if (flags & required_flags != required_flags or len(mounted) != 3
            or mounted_source != str(source_device) or mounted[1] != "ext4"
            or not {"ro", "nosuid", "nodev", "noexec"}.issubset(set(mounted[2].split(",")))):
        raise ValueError("qualification source mount controls changed")
    record = {"path": str(source_device), **identity}
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
