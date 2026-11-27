#!/usr/bin/env python3
"""Run the pinned Landlock driver as the disposable guest's unprivileged user."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import zlib


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 12 * 1024 * 1024
SOURCE_ROOT = Path("/run/symbi-qualification/source")
SOURCE_RECORD = Path("/run/symbi-qualification/source-device.json")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate guest input key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("guest input must be a JSON object")
    return result


def validate_source_device(expected):
    """Read the root-owned mount record and bind it to the expected disk."""
    info = SOURCE_RECORD.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o644
            or info.st_size > 16 * 1024):
        raise ValueError("unsafe qualification source-device record")
    observed = unique_json(SOURCE_RECORD.read_bytes())
    source = expected.get("source_disk")
    required = {"path", "TYPE", "LABEL", "UUID"}
    if (not isinstance(source, dict) or not isinstance(observed, dict)
            or set(observed) != required
            or re.fullmatch(r"/dev/vd[a-z]{1,3}", observed.get("path", "")) is None
            or observed.get("TYPE") != source.get("filesystem")
            or observed.get("LABEL") != source.get("label")
            or observed.get("UUID") != source.get("uuid")):
        raise ValueError("qualification source-device record differs")
    mounted = subprocess.run(
        ["/usr/bin/findmnt", "-n", "-o", "SOURCE,FSTYPE,OPTIONS",
         "--target", str(SOURCE_ROOT)], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    if (len(mounted.stdout.encode()) > 32 * 1024
            or len(mounted.stderr.encode()) > 32 * 1024):
        raise ValueError("qualification mount inspection exceeded its bound")
    mounted.check_returncode()
    fields = mounted.stdout.split()
    mounted_source = fields[0].split("[", 1)[0] if fields else ""
    if (len(fields) != 3 or mounted_source != observed["path"] or fields[1] != "ext4"
            or not {"ro", "nosuid", "nodev", "noexec"}.issubset(
                set(fields[2].split(",")))):
        raise ValueError("qualification source mount differs from its root record")
    return observed


def safe_public_path(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts)
            or "private-actions" in path.parts
            or any(part.lower().endswith((".pem", ".key", ".p12")) for part in path.parts)):
        raise ValueError("unsafe public qualification path")
    allowed = {"bootc-before.json", "bootc-after.json", "platform.json", "platform.log",
               "release-driver.log", "vertical-slice.json", "release"}
    if path.parts[0] not in allowed:
        raise ValueError("unexpected public qualification path")
    return path


def read_public_artifact(output, relative):
    root = output.lstat()
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid()
            or root.st_mode & 0o022):
        raise ValueError("unsafe public qualification root")
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, part in enumerate(relative.parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if index < len(relative.parts) - 1:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_mode & 0o022
                or not 0 <= before.st_size <= MAX_ARTIFACT_BYTES):
            raise ValueError("unsafe public qualification artifact")
        chunks = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, MAX_ARTIFACT_BYTES + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("public qualification artifact exceeded its bound")
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or total != before.st_size:
            raise ValueError("public qualification artifact changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def collect_public_artifacts(output, summary):
    reports = summary.get("public_reports")
    if not isinstance(reports, dict) or not reports:
        raise ValueError("qualification summary has no public report allowlist")
    result = {}
    total = 0
    for name, expected_hash in reports.items():
        relative = safe_public_path(name)
        raw = read_public_artifact(output, relative)
        total += len(raw)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise ValueError("total public qualification evidence exceeded its bound")
        observed = hashlib.sha256(raw).hexdigest()
        if observed != expected_hash:
            raise ValueError("public qualification artifact changed after validation")
        compressed = zlib.compress(raw, level=9)
        if len(compressed) > MAX_ARTIFACT_BYTES:
            raise ValueError("compressed public qualification artifact exceeded its bound")
        result[name] = {"bytes": len(raw), "sha256": observed,
                        "zlib_bytes": len(compressed),
                        "zlib_base64": base64.b64encode(compressed).decode()}
    return result


def write_channel(record):
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("guest qualification report exceeded its bound")
    channel = Path("/dev/virtio-ports/org.symbi.qualification")
    deadline = time.monotonic() + 15
    while not channel.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    with channel.open("wb", buffering=0) as stream:
        offset = 0
        while offset < len(raw):
            written = stream.write(raw[offset:])
            if not written:
                raise RuntimeError("guest report channel stopped accepting data")
            offset += written


def wait_status_socket(path):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            info = path.lstat()
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if (stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o666):
            return
        raise ValueError("fixed boot status socket has unsafe ownership or mode")
    raise TimeoutError("fixed boot status socket was not ready within 30 seconds")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("Expected the fixed driver, validator and expectation credentials")
    driver = Path(sys.argv[1])
    validator = Path(sys.argv[2])
    expected_path = Path(sys.argv[3])
    if (driver.name != "symbi-landlock.py" or validator.name != "vertical_slice.py"
            or driver.parent != validator.parent):
        raise ValueError("fixed sibling qualification driver and validator required")
    expected_raw = expected_path.read_bytes()
    if len(expected_raw) > 128 * 1024:
        raise ValueError("oversized guest expectation")
    expected = unique_json(expected_raw)
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    record = {"schema": 1, "passed": False, "qualified": False,
              "guest_booted": True, "os_qualified": False,
              "release_qualified": False, "product": product,
              "nonce": expected.get("nonce"), "expected_sha256": sha256(expected_path),
              "runner_sha256": sha256(Path(__file__)), "driver_sha256": sha256(driver),
              "validator_sha256": sha256(validator),
              "source_revision": expected.get("source_revision"),
              "source_manifest_sha256": expected.get("source_manifest_sha256"),
              "binary_sha256": expected.get("binary_sha256"),
              "image_ref": expected.get("image_ref")}
    output = Path("/var/lib/symbi-qualification/evidence/driver")
    try:
        process = {key: value.strip() for key, value in
                   (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
        if (os.geteuid() != 10001 or os.getegid() != 10001 or product != "Symbi-Hosted-Landlock-Probe"
                or Path("/run/.containerenv").exists() or platform.machine() != "x86_64"
                or process.get("CapEff") != "0000000000000000"
                or process.get("CapPrm") != "0000000000000000"
                or process.get("CapBnd") != "0000000000000000" or process.get("NoNewPrivs") != "1"):
            raise ValueError("unprivileged qualification guest identity changed")
        if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
            raise ValueError("qualification guest gained a network interface")
        source_root = SOURCE_ROOT
        flags = os.statvfs(source_root).f_flag
        required_flags = os.ST_RDONLY | os.ST_NOSUID
        for name in ("ST_NODEV", "ST_NOEXEC"):
            required_flags |= getattr(os, name, 0)
        if flags & required_flags != required_flags:
            raise ValueError("source disk mount lost read-only execution restrictions")
        record["source_device"] = validate_source_device(expected)
        source = source_root / "source"
        manifest_path = source_root / "manifest.json"
        if source.is_symlink() or manifest_path.is_symlink() or source.stat().st_uid != 10001:
            raise ValueError("source disk ownership or path changed")
        manifest = unique_json(manifest_path.read_bytes())
        if (sha256(manifest_path) != expected["source_manifest_sha256"]
                or manifest.get("source_revision") != expected["source_revision"]
                or manifest.get("cargo_lock_sha256") != sha256(source / "Cargo.lock")):
            raise ValueError("source disk manifest changed")
        binary = Path("/usr/bin/symbi")
        if binary.is_symlink() or not binary.is_file() or sha256(binary) != expected["binary_sha256"]:
            raise ValueError("installed runtime binary changed")
        manager = subprocess.run(["/usr/bin/systemctl", "--user", "is-active", "default.target"],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
        if manager.returncode != 0 or manager.stdout.strip() != "active":
            raise ValueError("delegated systemd user manager is unavailable")
        wait_status_socket(Path("/run/symbi-qualification/status.sock"))
        abi = ctypes.CDLL(None).syscall(444, 0, 0, 1)
        if abi < expected.get("minimum_landlock_abi", 6):
            raise ValueError("guest Landlock ABI is below the selected minimum")
        record["landlock_abi"] = abi
        command = ["/usr/bin/python3", "-E", "-s", "-B", str(driver),
                   "--source", str(source), "--binary", str(binary),
                   "--expected-revision", expected["source_revision"],
                   "--expected-binary-sha256", expected["binary_sha256"],
                   "--image-ref", expected["image_ref"], "--expected-abi", str(abi),
                   "--bootc-status-socket", "/run/symbi-qualification/status.sock",
                   "--output", str(output)]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": os.environ["HOME"],
               "USER": "symbi-qual", "LOGNAME": "symbi-qual",
               "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
               "DBUS_SESSION_BUS_ADDRESS": os.environ["DBUS_SESSION_BUS_ADDRESS"],
               "PYTHONDONTWRITEBYTECODE": "1", "CARGO_BUILD_JOBS": "1",
               "RUST_TEST_THREADS": "1", "RAYON_NUM_THREADS": "1"}
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, text=False, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=5400)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate(timeout=15)
            raise ValueError("Landlock qualification driver exceeded 90 minutes")
        if len(stdout) > 128 * 1024 or len(stderr) > 128 * 1024:
            raise ValueError("qualification driver console output exceeded its bound")
        record["driver_exit_code"] = child.returncode
        record["driver_stdout_bytes"] = len(stdout)
        record["driver_stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        record["driver_stderr_bytes"] = len(stderr)
        record["driver_stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
        if child.returncode != 0:
            raise ValueError("Landlock qualification driver failed")
        summary = unique_json((output / "summary.json").read_bytes())
        if (summary.get("passed") is not True or summary.get("qualified") is not True
                or summary.get("runtime_revision") != expected["source_revision"]
                or summary.get("binary_sha256") != expected["binary_sha256"]
                or summary.get("image_ref") != expected["image_ref"]):
            raise ValueError("Landlock driver did not qualify the selected bindings")
        record["summary"] = summary
        record["artifacts"] = collect_public_artifacts(output, summary)
        record["passed"] = True
        record["qualified"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
    write_channel(record)
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
