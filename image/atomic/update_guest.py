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
NEGATIVE_SOURCE = Path("/run/symbi-update-negative/source")
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
POSITIVE_OVERLAY_CASE = "valid-signature"
UPDATE_COMMAND_TIMEOUT_SECONDS = 1200
STATE = Path("/var/lib/symbi-update-test/phase")
CHANNEL = Path("/dev/virtio-ports/org.symbi.update")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def exact_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value)


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


def source_mount_observation(raw, mountpoint=SOURCE.parent):
    """Return one bounded kernel mount observation without accepting its controls."""
    if Path(mountpoint) != SOURCE.parent or not isinstance(raw, str):
        raise ValueError("fixed update mountpoint required")
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
                "mountpoint": observed_mountpoint,
                "root": root,
                "fstype": fields[separator + 1],
                "source": source,
                "major_minor": fields[2],
                "options": options,
                "super_options": super_options,
            })
    observation = {
        "mountinfo_sha256": hashlib.sha256(encoded).hexdigest(),
        "match_count": len(matches),
    }
    if len(matches) == 1:
        observation.update(matches[0])
    return observation


def validate_source_mount(observation, source_device, device_number):
    """Bind one mountinfo entry to the exact direct block node and controls."""
    required = {"mountinfo_sha256", "match_count", "mountpoint", "root",
                "fstype", "source", "major_minor", "options", "super_options"}
    source_device = Path(source_device)
    if (not isinstance(observation, dict) or set(observation) != required
            or observation.get("match_count") != 1
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
              "scope": "Offline ephemeral fixture-signed update and rollback only"}

    def run(command, *, timeout=120, check=True):
        if type(timeout) is not int or not 1 <= timeout <= UPDATE_COMMAND_TIMEOUT_SECONDS:
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
        return result.stdout

    try:
        if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
            raise ValueError("update guest gained a network interface")
        if run(["/usr/sbin/getenforce"]).strip() != "Enforcing":
            raise ValueError("SELinux is not enforcing")
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
        observation = source_mount_observation(read_mountinfo())
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
        raw_status = lambda: json.loads(run(["/usr/bin/bootc", "status", "--json"]))
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
            switch = ["/usr/bin/bootc", "switch", "--transport", "dir",
                      "--enforce-container-sigpolicy", str(NEGATIVE_SOURCE)]
            run(switch, timeout=UPDATE_COMMAND_TIMEOUT_SECONDS, check=False)
            switch_exit = record["commands"][-1]["exit_code"]
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
            run(["/usr/bin/bootc", "switch", "--transport", "dir",
                 "--enforce-container-sigpolicy", str(SOURCE)],
                timeout=UPDATE_COMMAND_TIMEOUT_SECONDS)
            phase_status(raw_status(), old, staged=new)
            write_state("updated")
            record["phase"] = {"name": "installed", "booted_digest": old,
                               "operation": "signed-update-staged", "staged_digest": new}
        elif state == "updated":
            phase_status(raw_status(), new, rollback=old)
            run(["/usr/bin/bootc", "rollback"], timeout=300)
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
    deadline = time.monotonic() + 15
    while not CHANNEL.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    with CHANNEL.open("wb", buffering=0) as output:
        output.write(raw)
    if not record["passed"]:
        raise RuntimeError("update guest phase failed")


if __name__ == "__main__":
    main()
