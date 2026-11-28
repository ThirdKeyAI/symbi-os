"""Validate the first graphical login and emit one source-bound guest report."""
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import subprocess
import sys
import time


USERNAME = "symbi-test"
CHANNEL = Path("/dev/virtio-ports/org.symbi.appliance")
STATUS_PREFIX = "SYMBI_APPLIANCE_STATUS:"
SCOPE = (
    "HIGHLY EXPERIMENTAL offline development appliance; no release, signature, "
    "security, containment or production-account qualification"
)
VERIFIER_SERVICE_TIMEOUT_SECONDS = 420
VERIFIER_APPLICATION_BUDGET_SECONDS = 400
VERIFIER_SERVICE_MARGIN_SECONDS = 20
VERIFIER_PHASE_BUDGETS = {
    "graphical-session-and-portal": 260,
    "fixed-commands": 55,
    "walker-lifecycle": 70,
    "local-validation-and-report": 15,
}
FIXED_COMMAND_TIMEOUTS = {
    "get-default": 5,
    "package-query": 2,
    "package-verify": 8,
    "kargs": 10,
    "graphical-dropin-paths": 5,
    "default-dropin-paths": 5,
}
WALKER_STEP_TIMEOUTS = {
    "reset-before": 5,
    "launch": 10,
    "observe": 20,
    "stop": 10,
    "observe-stopped": 20,
    "reset-after": 5,
}
GRAPHICAL_COMMAND_TIMEOUT_SECONDS = 5
PORTAL_START_TIMEOUT_SECONDS = 10
GRAPHICAL_SESSION_POLL_INTERVAL_SECONDS = 2
PORTAL_POLL_INTERVAL_SECONDS = 1
GRAPHICAL_SESSION_POLL_ATTEMPTS = (
    VERIFIER_PHASE_BUDGETS["graphical-session-and-portal"]
    // GRAPHICAL_SESSION_POLL_INTERVAL_SECONDS
)
TRANSIENT_BOOT_DROPIN_PATH = Path(
    "/run/systemd/generator.early/graphical.target.d/symbi-appliance.conf"
)
TRANSIENT_BOOT_DROPIN = b"[Unit]\nWants=p.service v.service\n"
PERSISTENT_SYSTEMD_UNIT_ROOTS = (
    Path("/etc/systemd/system.control"),
    Path("/etc/systemd/system"),
    Path("/etc/systemd/system.attached"),
    Path("/usr/local/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
)
FIXTURE_UNIT_NAMES = ("p.service", "v.service")
MAX_SYSTEMD_ROOT_ENTRIES = 8192
MAX_SYSTEMD_DROPIN_ENTRIES = 256
MAX_SYSTEMD_DROPIN_BYTES = 64 * 1024
MAX_SYSTEMD_DROPIN_TOTAL_BYTES = 2 * 1024 * 1024
FIXTURE_UNIT_REFERENCE = re.compile(
    rb"(?<![A-Za-z0-9_.@:-])(?:p|v)\.service(?![A-Za-z0-9_.@:-])"
)
PORTAL_POLL_ATTEMPTS = (
    VERIFIER_PHASE_BUDGETS["graphical-session-and-portal"]
    // PORTAL_POLL_INTERVAL_SECONDS
)


def status(name):
    """Emit one fixed public-safe lifecycle marker to the private serial log."""
    print(STATUS_PREFIX + name, flush=True)


def unique_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key: " + key)
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Expected one JSON object")
    return value


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def remaining_timeout(deadline, maximum):
    """Clamp one operation to both its reviewed maximum and an outer deadline."""
    if (type(deadline) not in (int, float) or type(maximum) not in (int, float)
            or maximum <= 0):
        raise ValueError("Invalid verifier deadline")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Verifier application deadline expired")
    return min(float(maximum), remaining)


def bounded_poll(predicate, *, deadline, interval, attempts):
    """Poll no more than the reviewed count or monotonic phase deadline."""
    if (not callable(predicate) or type(attempts) is not int or attempts <= 0
            or type(interval) not in (int, float) or interval <= 0):
        raise ValueError("Invalid bounded poll")
    for _ in range(attempts):
        if time.monotonic() >= deadline:
            return False
        ready = predicate()
        if time.monotonic() >= deadline:
            return False
        if ready:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(float(interval), remaining))
    return False


def run(command, *, check=True, timeout):
    if (type(check) is not bool or type(timeout) not in (int, float)
            or timeout <= 0):
        raise ValueError("Invalid verification command deadline")
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                  "LANG": "C.UTF-8"})
    if len(result.stdout.encode()) > 128*1024 or len(result.stderr.encode()) > 128*1024:
        raise ValueError("Verification command output exceeded its bound")
    if check:
        result.check_returncode()
    return result


def write_guest_report(path, raw, deadline):
    """Write every report byte through one nonblocking deadline-bound channel."""
    if type(raw) is not bytes or not 0 < len(raw) <= 128*1024:
        raise ValueError("Guest report is empty or oversized")
    maximum = VERIFIER_PHASE_BUDGETS["local-validation-and-report"]
    remaining_timeout(deadline, maximum)
    channel = os.fspath(path)
    channel_info = os.lstat(channel)
    if stat.S_ISLNK(channel_info.st_mode):
        link = os.readlink(channel)
        match = re.fullmatch(r"\.\./(vport[0-9]+p[0-9]+)", link)
        if Path(channel).parent != Path("/dev/virtio-ports") or match is None:
            raise ValueError("Guest report channel link is outside the reviewed device path")
        channel = os.fspath(Path("/dev") / match.group(1))
    elif not stat.S_ISCHR(channel_info.st_mode):
        raise ValueError("Guest report channel path is not a character device")
    remaining_timeout(deadline, maximum)
    flags = os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(channel, flags)
    try:
        remaining_timeout(deadline, maximum)
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
            raise ValueError("Guest report channel is not a character device")
        poller = select.poll()
        requested = select.POLLOUT | select.POLLERR | select.POLLHUP | select.POLLNVAL
        rejected = select.POLLERR | select.POLLHUP | select.POLLNVAL
        poller.register(descriptor, requested)
        view = memoryview(raw)
        written = 0
        while written < len(view):
            remaining = remaining_timeout(deadline, maximum)
            timeout_milliseconds = max(0, int(remaining * 1000))
            try:
                events = poller.poll(timeout_milliseconds)
            except InterruptedError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("Guest report channel deadline expired")
            event_mask = 0
            for event_descriptor, event in events:
                if event_descriptor == descriptor:
                    event_mask |= event
            if event_mask & rejected:
                raise ValueError("Guest report channel closed or failed")
            if not event_mask & select.POLLOUT:
                raise TimeoutError("Guest report channel was not writable before its deadline")
            try:
                count = os.write(descriptor, view[written:])
            except BlockingIOError as error:
                if error.errno not in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise
                continue
            except InterruptedError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("Guest report channel deadline expired")
            if type(count) is not int or not 0 < count <= len(view) - written:
                raise ValueError("Guest report channel made no bounded progress")
            written += count
        return written
    finally:
        os.close(descriptor)


def direct_regular(path, uid=None):
    info = path.lstat()
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink()
            and (uid is None or info.st_uid == uid))


def bound_regular(path, expected, uid=0):
    if (not isinstance(expected, dict) or set(expected) != {"sha256", "bytes", "mode"}
            or not re.fullmatch(r"[0-9a-f]{64}", expected.get("sha256", ""))
            or type(expected.get("bytes")) is not int or expected["bytes"] <= 0
            or type(expected.get("mode")) is not int or not 0 <= expected["mode"] <= 0o777):
        return False
    try:
        info = path.lstat()
    except (OSError, RuntimeError):
        return False
    return (stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid == uid
            and info.st_size == expected["bytes"]
            and stat.S_IMODE(info.st_mode) == expected["mode"]
            and digest(path) == expected["sha256"])


def reviewed_launcher(root, expected):
    """Accept only the reviewed relative launcher and its direct, bound target."""
    root = Path(root).resolve(strict=True)
    launcher = root / "usr/bin/Hyprland"
    target = root / "usr/lib/symbi/hyprland/bin/Hyprland"
    link = expected.get("link") if isinstance(expected, dict) else None
    if link != "../lib/symbi/hyprland/bin/Hyprland":
        return False
    try:
        actual = os.readlink(launcher)
        candidate = (launcher.parent / actual).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return (launcher.is_symlink() and actual == link and not Path(actual).is_absolute()
            and candidate == target and candidate.is_relative_to(root))


def path_absent(path):
    return not path.exists() and not path.is_symlink()


def bounded_root_regular(path, maximum, owner_uid=0, required_mode=None,
                         require_single_link=False):
    """Read one direct, root-owned, non-writable regular file within a hard bound."""
    if (type(maximum) is not int or maximum <= 0 or type(owner_uid) is not int
            or owner_uid < 0 or type(require_single_link) is not bool
            or (required_mode is not None
            and (type(required_mode) is not int or not 0 <= required_mode <= 0o777))):
        raise ValueError("Invalid bounded systemd file contract")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode)
                or (require_single_link and info.st_nlink != 1)
                or info.st_uid != owner_uid or info.st_mode & 0o022
                or (required_mode is not None
                    and stat.S_IMODE(info.st_mode) != required_mode)
                or not 0 < info.st_size <= maximum):
            return None
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != info.st_size or len(raw) > maximum:
            return None
        return raw
    except OSError:
        return None
    finally:
        os.close(descriptor)


def systemd_config_references_fixture(raw):
    """Conservatively C-unescape unit syntax before checking fixture unit names."""
    if not isinstance(raw, bytes):
        return True
    collapsed = raw.replace(b"\\\r\n", b"").replace(b"\\\n", b"")
    decoded = bytearray()
    index = 0
    simple = {
        ord("a"): b"\a", ord("b"): b"\b", ord("f"): b"\f",
        ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t",
        ord("v"): b"\v", ord("e"): b"\x1b", ord("s"): b" ",
        ord("\\"): b"\\",
        ord('"'): b'"', ord("'"): b"'",
    }
    while index < len(collapsed):
        value = collapsed[index]
        if value in {ord('"'), ord("'")}:
            index += 1
            continue
        if value != ord("\\"):
            decoded.append(value)
            index += 1
            continue
        index += 1
        if index >= len(collapsed):
            return True
        escape = collapsed[index]
        if escape in simple:
            decoded.extend(simple[escape])
            index += 1
            continue
        if escape == ord("x"):
            digits = collapsed[index + 1:index + 3]
            if len(digits) != 2 or re.fullmatch(rb"[0-9A-Fa-f]{2}", digits) is None:
                return True
            decoded.append(int(digits, 16))
            index += 3
            continue
        if escape in b"01234567":
            end = index + 1
            while end < min(index + 3, len(collapsed)) and collapsed[end] in b"01234567":
                end += 1
            number = int(collapsed[index:end], 8)
            if number > 255:
                return True
            decoded.append(number)
            index = end
            continue
        if escape in {ord("u"), ord("U")}:
            width = 4 if escape == ord("u") else 8
            digits = collapsed[index + 1:index + 1 + width]
            if (len(digits) != width
                    or re.fullmatch(rb"[0-9A-Fa-f]+", digits) is None):
                return True
            try:
                decoded.extend(chr(int(digits, 16)).encode("utf-8"))
            except (UnicodeError, ValueError):
                return True
            index += 1 + width
            continue
        return True
    return FIXTURE_UNIT_REFERENCE.search(bytes(decoded)) is not None


def runtime_path_is_direct(path, runtime_root=Path("/run"), owner_uid=0):
    """Require every runtime path component to be a direct safe directory on /run."""
    path = Path(path)
    runtime_root = Path(runtime_root)
    try:
        relative = path.relative_to(runtime_root)
    except ValueError:
        return False
    if not relative.parts or path.name != "symbi-appliance.conf":
        return False
    current = runtime_root
    try:
        root_info = current.lstat()
    except OSError:
        return False
    for component in relative.parts[:-1]:
        info = root_info if current == runtime_root else current.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != owner_uid or info.st_mode & 0o022):
            return False
        current /= component
    try:
        parent_info = current.lstat()
        file_info = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return (not stat.S_ISLNK(parent_info.st_mode)
            and stat.S_ISDIR(parent_info.st_mode)
            and parent_info.st_uid == owner_uid
            and not parent_info.st_mode & 0o022
            and resolved == path
            and stat.S_ISREG(file_info.st_mode)
            and file_info.st_dev == root_info.st_dev)


def persistent_fixture_boot_references_absent(
        roots=PERSISTENT_SYSTEMD_UNIT_ROOTS, owner_uid=0):
    """Reject persistent fixture units, target links, and target drop-in references."""
    if not isinstance(roots, (tuple, list)) or not roots:
        return False
    total_bytes = 0
    scanned_fragments = set()
    for root in roots:
        root = Path(root)
        try:
            root_info = root.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            return False
        for unit in FIXTURE_UNIT_NAMES:
            if not path_absent(root / unit):
                return False
        if not path_absent(
                root / "graphical.target.d" / "symbi-appliance.conf"):
            return False
        try:
            entries = tuple(root.iterdir())
        except OSError:
            return False
        if len(entries) > MAX_SYSTEMD_ROOT_ENTRIES:
            return False
        for entry in entries:
            fragment = re.fullmatch(r".+\.target", entry.name)
            relation = re.fullmatch(
                r".+\.target\.(?:wants|requires|upholds)", entry.name)
            dropin = entry.name == "target.d" or re.fullmatch(
                r".+\.target\.d", entry.name)
            if fragment is None and relation is None and dropin is None:
                continue
            try:
                entry_info = entry.lstat()
            except OSError:
                return False
            if fragment is not None:
                if stat.S_ISLNK(entry_info.st_mode):
                    try:
                        source = entry.resolve(strict=True)
                    except (OSError, RuntimeError):
                        return False
                    if source == Path("/dev/null"):
                        continue
                else:
                    source = entry
                identity = os.fspath(source)
                if identity in scanned_fragments:
                    continue
                raw = bounded_root_regular(
                    source, MAX_SYSTEMD_DROPIN_BYTES, owner_uid)
                if raw is None:
                    return False
                scanned_fragments.add(identity)
                total_bytes += len(raw)
                if (total_bytes > MAX_SYSTEMD_DROPIN_TOTAL_BYTES
                        or systemd_config_references_fixture(raw)):
                    return False
                continue
            if stat.S_ISLNK(entry_info.st_mode) or not stat.S_ISDIR(entry_info.st_mode):
                return False
            if relation is not None:
                try:
                    links = tuple(entry.iterdir())
                except OSError:
                    return False
                if len(links) > MAX_SYSTEMD_DROPIN_ENTRIES:
                    return False
                for link in links:
                    try:
                        link_info = link.lstat()
                        target = os.readlink(link)
                    except OSError:
                        return False
                    if (not stat.S_ISLNK(link_info.st_mode)
                            or not 0 < len(target.encode("utf-8")) <= 4096
                            or link.name in FIXTURE_UNIT_NAMES
                            or FIXTURE_UNIT_REFERENCE.search(
                                target.encode("utf-8")) is not None):
                        return False
                    try:
                        resolved = link.resolve(strict=True)
                    except (OSError, RuntimeError):
                        return False
                    if resolved.name in FIXTURE_UNIT_NAMES:
                        return False
                continue
            try:
                candidates = tuple(entry.iterdir())
            except OSError:
                return False
            if len(candidates) > MAX_SYSTEMD_DROPIN_ENTRIES:
                return False
            for candidate in candidates:
                if not candidate.name.endswith(".conf"):
                    continue
                raw = bounded_root_regular(
                    candidate, MAX_SYSTEMD_DROPIN_BYTES, owner_uid)
                if raw is None:
                    return False
                total_bytes += len(raw)
                if (total_bytes > MAX_SYSTEMD_DROPIN_TOTAL_BYTES
                        or systemd_config_references_fixture(raw)):
                    return False
    return True


def transient_boot_dropin_is_exact(deadline, path=TRANSIENT_BOOT_DROPIN_PATH,
                                   persistent_roots=PERSISTENT_SYSTEMD_UNIT_ROOTS,
                                   owner_uid=0, runtime_root=Path("/run")):
    """Bind the fixture Wants edge to one exact early-generator runtime drop-in."""
    expected = os.fspath(path)
    observed = {}
    for unit, timeout_name in (
            ("graphical.target", "graphical-dropin-paths"),
            ("default.target", "default-dropin-paths")):
        result = run([
            "/usr/bin/systemctl", "show", "--property=DropInPaths", "--value",
            unit,
        ], timeout=remaining_timeout(
            deadline, FIXED_COMMAND_TIMEOUTS[timeout_name]))
        names = result.stdout.split()
        if (len(names) > MAX_SYSTEMD_DROPIN_ENTRIES
                or len(names) != len(set(names))):
            return False
        observed[unit] = names
    if expected not in observed["graphical.target"]:
        return False
    if not runtime_path_is_direct(path, runtime_root, owner_uid):
        return False
    for names in observed.values():
        for name in names:
            if (not name.startswith("/")
                    or any(character.isspace() for character in name)):
                return False
            candidate = Path(name)
            raw = bounded_root_regular(
                candidate, MAX_SYSTEMD_DROPIN_BYTES, owner_uid,
                0o644 if candidate == Path(path) else None,
                candidate == Path(path))
            if raw is None:
                return False
            if candidate == Path(path):
                if raw != TRANSIENT_BOOT_DROPIN:
                    return False
            elif systemd_config_references_fixture(raw):
                return False
    return persistent_fixture_boot_references_absent(
        persistent_roots, owner_uid)


def user_executables(uid, deadline):
    executables = set()
    if os.geteuid() != 0:
        raise ValueError("Process observation must start as root")
    remaining_timeout(deadline, VERIFIER_APPLICATION_BUDGET_SECONDS)
    os.seteuid(uid)
    try:
        for entry in Path("/proc").iterdir():
            if time.monotonic() >= deadline:
                raise TimeoutError("Process observation deadline expired")
            if not entry.name.isdigit():
                continue
            try:
                owner = entry.stat().st_uid
                if time.monotonic() >= deadline:
                    raise TimeoutError("Process observation deadline expired")
                if owner == uid:
                    executable = os.readlink(entry / "exe")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Process observation deadline expired")
                    if executable:
                        executables.add(executable)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
    finally:
        os.seteuid(0)
    if time.monotonic() >= deadline:
        raise TimeoutError("Process observation deadline expired")
    return executables


def shadow_locked(name):
    lines = Path("/etc/shadow").read_text().splitlines()
    matches = [line.split(":", 2)[1] for line in lines if line.startswith(name + ":")]
    return len(matches) == 1 and matches[0] in {"!", "!!", "*", "!*"}


def verify_seed(expected, account):
    source_root = Path("/usr/share/symbiont/defaults")
    target_root = Path(account.pw_dir) / ".config"
    bindings = expected.get("seed_files")
    if not isinstance(bindings, dict) or not bindings:
        return False
    for relative, binding in bindings.items():
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or ".." in Path(relative).parts or str(Path(relative)) != relative):
            return False
        source = source_root / relative
        target = target_root / relative
        if (not bound_regular(source, binding)
                or not bound_regular(target, binding, account.pw_uid)):
            return False
    return True


def verify_packages(bindings, application_deadline):
    if not isinstance(bindings, dict) or set(bindings) != {"sddm", "sddm-wayland-sway", "waybar"}:
        return False
    query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"
    for name, identity in bindings.items():
        if not isinstance(identity, str) or identity.split("\t", 1)[0] != name:
            return False
        observed = run(
            ["/usr/bin/rpm", "-q", name, "--qf", query],
            check=False,
            timeout=remaining_timeout(
                application_deadline, FIXED_COMMAND_TIMEOUTS["package-query"]),
        )
        verified = run(
            ["/usr/bin/rpm", "-V", name],
            check=False,
            timeout=remaining_timeout(
                application_deadline, FIXED_COMMAND_TIMEOUTS["package-verify"]),
        )
        if (observed.returncode != 0 or observed.stdout != identity + "\n"
                or observed.stderr or verified.returncode != 0
                or verified.stdout or verified.stderr):
            return False
    return True


def interactive_device_observation():
    inventory = Path("/proc/bus/input/devices").read_text()
    if len(inventory.encode()) > 128*1024:
        raise ValueError("Input device inventory exceeded its bound")
    virtio_gpu = False
    for card in Path("/sys/class/drm").glob("card[0-9]*"):
        device = card / "device"
        driver = device / "driver"
        vendor = device / "vendor"
        nested = list(device.glob("virtio*/driver"))
        if ((driver.is_symlink() and vendor.is_file()
             and driver.resolve(strict=True).name == "virtio-pci"
             and vendor.read_text().strip() == "0x1af4")
                or any(path.is_symlink() and path.resolve(strict=True).name == "virtio_gpu"
                       for path in nested)):
            virtio_gpu = True
    return {
        "virtio_gpu": virtio_gpu,
        "virtio_keyboard": "virtio keyboard" in inventory.lower(),
        "virtio_pointer": "virtio tablet" in inventory.lower(),
    }


def user_systemctl(*arguments, check=True, timeout):
    return run([
        "/usr/sbin/runuser", "-u", USERNAME, "--", "/usr/bin/env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "/usr/bin/systemctl", "--user", *arguments,
    ], check=check, timeout=timeout)


def observe_bounded_walker(uid, application_deadline):
    """Launch Walker through a bounded transient unit and prove it then stopped."""
    unit = "symbi-appliance-walker.service"
    executable = "/usr/bin/walker"
    timeout_seconds = 30
    limits = {
        "memory_max": "512M", "memory_swap_max": "0", "cpu_quota": "100%",
        "tasks_max": "64", "runtime_max_seconds": "60",
        "no_new_privileges": "yes",
    }
    if executable in user_executables(uid, application_deadline):
        raise ValueError("Walker was already running before the bounded launch")
    lifecycle_deadline = min(
        application_deadline,
        time.monotonic() + VERIFIER_PHASE_BUDGETS["walker-lifecycle"],
    )
    launch_deadline = min(
        lifecycle_deadline,
        time.monotonic()
        + WALKER_STEP_TIMEOUTS["reset-before"]
        + WALKER_STEP_TIMEOUTS["launch"]
        + WALKER_STEP_TIMEOUTS["observe"],
    )
    user_systemctl(
        "reset-failed", unit, check=False,
        timeout=remaining_timeout(
            launch_deadline, WALKER_STEP_TIMEOUTS["reset-before"]),
    )
    launch_error = None
    cleanup_error = None
    observed = False
    stop_succeeded = False
    stopped = False
    try:
        run([
            "/usr/sbin/runuser", "-u", USERNAME, "--", "/usr/bin/env",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "/usr/bin/systemd-run", "--user", "--collect", "--service-type=exec",
            "--unit=" + unit,
            "--property=MemoryMax=" + limits["memory_max"],
            "--property=MemorySwapMax=" + limits["memory_swap_max"],
            "--property=CPUQuota=" + limits["cpu_quota"],
            "--property=TasksMax=" + limits["tasks_max"],
            "--property=RuntimeMaxSec=" + limits["runtime_max_seconds"],
            "--property=NoNewPrivileges=" + limits["no_new_privileges"],
            executable,
        ], timeout=remaining_timeout(
            launch_deadline, WALKER_STEP_TIMEOUTS["launch"]))
        observed = bounded_poll(
            lambda: executable in user_executables(uid, launch_deadline),
            deadline=launch_deadline,
            interval=1,
            attempts=WALKER_STEP_TIMEOUTS["observe"],
        )
        if not observed:
            raise ValueError("Walker was not observed after its bounded launch")
    except Exception as error:
        launch_error = error
    finally:
        cleanup_deadline = min(
            lifecycle_deadline,
            time.monotonic()
            + WALKER_STEP_TIMEOUTS["stop"]
            + WALKER_STEP_TIMEOUTS["observe-stopped"]
            + WALKER_STEP_TIMEOUTS["reset-after"],
        )
        try:
            stop_result = user_systemctl(
                "stop", unit, check=False,
                timeout=remaining_timeout(
                    cleanup_deadline, WALKER_STEP_TIMEOUTS["stop"]),
            )
            stop_succeeded = (type(stop_result.returncode) is int
                              and stop_result.returncode == 0)
            stopped = bounded_poll(
                lambda: executable not in user_executables(uid, cleanup_deadline),
                deadline=cleanup_deadline,
                interval=1,
                attempts=WALKER_STEP_TIMEOUTS["observe-stopped"],
            )
        except Exception as error:
            cleanup_error = error
        finally:
            try:
                user_systemctl(
                    "reset-failed", unit, check=False,
                    timeout=remaining_timeout(
                        cleanup_deadline, WALKER_STEP_TIMEOUTS["reset-after"]),
                )
            except Exception as error:
                if cleanup_error is None:
                    cleanup_error = error
    if cleanup_error is not None:
        raise ValueError("Walker cleanup failed") from cleanup_error
    if not stop_succeeded:
        raise ValueError("Walker transient unit did not stop successfully") from launch_error
    if launch_error is not None:
        raise ValueError("Bounded Walker launch failed") from launch_error
    if not stopped:
        raise ValueError("Walker remained after the bounded launch was stopped")
    return {
        "unit": unit, "executable": executable, "observed": observed,
        "stop_succeeded": stop_succeeded, "stopped": stopped,
        "timeout_seconds": timeout_seconds, "limits": limits,
    }


def observe_graphical_session(uid, application_deadline):
    """Observe SDDM, the session, and the portal inside one shared phase."""
    phase_deadline = min(
        application_deadline,
        time.monotonic()
        + VERIFIER_PHASE_BUDGETS["graphical-session-and-portal"],
    )
    session_executables = {
        "/usr/lib/symbi/hyprland/bin/Hyprland",
        "/usr/bin/waybar",
    }
    executables = set()

    def session_ready():
        nonlocal executables
        active = run(
            ["/usr/bin/systemctl", "is-active", "sddm.service"],
            check=False,
            timeout=remaining_timeout(
                phase_deadline, GRAPHICAL_COMMAND_TIMEOUT_SECONDS),
        )
        executables = user_executables(uid, phase_deadline)
        return (active.returncode == 0
                and session_executables.issubset(executables)
                and Path("/run/user/1000/bus").is_socket())

    if not bounded_poll(
            session_ready, deadline=phase_deadline,
            interval=GRAPHICAL_SESSION_POLL_INTERVAL_SECONDS,
            attempts=GRAPHICAL_SESSION_POLL_ATTEMPTS):
        raise ValueError("SDDM, Hyprland and Waybar did not reach the graphical session")

    run([
        "/usr/sbin/runuser", "-u", USERNAME, "--", "/usr/bin/env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
        "/usr/bin/systemctl", "--user", "start", "xdg-desktop-portal-hyprland.service",
    ], timeout=remaining_timeout(phase_deadline, PORTAL_START_TIMEOUT_SECONDS))
    portal_executable = "/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland"

    def portal_ready():
        nonlocal executables
        executables = user_executables(uid, phase_deadline)
        return portal_executable in executables

    if not bounded_poll(
            portal_ready, deadline=phase_deadline,
            interval=PORTAL_POLL_INTERVAL_SECONDS,
            attempts=PORTAL_POLL_ATTEMPTS):
        raise ValueError("The installed Hyprland portal did not start in the graphical session")
    return session_executables, portal_executable, executables


def main():
    status("verifier-start")
    product = Path("/sys/class/dmi/id/product_name").read_text().strip()
    if (os.geteuid() != 0 or product != "Symbi-Interactive-Appliance"
            or Path("/run/.containerenv").exists() or len(sys.argv) != 2):
        raise SystemExit("Use only the disposable hosted appliance guest")
    application_deadline = time.monotonic() + VERIFIER_APPLICATION_BUDGET_SECONDS
    expected_path = Path(sys.argv[1])
    if not direct_regular(expected_path, 0) or expected_path.stat().st_size > 128*1024:
        raise ValueError("Missing bounded appliance invocation binding")
    expected = unique_json(expected_path.read_bytes())
    if (not re.fullmatch(r"[0-9a-f]{32}", expected.get("nonce", ""))
            or expected.get("username") != USERNAME):
        raise ValueError("Invalid appliance invocation binding")
    state_path = Path("/run/symbi-appliance-provision.json")
    if (not direct_regular(state_path, 0) or stat.S_IMODE(state_path.stat().st_mode) != 0o600
            or state_path.stat().st_size > 128*1024):
        raise ValueError("Missing bounded ephemeral provisioning receipt")
    state = unique_json(state_path.read_bytes())
    if (state.get("nonce") != expected["nonce"] or state.get("source_binding") != expected["source_binding"]
            or state.get("account_created") is not True or state.get("password_set") is not False
            or state.get("authorized_key_written") is not False
            or state.get("production_image_modified") is not False
            or state.get("transient_boot_units") is not True
            or state.get("expected_sha256") != digest(expected_path)
            or state.get("autologin_sha256") != expected.get("sddm_config_sha256")):
        raise ValueError("Ephemeral provisioning receipt is incomplete")
    status("verifier-provision-receipt-accepted")
    account = pwd.getpwnam(USERNAME)
    wheel = grp.getgrnam("wheel")
    session_executables, portal_executable, executables = observe_graphical_session(
        account.pw_uid, application_deadline)
    status("verifier-graphical-session-observed")
    default_target = run(
        ["/usr/bin/systemctl", "get-default"],
        timeout=remaining_timeout(
            application_deadline, FIXED_COMMAND_TIMEOUTS["get-default"]),
    ).stdout.strip()
    display_link = Path("/etc/systemd/system/display-manager.service")
    if not display_link.is_symlink() or display_link.resolve().name != "sddm.service":
        raise ValueError("SDDM is not the enabled display manager")
    production_files = expected.get("production_files")
    required_production = {
        "/usr/share/wayland-sessions/symbi.desktop",
        "/usr/libexec/symbi-seed-config",
        "/usr/libexec/symbi-desktop-session",
    }
    if not isinstance(production_files, dict) or set(production_files) != required_production:
        raise ValueError("Installed desktop overlay binding is incomplete")
    for name, binding in production_files.items():
        path = Path(name)
        if not bound_regular(path, binding) or (binding["mode"] & 0o111 and not os.access(path, os.X_OK)):
            raise ValueError("Installed desktop overlay changed: " + name)
    components = expected.get("desktop_components")
    files = components.get("files") if isinstance(components, dict) else None
    packages = components.get("packages") if isinstance(components, dict) else None
    required_files = {
        "/usr/bin/Hyprland", "/usr/lib/symbi/hyprland/bin/Hyprland", "/usr/bin/walker",
        "/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland",
        "/usr/lib/systemd/user/xdg-desktop-portal-hyprland.service",
    }
    if (not isinstance(components, dict)
            or set(components) != {"preparation_sha256", "files", "packages"}
            or not re.fullmatch(r"[0-9a-f]{64}", components.get("preparation_sha256", ""))
            or not isinstance(files, dict) or set(files) != required_files
            or not reviewed_launcher(Path("/"), files["/usr/bin/Hyprland"])):
        raise ValueError("Desktop component source binding is incomplete")
    for name, binding in files.items():
        if name == "/usr/bin/Hyprland":
            continue
        path = Path(name)
        if not bound_regular(path, binding) or (binding["mode"] & 0o111 and not os.access(path, os.X_OK)):
            raise ValueError("Desktop component bytes changed: " + name)
    if not verify_packages(packages, application_deadline):
        raise ValueError("SDDM, Waybar or its installed package bytes changed")
    interactive = interactive_device_observation()
    if interactive != {"virtio_gpu": True, "virtio_keyboard": True, "virtio_pointer": True}:
        raise ValueError("The graphical VM is missing a virtio display, keyboard or pointer")
    if not verify_seed(expected, account):
        raise ValueError("First-login defaults were not seeded exactly")
    walker_launch = observe_bounded_walker(account.pw_uid, application_deadline)
    status("verifier-walker-observed")
    executables = user_executables(account.pw_uid, application_deadline)
    if not (session_executables | {portal_executable}).issubset(executables):
        raise ValueError("Desktop session changed during the bounded Walker observation")
    kargs = run(
        ["/usr/bin/rpm-ostree", "kargs"],
        timeout=remaining_timeout(
            application_deadline, FIXED_COMMAND_TIMEOUTS["kargs"]),
    ).stdout
    if "systemd.wants=p.service" in kargs or "systemd.wants=v.service" in kargs:
        raise ValueError("Fixture boot wants remain in the appliance deployment")
    if not transient_boot_dropin_is_exact(application_deadline):
        raise ValueError("Fixture boot units are not bound to one transient drop-in")
    local_deadline = min(
        application_deadline,
        time.monotonic() + VERIFIER_PHASE_BUDGETS["local-validation-and-report"],
    )
    remaining_timeout(
        local_deadline, VERIFIER_PHASE_BUDGETS["local-validation-and-report"])
    persistent_scripts = (
        Path("/usr/local/libexec/symbi-provision.py"), Path("/usr/local/libexec/symbi-verify.py"),
        Path("/var/lib/symbi-appliance"),
    )
    persistent_units = (Path("/etc/systemd/system/p.service"), Path("/etc/systemd/system/v.service"))
    if any(path.exists() or path.is_symlink() for path in (*persistent_scripts, *persistent_units)):
        raise ValueError("Fixture script or unit leaked onto the appliance disk")
    persistent_credentials = tuple(
        base / name
        for base in (
            Path("/etc/credstore"), Path("/etc/credstore.encrypted"),
            Path("/usr/local/lib/credstore"),
            Path("/usr/local/lib/credstore.encrypted"),
            Path("/usr/lib/credstore"), Path("/usr/lib/credstore.encrypted"),
        )
        for name in (
            "symbi-provision.py", "symbi-verify.py", "symbi-expected.json",
            "systemd.extra-unit.p.service", "systemd.extra-unit.v.service",
            "systemd.unit-dropin.graphical.target~symbi-appliance",
        )
    )
    if any(not path_absent(path) for path in persistent_credentials):
        raise ValueError("Fixture credential payload leaked onto the appliance disk")
    remaining_timeout(
        local_deadline, VERIFIER_PHASE_BUDGETS["local-validation-and-report"])
    autologin = Path("/etc/sddm.conf.d/90-symbi-development-appliance.conf")
    if (not direct_regular(autologin, 0) or stat.S_IMODE(autologin.stat().st_mode) != 0o644
            or digest(autologin) != expected.get("sddm_config_sha256")):
        raise ValueError("Development-only SDDM autologin configuration changed")
    fixture_group = grp.getgrnam(USERNAME)
    group_ids = os.getgrouplist(USERNAME, account.pw_gid)
    ssh_directory = Path(account.pw_dir) / ".ssh"
    authorized = ssh_directory / "authorized_keys"
    fixture_user = {
        "name": USERNAME, "password_locked": shadow_locked(USERNAME),
        "non_wheel": wheel.gr_gid not in group_ids and USERNAME not in wheel.gr_mem,
        "authorized_keys_absent": path_absent(ssh_directory) and path_absent(authorized),
    }
    if (account.pw_uid != 1000 or account.pw_gid != fixture_group.gr_gid
            or fixture_group.gr_mem or fixture_user != {
                "name": USERNAME, "password_locked": True, "non_wheel": True,
                "authorized_keys_absent": True,
            }):
        raise ValueError("Disposable account gained a password, key or administrative group")
    remaining_timeout(
        local_deadline, VERIFIER_PHASE_BUDGETS["local-validation-and-report"])
    report = {
        "schema": 1, "nonce": expected["nonce"], "source_binding": expected["source_binding"],
        "probe_sha256": digest(Path(__file__)), "expected_sha256": digest(expected_path),
        "passed": True, "guest_booted": True, "graphical_desktop_observed": True,
        "os_qualified": False, "release_qualified": False, "signature_qualified": False,
        "network_interfaces": sorted(path.name for path in Path("/sys/class/net").iterdir()),
        "default_target": default_target, "display_manager": "sddm.service",
        "session": "symbi.desktop", "fixture_user": fixture_user,
        "interactive_devices": interactive,
        "fixture_cleanup": {
            "persistent_boot_wants_absent": True, "persistent_scripts_absent": True,
            "persistent_units_absent": True, "credentials_absent": True,
        },
        "desktop_components": {
            "Hyprland": "/usr/lib/symbi/hyprland/bin/Hyprland" in executables,
            "Waybar": "/usr/bin/waybar" in executables,
            "Walker": walker_launch["observed"] and walker_launch["stopped"],
            "portal": portal_executable in executables,
            "first_login_seeded": True,
        },
        "walker_launch": walker_launch,
        "autologin_sha256": digest(autologin),
        "scope": SCOPE,
    }
    raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    remaining_timeout(
        local_deadline,
        VERIFIER_PHASE_BUDGETS["local-validation-and-report"],
    )
    status("verifier-report-write-start")
    write_guest_report(CHANNEL, raw, local_deadline)
    status("verifier-report-write-complete")


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        status("verifier-failed")
        raise
