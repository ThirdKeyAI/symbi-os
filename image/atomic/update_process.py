"""Long bounded runner for the one fixed multi-boot Atomic controller."""
import os
from pathlib import Path
import re
import selectors
import subprocess
import time


TIMEOUT_SECONDS = 5400
MAX_BYTES = 1024**2


def _bounded_absolute_path(value, maximum):
    return (isinstance(value, str) and value != "/"
            and Path(value).is_absolute() and os.path.normpath(value) == value
            and len(os.fsencode(value)) <= maximum
            and ".." not in Path(value).parts)


def validate_update_controller_command(command):
    """Reject use of the extended deadline by any other command shape."""
    if (not isinstance(command, list) or not command
            or any(not isinstance(item, str) or "\x00" in item
                   or any(ord(character) < 32 or ord(character) == 127 for character in item)
                   for item in command)
            or command.count("run") != 1
            or command[-1] != "/inputs/update_boot.py"
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", command[-2])):
        raise ValueError("extended timeout is restricted to the fixed Atomic controller")
    run_index = command.index("run")
    prefix = command[:run_index]
    if (len(prefix) != 6 or prefix[0:3] != ["podman", "--cgroup-manager=cgroupfs", "--root"]
            or prefix[4] != "--runroot"
            or not _bounded_absolute_path(prefix[3], 4096)
            or not _bounded_absolute_path(prefix[5], 50)):
        raise ValueError("Atomic controller Podman storage boundary changed")
    run = command[run_index + 1:-2]
    cgroup_options = [item for item in run if item.startswith("--cgroup-parent=")]
    if len(cgroup_options) != 1:
        raise ValueError("Atomic controller cgroup boundary changed")
    cgroup_parent = cgroup_options[0].partition("=")[2]
    unit = Path(cgroup_parent).name
    if (not _bounded_absolute_path(cgroup_parent, 4096)
            or not re.fullmatch(r"symbi-atomic-disk-[0-9]+-[0-9]+\.service", unit)
            or Path(prefix[5]).name + ".service" != unit):
        raise ValueError("Atomic controller cgroup boundary changed")
    flags = {"--rm", "--read-only"}
    expected = {
        "--name=": "--name=symbi-atomic-update-qemu",
        "--pull=": "--pull=never",
        "--network=": "--network=none",
        "--pid=": "--pid=private",
        "--cgroup-parent=": "--cgroup-parent=" + cgroup_parent,
        "--user=": "--user=10001:10001",
        "--cap-drop=": "--cap-drop=ALL",
        "--security-opt=": "--security-opt=no-new-privileges",
        "--memory=": "--memory=3g",
        "--memory-swap=": "--memory-swap=3g",
        "--cpus=": "--cpus=2",
        "--pids-limit=": "--pids-limit=64",
        "--entrypoint=": "--entrypoint=/usr/bin/python3",
    }
    if (any(run.count(flag) != 1 for flag in flags)
            or any([item for item in run if item.startswith(prefix)] != [value]
                   for prefix, value in expected.items())
            or sorted(item for item in run if item.startswith("--env="))
            != ["--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1"]
            or any(item == "--privileged" or item.startswith((
                "--privileged=", "--cap-add=", "--device=", "--volume="))
                   or item == "-v" or item.startswith("-v=") for item in run)):
        raise ValueError("Atomic controller isolation or resource limits changed")
    allowed = flags | set(expected.values()) | {
        "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1"}
    mounts = []
    index = 0
    while index < len(run):
        item = run[index]
        if item == "--mount":
            if index + 1 >= len(run):
                raise ValueError("missing Atomic controller mount")
            fields = {}
            for field in run[index + 1].split(","):
                key, separator, value = field.partition("=")
                if key in fields:
                    raise ValueError("malformed Atomic controller mount")
                fields[key] = value if separator else True
            mounts.append(fields)
            index += 2
        elif item in allowed:
            index += 1
        else:
            raise ValueError("unexpected Atomic controller option")
    by_target = {mount.get("dst"): mount for mount in mounts}
    if len(mounts) != 4 or set(by_target) != {
            "/inputs", "/inputs/atomic.raw", "/inputs/update.raw", "/output"}:
        raise ValueError("Atomic controller mount set changed")
    for target, mount in by_target.items():
        source = mount.get("src", "")
        expected_fields = {"type", "src", "dst"} | (set() if target == "/output" else {"ro"})
        if (set(mount) != expected_fields or mount.get("type") != "bind"
                or not _bounded_absolute_path(source, 4096)
                or (target != "/output" and mount.get("ro") is not True)):
            raise ValueError("Atomic controller mount access changed")
    return command


def run_update_controller(command, stdout_path, stderr_path):
    """Run only the validated eight-boot controller within its workflow deadline."""
    validate_update_controller_command(command)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    with Path(stdout_path).open("xb") as stdout, Path(stderr_path).open("xb") as stderr:
        logs = {"stdout": stdout, "stderr": stderr}
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as child, selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            deadline = time.monotonic() + TIMEOUT_SECONDS
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, TIMEOUT_SECONDS)
                    for key, _ in selector.select(min(remaining, 0.1)):
                        channel = key.data
                        chunk = os.read(
                            key.fileobj.fileno(),
                            min(4096, MAX_BYTES - len(captured[channel]) + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(captured[channel]) + len(chunk) > MAX_BYTES:
                            raise ValueError("Atomic controller output exceeded evidence bound: "
                                             + channel)
                        captured[channel].extend(chunk)
                        logs[channel].write(chunk)
                        logs[channel].flush()
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
    return subprocess.CompletedProcess(
        command, child.returncode, captured["stdout"].decode("utf-8"),
        captured["stderr"].decode("utf-8"))
