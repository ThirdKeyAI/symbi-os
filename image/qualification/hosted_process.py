"""Long bounded runner for the one fixed hosted Landlock controller."""
import os
from pathlib import Path
import re
import selectors
import subprocess
import time


TIMEOUT_SECONDS = 6000
MAX_BYTES = 1024**2


def _bounded_absolute_path(value, maximum):
    return (isinstance(value, str) and value != "/" and "," not in value
            and Path(value).is_absolute() and os.path.normpath(value) == value
            and len(os.fsencode(value)) <= maximum
            and ".." not in Path(value).parts)


def validate_landlock_controller_command(command, expected_cgroup_parent, expected_image):
    """Restrict the extended deadline to the constructed offline controller."""
    if (not isinstance(command, list) or len(command) < 10
            or any(not isinstance(item, str) or "\x00" in item
                   or any(ord(character) < 32 or ord(character) == 127
                          for character in item)
                   for item in command)
            or command[:3] != ["podman", "--cgroup-manager=cgroupfs", "--root"]
            or command[4] != "--runroot" or command[6] != "run"
            or not _bounded_absolute_path(command[3], 4096)
            or not _bounded_absolute_path(command[5], 50)
            or Path(command[3]).name != "root"):
        raise ValueError("extended timeout is restricted to the fixed Landlock controller")
    storage = Path(command[3]).parent
    expected_storage = Path.cwd().resolve() / ".cache/atomic-disk-storage"
    if storage != expected_storage:
        raise ValueError("Landlock controller private storage boundary changed")
    if (not _bounded_absolute_path(expected_cgroup_parent, 4096)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", expected_image or "") is None):
        raise ValueError("invalid trusted Landlock controller identity")
    unit = Path(expected_cgroup_parent).name
    if re.fullmatch(r"symbi-landlock-[0-9]+-[0-9]+\.service", unit) is None:
        raise ValueError("Landlock controller cgroup boundary changed")
    if command[5] != "/run/" + unit.removesuffix(".service"):
        raise ValueError("Landlock controller runtime boundary changed")
    expected = [
        "podman", "--cgroup-manager=cgroupfs", "--root", str(storage / "root"),
        "--runroot", command[5], "run", "--rm", "--name=symbi-landlock-qemu",
        "--pull=never", "--network=none", "--pid=private",
        "--cgroup-parent=" + expected_cgroup_parent,
        "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1", "--read-only",
        "--user=10001:10001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--memory=3g", "--memory-swap=3g", "--cpus=2", "--pids-limit=64",
        "--mount", f"type=bind,src={storage / 'landlock-input'},dst=/inputs,ro",
        "--mount", f"type=bind,src={storage / 'disk/atomic.raw'},dst=/inputs/atomic.raw,ro",
        "--mount", f"type=bind,src={storage / 'landlock-source.raw'},dst=/inputs/source.raw,ro",
        "--mount", f"type=bind,src={storage / 'landlock-output'},dst=/output",
        "--entrypoint=/usr/bin/python3", expected_image, "/inputs/boot.py",
    ]
    if command != expected:
        raise ValueError("Landlock controller isolation or input shape changed")
    return command


def run_landlock_controller(command, stdout_path, stderr_path,
                            expected_cgroup_parent, expected_image):
    """Run only the validated controller within its fixed hosted deadline."""
    validate_landlock_controller_command(command, expected_cgroup_parent, expected_image)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    with Path(stdout_path).open("xb") as stdout, Path(stderr_path).open("xb") as stderr:
        logs = {"stdout": stdout, "stderr": stderr}
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as child, \
                selectors.DefaultSelector() as selector:
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
                            min(4096, MAX_BYTES - len(captured[channel]) + 1),
                        )
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(captured[channel]) + len(chunk) > MAX_BYTES:
                            raise ValueError(
                                "Landlock controller output exceeded evidence bound: " + channel)
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
