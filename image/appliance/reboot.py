"""Independently reboot retained qcow2 bytes through a new writable overlay."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

try:
    from .contract import (SCOPE, failure_record, reboot_qemu_arguments, sha256,
                           unique_json, validate_source_binding)
except ImportError:  # Copied as a standalone hosted-container program.
    from contract import (SCOPE, failure_record, reboot_qemu_arguments, sha256,
                          unique_json, validate_source_binding)


MINIMUM_SCREENSHOT_SECONDS = 90
LOG_BOUNDS = {"reboot-qemu.log": 2*1024**2, "reboot-serial.log": 4*1024**2}


def require_empty_output(path):
    if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
        raise ValueError("Independent reboot output must be a new empty directory")


def bounded_log(path, maximum, required=False):
    if not path.exists() and not path.is_symlink():
        if required:
            raise ValueError("Missing independent reboot log: " + path.name)
        return
    info = path.lstat()
    if (path.is_symlink() or not path.is_file() or info.st_nlink != 1
            or info.st_size > maximum):
        raise ValueError("Independent reboot log exceeded its bound: " + path.name)


def qmp_message(stream):
    line = stream.readline(65537)
    if not line or len(line) > 65536:
        raise ValueError("Missing or oversized QMP response")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("QMP response must be an object")
    return value


def qmp_request(stream, name, arguments=None):
    request = {"execute": name, "id": name}
    if arguments is not None:
        request["arguments"] = arguments
    stream.write(json.dumps(request).encode() + b"\n")
    stream.flush()
    for _ in range(32):
        response = qmp_message(stream)
        if "event" in response:
            continue
        if response.get("id") != name or "error" in response or "return" not in response:
            raise ValueError("Unexpected QMP response")
        return response["return"]
    raise ValueError("QMP response exceeded event bound")


def ppm_observation(path):
    raw = path.read_bytes()
    if len(raw) > 4*1024**2 or not raw.startswith(b"P6\n"):
        raise ValueError("Unexpected QEMU screenshot format")
    parts = raw.split(b"\n", 3)
    if len(parts) != 4 or parts[2] != b"255":
        raise ValueError("Malformed QEMU screenshot")
    dimensions = parts[1].split()
    if len(dimensions) != 2 or not all(value.isdigit() for value in dimensions):
        raise ValueError("Malformed QEMU screenshot dimensions")
    width, height = map(int, dimensions)
    pixels = parts[3]
    if not 320 <= width <= 4096 or not 200 <= height <= 2160 or len(pixels) != width*height*3:
        raise ValueError("Unexpected QEMU screenshot size")
    stride = max(3, (len(pixels)//4096)//3*3)
    colors = {pixels[index:index+3] for index in range(0, len(pixels)-2, stride)}
    if len(colors) < 2 or colors <= {b"\x00\x00\x00"}:
        raise ValueError("Virtual display remains blank")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "width": width, "height": height, "sampled_colors": len(colors)}


def artifact_identity(path, expected):
    if (path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1
            or path.stat().st_size != expected.get("bytes") or sha256(path) != expected.get("sha256")):
        raise ValueError("Retained qcow2 differs from its exact binding")
    return dict(expected)


def main():
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use only the unprivileged hosted appliance reboot container")
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    process = {key: value.strip() for key, value in
               (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    if (limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                   "cpu.max": "200000 100000", "pids.max": "64"}
            or process["CapEff"] != "0000000000000000" or process["NoNewPrivs"] != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or not os.statvfs("/inputs/retained.qcow2").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("Independent reboot isolation changed")
    expected = unique_json(Path("/program/expected.json").read_bytes())
    source = validate_source_binding(expected.get("source_binding"))
    artifact = expected.get("artifact")
    retained, output = Path("/inputs/retained.qcow2"), Path("/output")
    result = failure_record(source, "reboot-incomplete") | {"limits": limits}
    child = None
    try:
        require_empty_output(output)
        before = artifact_identity(retained, artifact)
        subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                        "-b", str(retained), str(output / "reboot-overlay.qcow2")],
                       stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        command = reboot_qemu_arguments()
        result["command"] = command
        boot_start = time.monotonic()
        with (output / "reboot-qemu.log").open("x") as log:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/output"})
            deadline = time.monotonic() + 600
            while not (output / "qmp.sock").is_socket():
                for name, maximum in LOG_BOUNDS.items():
                    bounded_log(output / name, maximum)
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Independent reboot did not expose QMP")
                time.sleep(0.2)
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(30)
                channel.connect("/output/qmp.sock")
                with channel.makefile("rwb") as stream:
                    greeting = qmp_message(stream)
                    if "QMP" not in greeting:
                        raise ValueError("Invalid QMP greeting")
                    qmp_request(stream, "qmp_capabilities")
                    screenshot = None
                    while time.monotonic() < deadline and child.poll() is None:
                        for name, maximum in LOG_BOUNDS.items():
                            bounded_log(output / name, maximum)
                        status = qmp_request(stream, "query-status")
                        if status.get("running") is not True:
                            raise ValueError("Retained-byte VM is not running")
                        if time.monotonic() - boot_start < MINIMUM_SCREENSHOT_SECONDS:
                            time.sleep(2)
                            continue
                        screen = output / "reboot.ppm"
                        screen.unlink(missing_ok=True)
                        qmp_request(stream, "screendump", {"filename": str(screen)})
                        try:
                            screenshot = ppm_observation(screen)
                            screenshot["boot_elapsed_seconds"] = int(time.monotonic() - boot_start)
                            screen.replace(output / "display.ppm")
                            break
                        except ValueError:
                            time.sleep(5)
                    if screenshot is None:
                        raise TimeoutError("Retained-byte reboot never produced a nonblank display")
                    qmp_request(stream, "system_powerdown")
            child.wait(timeout=120)
        for name, maximum in LOG_BOUNDS.items():
            bounded_log(output / name, maximum, required=True)
        if child.returncode != 0:
            raise RuntimeError("Retained-byte reboot did not power down cleanly")
        after = artifact_identity(retained, artifact)
        if before != after:
            raise ValueError("Read-only retained appliance changed during reboot")
        retained_screen = ppm_observation(output / "display.ppm")
        if retained_screen != {key: screenshot[key] for key in retained_screen}:
            raise ValueError("Retained display evidence changed after capture")
        result = {
            "schema": 1, "passed": True, "guest_booted": True,
            "graphical_desktop_observed": True, "artifact_retained": True,
            "independent_reboot_passed": True, "os_qualified": False,
            "release_qualified": False, "signature_qualified": False,
            "source_binding": source, "artifact_before": before, "artifact_after": after,
            "screenshot": screenshot, "command": command, "limits": limits, "scope": SCOPE,
        }
    except Exception as error:
        result = failure_record(source, type(error).__name__ + ": " + str(error)) | {"limits": limits}
        raise
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
            result.update({"passed": False, "guest_booted": False,
                           "graphical_desktop_observed": False,
                           "artifact_retained": False, "independent_reboot_passed": False})
        result["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(line.split() for line in result["cgroup_final"]["memory.events"].splitlines())
        if any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill")):
            result.update({"passed": False, "guest_booted": False,
                           "graphical_desktop_observed": False,
                           "artifact_retained": False, "independent_reboot_passed": False})
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        for name in ("reboot-overlay.qcow2", "qmp.sock", "reboot.ppm"):
            path = output / name
            if path.exists() or path.is_symlink():
                path.unlink()
        if result.get("passed") is not True:
            display = output / "display.ppm"
            if display.exists() or display.is_symlink():
                display.unlink()
    if not result["passed"]:
        raise RuntimeError("Independent retained-byte reboot did not pass")


if __name__ == "__main__":
    main()
