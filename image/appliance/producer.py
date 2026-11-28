"""Convert one installed raw disk into a provisioned compressed qcow2."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

try:
    from .contract import (APPLIANCE_CONTAINER_LIMITS, ARTIFACT_NAME,
                           FIRST_BOOT_TIMEOUT_SECONDS, SCOPE,
                           VIRTUAL_DISK_BYTES, failure_record,
                           provision_qemu_arguments, sha256, unique_json,
                           validate_guest_report, validate_source_binding)
except ImportError:  # Copied as a standalone hosted-container program.
    from contract import (APPLIANCE_CONTAINER_LIMITS, ARTIFACT_NAME,
                          FIRST_BOOT_TIMEOUT_SECONDS, SCOPE,
                          VIRTUAL_DISK_BYTES, failure_record,
                          provision_qemu_arguments, sha256, unique_json,
                          validate_guest_report, validate_source_binding)


def bounded(path, maximum):
    if path.exists() and (path.is_symlink() or not path.is_file() or path.stat().st_size > maximum):
        raise ValueError("Appliance output exceeded its bound: " + path.name)


def load_guest_report(path):
    """Read the final bounded report without turning its absence into a JSON error."""
    if (not path.exists() or path.is_symlink() or not path.is_file()
            or not 0 < path.stat().st_size <= 128*1024):
        raise RuntimeError("Graphical fixture guest emitted no bounded guest report")
    return unique_json(path.read_bytes())


def await_first_boot_report(child, start, evidence):
    """Accept a report only after one timely, clean, success-triggered QEMU exit."""
    while child.poll() is None:
        for name, maximum in (("provision-qemu.log", 2*1024**2),
                              ("provision-serial.log", 4*1024**2),
                              ("guest-report.json", 128*1024)):
            bounded(evidence / name, maximum)
        if time.monotonic() - start >= FIRST_BOOT_TIMEOUT_SECONDS:
            raise TimeoutError("Graphical fixture boot did not finish in 20 minutes")
        time.sleep(0.5)
    elapsed = time.monotonic() - start
    if elapsed >= FIRST_BOOT_TIMEOUT_SECONDS:
        raise TimeoutError("Graphical fixture boot did not finish in 20 minutes")
    if child.returncode != 0:
        raise RuntimeError("Graphical fixture QEMU failed")
    return elapsed, load_guest_report(evidence / "guest-report.json")


def main():
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use only the unprivileged hosted appliance container")
    group = Path("/sys/fs/cgroup") / Path(
        Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    process = {key: value.strip() for key, value in
               (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    if (limits != APPLIANCE_CONTAINER_LIMITS
            or process["CapEff"] != "0000000000000000" or process["NoNewPrivs"] != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or not os.statvfs("/inputs/atomic.raw").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("Appliance producer isolation changed")
    inputs, output = Path("/inputs"), Path("/output")
    expected = unique_json((inputs / "expected.json").read_bytes())
    source = validate_source_binding(expected.get("source_binding"))
    result = failure_record(source, "producer-incomplete")
    result.update({"limits": limits, "command": provision_qemu_arguments()})
    child = None
    work, evidence, public = output / "work", output / "evidence", output / "public"
    try:
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise ValueError("Appliance producer requires a new empty output directory")
        for path in (work, evidence, public):
            path.mkdir(mode=0o700)
        raw = inputs / "atomic.raw"
        if (raw.is_symlink() or not raw.is_file() or raw.stat().st_size != VIRTUAL_DISK_BYTES
                or sha256(raw) != source["installed_raw_sha256"]):
            raise ValueError("Installed raw disk differs from its source binding")
        for name in ("contract.py", "p.service", "v.service", "provision.py", "verify.py", "expected.json"):
            path = inputs / name
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 256*1024:
                raise ValueError("Missing bounded appliance fixture input: " + name)
        result["qemu_version"] = subprocess.check_output(
            ["/usr/bin/qemu-system-x86_64", "--version"], text=True, timeout=15)
        result["tools"] = {name: sha256(Path("/usr/bin") / name)
                           for name in ("qemu-system-x86_64", "qemu-img")}
        with (evidence / "convert-raw.log").open("x") as log:
            subprocess.run(["/usr/bin/qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                            str(raw), str(work / "provisioned.qcow2")],
                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=1200)
        command = provision_qemu_arguments()
        start = time.monotonic()
        with (evidence / "provision-qemu.log").open("x") as log:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                          "HOME": "/output"})
            elapsed, report = await_first_boot_report(child, start, evidence)
        result["provision_exit_code"] = child.returncode
        result["provision_elapsed_seconds"] = elapsed
        report_path = evidence / "guest-report.json"
        validate_guest_report(report, expected, sha256(inputs / "verify.py"),
                              sha256(inputs / "expected.json"))
        if report.get("autologin_sha256") != expected.get("sddm_config_sha256"):
            raise ValueError("Development-only SDDM configuration changed")
        artifact_path = public / ARTIFACT_NAME
        with (evidence / "compress-qcow2.log").open("x") as log:
            subprocess.run(["/usr/bin/qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", "-c",
                            str(work / "provisioned.qcow2"), str(artifact_path)],
                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=1200)
            subprocess.run(["/usr/bin/qemu-img", "check", "-f", "qcow2", str(artifact_path)],
                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=300)
        info = json.loads(subprocess.check_output(
            ["/usr/bin/qemu-img", "info", "--output=json", str(artifact_path)],
            timeout=30, text=True))
        if (info.get("format") != "qcow2" or info.get("virtual-size") != VIRTUAL_DISK_BYTES
                or artifact_path.is_symlink() or not artifact_path.is_file()
                or not 0 < artifact_path.stat().st_size <= VIRTUAL_DISK_BYTES):
            raise ValueError("Compressed qcow2 identity changed")
        artifact = {
            "name": ARTIFACT_NAME, "bytes": artifact_path.stat().st_size,
            "sha256": sha256(artifact_path), "format": "qcow2",
            "compression": "qcow2-zlib-clusters", "virtual_bytes": VIRTUAL_DISK_BYTES,
        }
        result = {
            "schema": 1, "passed": True, "guest_booted": True,
            "graphical_desktop_observed": True, "artifact_retained": True,
            "independent_reboot_passed": False, "os_qualified": False,
            "release_qualified": False, "signature_qualified": False,
            "source_binding": source, "artifact": artifact,
            "guest_report_sha256": sha256(report_path), "limits": limits,
            "command": command, "qemu_version": result["qemu_version"],
            "tools": result["tools"], "scope": SCOPE,
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
                           "graphical_desktop_observed": False, "artifact_retained": False})
        if work.exists() and not work.is_symlink():
            shutil.rmtree(work)
        result["cgroup_final"] = {name: (group / name).read_text().strip()
                                  for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(line.split() for line in result["cgroup_final"]["memory.events"].splitlines())
        if any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill")):
            result.update({"passed": False, "guest_booted": False,
                           "graphical_desktop_observed": False, "artifact_retained": False})
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if not result["passed"]:
        raise RuntimeError("Interactive appliance production did not pass")


if __name__ == "__main__":
    main()
