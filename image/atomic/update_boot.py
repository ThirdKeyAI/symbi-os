"""Boot one persistent overlay through signed update and rollback phases."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


MAX_REPORT = 128 * 1024


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate update report key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("update report must be an object")
    return value


def firmware_arguments(directory=Path("/inputs")):
    if directory != Path("/inputs"):
        raise ValueError("fixed update firmware input required")
    files = [
        ("fstab.extra", "update-fstab.extra"),
        ("systemd.extra-unit.o.service", "update-o.service"),
        ("symbi-update.py", "update_guest.py"),
        ("symbi-update-expected.json", "expected.json"),
        ("symbi-update-policy.json", "update-policy.json"),
    ]
    result = []
    for name, filename in files:
        name = "opt/io.systemd.credentials/" + name
        if len(name.encode("ascii")) >= 56:
            raise ValueError("QEMU update firmware name is too long")
        result += ["-fw_cfg", "name=" + name + ",file=" + str(directory / filename)]
    return result


def qemu_command(index, directory=Path("/inputs"), output=Path("/output")):
    if type(index) is not int or not 0 <= index <= 2 or directory != Path("/inputs") or output != Path("/output"):
        raise ValueError("fixed update QEMU phase and mounts required")
    return [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=single", "-cpu", "max", "-m", "2048M", "-smp", "1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Update-Probe",
        "-drive", "file=/output/guest.qcow2,format=qcow2,if=virtio",
        "-drive", "file=/inputs/update.raw,format=raw,if=virtio,readonly=on",
        "-device", "virtio-rng-pci", "-device", "virtio-serial-pci",
        "-chardev", f"file,id=report,path=/output/phase-{index}.json",
        "-device", "virtserialport,chardev=report,name=org.symbi.update",
        "-serial", f"file:/output/serial-{index}.log", "-monitor", "none", "-display", "none",
        *firmware_arguments(directory),
    ]


def validate_phase_report(report, expected, expected_hash, runner_hash, phase):
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True,
                "phase": phase}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete update guest phase")
    commands = report.get("commands")
    if not isinstance(commands, list) or not commands or any(item.get("exit_code") != 0 for item in commands):
        raise ValueError("update guest command evidence is incomplete")


def main():
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use the unprivileged disposable hosted update VM container")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    process = {key: value.strip() for key, value in
               (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    inputs, output = Path("/inputs"), Path("/output")
    if (limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                   "cpu.max": "200000 100000", "pids.max": "64"}
            or process.get("CapEff") != "0000000000000000" or process.get("NoNewPrivs") != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or not os.statvfs(inputs / "atomic.raw").f_flag & os.ST_RDONLY
            or not os.statvfs(inputs / "update.raw").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("update QEMU container isolation changed")
    expected_raw = (inputs / "expected.json").read_bytes()
    if len(expected_raw) > 128 * 1024:
        raise ValueError("oversized update expectation")
    expected = unique_json(expected_raw)
    source = expected.get("source_disk", {})
    if ((inputs / "update.raw").stat().st_size != source.get("bytes")
            or sha256(inputs / "update.raw") != source.get("sha256")):
        raise ValueError("authenticated update source disk changed")
    hashes = {name: sha256(inputs / name)
              for name in ("update_guest.py", "expected.json", "update-policy.json",
                           "update-o.service", "update-fstab.extra")}
    phases = [
        {"name": "installed", "booted_digest": expected["old_digest"],
         "operation": "signed-update-staged", "staged_digest": expected["new_digest"]},
        {"name": "updated", "booted_digest": expected["new_digest"],
         "operation": "rollback-queued", "rollback_digest": expected["old_digest"]},
        {"name": "rolled-back", "booted_digest": expected["old_digest"],
         "rollback_from_digest": expected["new_digest"]},
    ]
    record = {"schema": 1, "passed": False, "guest_booted": False,
              "release_qualified": False, "limits": limits, "inputs": hashes,
              "source_disk": source, "phase_reports": [],
              "scope": "Offline fixture-signed update and booted rollback on one persistent VM overlay"}
    child = None
    try:
        with (output / "prepare.log").open("x") as log:
            subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
                            "-b", "/inputs/atomic.raw", "/output/guest.qcow2"],
                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=30)
        overlay = output / "guest.qcow2"
        overlay_identity = (overlay.stat().st_dev, overlay.stat().st_ino)
        for index, phase in enumerate(phases):
            command = qemu_command(index)
            record["active_phase"] = index
            record["commands"] = record.get("commands", []) + [command]
            (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
            started = time.monotonic()
            with (output / f"qemu-{index}.log").open("x") as log:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                         stderr=subprocess.STDOUT,
                                         env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                              "HOME": "/output", "TMPDIR": "/output"})
                while child.poll() is None:
                    for name, maximum in ((f"serial-{index}.log", 2 * 1024 * 1024),
                                          (f"qemu-{index}.log", 1024 * 1024),
                                          (f"phase-{index}.json", MAX_REPORT)):
                        path = output / name
                        if path.exists() and path.stat().st_size > maximum:
                            raise ValueError("update guest output exceeded its bound: " + name)
                    if time.monotonic() - started >= 1800:
                        raise TimeoutError("update guest phase exceeded 30 minutes")
                    time.sleep(0.5)
            if child.returncode != 0:
                raise RuntimeError("update QEMU phase failed; inspect original logs")
            path = output / f"phase-{index}.json"
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT:
                raise ValueError("missing bounded update phase report")
            report = unique_json(path.read_bytes())
            validate_phase_report(report, expected, hashes["expected.json"],
                                  hashes["update_guest.py"], phase)
            record["phase_reports"].append({"index": index, "elapsed_seconds": time.monotonic() - started,
                                            "phase": report["phase"], "report_sha256": sha256(path)})
            if ((overlay.stat().st_dev, overlay.stat().st_ino) != overlay_identity
                    or sha256(inputs / "update.raw") != source["sha256"]):
                raise ValueError("persistent overlay or read-only update source identity changed")
            child = None
        record.update(passed=True, guest_booted=True, phases=phases,
                      source_disk_unchanged=True, persistent_overlay=True)
        record.pop("active_phase", None)
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
            record["passed"] = False
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                   for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(line.split() for line in record["cgroup_final"]["memory.events"].splitlines())
        if any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill")):
            record["passed"] = False
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    if not record["passed"]:
        raise RuntimeError("hosted update resource controls failed")


if __name__ == "__main__":
    main()
