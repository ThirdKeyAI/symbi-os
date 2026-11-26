#!/usr/bin/env python3
"""Boot the installed Atomic disk for one bounded offline Landlock qualification."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time
import zlib


MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 12 * 1024 * 1024
MAX_REPORT_BYTES = 20 * 1024 * 1024


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate qualification report key")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("qualification report must be a JSON object")
    return result


def firmware_arguments(directory):
    if directory != Path("/inputs"):
        raise ValueError("fixed read-only firmware input mount required")
    files = [
        ("fstab.extra", "fstab.extra"),
        ("systemd.extra-unit.p.service", "p.service"),
        ("systemd.extra-unit.q.service", "q.service"),
        ("systemd.extra-unit.l.service", "l.service"),
        ("symbi-status-server.py", "status_server.py"),
        ("symbi-landlock.py", "landlock.py"),
        ("symbi-runner.py", "guest.py"),
        ("symbi-prepare.py", "prepare.py"),
        ("symbi-expected.json", "expected.json"),
        ("symbi-sysusers.conf", "sysusers.conf"),
    ]
    result = []
    for name, filename in files:
        name = "opt/io.systemd.credentials/" + name
        if len(name.encode("ascii")) >= 56:
            raise ValueError("QEMU firmware name is too long")
        result += ["-fw_cfg", f"name={name},file={directory / filename}"]
    return result


def qemu_command(inputs=Path("/inputs"), output=Path("/output")):
    if inputs != Path("/inputs") or output != Path("/output"):
        raise ValueError("fixed QEMU mounts required")
    return [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=single", "-cpu", "max", "-m", "2048M", "-smp", "1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Landlock-Probe",
        "-drive", "file=/inputs/atomic.raw,format=raw,if=virtio,snapshot=on,readonly=on",
        "-drive", "file=/inputs/source.raw,format=raw,if=virtio,readonly=on",
        "-device", "virtio-rng-pci", "-device", "virtio-serial-pci",
        "-chardev", "file,id=report,path=/output/report.json",
        "-device", "virtserialport,chardev=report,name=org.symbi.qualification",
        "-serial", "file:/output/serial.log", "-monitor", "none", "-display", "none",
        *firmware_arguments(inputs),
    ]


def _safe_artifact_name(name):
    if not isinstance(name, str) or not name or len(name.encode()) > 240:
        raise ValueError("invalid public report name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("unsafe public report path")
    if "private-actions" in path.parts or any(part.lower().endswith((".pem", ".key", ".p12")) for part in path.parts):
        raise ValueError("private qualification material cannot be retained")
    allowed = {"bootc-before.json", "bootc-after.json", "platform.json", "platform.log",
               "release-driver.log", "release"}
    if path.parts[0] not in allowed:
        raise ValueError("unexpected public report path")
    return path


def _bounded_decompress(encoded, compressed_bytes, expected_bytes):
    if (not isinstance(encoded, str) or not isinstance(compressed_bytes, int)
            or not isinstance(expected_bytes, int) or not 0 <= compressed_bytes <= MAX_ARTIFACT_BYTES
            or not 0 <= expected_bytes <= MAX_ARTIFACT_BYTES):
        raise ValueError("invalid artifact size")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid artifact encoding") from error
    if len(compressed) != compressed_bytes:
        raise ValueError("compressed artifact size changed")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("unbounded or malformed compressed artifact")
    raw += decoder.flush(MAX_ARTIFACT_BYTES + 1 - len(raw))
    if len(raw) != expected_bytes:
        raise ValueError("expanded artifact size changed")
    return raw


def validate_guest_report(report, expected, expected_hash, runner_hash, driver_hash):
    required = {
        "schema": 1, "passed": True, "qualified": True, "guest_booted": True,
        "os_qualified": False, "release_qualified": False,
        "product": "Symbi-Hosted-Landlock-Probe", "nonce": expected["nonce"],
        "expected_sha256": expected_hash, "runner_sha256": runner_hash,
        "driver_sha256": driver_hash, "source_revision": expected["source_revision"],
        "source_manifest_sha256": expected["source_manifest_sha256"],
        "binary_sha256": expected["binary_sha256"], "image_ref": expected["image_ref"],
    }
    if any(report.get(key) != value for key, value in required.items()):
        raise ValueError("unbound, incomplete or falsely qualified guest report")
    minimum = expected.get("minimum_landlock_abi", 6)
    if type(report.get("landlock_abi")) is not int or report["landlock_abi"] < minimum:
        raise ValueError("Landlock ABI does not meet the selected minimum")
    summary = report.get("summary")
    artifacts = report.get("artifacts")
    if (not isinstance(summary, dict) or summary.get("passed") is not True
            or summary.get("qualified") is not True or not isinstance(artifacts, dict)
            or not isinstance(summary.get("public_reports"), dict)
            or set(artifacts) != set(summary["public_reports"])):
        raise ValueError("public report allowlist differs from the qualified summary")
    if not artifacts:
        raise ValueError("qualification retained no public reports")
    expanded = {}
    total = 0
    for name, item in artifacts.items():
        path = _safe_artifact_name(name)
        if not isinstance(item, dict) or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")):
            raise ValueError("invalid public artifact metadata")
        raw = _bounded_decompress(item.get("zlib_base64"), item.get("zlib_bytes"), item.get("bytes"))
        total += len(raw)
        if total > MAX_TOTAL_ARTIFACT_BYTES:
            raise ValueError("total public qualification evidence exceeded its bound")
        observed = hashlib.sha256(raw).hexdigest()
        if observed != item["sha256"] or observed != summary["public_reports"].get(name):
            raise ValueError("public report bytes differ from the qualified summary")
        expanded[str(path)] = raw
    return expanded


def main():
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use the unprivileged disposable hosted QEMU container")
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    process = {key: value.strip() for key, value in
               (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    if (limits != {"memory.max": "3221225472", "memory.swap.max": "0",
                   "cpu.max": "200000 100000", "pids.max": "64"}
            or process["CapEff"] != "0000000000000000" or process["NoNewPrivs"] != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or not os.statvfs("/inputs/atomic.raw").f_flag & os.ST_RDONLY
            or not os.statvfs("/inputs/source.raw").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("qualification QEMU container isolation changed")
    inputs, output = Path("/inputs"), Path("/output")
    expected_raw = (inputs / "expected.json").read_bytes()
    if len(expected_raw) > 128 * 1024:
        raise ValueError("oversized qualification expectation")
    expected = unique_json(expected_raw)
    source_disk = expected.get("source_disk", {})
    if ((inputs / "source.raw").stat().st_size != source_disk.get("bytes")
            or sha256(inputs / "source.raw") != source_disk.get("sha256")):
        raise ValueError("authenticated source disk changed")
    hashes = {name: sha256(inputs / name) for name in ("guest.py", "landlock.py", "expected.json")}
    record = {"schema": 1, "passed": False, "guest_booted": False,
              "qualification_qualified": False, "os_qualified": False,
              "release_qualified": False, "limits": limits, "inputs": hashes,
              "source_disk": source_disk,
              "scope": "Offline Landlock qualification on the exact installed development image"}
    child = None
    try:
        command = qemu_command(inputs, output)
        record["command"] = command
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        started = time.monotonic()
        with (output / "qemu.log").open("x") as log:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                          "HOME": "/output", "TMPDIR": "/output"})
            while child.poll() is None:
                for name, maximum in (("serial.log", 2 * 1024 * 1024),
                                      ("qemu.log", 1024 * 1024),
                                      ("report.json", MAX_REPORT_BYTES)):
                    path = output / name
                    if path.exists() and path.stat().st_size > maximum:
                        raise ValueError("guest output exceeded its bound: " + name)
                if time.monotonic() - started >= 5700:
                    raise TimeoutError("Landlock guest did not report and power off within 95 minutes")
                time.sleep(0.5)
        record["exit_code"] = child.returncode
        record["elapsed_seconds"] = time.monotonic() - started
        if child.returncode != 0:
            raise RuntimeError("qualification QEMU failed; inspect original logs")
        path = output / "report.json"
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT_BYTES:
            raise ValueError("missing bounded guest qualification report")
        report = unique_json(path.read_bytes())
        files = validate_guest_report(report, expected, hashes["expected.json"],
                                      hashes["guest.py"], hashes["landlock.py"])
        evidence = output / "evidence"
        evidence.mkdir(mode=0o700)
        for name, raw in files.items():
            target = evidence / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
        (evidence / "summary.json").write_text(json.dumps(report["summary"], indent=2) + "\n")
        if sha256(inputs / "source.raw") != source_disk["sha256"]:
            raise ValueError("read-only source disk changed during qualification")
        record.update(passed=True, guest_booted=True, qualification_qualified=True,
                      source_revision=report["source_revision"],
                      binary_sha256=report["binary_sha256"], landlock_abi=report["landlock_abi"],
                      public_reports=report["summary"]["public_reports"])
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
        raise RuntimeError("hosted Landlock qualification resource controls failed")


if __name__ == "__main__":
    main()
