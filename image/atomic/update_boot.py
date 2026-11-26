"""Coordinate disposable signature controls and persistent update recovery."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


MAX_REPORT = 128 * 1024
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
NEGATIVE_UPDATE_SOURCE = "/run/symbi-update-negative/source"
POSITIVE_OVERLAY_CASE = "valid-signature"


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


def firmware_arguments(directory=Path("/inputs"), expected_filename="expected.json"):
    allowed = {"expected.json", "expected-positive.json",
               *("expected-" + case + ".json" for case in NEGATIVE_CASES)}
    if directory != Path("/inputs") or expected_filename not in allowed:
        raise ValueError("fixed update firmware input required")
    files = [
        ("fstab.extra", "update-fstab.extra"),
        ("systemd.extra-unit.o.service", "update-o.service"),
        ("symbi-update.py", "update_guest.py"),
        ("symbi-update-expected.json", expected_filename),
        ("symbi-update-policy.json", "update-policy.json"),
    ]
    result = []
    for name, filename in files:
        name = "opt/io.systemd.credentials/" + name
        if len(name.encode("ascii")) >= 56:
            raise ValueError("QEMU update firmware name is too long")
        result += ["-fw_cfg", "name=" + name + ",file=" + str(directory / filename)]
    return result


def _qemu_command(overlay, report, serial, expected_filename,
                  directory=Path("/inputs"), output=Path("/output")):
    if (directory != Path("/inputs") or output != Path("/output")
            or any(not isinstance(value, str) or not value.startswith("/output/")
                   for value in (overlay, report, serial))):
        raise ValueError("fixed update QEMU paths and mounts required")
    return [
        "/usr/bin/qemu-system-x86_64", "-machine", "q35,dump-guest-core=off",
        "-accel", "tcg,thread=single", "-cpu", "max", "-m", "2048M", "-smp", "1",
        "-nodefaults", "-no-user-config", "-no-reboot", "-net", "none",
        "-smbios", "type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Update-Probe",
        "-drive", "file=" + overlay + ",format=qcow2,if=virtio",
        "-drive", "file=/inputs/update.raw,format=raw,if=virtio,readonly=on",
        "-device", "virtio-rng-pci", "-device", "virtio-serial-pci",
        "-chardev", "file,id=report,path=" + report,
        "-device", "virtserialport,chardev=report,name=org.symbi.update",
        "-serial", "file:" + serial, "-monitor", "none", "-display", "none",
        *firmware_arguments(directory, expected_filename),
    ]


def qemu_command(index, directory=Path("/inputs"), output=Path("/output")):
    if type(index) is not int or not 0 <= index <= 2:
        raise ValueError("fixed update QEMU phase required")
    return _qemu_command("/output/guest.qcow2", f"/output/phase-{index}.json",
                         f"/output/serial-{index}.log", "expected.json", directory, output)


def negative_qemu_command(case, directory=Path("/inputs"), output=Path("/output")):
    if case not in NEGATIVE_CASES:
        raise ValueError("fixed update rejection case required")
    return _qemu_command(f"/output/negative-{case}.qcow2",
                         f"/output/negative-{case}.json",
                         f"/output/negative-{case}-serial.log",
                         f"expected-{case}.json", directory, output)


def positive_qemu_command(directory=Path("/inputs"), output=Path("/output")):
    return _qemu_command("/output/same-path-positive.qcow2",
                         "/output/same-path-positive.json",
                         "/output/same-path-positive-serial.log",
                         "expected-positive.json", directory, output)


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


def validate_positive_report(report, expected, expected_hash, runner_hash):
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete same-path positive update report")
    control = report.get("same_path_positive_control")
    if (not isinstance(control, dict) or control.get("case") != POSITIVE_OVERLAY_CASE
            or control.get("switch_accepted") is not True
            or control.get("switch_exit_code") != 0
            or control.get("booted_unchanged") is not True
            or control.get("deployment_staged") is not True
            or control.get("default_changed") is not True
            or control.get("staged_digest") != expected["new_digest"]
            or control.get("source") != NEGATIVE_UPDATE_SOURCE
            or control.get("source_readonly") is not True):
        raise ValueError("same-path valid signature did not stage the expected update")
    hashes = (control.get("state_before_sha256"), control.get("state_after_sha256"))
    if (hashes[0] == hashes[1]
            or any(not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None
                   for value in hashes)):
        raise ValueError("same-path positive control did not bind its state transition")
    expected_switch = ["/usr/bin/bootc", "switch", "--transport", "dir",
                       "--enforce-container-sigpolicy", NEGATIVE_UPDATE_SOURCE]
    commands = report.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("same-path positive command evidence is missing")
    switches = [item for item in commands if item.get("command") == expected_switch]
    if (len(switches) != 1 or switches[0].get("exit_code") != 0
            or any(item.get("exit_code") != 0 for item in commands)):
        raise ValueError("real enforced same-path bootc switch acceptance is incomplete")


def validate_negative_report(report, expected, expected_hash, runner_hash, case):
    if case not in NEGATIVE_CASES:
        raise ValueError("unknown update rejection case")
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete negative update guest report")
    control = report.get("negative_control")
    if (not isinstance(control, dict) or control.get("case") != case
            or control.get("switch_rejected") is not True
            or type(control.get("switch_exit_code")) is not int
            or control["switch_exit_code"] == 0
            or control.get("deployment_unchanged") is not True
            or control.get("default_unchanged") is not True
            or control.get("source") != NEGATIVE_UPDATE_SOURCE
            or control.get("source_readonly") is not True
            or not isinstance(control.get("state_sha256"), str)
            or len(control["state_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in control["state_sha256"])):
        raise ValueError("native bootc rejection did not preserve the deployment state")
    expected_switch = ["/usr/bin/bootc", "switch", "--transport", "dir",
                       "--enforce-container-sigpolicy", NEGATIVE_UPDATE_SOURCE]
    commands = report.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("negative update command evidence is missing")
    switches = [item for item in commands if item.get("command") == expected_switch]
    if (len(switches) != 1 or switches[0].get("exit_code") != control["switch_exit_code"]
            or switches[0]["exit_code"] == 0
            or any(item.get("exit_code") != 0 for item in commands if item is not switches[0])):
        raise ValueError("real enforced bootc switch rejection evidence is incomplete")


def validate_shared_baseline(positive_report, negative_report):
    try:
        accepted = positive_report["same_path_positive_control"]["state_before_sha256"]
        rejected = negative_report["negative_control"]["state_sha256"]
    except (KeyError, TypeError) as error:
        raise ValueError("disposable signature control baseline is missing") from error
    if (accepted != rejected or not isinstance(accepted, str)
            or re.fullmatch(r"[a-f0-9]{64}", accepted) is None):
        raise ValueError("negative control did not start from the positive baseline")
    return accepted


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
    names = ["update_guest.py", "expected.json", "update-policy.json",
             "update-o.service", "update-fstab.extra"]
    positive_name = "expected-positive.json"
    positive_raw = (inputs / positive_name).read_bytes()
    if len(positive_raw) > 128 * 1024:
        raise ValueError("oversized same-path positive update expectation")
    positive_candidate = unique_json(positive_raw)
    positive_control = positive_candidate.pop("same_path_positive_control", None)
    if (positive_candidate != expected or positive_control != {
            "case": POSITIVE_OVERLAY_CASE, "source": NEGATIVE_UPDATE_SOURCE}):
        raise ValueError("same-path positive expectation differs from the accepted input")
    positive_expected = unique_json(positive_raw)
    names.append(positive_name)
    negative_expected = {}
    for case in NEGATIVE_CASES:
        name = "expected-" + case + ".json"
        raw = (inputs / name).read_bytes()
        if len(raw) > 128 * 1024:
            raise ValueError("oversized negative update expectation")
        candidate = unique_json(raw)
        control = candidate.pop("negative_control", None)
        signature = control.get("signature") if isinstance(control, dict) else "invalid"
        if (candidate != expected or not isinstance(control, dict)
                or set(control) != {"case", "source", "signature"}
                or control.get("case") != case
                or control.get("source") != NEGATIVE_UPDATE_SOURCE
                or (case == "unsigned" and signature is not None)
                or (case != "unsigned"
                    and (not isinstance(signature, dict)
                         or set(signature) != {"base64", "sha256"}))):
            raise ValueError("negative update expectation differs from the accepted input")
        negative_expected[case] = unique_json(raw)
        names.append(name)
    hashes = {name: sha256(inputs / name) for name in names}
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
              "source_disk": source, "negative_reports": [], "phase_reports": [],
              "scope": "One valid-signature same-path disposable control, four rejection "
                       "overlays, then signed update and rollback on a persistent overlay"}
    child = None
    try:
        def create_overlay(name):
            path = output / name
            with (output / ("prepare-" + name + ".log")).open("x") as log:
                subprocess.run(["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
                                "-b", "/inputs/atomic.raw", str(path)],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=30)
            return path, (path.stat().st_dev, path.stat().st_ino)

        def run_qemu(command, label, report_name, serial_name, timeout):
            nonlocal child
            record["active_phase"] = label
            record["commands"] = record.get("commands", []) + [command]
            (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
            started = time.monotonic()
            log_name = "qemu-" + label + ".log"
            with (output / log_name).open("x") as log:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                         stderr=subprocess.STDOUT,
                                         env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                              "HOME": "/output", "TMPDIR": "/output"})
                while child.poll() is None:
                    for name, maximum in ((serial_name, 2 * 1024 * 1024),
                                          (log_name, 1024 * 1024),
                                          (report_name, MAX_REPORT)):
                        path = output / name
                        if path.exists() and path.stat().st_size > maximum:
                            raise ValueError("update guest output exceeded its bound: " + name)
                    if time.monotonic() - started >= timeout:
                        raise TimeoutError("update guest phase exceeded its bound")
                    time.sleep(0.5)
            if child.returncode != 0:
                raise RuntimeError("update QEMU phase failed; inspect original logs")
            child = None
            path = output / report_name
            if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT:
                raise ValueError("missing bounded update phase report")
            return path, time.monotonic() - started

        positive_overlay, positive_identity = create_overlay("same-path-positive.qcow2")
        path, elapsed = run_qemu(
            positive_qemu_command(), "same-path-positive", "same-path-positive.json",
            "same-path-positive-serial.log", 1200)
        positive_report = unique_json(path.read_bytes())
        validate_positive_report(positive_report, positive_expected,
                                 hashes[positive_name], hashes["update_guest.py"])
        baseline_hash = positive_report["same_path_positive_control"]["state_before_sha256"]
        staged_hash = positive_report["same_path_positive_control"]["state_after_sha256"]
        if ((positive_overlay.stat().st_dev, positive_overlay.stat().st_ino)
                != positive_identity or sha256(inputs / "update.raw") != source["sha256"]):
            raise ValueError("same-path positive overlay or update source identity changed")
        positive_overlay.unlink()
        if positive_overlay.exists() or positive_overlay.is_symlink():
            raise ValueError("same-path positive overlay was not discarded")
        positive_summary = {
            "passed": True, "overlay_discarded": True,
            "negative_baselines_clean": False,
            "source": NEGATIVE_UPDATE_SOURCE, "elapsed_seconds": elapsed,
            "report_sha256": sha256(path), "state_before_sha256": baseline_hash,
            "state_after_sha256": staged_hash,
        }
        record["same_path_positive_control"] = positive_summary

        controls = {}
        for case in NEGATIVE_CASES:
            overlay, identity = create_overlay("negative-" + case + ".qcow2")
            path, elapsed = run_qemu(
                negative_qemu_command(case), "negative-" + case,
                "negative-" + case + ".json", "negative-" + case + "-serial.log", 1200)
            report = unique_json(path.read_bytes())
            validate_negative_report(report, negative_expected[case],
                                     hashes["expected-" + case + ".json"],
                                     hashes["update_guest.py"], case)
            if validate_shared_baseline(positive_report, report) != baseline_hash:
                raise ValueError("positive baseline identity changed between controls")
            if ((overlay.stat().st_dev, overlay.stat().st_ino) != identity
                    or sha256(inputs / "update.raw") != source["sha256"]):
                raise ValueError("negative overlay or read-only update source identity changed")
            overlay.unlink()
            if overlay.exists() or overlay.is_symlink():
                raise ValueError("negative update overlay was not discarded")
            controls[case] = True
            record["negative_reports"].append({
                "case": case, "elapsed_seconds": elapsed,
                "report_sha256": sha256(path), "overlay_discarded": True,
                "state_sha256": report["negative_control"]["state_sha256"],
            })
        positive_summary["negative_baselines_clean"] = True

        overlay, overlay_identity = create_overlay("guest.qcow2")
        for index, phase in enumerate(phases):
            command = qemu_command(index)
            path, elapsed = run_qemu(command, str(index), f"phase-{index}.json",
                                     f"serial-{index}.log", 1800)
            report = unique_json(path.read_bytes())
            validate_phase_report(report, expected, hashes["expected.json"],
                                  hashes["update_guest.py"], phase)
            record["phase_reports"].append({"index": index, "elapsed_seconds": elapsed,
                                            "phase": report["phase"], "report_sha256": sha256(path)})
            if ((overlay.stat().st_dev, overlay.stat().st_ino) != overlay_identity
                    or sha256(inputs / "update.raw") != source["sha256"]):
                raise ValueError("persistent overlay or read-only update source identity changed")
        record.update(passed=True, guest_booted=True, phases=phases,
                      same_path_positive_control=positive_summary,
                      bootc_negative_controls=controls,
                      negative_overlays_discarded=True,
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
