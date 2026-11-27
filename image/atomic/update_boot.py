"""Coordinate disposable signature controls and persistent update recovery."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


MAX_REPORT = 128 * 1024
DISPOSABLE_PHASE_TIMEOUT_SECONDS = 1800
NEGATIVE_CASES = ("unsigned", "wrong-key", "wrong-reference", "altered-signature")
NEGATIVE_UPDATE_SOURCE = "/run/symbi-update-negative/source"
POSITIVE_OVERLAY_CASE = "valid-signature"
LAUNCHER_FAILURE_SCOPE = "Bounded launcher-preparation diagnostics; no update action ran"
LAUNCHER_FAILURE_JOURNAL_COMMAND = [
    "/usr/bin/journalctl", "--unit=b.service", "--boot=0", "--no-pager",
    "--output=short-monotonic", "--lines=24",
]
LAUNCHER_FAILURE_JOURNAL_MAX_BYTES = 8 * 1024
LAUNCHER_FAILURE_JOURNAL_MAX_LINES = 24
LAUNCHER_FAILURE_JOURNAL_MAX_LINE_BYTES = 512
_SENSITIVE_COMPONENT = (
    r"(?:(?:api|private)[_.-]key|authorization|authentication|auth|cookie|"
    r"credential|password|passwd|passphrase|secret|token|jwt|pat|key)"
)
_SENSITIVE_IDENTIFIER = (
    r"(?:[A-Za-z0-9]+[_.-])*" + _SENSITIVE_COMPONENT
    + r"(?:[_.-][A-Za-z0-9]+)*"
)
_SENSITIVE_KEY = (
    r"(?:[\"']" + _SENSITIVE_IDENTIFIER + r"[\"']"
    + r"|-{1,2}" + _SENSITIVE_IDENTIFIER
    + r"|" + _SENSITIVE_IDENTIFIER + r")"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(" + _SENSITIVE_KEY
    + r")(\s*[:=]\s*|\s+)(.*)$"
)


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


def validate_launcher_failure_report(report, runner_hash):
    """Accept only the hash-bound, bounded launcher failure diagnostic."""
    required = {
        "schema", "passed", "guest_booted", "release_qualified", "product",
        "diagnostic", "unit", "runner_sha256", "service", "journal", "scope",
    }
    if (not isinstance(report, dict) or set(report) != required
            or report.get("schema") != 1 or report.get("passed") is not False
            or report.get("guest_booted") is not True
            or report.get("release_qualified") is not False
            or report.get("product") != "Symbi-Hosted-Update-Probe"
            or report.get("diagnostic") != "launcher-preparation-failure"
            or report.get("unit") != "b.service"
            or report.get("runner_sha256") != runner_hash
            or re.fullmatch(r"[a-f0-9]{64}", runner_hash or "") is None
            or report.get("scope") != LAUNCHER_FAILURE_SCOPE):
        raise ValueError("unbound launcher-preparation failure report")
    service = report.get("service")
    service_fields = {
        "Result", "ExecMainCode", "ExecMainStatus", "ActiveState", "SubState",
    }
    if (not isinstance(service, dict) or set(service) != service_fields
            or service.get("Result") == "success"
            or service.get("ActiveState") != "failed"
            or service.get("SubState") != "failed"
            or re.fullmatch(r"[0-9]{1,3}", service.get("ExecMainCode", "")) is None
            or re.fullmatch(r"[0-9]{1,3}", service.get("ExecMainStatus", "")) is None
            or service.get("ExecMainStatus") == "0"
            or any(not isinstance(value, str) or not value or len(value.encode()) > 128
                   for value in service.values())):
        raise ValueError("launcher-preparation service failure is incomplete")
    journal = report.get("journal")
    journal_fields = {
        "unit", "command", "line_count", "bytes", "sha256", "truncated", "excerpt",
    }
    if (not isinstance(journal, dict) or set(journal) != journal_fields
            or journal.get("unit") != "b.service"
            or journal.get("command") != LAUNCHER_FAILURE_JOURNAL_COMMAND
            or type(journal.get("line_count")) is not int
            or not 0 <= journal["line_count"] <= LAUNCHER_FAILURE_JOURNAL_MAX_LINES
            or type(journal.get("bytes")) is not int
            or not 0 <= journal["bytes"] <= LAUNCHER_FAILURE_JOURNAL_MAX_BYTES
            or type(journal.get("truncated")) is not bool
            or re.fullmatch(r"[a-f0-9]{64}", journal.get("sha256", "")) is None
            or not isinstance(journal.get("excerpt"), list)
            or len(journal["excerpt"]) != journal["line_count"]):
        raise ValueError("launcher-preparation journal metadata is incomplete")
    for line in journal["excerpt"]:
        sensitive_assignment = (_SENSITIVE_ASSIGNMENT.search(line)
                                if isinstance(line, str) else None)
        if (not isinstance(line, str)
                or len(line.encode("ascii", errors="ignore")) != len(line)
                or len(line.encode("ascii")) > LAUNCHER_FAILURE_JOURNAL_MAX_LINE_BYTES
                or any(not " " <= character <= "~" for character in line)
                or (sensitive_assignment is not None
                    and sensitive_assignment.group(3) != "<redacted>")
                or re.search(r"(?i)\bbearer\s+(?!<redacted>)[^ ]+", line)
                or re.search(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{48,}(?![A-Za-z0-9])",
                             line)):
            raise ValueError("launcher-preparation journal excerpt is unsafe")
    payload = ("\n".join(journal["excerpt"])
               + ("\n" if journal["excerpt"] else "")).encode("ascii")
    if (len(payload) != journal["bytes"]
            or hashlib.sha256(payload).hexdigest() != journal["sha256"]):
        raise ValueError("launcher-preparation journal digest differs")
    return report


def stop_child(child):
    """Best-effort QEMU cleanup that never masks the primary gate failure."""
    result = {"attempted": False, "terminated": False, "killed": False, "errors": []}
    if child is None or child.poll() is not None:
        return result
    result["attempted"] = True
    try:
        child.terminate()
        result["terminated"] = True
    except OSError as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    else:
        try:
            child.wait(timeout=10)
            return result
        except subprocess.TimeoutExpired:
            pass
    try:
        child.kill()
        result["killed"] = True
    except OSError as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    else:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            result["errors"].append(type(error).__name__ + ": " + str(error))
    return result


def firmware_arguments(directory=Path("/inputs"), expected_filename="expected.json"):
    allowed = {"expected.json", "expected-positive.json",
               *("expected-" + case + ".json" for case in NEGATIVE_CASES)}
    if directory != Path("/inputs") or expected_filename not in allowed:
        raise ValueError("fixed update firmware input required")
    files = [
        ("systemd.extra-unit.o.service", "update-o.service"),
        ("systemd.extra-unit.s.service", "s.service"),
        ("systemd.extra-unit.b.service", "update-b.service"),
        ("systemd.extra-unit.f.service", "update-f.service"),
        ("symbi-update.py", "update_guest.py"),
        ("symbi-update-failure.py", "update_boot_failure.py"),
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
        "-drive", "file=" + overlay + ",format=qcow2,if=none,id=symbi-boot-disk",
        "-device", "virtio-blk-pci,drive=symbi-boot-disk,bootindex=1",
        "-drive", "file=/inputs/update.raw,format=raw,if=none,"
                  "id=symbi-update-source,readonly=on",
        "-device", "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE",
        "-boot", "strict=on",
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


def validate_source_device(report, expected):
    """Bind guest block evidence to the authenticated source-disk identity."""
    try:
        observed = report["source_device"]
        source = expected["source_disk"]
    except (KeyError, TypeError) as error:
        raise ValueError("update source-device evidence is missing") from error
    required = {"path", "serial", "TYPE", "LABEL", "UUID"}
    if (not isinstance(observed, dict) or set(observed) != required
            or re.fullmatch(r"/dev/vd[a-z]{1,3}", observed.get("path", "")) is None
            or observed.get("serial") != "SYMBIUPDATE"
            or source.get("serial") != "SYMBIUPDATE"
            or observed.get("TYPE") != source.get("filesystem")
            or observed.get("LABEL") != source.get("label")
            or observed.get("UUID") != source.get("uuid")):
        raise ValueError("update source-device evidence is unbound")


def validate_status_observations(report, expected_count):
    """Require every deployment snapshot to come from the fixed direct unit."""
    expected_service = {
        "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
        "ActiveState": "active", "SubState": "exited",
    }
    observations = report.get("status_observations")
    commands = report.get("commands")
    if (type(expected_count) is not int or expected_count < 1
            or not isinstance(observations, list)
            or len(observations) != expected_count
            or not isinstance(commands, list)):
        raise ValueError("fixed bootc status observations are incomplete")
    for sequence, observation in enumerate(observations, 1):
        if (not isinstance(observation, dict)
                or set(observation) != {
                    "sequence", "unit", "service", "bytes", "sha256"
                }
                or observation.get("sequence") != sequence
                or observation.get("unit") != "s.service"
                or observation.get("service") != expected_service
                or type(observation.get("bytes")) is not int
                or not 0 < observation["bytes"] <= MAX_REPORT
                or re.fullmatch(r"[a-f0-9]{64}",
                                observation.get("sha256", "")) is None):
            raise ValueError("fixed bootc status observation is unbound")
    starts = [item for item in commands if item.get("command") ==
              ["/usr/bin/systemctl", "restart", "s.service"]]
    shows = [item for item in commands if item.get("command") == [
        "/usr/bin/systemctl", "show", "s.service",
        "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState",
    ]]
    if (len(starts) != expected_count or len(shows) != expected_count
            or any(item.get("exit_code") != 0 for item in starts + shows)
            or any(item.get("command", [None])[0:1] == ["/usr/bin/bootc"]
                   for item in commands)):
        raise ValueError("status bypassed the fixed direct bootc unit")


def validate_launcher(report):
    """Require the root-only bootc copy prepared and labeled by install_t."""
    launcher = report.get("bootc_launcher")
    service = {
        "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
        "ActiveState": "active", "SubState": "exited",
    }
    commands = report.get("commands")
    show_command = [
        "/usr/bin/systemctl", "show", "b.service",
        "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState",
    ]
    if (not isinstance(launcher, dict)
            or set(launcher) != {
                "unit", "service", "source", "path", "label_reference",
                "source_sha256", "copy_sha256", "selinux_label", "mode",
                "removed",
            }
            or launcher.get("unit") != "b.service"
            or launcher.get("service") != service
            or launcher.get("source") != "/usr/bin/bootc"
            or launcher.get("path") != "/run/symbi-update-bootc"
            or launcher.get("label_reference") != "/usr/bin/ostree"
            or launcher.get("source_sha256") != launcher.get("copy_sha256")
            or re.fullmatch(r"[a-f0-9]{64}",
                            launcher.get("source_sha256", "")) is None
            or not isinstance(launcher.get("selinux_label"), str)
            or re.fullmatch(r"[^:\x00]+:object_r:install_exec_t:[^\x00]+",
                            launcher["selinux_label"]) is None
            or launcher.get("mode") != "0700"
            or launcher.get("removed") is not True
            or not isinstance(commands, list)
            or len([item for item in commands
                    if item.get("command") == show_command
                    and item.get("exit_code") == 0]) != 1):
        raise ValueError("fixed SELinux bootc launcher is unbound")
    return launcher


def validate_operation_observation(report, operation, expected_success):
    """Bind one exact mutation to the validated labeled bootc copy."""
    paths = {
        "negative": ["switch", "--transport", "dir",
                     "--enforce-container-sigpolicy", NEGATIVE_UPDATE_SOURCE],
        "positive": ["switch", "--transport", "dir",
                     "--enforce-container-sigpolicy", "/run/symbi-update/source"],
        "rollback": ["rollback"],
    }
    observation = report.get("bootc_operation")
    commands = report.get("commands")
    expected_command = ["/run/symbi-update-bootc", *paths.get(operation, [])]
    validate_launcher(report)
    if (operation not in paths or type(expected_success) is not bool
            or not isinstance(observation, dict)
            or set(observation) != {
                "name", "command", "exit_code", "stderr", "stderr_sha256"
            }
            or observation.get("name") != operation
            or observation.get("command") != expected_command
            or type(observation.get("exit_code")) is not int
            or not isinstance(observation.get("stderr"), str)
            or len(observation["stderr"].encode()) > 128 * 1024
            or hashlib.sha256(observation["stderr"].encode()).hexdigest()
               != observation.get("stderr_sha256")
            or not isinstance(commands, list)):
        raise ValueError("fixed bootc operation observation is unbound")
    if expected_success:
        if observation["exit_code"] != 0:
            raise ValueError("fixed bootc operation did not succeed")
    elif (observation["exit_code"] == 0
          or "signature" not in observation["stderr"].lower()):
        raise ValueError("native bootc signature rejection reason is incomplete")
    matches = [item for item in commands if item.get("command") == expected_command]
    other_bootc = [item for item in commands
                   if item.get("command", [None])[0:1]
                   in (["/usr/bin/bootc"], ["/run/symbi-update-bootc"])
                   and item.get("command") != expected_command]
    if (len(matches) != 1
            or matches[0].get("exit_code") != observation["exit_code"]
            or matches[0].get("stderr") != observation["stderr"]
            or other_bootc):
        raise ValueError("mutation bypassed the fixed labeled bootc command")


def validate_phase_report(report, expected, expected_hash, runner_hash, phase):
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True,
                "phase": phase}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete update guest phase")
    validate_source_device(report, expected)
    name = phase.get("name")
    validate_status_observations(report, 1 if name == "rolled-back" else 2)
    if name == "installed":
        validate_operation_observation(report, "positive", True)
    elif name == "updated":
        validate_operation_observation(report, "rollback", True)
    elif name == "rolled-back":
        if "bootc_operation" in report:
            raise ValueError("rollback verification unexpectedly mutated the deployment")
        validate_launcher(report)
    else:
        raise ValueError("unknown update phase report")
    commands = report.get("commands")
    if (not isinstance(commands, list) or not commands
            or any(item.get("exit_code") != 0 for item in commands)):
        raise ValueError("update guest command evidence is incomplete")


def validate_positive_report(report, expected, expected_hash, runner_hash):
    required = {"schema": 1, "passed": True, "guest_booted": True,
                "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
                "nonce": expected["nonce"], "expected_sha256": expected_hash,
                "runner_sha256": runner_hash, "source_mounted_readonly": True}
    if any(report.get(key) != value for key, value in required.items()) or "failure" in report:
        raise ValueError("unbound or incomplete same-path positive update report")
    validate_source_device(report, expected)
    validate_status_observations(report, 2)
    validate_operation_observation(report, "negative", True)
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
    commands = report.get("commands")
    if (not isinstance(commands, list) or not commands
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
    validate_source_device(report, expected)
    validate_status_observations(report, 2)
    validate_operation_observation(report, "negative", False)
    control = report.get("negative_control")
    if (not isinstance(control, dict) or control.get("case") != case
            or control.get("switch_rejected") is not True
            or type(control.get("switch_exit_code")) is not int
            or control["switch_exit_code"] == 0
            or control["switch_exit_code"] != report["bootc_operation"]["exit_code"]
            or control.get("deployment_unchanged") is not True
            or control.get("default_unchanged") is not True
            or control.get("source") != NEGATIVE_UPDATE_SOURCE
            or control.get("source_readonly") is not True
            or not isinstance(control.get("state_sha256"), str)
            or len(control["state_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in control["state_sha256"])):
        raise ValueError("native bootc rejection did not preserve the deployment state")
    commands = report.get("commands")
    failed_switches = [item for item in commands if item.get("command") ==
                       report["bootc_operation"]["command"]]
    if (len(failed_switches) != 1 or failed_switches[0].get("exit_code") == 0
            or any(item.get("exit_code") != 0 for item in commands
                   if item is not failed_switches[0])):
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
    if (source.get("serial") != "SYMBIUPDATE"
            or (inputs / "update.raw").stat().st_size != source.get("bytes")
            or sha256(inputs / "update.raw") != source.get("sha256")):
        raise ValueError("authenticated update source disk changed")
    names = ["update_guest.py", "update_boot_failure.py", "expected.json",
             "update-policy.json", "update-o.service", "s.service",
             "update-b.service", "update-f.service"]
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
            "same-path-positive-serial.log", DISPOSABLE_PHASE_TIMEOUT_SECONDS)
        positive_report = unique_json(path.read_bytes())
        if positive_report.get("diagnostic") == "launcher-preparation-failure":
            record["launcher_failure"] = validate_launcher_failure_report(
                positive_report, hashes["update_boot_failure.py"])
            raise RuntimeError("launcher preparation failed; inspect bounded report")
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
                "negative-" + case + ".json", "negative-" + case + "-serial.log",
                DISPOSABLE_PHASE_TIMEOUT_SECONDS)
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
        cleanup = stop_child(child)
        record["child_cleanup"] = cleanup
        if cleanup["attempted"]:
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
