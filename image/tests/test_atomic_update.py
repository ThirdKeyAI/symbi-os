"""Contracts for the signed installed-image update and booted rollback gate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from image.atomic.update_contract import (NEGATIVE_UPDATE_SOURCE, POSITIVE_OVERLAY_CASE,
                                          update_policy,
                                          update_command, rollback_command,
                                          negative_signature_payloads,
                                          validate_report, require_update_base,
                                          validate_artifact_metadata)
from image.atomic.update_boot import (DISPOSABLE_PHASE_TIMEOUT_SECONDS,
                                      _SENSITIVE_ASSIGNMENT as VALIDATOR_SENSITIVE,
                                      qemu_command, negative_qemu_command,
                                      positive_qemu_command,
                                      firmware_arguments,
                                      stop_child,
                                      validate_transition_failure_report,
                                      validate_phase_report,
                                      validate_negative_report,
                                      validate_positive_report,
                                      validate_shared_baseline)
from image.atomic.update_boot_failure import (JOURNAL_MAX_BYTES,
                                              JOURNAL_MAX_LINES,
                                              JOURNAL_MAX_LINE_BYTES,
                                              _SENSITIVE_ASSIGNMENT as PRODUCER_SENSITIVE,
                                              bounded_journal_excerpt,
                                              service_properties,
                                              write_report as write_failure_report)
from image.atomic.update_process import TIMEOUT_SECONDS, validate_update_controller_command
from image.atomic.update_guest import (UPDATE_COMMAND_TIMEOUT_SECONDS,
                                       BOOTC_CONTEXT, BOOTC_LABEL_REFERENCE,
                                       BOOTC_RUNCON, BOOTC_SOURCE,
                                       FDINFO_MAX_BYTES,
                                       MOUNTINFO_MAX_BYTES,
                                       SOURCE, STATE, SOURCE_SERIAL,
                                       SOURCE_DEVICE_TIMEOUT_SECONDS,
                                       phase_status, deployment_snapshot,
                                       staged_deployment_snapshot,
                                       validate_source_identity,
                                       discover_source_device,
                                       wait_for_source_device,
                                       mount_observation,
                                       parse_visible_mount_id,
                                       read_visible_mount_id,
                                       source_mount_observation,
                                       observe_visible_source_mount,
                                       validate_source_mount,
                                       validate_mounted_device,
                                       _bootc_file_observation,
                                       fixed_bootc_transition,
                                       fixed_bootc_operation,
                                       fixed_bootc_status,
                                       write_channel)
from image.atomic.update_hosted import retain_controller_output, run_update
from image.atomic.hosted import (RETAINED_REPORT_MAX_BYTES,
                                 validate_retained_preflight)
from image.boot.inputs import require_desktop_image
from image.boot.preflight import expected_inputs


class AtomicUpdateTests(unittest.TestCase):
    class ShortWriter:
        def __init__(self, maximum):
            self.maximum = maximum
            self.raw = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, raw):
            count = min(self.maximum, len(raw))
            self.raw.extend(raw[:count])
            return count

    def test_virtio_report_writers_complete_short_writes_and_reject_zero(self):
        payload = b'{"passed":false}\n'
        guest = self.ShortWriter(3)
        with patch.object(Path, "exists", return_value=True), \
                patch.object(Path, "open", return_value=guest):
            write_channel(payload, Path("/unused-channel"))
        self.assertEqual(bytes(guest.raw), payload)

        failure = self.ShortWriter(5)
        with patch.object(Path, "exists", return_value=True), \
                patch.object(Path, "open", return_value=failure):
            write_failure_report({"passed": False}, Path("/unused-channel"))
        self.assertEqual(json.loads(bytes(failure.raw)), {"passed": False})

        for writer in (write_channel,
                       lambda raw, channel: write_failure_report(
                           {"passed": False}, channel)):
            with self.subTest(writer=writer), \
                    patch.object(Path, "exists", return_value=True), \
                    patch.object(Path, "open", return_value=self.ShortWriter(0)), \
                    self.assertRaises(RuntimeError):
                writer(payload, Path("/unused-channel"))

    def test_disposable_vm_deadline_exceeds_the_longest_guest_command(self):
        self.assertEqual(UPDATE_COMMAND_TIMEOUT_SECONDS, 1200)
        self.assertEqual(DISPOSABLE_PHASE_TIMEOUT_SECONDS, 1800)
        self.assertGreater(DISPOSABLE_PHASE_TIMEOUT_SECONDS,
                           UPDATE_COMMAND_TIMEOUT_SECONDS)

    def test_update_qemu_cleanup_does_not_mask_a_primary_failure(self):
        child = Mock()
        child.poll.return_value = None
        child.terminate.side_effect = PermissionError(13, "denied")
        child.kill.side_effect = PermissionError(13, "denied")
        result = stop_child(child)
        self.assertTrue(result["attempted"])
        self.assertFalse(result["terminated"])
        self.assertFalse(result["killed"])
        self.assertEqual(len(result["errors"]), 2)
        self.assertTrue(all("PermissionError" in error for error in result["errors"]))

    def test_exited_update_qemu_receives_no_cleanup_signal(self):
        child = Mock()
        child.poll.return_value = 1
        result = stop_child(child)
        self.assertFalse(result["attempted"])
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_update_qemu_cleanup_escalates_after_terminate_timeout(self):
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [
            subprocess.TimeoutExpired(["qemu-system-x86_64"], 10), None,
        ]
        result = stop_child(child)
        self.assertTrue(result["attempted"])
        self.assertTrue(result["terminated"])
        self.assertTrue(result["killed"])
        self.assertEqual(result["errors"], [])
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()

    def test_failed_update_retains_only_bounded_direct_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed": false}\n')
            (output / "same-path-positive-serial.log").write_text("guest stalled\n")
            (output / "same-path-positive.qcow2").write_bytes(b"private disk")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained,
                             ["controller-result.json", "same-path-positive-serial.log"])
            self.assertEqual((evidence / "controller-result.json").read_text(),
                             '{"passed": false}\n')
            self.assertFalse((evidence / "same-path-positive.qcow2").exists())

    @staticmethod
    def missing_report_controller():
        command = positive_qemu_command()
        command_hash = hashlib.sha256(json.dumps(
            command, separators=(",", ":")).encode()).hexdigest()
        names = {
            "update_boot.py", "update_guest.py", "update_boot_failure.py",
            "expected.json", "update-policy.json", "update-o.service", "s.service",
            "update-b.service", "update-f.service", "expected-positive.json",
            *("expected-" + case + ".json" for case in (
                "unsigned", "wrong-key", "wrong-reference", "altered-signature")),
        }
        limits = {"memory.max": "3221225472", "memory.swap.max": "0",
                  "cpu.max": "200000 100000", "pids.max": "64"}
        return {
            "schema": 1, "passed": False, "guest_booted": False,
            "release_qualified": False, "active_phase": "same-path-positive",
            "failure": "ValueError: missing bounded update phase report",
            "negative_reports": [], "phase_reports": [],
            "commands": [command], "inputs": {name: "a" * 64 for name in names},
            "phase_failure": {
                "label": "same-path-positive", "command_sha256": command_hash,
                "exit_code": 0, "log_name": "qemu-same-path-positive.log",
                "serial_name": "same-path-positive-serial.log",
                "report": {"name": "same-path-positive.json", "state": "empty",
                           "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
            },
            "child_cleanup": {"attempted": False, "terminated": False,
                              "killed": False, "errors": []},
            "limits": limits,
            "cgroup_final": {**limits, "memory.peak": "2147483648",
                             "memory.events": ("low 0\nhigh 0\nmax 17\noom 0\n"
                                               "oom_kill 0\noom_group_kill 0\n"),
                             "cpu.stat": "usage_usec 1\n"},
        }

    def test_missing_report_retains_only_content_free_bound_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            controller = self.missing_report_controller()
            (output / "result.json").write_text(json.dumps(controller) + "\n")
            (output / "same-path-positive.json").write_bytes(b"")
            (output / "same-path-positive-serial.log").write_text(
                "API_TOKEN=must-not-be-retained\n")
            (output / "qemu-same-path-positive.log").write_text(
                "PRIVATE_KEY=must-not-be-retained\n")
            (output / "same-path-positive.qcow2").write_bytes(b"private disk")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json",
                                        "same-path-positive-diagnostic.json"])
            summary = json.loads((evidence / "controller-result.json").read_bytes())
            self.assertTrue(summary["phase_diagnostic_validated"])
            self.assertFalse(summary["transition_failure_validated"])
            diagnostic = json.loads(
                (evidence / "same-path-positive-diagnostic.json").read_bytes())
            self.assertEqual(diagnostic["diagnostic"], "missing-update-phase-report")
            self.assertEqual(diagnostic["process"]["exit_code"], 0)
            self.assertEqual(diagnostic["report"]["state"], "empty")
            self.assertEqual(diagnostic["resources"]["memory.events"], {
                "max": "17", "oom": "0", "oom_group_kill": "0", "oom_kill": "0"})
            retained_raw = b"".join(path.read_bytes() for path in evidence.iterdir())
            self.assertNotIn(b"API_TOKEN", retained_raw)
            self.assertNotIn(b"PRIVATE_KEY", retained_raw)
            self.assertFalse((evidence / "same-path-positive-serial.log").exists())
            self.assertFalse((evidence / "qemu-same-path-positive.log").exists())
            self.assertFalse((evidence / "same-path-positive.qcow2").exists())

    def test_missing_report_diagnostic_rejects_identity_mutations(self):
        for case in ("command", "exit", "report", "input", "cleanup", "resource"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                controller = self.missing_report_controller()
                if case == "command":
                    controller["commands"][0][-1] = "--help"
                elif case == "exit":
                    controller["phase_failure"]["exit_code"] = 1
                elif case == "report":
                    controller["phase_failure"]["report"]["sha256"] = "b" * 64
                elif case == "input":
                    controller["inputs"]["update_guest.py"] = "not-a-hash"
                elif case == "cleanup":
                    controller["child_cleanup"]["attempted"] = True
                else:
                    controller["cgroup_final"]["memory.peak"] = "not-a-number"
                (output / "result.json").write_text(json.dumps(controller) + "\n")
                (output / "same-path-positive.json").write_bytes(b"")
                (output / "same-path-positive-serial.log").write_text(
                    "API_TOKEN=must-not-be-retained\n")
                retained = retain_controller_output(output, evidence)
                self.assertEqual(retained, ["controller-result.json"])
                summary = json.loads(
                    (evidence / "controller-result.json").read_bytes())
                self.assertFalse(summary["transition_failure_validated"])
                self.assertNotIn("phase_diagnostic_validated", summary)
                self.assertEqual([path.name for path in evidence.iterdir()],
                                 ["controller-result.json"])

    def test_transition_failure_report_is_retained_without_private_overlay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            report = self.transition_failure_report()
            controller = self.transition_failure_controller(report)
            controller["unreviewed"] = "API_TOKEN=short"
            controller_raw = (json.dumps(controller, sort_keys=True) + "\n").encode()
            (output / "result.json").write_bytes(controller_raw)
            raw = (json.dumps(report, sort_keys=True) + "\n").encode()
            (output / "same-path-positive.json").write_bytes(raw)
            (output / "same-path-positive-serial.log").write_text(
                "b.service: API_TOKEN=short\n")
            (output / "qemu-same-path-positive.log").write_text(
                "guest console API_TOKEN=short\n")
            (output / "same-path-positive.qcow2").write_bytes(b"private disk")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained,
                             ["controller-result.json", "same-path-positive.json"])
            retained_controller = json.loads(
                (evidence / "controller-result.json").read_bytes())
            self.assertEqual(set(retained_controller), {
                "schema", "passed", "guest_booted", "release_qualified",
                "active_phase", "failure", "negative_reports", "phase_reports",
                "inputs", "transition_failure_validated",
            })
            self.assertTrue(retained_controller["transition_failure_validated"])
            self.assertEqual(retained_controller["inputs"],
                             {"update_boot_failure.py": "a" * 64})
            self.assertEqual(
                retained_controller["failure"],
                "same-path-positive failed; bounded transition report validated")
            self.assertEqual((evidence / "same-path-positive.json").read_bytes(), raw)
            self.assertFalse((evidence / "same-path-positive.qcow2").exists())
            retained_raw = b"".join(path.read_bytes() for path in evidence.iterdir())
            self.assertNotIn(b"API_TOKEN", retained_raw)
            self.assertNotIn(b"API_TOKEN=short", retained_raw)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            report = self.transition_failure_report()
            unredacted = "b.service: API_TOKEN=short"
            payload = (unredacted + "\n").encode("ascii")
            report["journal"].update(
                excerpt=[unredacted], line_count=1, bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest())
            controller = self.transition_failure_controller(
                failure="ValueError: transition-probe journal excerpt is unsafe")
            controller["unreviewed"] = "API_TOKEN=short"
            (output / "result.json").write_text(
                json.dumps(controller, sort_keys=True) + "\n")
            (output / "same-path-positive.json").write_text(
                json.dumps(report, sort_keys=True) + "\n")
            (output / "same-path-positive-serial.log").write_text(
                unredacted + "\n")
            (output / "qemu-same-path-positive.log").write_text(
                unredacted + "\n")
            retained = retain_controller_output(output, evidence)
            self.assertEqual(retained, ["controller-result.json"])
            retained_raw = (evidence / "controller-result.json").read_bytes()
            self.assertNotIn(b"API_TOKEN", retained_raw)
            retained_controller = json.loads(retained_raw)
            self.assertFalse(retained_controller["transition_failure_validated"])
            self.assertEqual(
                retained_controller["failure"],
                "same-path-positive failed; bounded transition report unavailable or rejected")
            self.assertFalse((evidence / "same-path-positive.json").exists())
            self.assertFalse((evidence / "same-path-positive-serial.log").exists())
            self.assertFalse((evidence / "qemu-same-path-positive.log").exists())

        for case, report_raw in (
            ("malformed", b'{"diagnostic":'),
            ("missing-diagnostic", b'{"API_TOKEN":"short","schema":1}\n'),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                controller = self.transition_failure_controller(
                    failure="ValueError: rejected same-path-positive report")
                controller["unreviewed"] = "API_TOKEN=short"
                (output / "result.json").write_text(
                    json.dumps(controller, sort_keys=True) + "\n")
                (output / "same-path-positive.json").write_bytes(report_raw)
                (output / "same-path-positive-serial.log").write_text(
                    "API_TOKEN=short\n")
                (output / "qemu-same-path-positive.log").write_text(
                    "API_TOKEN=short\n")
                retained = retain_controller_output(output, evidence)
                self.assertEqual(retained, ["controller-result.json"])
                retained_raw = (evidence / "controller-result.json").read_bytes()
                self.assertNotIn(b"API_TOKEN", retained_raw)
                self.assertFalse(json.loads(retained_raw)["transition_failure_validated"])
                self.assertEqual([path.name for path in evidence.iterdir()],
                                 ["controller-result.json"])

    def test_failed_update_refuses_unsafe_diagnostic_entries(self):
        for case in ("unexpected", "symlink", "hardlink", "fifo", "socket",
                     "directory", "oversized"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
                (output / "result.json").write_text('{"passed": false}\n')
                path = output / "same-path-positive-serial.log"
                if case == "unexpected":
                    (output / "unreviewed.txt").write_text("x")
                elif case == "symlink":
                    target = root / "target"
                    target.write_text("x")
                    path.symlink_to(target)
                elif case == "hardlink":
                    target = root / "target"
                    target.write_text("x")
                    os.link(target, path)
                elif case == "fifo":
                    os.mkfifo(path)
                elif case == "socket":
                    with socket.socket(socket.AF_UNIX) as server:
                        server.bind(str(path))
                        with self.assertRaises((OSError, ValueError)):
                            retain_controller_output(output, evidence)
                    continue
                elif case == "directory":
                    path.mkdir()
                else:
                    with path.open("wb") as stream:
                        stream.truncate(2 * 1024**2 + 1)
                with self.assertRaises((OSError, ValueError)):
                    retain_controller_output(output, evidence)

    def test_failed_update_refuses_existing_evidence_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed": false}\n')
            (evidence / "controller-result.json").write_text("preexisting\n")
            with self.assertRaises(FileExistsError):
                retain_controller_output(output, evidence)
            self.assertEqual((evidence / "controller-result.json").read_text(),
                             "preexisting\n")

    def test_failed_update_detects_same_size_in_place_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "output", root / "evidence"
            output.mkdir()
            evidence.mkdir()
            (output / "result.json").write_text('{"passed": false}\n')
            path = output / "same-path-positive-serial.log"
            path.write_bytes(b"a" * 4096)
            initial = path.stat()
            original_read = os.read
            changed = False

            def changing_read(descriptor, count):
                nonlocal changed
                raw = original_read(descriptor, count)
                if not changed and os.fstat(descriptor).st_ino == initial.st_ino:
                    changed = True
                    path.write_bytes(b"b" * 4096)
                    os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                return raw

            with patch("image.atomic.update_hosted.os.read", side_effect=changing_read):
                with self.assertRaisesRegex(ValueError, "changed while retained"):
                    retain_controller_output(output, evidence)

    def retained_preflight_context(self):
        root = Path(__file__).resolve().parents[2]
        lock = json.loads((root / "image/desktop-images.lock.json").read_text())
        pins = json.loads((root / "image/base-images.json").read_text())
        selected = lock["images"]["generic"]
        manifest = require_desktop_image(lock, pins, "generic")
        expected = expected_inputs(root, lock, pins, "generic")
        readiness = json.loads((root / "image/atomic/preflight.lock.json").read_text())
        return root, selected, manifest, expected, readiness

    def retained_preflight_fixture(self, destination):
        source, selected, manifest, expected, readiness = self.retained_preflight_context()
        root = Path(destination)
        (root / "image").mkdir()
        shutil.copyfile(source / "image/desktop-images.lock.json",
                        root / "image/desktop-images.lock.json")
        for relative in ("image/boot/probe.py", "image/desktop/verify.py",
                         "image/fonts/verify.py"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target)
        evidence = (root / "docs/security/reports/P0-03-atomic-preflight"
                    / str(readiness["preflight_run"]))
        evidence.mkdir(parents=True)
        source_evidence = (source / "docs/security/reports/P0-03-atomic-preflight"
                           / str(readiness["preflight_run"]))
        for name in ("inspect.json", "prepare.json", "independent-check.json"):
            shutil.copyfile(source_evidence / name, evidence / name)
        validate_retained_preflight(root, readiness, selected, manifest, expected)
        return root, selected, manifest, expected, copy.deepcopy(readiness), evidence

    def replace_retained_report(self, evidence, readiness, phase, item):
        raw = (json.dumps(item, indent=2) + "\n").encode()
        (evidence / (phase + ".json")).write_bytes(raw)
        report_sha256 = hashlib.sha256(raw).hexdigest()
        readiness[phase + "_sha256"] = report_sha256
        check_path = evidence / "independent-check.json"
        check = json.loads(check_path.read_text())
        check["retained_reports"][phase + ".json"] = report_sha256
        check_raw = (json.dumps(check, indent=2) + "\n").encode()
        check_path.write_bytes(check_raw)
        readiness["independent_check_sha256"] = hashlib.sha256(check_raw).hexdigest()

    def test_hosted_controller_imports(self):
        self.assertTrue(callable(run_update))

    def test_retained_preflight_matches_the_complete_current_image_lock(self):
        root, selected, manifest, expected, readiness = self.retained_preflight_context()
        reports = validate_retained_preflight(
            root, readiness, selected, manifest, expected)
        current_lock_sha256 = hashlib.sha256(
            (root / "image/desktop-images.lock.json").read_bytes()).hexdigest()
        self.assertEqual(reports["prepare"]["lock_sha256"], current_lock_sha256)

        stale_run = 45901694620
        stale_path = root / "docs/security/reports/P0-03-atomic-preflight" / str(stale_run)
        stale = {
            **readiness,
            "preflight_run": stale_run,
            "source_commit": "370ac0af566cd94d7452fd415c59d3def9619b85",
            "inspect_sha256": hashlib.sha256(
                (stale_path / "inspect.json").read_bytes()).hexdigest(),
            "prepare_sha256": hashlib.sha256(
                (stale_path / "prepare.json").read_bytes()).hexdigest(),
        }
        with self.assertRaisesRegex(ValueError, "Exact saved-image preflight"):
            validate_retained_preflight(root, stale, selected, manifest, expected)

        mismatched_report = {**readiness, "inspect_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "evidence bytes changed"):
            validate_retained_preflight(
                root, mismatched_report, selected, manifest, expected)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.retained_preflight_fixture(temporary)
            fixture_root, fixture_selected, fixture_manifest, fixture_expected, \
                fixture_readiness, evidence = fixture
            item = json.loads((evidence / "inspect.json").read_text())
            item["cgroup_final"]["cpu.stat"] += "\n"
            (evidence / "inspect.json").write_text(json.dumps(item) + "\n")
            with self.assertRaisesRegex(ValueError, "evidence bytes changed"):
                validate_retained_preflight(
                    fixture_root, fixture_readiness, fixture_selected,
                    fixture_manifest, fixture_expected)

        boolean_schema = {**readiness, "schema": True}
        with self.assertRaisesRegex(ValueError, "Unknown preflight readiness"):
            validate_retained_preflight(
                root, boolean_schema, selected, manifest, expected)
        for field, value in (("preflight_run", -1),
                             ("preflight_run", "../../45910498271"),
                             ("repository_id", True),
                             ("evidence_artifact_id", True),
                             ("evidence_artifact_bytes", -1),
                             ("evidence_artifact_sha256", 1),
                             ("inspect_sha256", 1),
                             ("kernel_observation_sha256", True),
                             ("manifest_digest", True)):
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, "Unknown preflight readiness"):
                validate_retained_preflight(
                    root, {**readiness, field: value}, selected, manifest, expected)

    def test_retained_preflight_rejects_envelope_and_resource_mutations(self):
        mutations = (
            ("boolean schema", "inspect", lambda item: item.__setitem__("schema", True)),
            ("wrong phase", "prepare", lambda item: item.__setitem__("phase", "inspect")),
            ("wrong base", "inspect", lambda item: item.__setitem__("base", "wrong")),
            ("wrong limits", "prepare", lambda item: item["limits"].__setitem__(
                "memory.max", "1")),
            ("wrong final limits", "inspect", lambda item: item["cgroup_final"].__setitem__(
                "pids.max", "1")),
            ("oom event", "inspect", lambda item: item["cgroup_final"].__setitem__(
                "memory.events", item["cgroup_final"]["memory.events"].replace(
                    "oom 0", "oom 1", 1))),
            ("missing oom event", "inspect", lambda item: item[
                "cgroup_final"].__setitem__("memory.events", item["cgroup_final"][
                    "memory.events"].replace("oom 0\n", "", 1))),
            ("duplicate oom event", "inspect", lambda item: item[
                "cgroup_final"].__setitem__("memory.events", item["cgroup_final"][
                    "memory.events"].replace("oom 0\n", "oom 0\noom 0\n", 1))),
            ("empty cpu stat", "prepare", lambda item: item[
                "cgroup_final"].__setitem__("cpu.stat", "")),
            ("boot input oom event", "inspect", lambda item: item["boot_inputs"][
                "cgroup_final"].__setitem__("memory.events", item["boot_inputs"][
                    "cgroup_final"]["memory.events"].replace("oom 0", "oom 1", 1))),
            ("changed command result", "inspect", lambda item: item["commands"][0].__setitem__(
                "exit_code", 1)),
            ("qualification scope", "inspect", lambda item: item.__setitem__(
                "scope", "Release qualified")),
            ("qualification field", "inspect", lambda item: item.__setitem__(
                "release_qualified", True)),
            ("nonstandard JSON number", "inspect", lambda item: item.__setitem__(
                "disk_free_before_load", float("nan"))),
        )
        for name, phase, mutate in mutations:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / (phase + ".json")).read_text())
                mutate(item)
                self.replace_retained_report(evidence, readiness, phase, item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_artifact_archive_and_boot_input_mutations(self):
        mutations = (
            ("artifact", "prepare", lambda item: item["artifact"].__setitem__(
                "id", item["artifact"]["id"] + 1)),
            ("artifact workflow", "prepare", lambda item: item["artifact"][
                "workflow_run"].__setitem__("head_sha", "0" * 40)),
            ("artifact repository", "prepare", lambda item: item["artifact"][
                "workflow_run"].__setitem__("repository_id", 1)),
            ("verified archive", "prepare", lambda item: item[
                "verified_archive"].__setitem__("image_id", "sha256:" + "0" * 64)),
            ("boot inputs", "inspect", lambda item: item["boot_inputs"][
                "os"].__setitem__("ID", "fedora")),
            ("boot command", "inspect", lambda item: item["boot_inputs"][
                "commands"][0].__setitem__("exit_code", 77)),
            ("boot backend", "inspect", lambda item: item["boot_inputs"].__setitem__(
                "backend_files", {})),
            ("boot tools", "inspect", lambda item: item["boot_inputs"][
                "tools"]["bootc"].__setitem__("present", False)),
            ("boot install configuration", "inspect", lambda item: item[
                "boot_inputs"]["install_configuration"].__setitem__("filesystem", "xfs")),
            ("boot memory peak", "inspect", lambda item: item["boot_inputs"][
                "cgroup_final"].__setitem__("memory.peak", "999999999999")),
        )
        for name, phase, mutate in mutations:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / (phase + ".json")).read_text())
                mutate(item)
                self.replace_retained_report(evidence, readiness, phase, item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_run_is_bound_to_independent_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, selected, manifest, expected, readiness, evidence = \
                self.retained_preflight_fixture(temporary)
            relabeled = evidence.parent / "1"
            shutil.copytree(evidence, relabeled)
            readiness["preflight_run"] = 1
            with self.assertRaisesRegex(ValueError, "Independent preflight reconciliation"):
                validate_retained_preflight(
                    root, readiness, selected, manifest, expected)

        with tempfile.TemporaryDirectory() as temporary:
            root, selected, manifest, expected, readiness, evidence = \
                self.retained_preflight_fixture(temporary)
            path = evidence / "independent-check.json"
            check = json.loads(path.read_text())
            check["evidence_artifact"].update({
                "id": 1, "bytes": 1, "sha256": "0" * 64})
            raw = (json.dumps(check, indent=2) + "\n").encode()
            path.write_bytes(raw)
            readiness["independent_check_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(ValueError, "Independent preflight reconciliation"):
                validate_retained_preflight(
                    root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_loaded_image_mutations(self):
        mutations = {
            "Id": "0" * 64,
            "Digest": "sha256:" + "0" * 64,
            "Architecture": "arm64",
            "Os": "windows",
        }
        for field, value in mutations.items():
            with self.subTest(field), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / "inspect.json").read_text())
                item["loaded_image"][field] = value
                self.replace_retained_report(evidence, readiness, "inspect", item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_incomplete_payload_kernel_and_cleanup(self):
        def forge_both_kernel_observations(item):
            forged = "0" * 64
            item["boot_inputs"]["kernel"]["vmlinuz"]["sha256"] = forged
            item["kernel_copy"]["kernel"]["vmlinuz"]["sha256"] = forged
            observation = hashlib.sha256((json.dumps(
                item["boot_inputs"]["kernel"], sort_keys=True) + "\n").encode()).hexdigest()
            item["boot_inputs"]["kernel_source_sha256"] = observation
            item["kernel_copy"]["observation_sha256"] = observation

        mutations = (
            ("installed files", lambda item: item["installed_files"].__setitem__(
                "installed_files_checked", 211)),
            ("package identities", lambda item: item["installed_files"].__setitem__(
                "all_package_identities_preserved_after_build", False)),
            ("font verification", lambda item: item["installed_files"].__setitem__(
                "fonts", {"checked": False, "scanned_fonts": 0, "families": []})),
            ("kernel observation", lambda item: item["kernel_copy"].__setitem__(
                "observation_sha256", "0" * 64)),
            ("dual kernel observation", forge_both_kernel_observations),
            ("container cleanup", lambda item: item["cleanup"][
                "symbi-atomic-boot-inputs"].__setitem__("absent", False)),
            ("image cleanup", lambda item: item.__setitem__("image_removed", False)),
        )
        for name, mutate in mutations:
            with self.subTest(name), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                item = json.loads((evidence / "inspect.json").read_text())
                mutate(item)
                self.replace_retained_report(evidence, readiness, "inspect", item)
                with self.assertRaises(ValueError):
                    validate_retained_preflight(
                        root, readiness, selected, manifest, expected)

    def test_retained_preflight_rejects_unsafe_report_files(self):
        for case in ("symlink", "hardlink", "fifo", "oversize", "parent-symlink"):
            with self.subTest(case), tempfile.TemporaryDirectory() as temporary:
                root, selected, manifest, expected, readiness, evidence = \
                    self.retained_preflight_fixture(temporary)
                path = evidence / "inspect.json"
                if case == "symlink":
                    target = evidence / "inspect-target.json"
                    path.rename(target)
                    path.symlink_to(target.name)
                elif case == "hardlink":
                    os.link(path, evidence / "inspect-hardlink.json")
                elif case == "fifo":
                    path.unlink()
                    os.mkfifo(path)
                elif case == "oversize":
                    item = json.loads(path.read_text())
                    item["cgroup_final"]["cpu.stat"] = "x" * RETAINED_REPORT_MAX_BYTES
                    raw = (json.dumps(item) + "\n").encode()
                    path.write_bytes(raw)
                    readiness["inspect_sha256"] = hashlib.sha256(raw).hexdigest()
                else:
                    target = evidence.with_name(evidence.name + "-target")
                    evidence.rename(target)
                    evidence.symlink_to(target.name, target_is_directory=True)
                messages = {"symlink": "direct regular file",
                            "hardlink": "bounded regular file",
                            "fifo": "bounded regular file",
                            "oversize": "bounded regular file",
                            "parent-symlink": "Linked preflight evidence"}
                previous_handler = signal.getsignal(signal.SIGALRM)
                if case == "fifo":
                    signal.signal(signal.SIGALRM,
                                  lambda *_: (_ for _ in ()).throw(TimeoutError()))
                    signal.setitimer(signal.ITIMER_REAL, 1)
                try:
                    with self.assertRaisesRegex(ValueError, messages[case]):
                        validate_retained_preflight(
                            root, readiness, selected, manifest, expected)
                finally:
                    if case == "fifo":
                        signal.setitimer(signal.ITIMER_REAL, 0)
                        signal.signal(signal.SIGALRM, previous_handler)

    def test_retained_preflight_rejects_duplicate_report_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, selected, manifest, expected, readiness, evidence = \
                self.retained_preflight_fixture(temporary)
            item = json.loads((evidence / "inspect.json").read_text())
            needle = '"Digest": ' + json.dumps(item["loaded_image"]["Digest"])
            text = (evidence / "inspect.json").read_text()
            raw = text.replace(needle, needle + ",\n    " + needle, 1).encode()
            (evidence / "inspect.json").write_bytes(raw)
            readiness["inspect_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
                validate_retained_preflight(
                    root, readiness, selected, manifest, expected)

    old = "sha256:" + "1" * 64
    new = "sha256:" + "2" * 64
    source_uuid = "88888888-8888-4888-8888-888888888888"

    def entry(self, digest, transport="registry"):
        return {"incompatible": False, "image": {
            "image": {"image": "fixture", "transport": transport,
                      "signature": "containerPolicy"},
            "imageDigest": digest, "architecture": "amd64"}}

    def status(self, booted, staged=None, rollback=None, queued=False,
               default=None, default_transport="registry"):
        return {"apiVersion": "org.containers.bootc/v1", "kind": "BootcHost",
                "spec": {"image": self.entry(
                    default or booted, default_transport)["image"]["image"]},
                "status": {"type": "bootcHost", "booted": self.entry(booted),
                           "staged": self.entry(staged, "dir") if staged else None,
                           "rollback": self.entry(rollback) if rollback else None,
                           "rollbackQueued": queued}}

    def test_retained_update_base_is_exact_and_precedes_current_image(self):
        root = Path(__file__).resolve().parents[2]
        config = json.loads((root / "image/atomic/update-base.lock.json").read_text())
        pins = json.loads((root / "image/base-images.json").read_text())
        current = json.loads((root / "image/desktop-images.lock.json").read_text())
        selected = require_update_base(config, pins, current)
        self.assertEqual(selected["run_id"], 45792057599)
        self.assertEqual(config["manifest_digest"],
                         "sha256:9b6e8fdd9f6f98631895ccdfaaed6ffd88febd3ea6238d543935a524b572faf3")
        self.assertLess(selected["run_id"], current["images"]["generic"]["run_id"])
        evidence_path = root / current["images"]["generic"]["evidence"]
        evidence = json.loads(evidence_path.read_text())
        self.assertEqual(evidence["source_commit"], current["images"]["generic"]["tested_commit"])
        self.assertEqual(evidence["image_manifest_sha256"],
                         current["images"]["generic"]["manifest_sha256"])
        self.assertEqual(evidence["hosted_image_artifact"]["id"],
                         current["images"]["generic"]["artifact"]["id"])

        changed = copy.deepcopy(config)
        changed["image"]["tested_commit"] = current["images"]["generic"]["tested_commit"]
        with self.assertRaises(ValueError):
            require_update_base(changed, pins, current)

    def test_hosted_artifact_metadata_must_match_predecessor_lock(self):
        root = Path(__file__).resolve().parents[2]
        config = json.loads((root / "image/atomic/update-base.lock.json").read_text())
        selected = config["image"]
        metadata = {
            "id": selected["artifact"]["id"],
            "name": selected["artifact"]["name"],
            "size_in_bytes": selected["artifact"]["bytes"],
            "digest": "sha256:" + selected["artifact"]["sha256"],
            "expired": False,
            "workflow_run": {
                "id": selected["run_id"],
                "head_sha": selected["tested_commit"],
            },
        }
        validate_artifact_metadata(config, metadata)
        for field in ("id", "digest", "expired"):
            with self.subTest(field=field):
                changed = copy.deepcopy(metadata)
                changed[field] = True if field == "expired" else "changed"
                with self.assertRaises(ValueError):
                    validate_artifact_metadata(config, changed)

    def policy(self):
        return {
            "default": [{"type": "reject"}],
            "transports": {"docker": {"ghcr.io/thirdkeyai/symbiont-os": [{
                "type": "sigstoreSigned", "keyData": "release-public",
                "signedIdentity": {"type": "exactRepository",
                                   "dockerRepository": "ghcr.io/thirdkeyai/symbiont-os"},
            }]}},
        }

    def test_update_policy_preserves_release_rules_and_scopes_fixture_key(self):
        original = self.policy()
        result = update_policy(original, b"fixture public key", self.new)
        self.assertEqual(original, self.policy())
        self.assertEqual(result["default"], [{"type": "reject"}])
        self.assertEqual(result["transports"]["docker"], original["transports"]["docker"])
        self.assertEqual(set(result["transports"]["dir"]),
                         {"/run/symbi-update/source", NEGATIVE_UPDATE_SOURCE})
        rule = result["transports"]["dir"]["/run/symbi-update/source"][0]
        self.assertEqual(rule["type"], "signedBy")
        self.assertEqual(rule["signedIdentity"]["dockerReference"],
                         "localhost/symbi-ci/development@" + self.new)
        self.assertNotIn("insecureAcceptAnything", json.dumps(result))

    def test_real_source_negative_signatures_are_hash_bound_and_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authentication = {"negative_source_signatures": {"unsigned": None}}
            for case in ("wrong-key", "wrong-reference", "altered-signature"):
                payload = ("fixture-" + case).encode()
                (root / ("negative-" + case + "-signature-1")).write_bytes(payload)
                authentication["negative_source_signatures"][case] = hashlib.sha256(
                    payload).hexdigest()
            controls = negative_signature_payloads(root, authentication)
            self.assertIsNone(controls["unsigned"])
            self.assertEqual(set(controls), {
                "unsigned", "wrong-key", "wrong-reference", "altered-signature"})
            authentication["negative_source_signatures"]["wrong-key"] = "0" * 64
            with self.assertRaises(ValueError):
                negative_signature_payloads(root, authentication)

    def test_update_and_rollback_commands_keep_signature_enforcement(self):
        switch = update_command()
        prefix = ["/usr/bin/runcon", "system_u:system_r:install_t:s0",
                  "/usr/bin/bootc"]
        self.assertEqual(switch[:5], [*prefix, "switch", "--transport"])
        self.assertIn("--enforce-container-sigpolicy", switch)
        self.assertEqual(switch[-1], "/run/symbi-update/source")
        self.assertEqual(rollback_command(), [*prefix, "rollback"])
        forbidden = {"--target-no-signature-verification", "--disable-selinux",
                     "--allow-missing-verity"}
        self.assertFalse(forbidden.intersection(switch))

        negative = update_command(NEGATIVE_UPDATE_SOURCE)
        self.assertIn("--enforce-container-sigpolicy", negative)
        self.assertEqual(negative[-1], NEGATIVE_UPDATE_SOURCE)
        with self.assertRaises(ValueError):
            update_command("/tmp/caller-selected-source")

    def test_three_boot_vm_uses_one_persistent_overlay_and_read_only_source(self):
        command = qemu_command(1)
        joined = " ".join(command)
        self.assertIn(
            "file=/output/guest.qcow2,format=qcow2,if=none,id=symbi-boot-disk",
            joined)
        self.assertIn(
            "virtio-blk-pci,drive=symbi-boot-disk,bootindex=1", joined)
        self.assertNotIn("snapshot=on", joined)
        self.assertIn(
            "file=/inputs/update.raw,format=raw,if=none,id=symbi-update-source,readonly=on",
            joined)
        self.assertIn(
            "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE", joined)
        self.assertNotIn("file=/inputs/update.raw,format=raw,if=virtio", joined)
        self.assertIn("-net none", joined)
        self.assertIn("phase-1.json", joined)
        firmware = firmware_arguments()
        self.assertIn("systemd.extra-unit.o.service", " ".join(firmware))
        self.assertIn("systemd.extra-unit.s.service", " ".join(firmware))
        self.assertIn("systemd.extra-unit.b.service", " ".join(firmware))
        self.assertIn("systemd.extra-unit.f.service", " ".join(firmware))
        self.assertIn("symbi-update-failure.py", " ".join(firmware))
        self.assertNotIn("fstab.extra", " ".join(firmware))

    def transition_failure_report(self):
        excerpt = bounded_journal_excerpt(
            "b.service: /usr/bin/runcon: permission denied while executing /usr/bin/bootc: "
            "Permission denied\n")
        return {
            "schema": 1,
            "passed": False,
            "guest_booted": True,
            "release_qualified": False,
            "product": "Symbi-Hosted-Update-Probe",
            "diagnostic": "bootc-transition-probe-failure",
            "unit": "b.service",
            "runner_sha256": "a" * 64,
            "service": {
                "Result": "exit-code", "ExecMainCode": "1",
                "ExecMainStatus": "229", "ActiveState": "failed",
                "SubState": "failed",
            },
            "journal": excerpt,
            "scope": "Bounded explicit-transition diagnostics; no update action ran",
        }

    @staticmethod
    def transition_failure_controller(report=None, failure=None):
        result = {
            "schema": 1,
            "passed": False,
            "guest_booted": False,
            "release_qualified": False,
            "active_phase": "same-path-positive",
            "failure": (failure or
                        "RuntimeError: bootc transition probe failed; inspect bounded report"),
            "negative_reports": [],
            "phase_reports": [],
            "inputs": {"update_boot_failure.py": "a" * 64},
        }
        if report is not None:
            result["transition_failure"] = report
        return result

    def test_transition_failure_report_binds_exact_fields_and_bounds(self):
        report = self.transition_failure_report()
        self.assertEqual(validate_transition_failure_report(report, "a" * 64), report)
        mutations = []
        changed = copy.deepcopy(report)
        changed["extra"] = True
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["service"]["ActiveState"] = "active"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["service"]["ExecMainStatus"] = "not-a-number"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["service"]["ExecMainStatus"] = "0"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["journal"]["excerpt"][0] = "x" * (JOURNAL_MAX_LINE_BYTES + 1)
        changed["journal"]["bytes"] = len(changed["journal"]["excerpt"][0]) + 1
        changed["journal"]["sha256"] = hashlib.sha256(
            (changed["journal"]["excerpt"][0] + "\n").encode()).hexdigest()
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["journal"]["sha256"] = "b" * 64
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["journal"]["excerpt"][0] += "\x00"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_transition_failure_report(changed, "a" * 64)
        with self.assertRaises(ValueError):
            validate_transition_failure_report(report, "b" * 64)
        properties = ("Result=exit-code\nExecMainCode=1\nExecMainStatus=229\n"
                      "ActiveState=failed\nSubState=failed\n")
        self.assertEqual(service_properties(properties), report["service"])
        with self.assertRaisesRegex(ValueError, "did not fail closed"):
            service_properties(properties.replace("ExecMainStatus=229",
                                                  "ExecMainStatus=0"))

    def test_transition_failure_journal_is_bounded_and_redacts_secret_shapes(self):
        secret = "s" * 64
        long_value = "a" * 64
        raw = ("token=" + secret + "\n" + long_value + "\n"
               + "Authorization: Bearer bearer-value\n"
               + ("z!" * (JOURNAL_MAX_LINE_BYTES + 100)) + "\n"
               + "control\x00value\n"
               + (("q!" * (JOURNAL_MAX_LINE_BYTES // 2) + "\n")
                  * JOURNAL_MAX_LINES))
        observed = bounded_journal_excerpt(raw)
        rendered = "\n".join(observed["excerpt"])
        self.assertNotIn(secret, rendered)
        self.assertNotIn(long_value, rendered)
        self.assertNotIn("bearer-value", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertTrue(observed["truncated"])
        self.assertLessEqual(observed["bytes"], JOURNAL_MAX_BYTES)
        self.assertLessEqual(observed["line_count"], JOURNAL_MAX_LINES)
        self.assertTrue(all(len(line.encode("ascii")) <= JOURNAL_MAX_LINE_BYTES
                            for line in observed["excerpt"]))
        self.assertNotIn("\x00", rendered)
        payload = ("\n".join(observed["excerpt"]) + "\n").encode("ascii")
        self.assertEqual(len(payload), observed["bytes"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), observed["sha256"])

        sensitive_keys = (
            ("API_TOKEN", "=", "x"),
            ("GH_TOKEN", "=", "gh"),
            ("client-secret", "=", "s"),
            ("client_secret", "=", "tiny"),
            ("client.secret", "=", "dot"),
            ("Authorization", ": ", "short"),
            ("--token", "=", "short"),
            ('"token"', ": ", '"short"'),
            ("X-API-Key", ": ", "short"),
            ("API_KEY", "=", "short"),
            ("OPENAI_API_KEY", "=", "short"),
            ("DB_KEY", "=", "short"),
            ("AWS_ACCESS_KEY_ID", "=", "short"),
            ("PRIVATE_KEY", "=", "short"),
            ("GITHUB_PAT", "=", "short"),
            ("AUTH", "=", "short"),
            ("AUTH_TOKEN", "=", "short"),
            ("Authentication", ": ", "short"),
            ("JWT", "=", "short"),
            ("JWT_SECRET", "=", "short"),
            ("PASSWD", "=", "short"),
            ("PASSPHRASE", "=", "short"),
            ("--password", " ", "short"),
        )
        self.assertEqual(PRODUCER_SENSITIVE.pattern,
                         VALIDATOR_SENSITIVE.pattern)
        for key, separator, value in sensitive_keys:
            with self.subTest(key=key):
                prefix = "b.service: "
                sanitized = bounded_journal_excerpt(
                    prefix + key + separator + value + "\n")
                self.assertEqual(
                    sanitized["excerpt"],
                    [prefix + key + separator + "<redacted>"],
                )
                report = self.transition_failure_report()
                report["journal"] = sanitized
                self.assertEqual(
                    validate_transition_failure_report(report, "a" * 64), report)

                changed = copy.deepcopy(report)
                unredacted = prefix + key + separator + value
                changed["journal"]["excerpt"] = [unredacted]
                changed["journal"]["line_count"] = 1
                raw_unredacted = (unredacted + "\n").encode("ascii")
                changed["journal"]["bytes"] = len(raw_unredacted)
                changed["journal"]["sha256"] = hashlib.sha256(
                    raw_unredacted).hexdigest()
                with self.assertRaisesRegex(ValueError, "excerpt is unsafe"):
                    validate_transition_failure_report(changed, "a" * 64)

    def test_each_bootc_rejection_uses_a_distinct_disposable_overlay(self):
        commands = {case: negative_qemu_command(case) for case in (
            "unsigned", "wrong-key", "wrong-reference", "altered-signature")}
        for case, command in commands.items():
            joined = " ".join(command)
            self.assertIn(
                f"file=/output/negative-{case}.qcow2,format=qcow2,"
                "if=none,id=symbi-boot-disk", joined)
            self.assertIn(f"path=/output/negative-{case}.json", joined)
            self.assertIn(f"file=/inputs/expected-{case}.json", joined)
            self.assertIn(
                "file=/inputs/update.raw,format=raw,if=none,id=symbi-update-source,readonly=on",
                joined)
            self.assertIn(
                "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE", joined)
            self.assertNotIn("file=/output/guest.qcow2", joined)
        self.assertEqual(len({tuple(command) for command in commands.values()}), 4)
        positive = " ".join(positive_qemu_command())
        self.assertIn(
            "file=/output/same-path-positive.qcow2,format=qcow2,"
            "if=none,id=symbi-boot-disk", positive)
        self.assertIn("path=/output/same-path-positive.json", positive)
        self.assertIn("file=/inputs/expected-positive.json", positive)
        self.assertNotIn("file=/output/guest.qcow2", positive)
        self.assertNotIn("file=/output/negative-", positive)
        with self.assertRaises(ValueError):
            negative_qemu_command("caller-selected")

    def test_all_update_vms_boot_only_the_explicit_overlay(self):
        commands = [
            positive_qemu_command(),
            *(negative_qemu_command(case) for case in (
                "unsigned", "wrong-key", "wrong-reference", "altered-signature")),
            *(qemu_command(index) for index in range(3)),
        ]
        for command in commands:
            with self.subTest(report=command[command.index("-chardev") + 1]):
                drives = [command[index + 1] for index, value in enumerate(command)
                          if value == "-drive"]
                devices = [command[index + 1] for index, value in enumerate(command)
                           if value == "-device"]
                self.assertEqual(len(drives), 2)
                self.assertEqual(len(set(drives)), 2)
                self.assertTrue(any(
                    value.endswith("if=none,id=symbi-boot-disk") for value in drives))
                self.assertIn(
                    "file=/inputs/update.raw,format=raw,if=none,"
                    "id=symbi-update-source,readonly=on", drives)
                self.assertEqual(
                    [value for value in devices if "bootindex=" in value],
                    ["virtio-blk-pci,drive=symbi-boot-disk,bootindex=1"])
                self.assertIn(
                    "virtio-blk-pci,drive=symbi-update-source,serial=SYMBIUPDATE",
                    devices)
                self.assertEqual(command.count("-boot"), 1)
                self.assertEqual(command[command.index("-boot") + 1], "strict=on")
                self.assertFalse(any("if=virtio" in value for value in command))

    def test_guest_status_requires_exact_signed_slots_and_rollback_queue(self):
        phase_status(self.status(self.old), self.old)
        phase_status(self.status(self.old, staged=self.new), self.old, staged=self.new)
        phase_status(self.status(self.new, rollback=self.old, queued=True), self.new,
                     rollback=self.old, rollback_queued=True)
        cases = [
            self.status(self.new),
            self.status(self.old, staged=self.old),
            self.status(self.new, rollback=self.old, queued=False),
            self.status(self.old),
        ]
        cases[-1]["status"]["booted"]["image"]["image"]["signature"] = "insecure"
        expected = [(self.old, {}), (self.old, {"staged": self.new}),
                    (self.new, {"rollback": self.old, "rollback_queued": True}),
                    (self.old, {})]
        for status, (booted, options) in zip(cases, expected):
            with self.assertRaises(ValueError):
                phase_status(status, booted, **options)

    def test_negative_switch_snapshot_binds_default_and_all_deployments(self):
        original = self.status(self.old)
        snapshot = deployment_snapshot(original, self.old)
        self.assertEqual(snapshot["default"], original["spec"]["image"])
        self.assertEqual(snapshot["booted"], original["status"]["booted"])
        changes = []
        changed = copy.deepcopy(original)
        changed["spec"]["image"]["image"] = "changed"
        changes.append((changed, True))
        changed = copy.deepcopy(original)
        changed["status"]["booted"]["ostree"] = {"checksum": "0" * 64}
        changes.append((changed, False))
        changed = copy.deepcopy(original)
        changed["status"]["staged"] = self.entry(self.new, "dir")
        changes.append((changed, True))
        for changed, rejected in changes:
            with self.subTest(changed=changed):
                if rejected:
                    with self.assertRaises(ValueError):
                        deployment_snapshot(changed, self.old)
                else:
                    self.assertNotEqual(deployment_snapshot(changed, self.old), snapshot)
        staged = staged_deployment_snapshot(
            self.status(self.old, staged=self.new, default=self.new,
                        default_transport="dir"), self.old, self.new)
        self.assertEqual(staged["default"], staged["staged"]["image"]["image"])
        self.assertEqual(staged["booted"], snapshot["booted"])
        invalid = self.status(self.old, staged=self.new, default=self.new)
        with self.assertRaises(ValueError):
            staged_deployment_snapshot(invalid, self.old, self.new)

    @staticmethod
    def transition_report():
        return {
            "unit": "b.service",
            "service": {"Result": "success", "ExecMainCode": "1",
                        "ExecMainStatus": "0", "ActiveState": "active",
                        "SubState": "exited"},
            "context": "system_u:system_r:install_t:s0",
            "probe_command": [
                "/usr/bin/runcon", "system_u:system_r:install_t:s0",
                "/usr/bin/bootc", "--version",
            ],
            "scope": "Explicit transition availability only; no update qualification",
            "runcon": "/usr/bin/runcon", "runcon_sha256": "7" * 64,
            "runcon_selinux_label": "system_u:object_r:bin_t:s0",
            "source": "/usr/bin/bootc",
            "label_reference": "/usr/bin/ostree",
            "source_sha256": "8" * 64, "label_reference_sha256": "9" * 64,
            "selinux_label": "system_u:object_r:install_exec_t:s0",
            "mode": "0755",
        }

    @staticmethod
    def status_evidence(count):
        service = {"Result": "success", "ExecMainCode": "1",
                   "ExecMainStatus": "0", "ActiveState": "active",
                   "SubState": "exited"}
        observations = [
            {"sequence": sequence, "unit": "s.service", "service": service,
             "bytes": 1024, "sha256": f"{sequence}" * 64}
            for sequence in range(1, count + 1)
        ]
        commands = [{
            "command": ["/usr/bin/systemctl", "show", "b.service",
                        "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"],
            "exit_code": 0,
        }]
        for _sequence in range(count):
            commands.extend([
                {"command": ["/usr/bin/systemctl", "restart", "s.service"],
                 "exit_code": 0},
                {"command": ["/usr/bin/systemctl", "show", "s.service",
                             "--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState"],
                 "exit_code": 0},
            ])
        return observations, commands

    @staticmethod
    def operation_report(name, exit_code=0, stderr=""):
        arguments = {
            "negative": ["switch", "--transport", "dir",
                         "--enforce-container-sigpolicy", NEGATIVE_UPDATE_SOURCE],
            "positive": ["switch", "--transport", "dir",
                         "--enforce-container-sigpolicy", "/run/symbi-update/source"],
            "rollback": ["rollback"],
        }[name]
        command = [
            "/usr/bin/runcon", "system_u:system_r:install_t:s0",
            "/usr/bin/bootc", *arguments,
        ]
        return {
            "name": name, "command": command, "exit_code": exit_code,
            "stderr": stderr,
            "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
        }

    def positive_report(self):
        observations, commands = self.status_evidence(2)
        operation = self.operation_report("negative")
        commands.insert(3, {"command": operation["command"], "exit_code": 0,
                            "stderr": operation["stderr"]})
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "serial": "SYMBIUPDATE",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "status_observations": observations,
            "bootc_transition": self.transition_report(),
            "bootc_operation": operation,
            "same_path_positive_control": {
                "case": POSITIVE_OVERLAY_CASE, "switch_accepted": True,
                "switch_exit_code": 0, "booted_unchanged": True,
                "deployment_staged": True, "default_changed": True,
                "staged_digest": self.new, "state_before_sha256": "3" * 64,
                "state_after_sha256": "7" * 64,
                "source": NEGATIVE_UPDATE_SOURCE, "source_readonly": True,
            },
            "commands": commands,
        }

    def test_same_path_positive_report_binds_success_and_controlled_state(self):
        expected = {"nonce": "4" * 32, "new_digest": self.new,
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        report = self.positive_report()
        validate_positive_report(report, expected, "5" * 64, "6" * 64)
        validate_shared_baseline(report, self.negative_report())
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][3]["exit_code"] = 1
        changed["bootc_operation"]["exit_code"] = 1
        changed["same_path_positive_control"]["switch_exit_code"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["same_path_positive_control"]["state_after_sha256"] = "3" * 64
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["same_path_positive_control"]["source"] = "/tmp/other"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["source_device"]["UUID"] = "9" * 32
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_positive_report(changed, expected, "5" * 64, "6" * 64)
        negative = self.negative_report()
        negative["negative_control"]["state_sha256"] = "9" * 64
        with self.assertRaises(ValueError):
            validate_shared_baseline(report, negative)

    def test_controller_rejects_transition_input_and_command_substitution(self):
        expected = {"nonce": "4" * 32, "new_digest": self.new,
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        report = self.positive_report()
        mutations = []
        for field, value in (
                ("context", "system_u:system_r:unconfined_service_t:s0"),
                ("probe_command", ["/usr/bin/bootc", "--version"]),
                ("scope", "Update qualified"),
                ("runcon", "/tmp/runcon"),
                ("runcon_sha256", "0" * 63),
                ("runcon_selinux_label", "system_u:object_r:install_exec_t:s0"),
                ("runcon_selinux_label", "not-a-selinux-label"),
                ("source", "/tmp/bootc"),
                ("source_sha256", "0" * 63),
                ("label_reference", "/tmp/ostree"),
                ("label_reference_sha256", "0" * 63),
                ("selinux_label", "system_u:object_r:bin_t:s0"),
                ("mode", "0700")):
            changed = copy.deepcopy(report)
            changed["bootc_transition"][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(report)
        del changed["bootc_transition"]["runcon_selinux_label"]
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["bootc_operation"]["command"][0] = "/tmp/runcon"
        changed["commands"][3]["command"][0] = "/tmp/runcon"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"].append({
            "command": ["/usr/bin/bootc", "rollback"], "exit_code": 0,
        })
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_positive_report(changed, expected, "5" * 64, "6" * 64)

    def negative_report(self, case="unsigned"):
        state_hash = "3" * 64
        observations, commands = self.status_evidence(2)
        operation = self.operation_report(
            "negative", exit_code=1, stderr="signature verification failed\n")
        commands.insert(3, {"command": operation["command"], "exit_code": 1,
                            "stderr": operation["stderr"]})
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "serial": "SYMBIUPDATE",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "status_observations": observations,
            "bootc_transition": self.transition_report(),
            "bootc_operation": operation,
            "negative_control": {
                "case": case, "switch_rejected": True, "switch_exit_code": 1,
                "deployment_unchanged": True, "default_unchanged": True,
                "state_sha256": state_hash, "source": NEGATIVE_UPDATE_SOURCE,
                "source_readonly": True,
            },
            "commands": commands,
        }

    def test_negative_report_requires_failed_real_switch_and_unchanged_state(self):
        report = self.negative_report()
        expected = {"nonce": "4" * 32,
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        validate_negative_report(report, expected, "5" * 64, "6" * 64, "unsigned")
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][3]["exit_code"] = 0
        changed["bootc_operation"]["exit_code"] = 0
        changed["negative_control"]["switch_exit_code"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["negative_control"]["deployment_unchanged"] = False
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"][3]["command"][-1] = "/tmp/other"
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["source_device"]["LABEL"] = "OTHER"
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_negative_report(changed, expected, "5" * 64,
                                         "6" * 64, "unsigned")

    def test_phase_report_binds_the_exact_source_device(self):
        expected = {"nonce": "4" * 32,
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "serial": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        phase = {"name": "installed", "booted_digest": self.old,
                 "operation": "signed-update-staged", "staged_digest": self.new}
        observations, commands = self.status_evidence(2)
        operation = self.operation_report("positive")
        commands.insert(3, {"command": operation["command"], "exit_code": 0,
                            "stderr": operation["stderr"]})
        report = {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "serial": "SYMBIUPDATE",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "phase": phase,
            "status_observations": observations,
            "bootc_transition": self.transition_report(),
            "bootc_operation": operation,
            "commands": commands,
        }
        validate_phase_report(report, expected, "5" * 64, "6" * 64, phase)
        for field in ("path", "serial", "TYPE", "LABEL", "UUID"):
            changed = copy.deepcopy(report)
            changed["source_device"].pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_phase_report(changed, expected, "5" * 64, "6" * 64, phase)
        changed = copy.deepcopy(report)
        changed["source_device"]["serial"] = "OTHER"
        with self.assertRaises(ValueError):
            validate_phase_report(changed, expected, "5" * 64, "6" * 64, phase)
        changed_expected = copy.deepcopy(expected)
        changed_expected["source_disk"]["serial"] = "OTHER"
        with self.assertRaises(ValueError):
            validate_phase_report(report, changed_expected, "5" * 64,
                                  "6" * 64, phase)

    def test_update_service_and_mount_are_bounded_and_offline(self):
        root = Path(__file__).resolve().parents[2]
        settings = dict(line.split("=", 1) for line in
                        (root / "image/atomic/update-o.service").read_text().splitlines()
                        if "=" in line and not line.startswith("#"))
        self.assertNotIn("RequiresMountsFor", settings)
        self.assertEqual(settings["Requires"], "b.service")
        self.assertNotIn("Wants", settings)
        self.assertEqual(settings["After"], "local-fs.target b.service")
        self.assertNotIn("s.service", settings.get("Requires", ""))
        self.assertNotIn("s.service", settings.get("After", ""))
        self.assertNotIn("OnFailure", settings)

        status_settings = dict(line.split("=", 1) for line in
                               (root / "image/atomic/s.service").read_text().splitlines()
                               if "=" in line and not line.startswith("#"))
        self.assertNotIn("o.service", status_settings.get("Before", ""))
        self.assertNotIn("o.service", status_settings.get("After", ""))
        self.assertEqual(settings["RuntimeDirectory"], "symbi-update")
        self.assertEqual(settings["RuntimeDirectoryMode"], "0700")
        self.assertEqual(settings["StateDirectory"], "symbi-update-test")
        self.assertEqual(settings["PrivateMounts"], "yes")
        self.assertEqual(settings["MemorySwapMax"], "0")
        self.assertEqual(settings["TasksMax"], "128")
        self.assertFalse((root / "image/atomic/update-fstab.extra").exists())
        self.assertNotIn("udev", (root / "image/atomic/update-o.service").read_text())

        transition = dict(line.split("=", 1) for line in
                          (root / "image/atomic/update-b.service").read_text().splitlines()
                          if "=" in line and not line.startswith("#"))
        self.assertEqual(transition["User"], "root")
        self.assertEqual(transition["Group"], "root")
        self.assertEqual(transition["CapabilityBoundingSet"], "")
        self.assertEqual(transition["MemorySwapMax"], "0")
        self.assertEqual(transition["TasksMax"], "16")
        self.assertEqual(transition["OnFailure"], "f.service")
        self.assertEqual(transition["PrivateTmp"], "yes")
        self.assertEqual(transition["ProtectSystem"], "strict")
        self.assertEqual(transition["ProtectKernelTunables"], "yes")
        self.assertEqual(transition["ProtectKernelModules"], "yes")
        self.assertEqual(transition["ProtectKernelLogs"], "yes")
        self.assertEqual(transition["ProtectControlGroups"], "yes")
        self.assertEqual(
            transition["ExecStart"],
            "/usr/bin/runcon system_u:system_r:install_t:s0 /usr/bin/bootc --version")
        text = (root / "image/atomic/update-b.service").read_text()
        self.assertNotIn("SELinuxContext=", text)
        self.assertNotIn("ExecStopPost=", text)
        self.assertNotIn("NoNewPrivileges=", text)
        self.assertNotIn("/usr/bin/install", text)
        self.assertNotIn("/usr/bin/chcon", text)
        self.assertNotIn("/usr/bin/mv", text)
        self.assertNotIn("/usr/bin/rm", text)
        self.assertNotIn("/run/symbi-update-bootc", text)
        self.assertNotIn("PrivateMounts=", text)
        self.assertNotIn("/bin/sh", text)
        conditions = [line for line in text.splitlines()
                      if line.startswith("ConditionPathExists=")]
        self.assertEqual(conditions, ["ConditionPathExists=!/etc/initrd-release"])

        failure = dict(line.split("=", 1) for line in
                       (root / "image/atomic/update-f.service").read_text().splitlines()
                       if "=" in line and not line.startswith("#"))
        self.assertEqual(failure["After"], "b.service")
        self.assertEqual(failure["OnFailure"], "poweroff.target")
        self.assertEqual(failure["ImportCredential"], "symbi-update-failure.py")
        self.assertEqual(failure["ExecStartPre"],
                         "/usr/bin/systemctl --quiet is-failed b.service")
        self.assertNotIn("ExecCondition", failure)
        self.assertEqual(failure["ExecStart"],
                         "/usr/bin/python3 %d/symbi-update-failure.py")
        self.assertEqual(failure["ExecStopPost"],
                         "/usr/bin/systemctl --no-block poweroff")
        self.assertEqual(failure["NoNewPrivileges"], "yes")
        self.assertEqual(failure["CapabilityBoundingSet"], "")
        self.assertEqual(failure["PrivateMounts"], "yes")
        self.assertEqual(failure["MemorySwapMax"], "0")
        self.assertEqual(failure["TasksMax"], "16")
        self.assertEqual(failure["TimeoutStartSec"], "30")
        self.assertNotIn("SELinuxContext", failure)
        failure_text = (root / "image/atomic/update-f.service").read_text()
        self.assertNotIn("[Install]", failure_text)
        self.assertNotIn("f.service", (root / "image/atomic/contract.py").read_text())

        skipped = ("Result=success\nExecMainCode=0\nExecMainStatus=0\n"
                   "ActiveState=inactive\nSubState=dead\n")
        with self.assertRaisesRegex(ValueError, "transition probe did not complete"):
            fixed_bootc_transition(Mock(return_value=skipped))

    @staticmethod
    def root_file_stat(real_fstat, changed_gid_path=None):
        def reader(descriptor):
            observed = real_fstat(descriptor)
            path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            return SimpleNamespace(
                st_mode=observed.st_mode, st_uid=0,
                st_gid=1 if changed_gid_path == path else 0,
                st_size=observed.st_size, st_nlink=observed.st_nlink,
                st_dev=observed.st_dev, st_ino=observed.st_ino,
                st_mtime_ns=observed.st_mtime_ns,
                st_ctime_ns=observed.st_ctime_ns,
            )
        return reader

    def bootc_fixture(self, root):
        source, reference, runcon = root / "bootc", root / "ostree", root / "runcon"
        source.write_bytes(b"fixed bootc bytes")
        reference.write_bytes(b"label reference")
        runcon.write_bytes(b"fixed runcon bytes")
        source.chmod(0o755)
        reference.chmod(0o755)
        runcon.chmod(0o755)
        return source, reference, runcon

    def test_fixed_transition_binds_runcon_bootc_owner_mode_bytes_and_label(self):
        real_fstat = os.fstat
        label = b"system_u:object_r:install_exec_t:s0\0"
        runcon_label = b"system_u:object_r:bin_t:s0\0"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, reference, runcon = self.bootc_fixture(root)
            root_stat = self.root_file_stat(real_fstat)

            def labels(descriptor, _name):
                target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                return runcon_label if target == runcon else label

            with patch("image.atomic.update_guest.os.fstat", side_effect=root_stat), \
                    patch("image.atomic.update_guest.os.getxattr", side_effect=labels):
                observation = _bootc_file_observation(source, reference, runcon)
            self.assertEqual(observation["source_sha256"],
                             hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(observation["label_reference_sha256"],
                             hashlib.sha256(reference.read_bytes()).hexdigest())
            self.assertEqual(observation["runcon_sha256"],
                             hashlib.sha256(runcon.read_bytes()).hexdigest())
            self.assertEqual(observation["mode"], "0755")
            self.assertEqual(observation["selinux_label"], label[:-1].decode())
            self.assertEqual(observation["runcon_selinux_label"],
                             runcon_label[:-1].decode())

            mutations = (
                "source-gid", "reference-gid", "runcon-gid",
                "source-mode", "reference-mode", "runcon-mode", "label",
                "runcon-label-transition", "runcon-label-malformed",
                "source-symlink", "reference-symlink", "runcon-symlink",
            )
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    source, reference, runcon = self.bootc_fixture(root)
                    changed_gid = {
                        "source-gid": source,
                        "reference-gid": reference,
                        "runcon-gid": runcon,
                    }.get(mutation)
                    def fixed_labels(descriptor, _name):
                        target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                        return runcon_label if target == runcon else label

                    getxattr = Mock(side_effect=fixed_labels)
                    original = None
                    if mutation == "source-mode":
                        source.chmod(0o775)
                    elif mutation == "reference-mode":
                        reference.chmod(0o775)
                    elif mutation == "runcon-mode":
                        runcon.chmod(0o744)
                    elif mutation == "label":
                        def labels(descriptor, _name):
                            target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                            if target == runcon:
                                return runcon_label
                            return (b"system_u:object_r:bin_t:s0\0"
                                    if target == source else label)
                        getxattr.side_effect = labels
                    elif mutation == "runcon-label-transition":
                        getxattr.side_effect = lambda _descriptor, _name: label
                    elif mutation == "runcon-label-malformed":
                        def malformed_label(descriptor, _name):
                            target = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                            return (b"system_u:object_r:bin_t:s0\0junk"
                                    if target == runcon else label)
                        getxattr.side_effect = malformed_label
                    elif mutation.endswith("-symlink"):
                        target = {"source-symlink": source,
                                  "reference-symlink": reference,
                                  "runcon-symlink": runcon}[mutation]
                        original = target.with_name(target.name + ".real")
                        target.rename(original)
                        target.symlink_to(original)
                    stat_reader = self.root_file_stat(real_fstat, changed_gid)
                    with patch("image.atomic.update_guest.os.fstat",
                               side_effect=stat_reader), \
                            patch("image.atomic.update_guest.os.getxattr", getxattr):
                        with self.assertRaises((OSError, ValueError)):
                            _bootc_file_observation(source, reference, runcon)
                    if original is not None:
                        target = {"source-symlink": source,
                                  "reference-symlink": reference,
                                  "runcon-symlink": runcon}[mutation]
                        target.unlink()
                        original.rename(target)

    def test_fixed_status_replaces_stale_output_and_binds_service_freshness(self):
        real_fstat = os.fstat
        properties = ("Result=success\nExecMainCode=1\nExecMainStatus=0\n"
                      "ActiveState=active\nSubState=exited\n")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "status.json"
            output.write_bytes(b'{"stale":true}\n')
            output.chmod(0o600)
            fresh = b'{"fresh":true}\n'
            commands = []

            def run(command, **_options):
                commands.append(command)
                if command[1] == "restart":
                    output.write_bytes(fresh)
                    output.chmod(0o600)
                    return ""
                return properties

            observations = []
            with patch("image.atomic.update_guest.os.fstat",
                       side_effect=self.root_file_stat(real_fstat)):
                self.assertEqual(fixed_bootc_status(run, observations, output),
                                 {"fresh": True})
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0]["bytes"], len(fresh))
            self.assertEqual(observations[0]["sha256"],
                             hashlib.sha256(fresh).hexdigest())
            self.assertEqual(commands[0],
                             ["/usr/bin/systemctl", "restart", "s.service"])

            output.write_bytes(b'{"stale":true}\n')
            output.chmod(0o600)
            with patch("image.atomic.update_guest.os.fstat",
                       side_effect=self.root_file_stat(real_fstat)):
                with self.assertRaises(FileNotFoundError):
                    fixed_bootc_status(
                        lambda command, **_options: properties,
                        [], output)
            self.assertFalse(output.exists())

    def test_fixed_bootc_operation_revalidates_before_and_after_execution(self):
        transition = self.transition_report()
        record = {"bootc_transition": transition}
        current = {key: transition[key] for key in {
            "runcon", "runcon_sha256", "source", "source_sha256",
            "runcon_selinux_label", "label_reference", "label_reference_sha256",
            "selinux_label", "mode",
        }}
        result = SimpleNamespace(returncode=0, stderr="")
        runner = Mock(return_value=result)
        with patch("image.atomic.update_guest._bootc_file_observation",
                   side_effect=[current, current]):
            observed = fixed_bootc_operation(
                runner, record, "positive", expected_success=True, timeout=120)
        self.assertEqual(observed["command"], [
            "/usr/bin/runcon", "system_u:system_r:install_t:s0",
            "/usr/bin/bootc", "switch", "--transport", "dir",
            "--enforce-container-sigpolicy", "/run/symbi-update/source",
        ])
        runner.assert_called_once_with(observed["command"], timeout=120,
                                       check=False, return_result=True)

        changed = dict(current, source_sha256="0" * 64)
        before_runner = Mock(return_value=result)
        with patch("image.atomic.update_guest._bootc_file_observation",
                   return_value=changed), self.assertRaisesRegex(
                       ValueError, "changed before use"):
            fixed_bootc_operation(before_runner, record, "positive",
                                  expected_success=True, timeout=120)
        before_runner.assert_not_called()

        after_runner = Mock(return_value=result)
        with patch("image.atomic.update_guest._bootc_file_observation",
                   side_effect=[current, changed]), self.assertRaisesRegex(
                       ValueError, "changed during use"):
            fixed_bootc_operation(after_runner, record, "positive",
                                  expected_success=True, timeout=120)
        after_runner.assert_called_once()

    def test_transition_command_and_inputs_are_fixed(self):
        self.assertEqual(BOOTC_SOURCE, Path("/usr/bin/bootc"))
        self.assertEqual(BOOTC_LABEL_REFERENCE, Path("/usr/bin/ostree"))
        self.assertEqual(BOOTC_RUNCON, Path("/usr/bin/runcon"))
        self.assertEqual(BOOTC_CONTEXT, "system_u:system_r:install_t:s0")

    def test_update_device_readiness_wait_is_fixed_and_bounded(self):
        self.assertEqual(SOURCE_SERIAL, "SYMBIUPDATE")
        self.assertEqual(SOURCE_DEVICE_TIMEOUT_SECONDS, 30)
        source = Path("/dev/vdb")
        scan = Mock(side_effect=[(None, ["vda"]),
                                 (source, ["vda", "vdb"])])
        clock = Mock(side_effect=[0.0, 0.0, 0.1])
        sleeper = Mock()
        self.assertEqual(wait_for_source_device(scan=scan, clock=clock,
                                                sleeper=sleeper),
                         (source, ["vda", "vdb"]))
        sleeper.assert_called_once_with(0.25)

        scan = Mock(return_value=(None, ["vda"]))
        with self.assertRaisesRegex(ValueError, "virtio serial is absent"):
            wait_for_source_device(scan=scan,
                                   clock=Mock(side_effect=[0.0, 0.0, 30.0]),
                                   sleeper=Mock())
        self.assertEqual(scan.call_count, 1)

    def test_source_device_discovery_binds_exact_serial_and_device_number(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block, dev_root = root / "sys", root / "dev"
            sys_block.mkdir()
            dev_root.mkdir()
            numbers = {"vda": (252, 0), "vdb": (252, 16)}

            def add(name, serial_value, number):
                entry = sys_block / name
                entry.mkdir()
                (entry / "dev").write_text(f"{number[0]}:{number[1]}\n")
                if serial_value is not None:
                    (entry / "serial").write_bytes(serial_value)

            add("vda", b"", numbers["vda"])
            add("vda1", b"SYMBIUPDATE", (252, 1))
            add("vdb", b"SYMBIUPDATE", numbers["vdb"])
            (sys_block / "zram0").mkdir()

            def block_lstat(path):
                major, minor = numbers[Path(path).name]
                return Mock(st_mode=stat.S_IFBLK | 0o600,
                            st_rdev=os.makedev(major, minor))

            source, inventory = discover_source_device(sys_block, dev_root,
                                                        block_lstat)
            self.assertEqual(source, dev_root / "vdb")
            self.assertEqual(inventory, ["vda", "vda1", "vdb", "zram0"])

            (sys_block / "vdb" / "serial").write_bytes(b"symbiupdate")
            self.assertIsNone(discover_source_device(sys_block, dev_root,
                                                     block_lstat)[0])
            (sys_block / "vdb" / "serial").write_bytes(b"SYMBIUPDATE\n")
            self.assertIsNone(discover_source_device(sys_block, dev_root,
                                                     block_lstat)[0])
            (sys_block / "vdb" / "serial").write_bytes(b"SYMBIUPDATE-X")
            self.assertIsNone(discover_source_device(sys_block, dev_root,
                                                     block_lstat)[0])

    def test_source_device_discovery_rejects_ambiguity_and_node_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block, dev_root = root / "sys", root / "dev"
            sys_block.mkdir()
            dev_root.mkdir()

            def add(name, number):
                entry = sys_block / name
                entry.mkdir()
                (entry / "serial").write_bytes(b"SYMBIUPDATE")
                (entry / "dev").write_text(f"{number[0]}:{number[1]}\n")

            add("vdb", (252, 16))
            self.assertIsNone(discover_source_device(sys_block, dev_root)[0])
            (dev_root / "vdb").write_text("not a device")
            with self.assertRaisesRegex(ValueError, "device node differs"):
                discover_source_device(sys_block, dev_root)
            (dev_root / "vdb").unlink()
            target = dev_root / "target"
            target.write_text("not a device")
            (dev_root / "vdb").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "device node differs"):
                discover_source_device(sys_block, dev_root)

            mismatch = Mock(st_mode=stat.S_IFBLK | 0o600,
                            st_rdev=os.makedev(252, 17))
            with self.assertRaisesRegex(ValueError, "device node differs"):
                discover_source_device(sys_block, dev_root,
                                       lambda _path: mismatch)

            add("vdc", (252, 32))
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                discover_source_device(sys_block, dev_root,
                                       lambda _path: mismatch)

    def test_source_device_discovery_rejects_unbounded_or_unsafe_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            sys_block = Path(temporary)
            (sys_block / "bad name").mkdir()
            with self.assertRaisesRegex(ValueError, "invalid block-device inventory"):
                discover_source_device(sys_block, sys_block)
        with tempfile.TemporaryDirectory() as temporary:
            sys_block = Path(temporary)
            for index in range(65):
                (sys_block / f"loop{index}").mkdir()
            with self.assertRaisesRegex(ValueError, "invalid block-device inventory"):
                discover_source_device(sys_block, sys_block)

    def test_source_mount_is_boot_ephemeral_while_phase_state_persists(self):
        self.assertEqual(SOURCE, Path("/run/symbi-update/source"))
        self.assertEqual(STATE, Path("/var/lib/symbi-update-test/phase"))
        self.assertNotEqual(SOURCE.parent, STATE.parent)

    def test_update_source_identity_is_exact_and_rejects_ambiguity(self):
        expected = {"filesystem": "ext4", "label": "SYMBIUPDATE",
                    "uuid": "1d3a0ad0-0fdb-4338-a56d-12061df7b091"}
        raw = ("DEVNAME=/dev/vdb\nLABEL=SYMBIUPDATE\n"
               "UUID=1d3a0ad0-0fdb-4338-a56d-12061df7b091\nTYPE=ext4\n")
        self.assertEqual(validate_source_identity(raw, expected), {
            "TYPE": "ext4", "LABEL": "SYMBIUPDATE",
            "UUID": "1d3a0ad0-0fdb-4338-a56d-12061df7b091"})
        mutations = [
            raw.replace("TYPE=ext4", "TYPE=xfs"),
            raw.replace("LABEL=SYMBIUPDATE", "LABEL=OTHER"),
            raw.replace(expected["uuid"], "2d3a0ad0-0fdb-4338-a56d-12061df7b091"),
            raw + "TYPE=ext4\n",
            raw + "malformed\n",
        ]
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_source_identity(changed, expected)

    def test_source_mount_observation_binds_kernel_mountinfo_to_the_device(self):
        raw = (r"46 23 0:1 /cache\040root /run/other\040mount ro - tmpfs "
               "tmpfs\\134name rw\n"
               "99 23 0:44 / /run/symbi-update "
               "rw,nosuid,nodev,noexec - tmpfs runtime rw\n"
               "47 23 252:16 / /run/symbi-update "
               "ro,nosuid,nodev,noexec,relatime - ext4 /dev/vdb ro,seclabel\n")
        observation = source_mount_observation(raw, 47)
        self.assertEqual(observation, {
            "mountinfo_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "path_match_count": 2,
            "selected_match_count": 1,
            "visible_mount_id": 47,
            "selected_mount_id": 47,
            "mountpoint": "/run/symbi-update",
            "root": "/",
            "fstype": "ext4",
            "source": "/dev/vdb",
            "major_minor": "252:16",
            "options": ["ro", "nosuid", "nodev", "noexec", "relatime"],
            "super_options": ["ro", "seclabel"],
        })
        self.assertEqual(validate_source_mount(
            observation, Path("/dev/vdb"), (252, 16)), observation)

    def test_source_mount_validation_rejects_changed_controls(self):
        valid = ("47 23 252:16 / /run/symbi-update "
                 "ro,nosuid,nodev,noexec,relatime - ext4 /dev/vdb ro,seclabel\n")
        mutations = {
            "device number": valid.replace("252:16", "252:17"),
            "filesystem root": valid.replace("252:16 / /run", "252:16 /subtree /run"),
            "mountpoint": valid.replace("/run/symbi-update", "/run/other"),
            "source": valid.replace("/dev/vdb", "/dev/vdc"),
            "filesystem": valid.replace(" ext4 ", " xfs "),
            "read only": valid.replace("ro,nosuid", "rw,nosuid"),
            "nosuid": valid.replace(",nosuid", ""),
            "nodev": valid.replace(",nodev", ""),
            "noexec": valid.replace(",noexec", ""),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_source_mount(
                    source_mount_observation(raw, 47), Path("/dev/vdb"), (252, 16))

    def test_source_mount_observation_rejects_ambiguous_or_unsafe_input(self):
        valid = ("47 23 252:16 / /run/symbi-update "
                 "ro,nosuid,nodev,noexec - ext4 /dev/vdb ro,seclabel\n")
        cases = {
            "duplicate selected ID": valid + valid,
            "malformed escape": valid.replace("symbi-update", r"symbi\041update"),
            "unknown escape": valid.replace("/dev/vdb", r"/dev/vd\142"),
            "nul": valid.replace("ext4", "ext4\x00"),
            "oversized": valid + ("x" * MOUNTINFO_MAX_BYTES),
        }
        for name, raw in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                observation = source_mount_observation(raw, 47)
                validate_source_mount(observation, Path("/dev/vdb"), (252, 16))

    def test_visible_mount_id_selection_fails_closed_without_guessing(self):
        visible = ("47 23 252:16 / /run/symbi-update "
                   "ro,nosuid,nodev,noexec - ext4 /dev/vdb ro,seclabel\n")
        hidden = ("99 23 0:44 / /run/symbi-update "
                  "rw,nosuid,nodev,noexec - tmpfs runtime rw\n")
        selected = source_mount_observation(visible + hidden, 47)
        self.assertEqual(selected["path_match_count"], 2)
        self.assertEqual(selected["visible_mount_id"], 47)
        self.assertEqual(selected["selected_mount_id"], 47)
        self.assertEqual(selected["source"], "/dev/vdb")
        for raw, visible_id in (
            (visible + visible, 47),
            (visible + hidden, 48),
        ):
            with self.subTest(visible_id=visible_id), self.assertRaises(ValueError):
                validate_source_mount(
                    source_mount_observation(raw, visible_id),
                    Path("/dev/vdb"), (252, 16))

    def test_fdinfo_mount_id_parser_is_bounded_and_unambiguous(self):
        raw = "pos:\t0\nflags:\t012000000\nmnt_id:\t47\nino:\t123\n"
        self.assertEqual(parse_visible_mount_id(raw), 47)
        mutations = {
            "missing": raw.replace("mnt_id:\t47\n", ""),
            "duplicate": raw + "mnt_id:\t47\n",
            "negative": raw.replace("mnt_id:\t47", "mnt_id:\t-1"),
            "leading zero": raw.replace("mnt_id:\t47", "mnt_id:\t047"),
            "non-numeric": raw.replace("mnt_id:\t47", "mnt_id:\tabc"),
            "nul": raw.replace("mnt_id", "mnt\x00_id"),
            "no newline": raw.rstrip("\n"),
            "oversized": raw + ("x" * FDINFO_MAX_BYTES),
        }
        for name, changed in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_visible_mount_id(changed)

    def test_visible_mount_open_binds_fdinfo_mountinfo_and_named_path(self):
        raw = ("47 23 252:16 / /run/symbi-update "
               "ro,nosuid,nodev,noexec - ext4 /dev/vdb ro,seclabel\n")
        opened = Mock(st_mode=stat.S_IFDIR | 0o700, st_dev=11, st_ino=22)
        named = Mock(st_mode=stat.S_IFDIR | 0o700, st_dev=11, st_ino=22)
        close = Mock()
        opener = Mock(return_value=9)
        observation = observe_visible_source_mount(
            opener=opener, descriptor_stat=Mock(return_value=opened),
            path_lstat=Mock(side_effect=[named, named]), closer=close,
            fdinfo_reader=Mock(return_value=47), mountinfo_reader=Mock(return_value=raw))
        self.assertEqual(observation["selected_mount_id"], 47)
        opened_path, opened_flags = opener.call_args.args
        self.assertEqual(opened_path, SOURCE.parent)
        self.assertTrue(opened_flags & os.O_PATH)
        self.assertTrue(opened_flags & os.O_DIRECTORY)
        self.assertTrue(opened_flags & os.O_NOFOLLOW)
        close.assert_called_once_with(9)

        symlink = Mock(st_mode=stat.S_IFLNK | 0o777, st_dev=11, st_ino=22)
        changed = Mock(st_mode=stat.S_IFDIR | 0o700, st_dev=11, st_ino=23)
        for name, named_states in {
            "symlink": [symlink],
            "descriptor mismatch": [changed],
            "changed path": [named, changed],
        }.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                observe_visible_source_mount(
                    opener=Mock(return_value=9),
                    descriptor_stat=Mock(return_value=opened),
                    path_lstat=Mock(side_effect=named_states), closer=Mock(),
                    fdinfo_reader=Mock(return_value=47),
                    mountinfo_reader=Mock(return_value=raw))

    def test_real_host_fdinfo_mount_id_selects_the_visible_root_mount(self):
        descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            visible_mount_id = read_visible_mount_id(descriptor)
        finally:
            os.close(descriptor)
        observation = mount_observation(
            Path("/proc/self/mountinfo").read_text(), Path("/"), visible_mount_id)
        self.assertEqual(observation["selected_match_count"], 1)
        self.assertEqual(observation["selected_mount_id"], visible_mount_id)
        self.assertEqual(observation["mountpoint"], "/")

    def test_mounted_device_binding_requires_one_real_mount_of_the_block_node(self):
        source = Mock(st_mode=stat.S_IFBLK | 0o600,
                      st_rdev=os.makedev(252, 16))
        mounted = Mock(st_mode=stat.S_IFDIR | 0o755,
                       st_dev=os.makedev(252, 16))
        kwargs = {
            "device_lstat": Mock(return_value=source),
            "mount_stat": Mock(return_value=mounted),
            "is_mount": Mock(return_value=True),
        }
        self.assertEqual(validate_mounted_device(
            Path("/dev/vdb"), SOURCE.parent, **kwargs), (252, 16))
        for name, change in {
            "not mounted": {"is_mount": Mock(return_value=False)},
            "not block": {"device_lstat": Mock(return_value=Mock(
                st_mode=stat.S_IFREG | 0o600, st_rdev=os.makedev(252, 16)))},
            "other mounted device": {"mount_stat": Mock(return_value=Mock(
                st_mode=stat.S_IFDIR | 0o755, st_dev=os.makedev(252, 17)))},
        }.items():
            changed = dict(kwargs)
            changed.update(change)
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_mounted_device(Path("/dev/vdb"), SOURCE.parent, **changed)

    def test_existing_atomic_workflow_downloads_both_exact_artifacts(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/atomic-boot.yml").read_text()
        script = (root / "scripts/check-atomic-boot.sh").read_text()
        hosted = (root / "image/atomic/hosted.py").read_text()
        self.assertIn("SYMBI_QUALIFICATION: update", workflow)
        self.assertIn("atomic-update-artifact.json", workflow)
        self.assertIn("atomic-update-image.zip", workflow)
        self.assertIn("require_update_base(lock,pins,current)", workflow)
        self.assertIn(".cache/atomic-update-evidence", workflow)
        self.assertIn("SYMBI_QUALIFICATION=update", script)
        self.assertIn("--property=MemoryMax=5G", script)
        self.assertIn("else '5368709120'", hosted)
        self.assertIn("qualification in ('landlock','containers')", hosted)
        self.assertIn(
            "qualification not in ('','landlock','update','containers')", hosted)
        self.assertIn("qualification=='landlock'", hosted)
        self.assertIn("qualification=='update'", hosted)

    def test_only_the_fixed_atomic_controller_can_use_the_extended_timeout(self):
        command = [
            "podman", "--cgroup-manager=cgroupfs", "--root", "/private/root",
            "--runroot", "/run/symbi-atomic-disk-123-1", "run", "--rm",
            "--name=symbi-atomic-update-qemu", "--pull=never", "--network=none",
            "--pid=private",
            "--cgroup-parent=/system.slice/symbi-atomic-disk-123-1.service",
            "--env=LANG=C.UTF-8",
            "--env=PYTHONDONTWRITEBYTECODE=1", "--read-only", "--user=10001:10001",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=3g",
            "--memory-swap=3g", "--cpus=2", "--pids-limit=64",
            "--mount", "type=bind,src=/private/input,dst=/inputs,ro",
            "--mount", "type=bind,src=/private/old,dst=/inputs/atomic.raw,ro",
            "--mount", "type=bind,src=/private/update,dst=/inputs/update.raw,ro",
            "--mount", "type=bind,src=/private/output,dst=/output",
            "--entrypoint=/usr/bin/python3", "sha256:" + "a" * 64,
            "/inputs/update_boot.py",
        ]
        self.assertEqual(TIMEOUT_SECONDS, 5400)
        validate_update_controller_command(command)
        for mutation in ("network", "entrypoint", "script", "memory",
                         "memory-override", "read-write-override", "remote",
                         "global-manager", "global-root", "relative-root",
                         "long-runroot", "cgroup", "mount-option", "ro-false",
                         "output-ro"):
            with self.subTest(mutation=mutation):
                changed = list(command)
                if mutation == "network":
                    changed.remove("--network=none")
                elif mutation == "entrypoint":
                    changed[changed.index("--entrypoint=/usr/bin/python3")] = "--entrypoint=/bin/sh"
                elif mutation == "script":
                    changed[-1] = "/inputs/caller.py"
                elif mutation == "memory-override":
                    changed.insert(-2, "--memory=4g")
                elif mutation == "read-write-override":
                    changed.insert(-2, "--read-only=false")
                elif mutation == "remote":
                    changed.insert(1, "--remote")
                elif mutation == "global-manager":
                    changed[1] = "--cgroup-manager=systemd"
                elif mutation == "global-root":
                    changed.insert(changed.index("run"), "--root=/other")
                elif mutation == "relative-root":
                    changed[changed.index("/private/root")] = "relative/root"
                elif mutation == "long-runroot":
                    changed[changed.index("/run/symbi-atomic-disk-123-1")] = "/run/" + "x" * 51
                elif mutation == "cgroup":
                    changed[changed.index(
                        "--cgroup-parent=/system.slice/symbi-atomic-disk-123-1.service"
                    )] = "--cgroup-parent=/system.slice/symbi-atomic-disk-999-1.service"
                elif mutation == "mount-option":
                    index = changed.index("type=bind,src=/private/input,dst=/inputs,ro")
                    changed[index] += ",rw"
                elif mutation == "ro-false":
                    index = changed.index("type=bind,src=/private/input,dst=/inputs,ro")
                    changed[index] = "type=bind,src=/private/input,dst=/inputs,ro=false"
                elif mutation == "output-ro":
                    index = changed.index("type=bind,src=/private/output,dst=/output")
                    changed[index] += ",ro"
                else:
                    changed[changed.index("--memory=3g")] = "--memory=4g"
                with self.assertRaises(ValueError):
                    validate_update_controller_command(changed)

    def test_atomic_wrapper_reclaims_only_exact_evidence_directories(self):
        root = Path(__file__).resolve().parents[2]
        script = (root / "scripts/check-atomic-boot.sh").read_text()
        for name in ("atomic-image-evidence", "atomic-disk-evidence",
                     "atomic-update-evidence"):
            self.assertIn(f'"$root/.cache/{name}"', script)
        self.assertIn('find -P "$path" -xdev', script)
        self.assertIn('-type f -links 1', script)
        self.assertIn('chown --no-dereference', script)
        self.assertIn('[[ -L "$path" || ! -d "$path" ]]', script)
        self.assertNotIn(".cache/atomic-*", script)
        self.assertLess(script.index('cache="$root/.cache"'),
                        script.index('mkdir -p "$evidence"'))
        self.assertLess(script.index("before use: $path"),
                        script.index("sudo systemd-run"))

    def report(self):
        return {
            "schema": 1,
            "passed": True,
            "guest_booted": True,
            "release_qualified": False,
            "source_authentication": {
                "positive_controls": {"install": True, "update": True},
                "negative_controls": {
                    "unsigned": True, "wrong-key": True,
                    "wrong-reference": True, "altered-signature": True,
                },
            },
            "bootc_negative_controls": {
                "unsigned": True, "wrong-key": True,
                "wrong-reference": True, "altered-signature": True,
            },
            "same_path_positive_control": {
                "passed": True, "overlay_discarded": True,
                "negative_baselines_clean": True,
                "source": NEGATIVE_UPDATE_SOURCE,
                "report_sha256": "8" * 64,
                "state_before_sha256": "3" * 64,
                "state_after_sha256": "7" * 64,
            },
            "negative_overlays_discarded": True,
            "phases": [
                {"name": "installed", "booted_digest": self.old,
                 "operation": "signed-update-staged",
                 "staged_digest": self.new},
                {"name": "updated", "booted_digest": self.new,
                 "operation": "rollback-queued",
                 "rollback_digest": self.old},
                {"name": "rolled-back", "booted_digest": self.old,
                 "rollback_from_digest": self.new},
            ],
            "source_disk_unchanged": True,
            "persistent_overlay": True,
        }

    def test_complete_signed_update_and_booted_rollback_pass(self):
        result = validate_report(self.report(), self.old, self.new)
        self.assertEqual(result["updated_digest"], self.new)
        self.assertEqual(result["rolled_back_digest"], self.old)
        self.assertTrue(result["signed_update"])
        self.assertTrue(result["booted_rollback"])
        self.assertTrue(result["same_path_signature_acceptance"])

    def test_missing_phase_or_signature_control_fails(self):
        cases = []
        report = self.report()
        report["phases"].pop()
        cases.append(report)
        report = self.report()
        report["source_authentication"]["negative_controls"]["unsigned"] = False
        cases.append(report)
        report = self.report()
        report["bootc_negative_controls"]["unsigned"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["passed"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["negative_baselines_clean"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["overlay_discarded"] = False
        cases.append(report)
        report = self.report()
        report["same_path_positive_control"]["state_after_sha256"] = "3" * 64
        cases.append(report)
        report = self.report()
        report["negative_overlays_discarded"] = False
        cases.append(report)
        report = self.report()
        report["phases"][1]["booted_digest"] = self.old
        cases.append(report)
        report = self.report()
        report["release_qualified"] = True
        cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report(report, self.old, self.new)


if __name__ == "__main__":
    unittest.main()
