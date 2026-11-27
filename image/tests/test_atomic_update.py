"""Contracts for the signed installed-image update and booted rollback gate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from image.atomic.update_contract import (NEGATIVE_UPDATE_SOURCE, POSITIVE_OVERLAY_CASE,
                                          update_policy,
                                          update_command, rollback_command,
                                          negative_signature_payloads,
                                          validate_report, require_update_base,
                                          validate_artifact_metadata)
from image.atomic.update_boot import (DISPOSABLE_PHASE_TIMEOUT_SECONDS,
                                      qemu_command, negative_qemu_command,
                                      positive_qemu_command,
                                      firmware_arguments,
                                      stop_child,
                                      validate_phase_report,
                                      validate_negative_report,
                                      validate_positive_report,
                                      validate_shared_baseline)
from image.atomic.update_process import TIMEOUT_SECONDS, validate_update_controller_command
from image.atomic.update_guest import (UPDATE_COMMAND_TIMEOUT_SECONDS,
                                       SOURCE, STATE,
                                       phase_status, deployment_snapshot,
                                       staged_deployment_snapshot,
                                       validate_source_identity,
                                       device_settle_command)
from image.atomic.update_hosted import retain_controller_output, run_update
from image.atomic.hosted import (RETAINED_REPORT_MAX_BYTES,
                                 validate_retained_preflight)
from image.boot.inputs import require_desktop_image
from image.boot.preflight import expected_inputs


class AtomicUpdateTests(unittest.TestCase):
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

    def test_failed_update_refuses_unsafe_diagnostic_entries(self):
        for case in ("unexpected", "symlink", "hardlink", "fifo", "socket",
                     "directory", "oversized"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output, evidence = root / "output", root / "evidence"
                output.mkdir()
                evidence.mkdir()
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
            path = output / "same-path-positive-serial.log"
            path.write_bytes(b"a" * 4096)
            initial = path.stat()
            original_read = os.read
            changed = False

            def changing_read(descriptor, count):
                nonlocal changed
                raw = original_read(descriptor, count)
                if not changed:
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
        self.assertEqual(switch[:3], ["/usr/bin/bootc", "switch", "--transport"])
        self.assertIn("--enforce-container-sigpolicy", switch)
        self.assertEqual(switch[-1], "/run/symbi-update/source")
        self.assertEqual(rollback_command(), ["/usr/bin/bootc", "rollback"])
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
        self.assertIn("file=/output/guest.qcow2,format=qcow2,if=virtio", joined)
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
        self.assertNotIn("fstab.extra", " ".join(firmware))

    def test_each_bootc_rejection_uses_a_distinct_disposable_overlay(self):
        commands = {case: negative_qemu_command(case) for case in (
            "unsigned", "wrong-key", "wrong-reference", "altered-signature")}
        for case, command in commands.items():
            joined = " ".join(command)
            self.assertIn(f"file=/output/negative-{case}.qcow2,format=qcow2,if=virtio", joined)
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
        self.assertIn("file=/output/same-path-positive.qcow2,format=qcow2,if=virtio", positive)
        self.assertIn("path=/output/same-path-positive.json", positive)
        self.assertIn("file=/inputs/expected-positive.json", positive)
        self.assertNotIn("file=/output/guest.qcow2", positive)
        self.assertNotIn("file=/output/negative-", positive)
        with self.assertRaises(ValueError):
            negative_qemu_command("caller-selected")

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

    def positive_report(self):
        switch = update_command(NEGATIVE_UPDATE_SOURCE)
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "same_path_positive_control": {
                "case": POSITIVE_OVERLAY_CASE, "switch_accepted": True,
                "switch_exit_code": 0, "booted_unchanged": True,
                "deployment_staged": True, "default_changed": True,
                "staged_digest": self.new, "state_before_sha256": "3" * 64,
                "state_after_sha256": "7" * 64,
                "source": NEGATIVE_UPDATE_SOURCE, "source_readonly": True,
            },
            "commands": [
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
                {"command": switch, "exit_code": 0},
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
            ],
        }

    def test_same_path_positive_report_binds_success_and_controlled_state(self):
        expected = {"nonce": "4" * 32, "new_digest": self.new,
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        report = self.positive_report()
        validate_positive_report(report, expected, "5" * 64, "6" * 64)
        validate_shared_baseline(report, self.negative_report())
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][1]["exit_code"] = 1
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

    def negative_report(self, case="unsigned"):
        switch = update_command(NEGATIVE_UPDATE_SOURCE)
        state_hash = "3" * 64
        return {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "negative_control": {
                "case": case, "switch_rejected": True, "switch_exit_code": 1,
                "deployment_unchanged": True, "default_unchanged": True,
                "state_sha256": state_hash, "source": NEGATIVE_UPDATE_SOURCE,
                "source_readonly": True,
            },
            "commands": [
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
                {"command": switch, "exit_code": 1},
                {"command": ["/usr/bin/bootc", "status", "--json"], "exit_code": 0},
            ],
        }

    def test_negative_report_requires_failed_real_switch_and_unchanged_state(self):
        report = self.negative_report()
        expected = {"nonce": "4" * 32,
                    "source_disk": {"filesystem": "ext4", "label": "SYMBIUPDATE",
                                    "uuid": self.source_uuid}}
        validate_negative_report(report, expected, "5" * 64, "6" * 64, "unsigned")
        mutations = []
        changed = copy.deepcopy(report)
        changed["commands"][1]["exit_code"] = 0
        changed["negative_control"]["switch_exit_code"] = 0
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["negative_control"]["deployment_unchanged"] = False
        mutations.append(changed)
        changed = copy.deepcopy(report)
        changed["commands"][1]["command"][-1] = "/tmp/other"
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
                                    "uuid": self.source_uuid}}
        phase = {"name": "installed", "booted_digest": self.old,
                 "operation": "signed-update-staged", "staged_digest": self.new}
        report = {
            "schema": 1, "passed": True, "guest_booted": True,
            "release_qualified": False, "product": "Symbi-Hosted-Update-Probe",
            "nonce": "4" * 32, "expected_sha256": "5" * 64,
            "runner_sha256": "6" * 64, "source_mounted_readonly": True,
            "source_device": {"path": "/dev/vdb", "TYPE": "ext4",
                              "LABEL": "SYMBIUPDATE", "UUID": self.source_uuid},
            "phase": phase,
            "commands": [{"command": ["/usr/bin/bootc", "status", "--json"],
                          "exit_code": 0}],
        }
        validate_phase_report(report, expected, "5" * 64, "6" * 64, phase)
        for field in ("path", "TYPE", "LABEL", "UUID"):
            changed = copy.deepcopy(report)
            changed["source_device"].pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_phase_report(changed, expected, "5" * 64, "6" * 64, phase)

    def test_update_service_and_mount_are_bounded_and_offline(self):
        root = Path(__file__).resolve().parents[2]
        settings = dict(line.split("=", 1) for line in
                        (root / "image/atomic/update-o.service").read_text().splitlines()
                        if "=" in line and not line.startswith("#"))
        self.assertNotIn("RequiresMountsFor", settings)
        self.assertEqual(settings["After"], "local-fs.target systemd-udev-trigger.service")
        self.assertEqual(settings["RuntimeDirectory"], "symbi-update")
        self.assertEqual(settings["RuntimeDirectoryMode"], "0700")
        self.assertEqual(settings["StateDirectory"], "symbi-update-test")
        self.assertEqual(settings["PrivateMounts"], "yes")
        self.assertEqual(settings["MemorySwapMax"], "0")
        self.assertEqual(settings["TasksMax"], "128")
        self.assertFalse((root / "image/atomic/update-fstab.extra").exists())

    def test_update_device_readiness_wait_is_fixed_and_bounded(self):
        self.assertEqual(device_settle_command(), [
            "/usr/bin/udevadm", "settle", "--timeout=30",
            "--exit-if-exists=/dev/disk/by-id/virtio-SYMBIUPDATE"])

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
        self.assertIn("'memory.max':'5368709120'", hosted)
        self.assertIn("qualification not in ('','update')", hosted)
        self.assertNotIn("qualification=='landlock'", hosted)
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
