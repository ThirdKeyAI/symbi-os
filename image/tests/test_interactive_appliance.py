"""Offline contract tests for the HIGHLY EXPERIMENTAL graphical appliance."""
import ast
import base64
import copy
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import yaml

from image.appliance.contract import (APPLIANCE_CONTAINER_LIMITS,
    APPLIANCE_CONTAINER_MEMORY_BYTES, APPLIANCE_CONTROLLER_MARGIN_BYTES,
    APPLIANCE_CONTROLLER_MEMORY_BYTES, ARTIFACT_NAME, FAILURE_STATUS_SENTINELS,
    PROVISION_STATUS_PHASES, SCOPE, SDDM_CONFIGURATION, TRANSIENT_BOOT_CREDENTIAL,
    TRANSIENT_BOOT_DROPIN,
    VIRTUAL_DISK_BYTES, build_manifest, controller_failure_record, failure_record,
    firmware_arguments, installer_arguments, provision_qemu_arguments,
    reboot_qemu_arguments, user_launch_arguments, validate_guest_report,
    validate_producer_failure_status, validate_reboot_report, transient_boot_arguments,
    validate_source_binding)
from image.appliance.hosted import (EVIDENCE_FILE_LIMITS,
                                    MAX_RETAINED_EVIDENCE_BYTES,
                                    PUBLIC_ARTIFACT_FILES,
                                    SUCCESS_EVIDENCE_FILES,
                                    _failure_diagnostic, _installed_desktop_bindings,
                                    create_outer_failure_evidence,
                                    invalidate_appliance_output, outer_failure_record,
                                    produce_appliance,
                                    validate_public_artifact,
                                    validate_retained_evidence)
from image.appliance.prerequisite import (DOWNLOAD_WORKING_MARGIN_BYTES,
    require_download_capacity, required_free_before_download,
    validate_appliance_prerequisites)
from image.appliance.reboot import (bounded_log, ppm_observation,
                                    require_empty_output)
from image.appliance.verify import (bound_regular, observe_bounded_walker,
                                    path_absent,
                                    persistent_systemd_alias_is_exact,
                                    persistent_fixture_boot_references_absent,
                                    reviewed_launcher,
                                    transient_boot_dropin_is_exact)
from image.atomic.hosted import MINIMUM_DISK_FREE_BYTES, enforce_appliance_final_status


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_EXPIRY = "2026-11-29T00:00:00Z"
CHILD_LIMITS = dict(APPLIANCE_CONTAINER_LIMITS)
OUTER_ENVIRONMENT = {
    "GITHUB_SHA": "a" * 40,
    "SYMBI_APPLIANCE_SOURCE_TREE": "9" * 40,
}


def cgroup_final():
    return CHILD_LIMITS | {
        "memory.peak": "1048576",
        "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
        "cpu.stat": "usage_usec 1000\nuser_usec 600\nsystem_usec 400\n",
    }


def outer_systemd_result(result="success", code=1, status=0,
                         active="active", sub="exited"):
    """Match fixed fields emitted by systemctl show for the retained oneshot."""
    return {
        "LoadState": "loaded", "Type": "oneshot", "RemainAfterExit": "yes",
        "ActiveState": active, "SubState": sub, "Result": result,
        "OOMPolicy": "stop", "MemoryMax": str(5 * 1024**3), "MemoryPeak": "1",
        "MemorySwapMax": "0", "MemorySwapPeak": "0", "CPUUsageNSec": "1",
        "ExecMainCode": str(code), "ExecMainStatus": str(status),
    }


def write_outer_systemd_result(path, **changes):
    record = outer_systemd_result()
    record.update(changes)
    path.write_text("".join(f"{name}={value}\n" for name, value in record.items()))


def source_binding():
    return {
        "repository": "ThirdKeyAI/symbi-os", "source_commit": "a"*40,
        "source_tree": "9"*40,
        "image_source_commit": "b"*40, "image_run_id": 123,
        "image_artifact_id": 456, "image_artifact_sha256": "c"*64,
        "oci_manifest_digest": "sha256:" + "d"*64,
        "installed_raw_sha256": "e"*64,
    }


def artifact():
    return {"name": ARTIFACT_NAME, "bytes": 4096, "sha256": "f"*64,
            "format": "qcow2", "compression": "qcow2-zlib-clusters",
            "virtual_bytes": VIRTUAL_DISK_BYTES}


def producer_status(**changes):
    value = {
        "phase": "guest-report", "kind": "exception", "exit_code": None,
        "timeout_seconds": None, "qemu_exit_code": 0,
    }
    value.update(changes)
    return value


def child_failure(reason="RuntimeError: QEMU could not allocate guest memory"):
    source = source_binding()
    result = failure_record(source, reason)
    result.update({
        "limits": dict(APPLIANCE_CONTAINER_LIMITS),
        "producer_status": producer_status(),
        "cgroup_final": {
            **APPLIANCE_CONTAINER_LIMITS,
            "memory.peak": str(3 * 1024**3),
            "memory.events": (
                "low 0\nhigh 0\nmax 17\noom 0\noom_kill 0\noom_group_kill 0\n"
                "sock_throttled 0\n"
            ),
            "cpu.stat": (
                "usage_usec 200\nuser_usec 100\nsystem_usec 100\nnr_periods 2\n"
                "nice_usec 0\ncore_sched.force_idle_usec 0\nnr_throttled 0\n"
                "throttled_usec 0\nnr_bursts 0\nburst_usec 0\n"
            ),
        },
    })
    return result


def guest(expected):
    return {
        "schema": 1, "nonce": expected["nonce"], "source_binding": expected["source_binding"],
        "probe_sha256": "1"*64, "expected_sha256": "2"*64,
        "passed": True, "guest_booted": True, "graphical_desktop_observed": True,
        "os_qualified": False, "release_qualified": False, "signature_qualified": False,
        "network_interfaces": ["lo"], "default_target": "graphical.target",
        "display_manager": "sddm.service", "session": "symbi.desktop",
        "interactive_devices": {"virtio_gpu": True, "virtio_keyboard": True,
                                "virtio_pointer": True},
        "fixture_user": {"name": "symbi-test", "password_locked": True,
                         "non_wheel": True, "authorized_keys_absent": True},
        "fixture_cleanup": {"persistent_boot_wants_absent": True, "persistent_scripts_absent": True,
                            "persistent_units_absent": True, "credentials_absent": True},
        "desktop_components": {"Hyprland": True, "Waybar": True, "Walker": True,
                               "portal": True, "first_login_seeded": True},
        "walker_launch": {
            "unit": "symbi-appliance-walker.service", "executable": "/usr/bin/walker",
            "observed": True, "stop_succeeded": True, "stopped": True,
            "timeout_seconds": 30,
            "limits": {"memory_max": "512M", "memory_swap_max": "0",
                       "cpu_quota": "100%", "tasks_max": "64",
                       "runtime_max_seconds": "60", "no_new_privileges": "yes"},
        },
        "autologin_sha256": expected.get("sddm_config_sha256"),
        "scope": SCOPE,
    }


def reboot(source=None, bound_artifact=None):
    source = source or source_binding()
    bound_artifact = bound_artifact or artifact()
    return {
        "schema": 1, "passed": True, "guest_booted": True,
        "graphical_desktop_observed": True, "artifact_retained": True,
        "independent_reboot_passed": True, "os_qualified": False,
        "release_qualified": False, "signature_qualified": False,
        "source_binding": source, "artifact_before": bound_artifact,
        "artifact_after": bound_artifact,
        "screenshot": {"bytes": 8192, "sha256": "3"*64, "width": 800,
                       "height": 600, "sampled_colors": 8,
                       "boot_elapsed_seconds": 90},
        "command": reboot_qemu_arguments(),
        "limits": dict(CHILD_LIMITS), "cgroup_final": cgroup_final(),
        "scope": SCOPE,
    }


def retained_success_evidence(root):
    """Write one compact, internally bound success inventory for offline tests."""
    evidence = root / ".cache/interactive-appliance-evidence"
    evidence.mkdir(parents=True)
    source = source_binding()
    qcow_bytes = b"QFI\xfb compact public appliance fixture\n"
    disk = {
        "name": ARTIFACT_NAME, "bytes": len(qcow_bytes),
        "sha256": hashlib.sha256(qcow_bytes).hexdigest(), "format": "qcow2",
        "compression": "qcow2-zlib-clusters", "virtual_bytes": VIRTUAL_DISK_BYTES,
    }
    verifier = root / "image/appliance/verify.py"
    verifier.parent.mkdir(parents=True)
    verifier.write_text("# retained verifier fixture\n")
    expected = {
        "schema": 1, "nonce": "0" * 32, "username": "symbi-test",
        "source_binding": source,
        "sddm_config_sha256": hashlib.sha256(SDDM_CONFIGURATION.encode()).hexdigest(),
        "production_files": {}, "seed_files": {},
        "desktop_components": {"preparation_sha256": "4" * 64,
                               "files": {}, "packages": {}},
    }
    screenshot_path = evidence / "display.ppm"
    pixels = bytearray(b"\0\0\0" * (320 * 200))
    pixels[:3] = b"\xff\xff\xff"
    screenshot_path.write_bytes(b"P6\n320 200\n255\n" + pixels)
    screenshot = ppm_observation(screenshot_path)
    screenshot["boot_elapsed_seconds"] = 90
    reboot_result = reboot(source, disk)
    reboot_result["screenshot"] = screenshot
    guest_result = guest(expected)
    guest_result["probe_sha256"] = hashlib.sha256(verifier.read_bytes()).hexdigest()
    guest_result["expected_sha256"] = hashlib.sha256(
        (json.dumps(expected, sort_keys=True) + "\n").encode()).hexdigest()
    (evidence / "guest-report.json").write_text(json.dumps(guest_result, indent=2) + "\n")
    producer = {
        "schema": 1,
        "passed": True, "guest_booted": True, "graphical_desktop_observed": True,
        "artifact_retained": True, "independent_reboot_passed": False,
        "os_qualified": False, "release_qualified": False,
        "signature_qualified": False, "source_binding": source, "artifact": disk,
        "guest_report_sha256": hashlib.sha256(
            (evidence / "guest-report.json").read_bytes()).hexdigest(),
        "limits": dict(CHILD_LIMITS), "command": provision_qemu_arguments(),
        "qemu_version": "QEMU emulator version 9.2.0\n",
        "tools": {"qemu-system-x86_64": "5" * 64, "qemu-img": "6" * 64},
        "scope": SCOPE, "cgroup_final": cgroup_final(),
    }
    manifest = build_manifest(
        source, disk, producer, reboot_result,
        datetime(2026, 11, 27, tzinfo=timezone.utc),
    )
    documents = {
        "producer-result.json": producer,
        "reboot-result.json": reboot_result,
        "manifest.json": manifest,
    }
    for name, document in documents.items():
        (evidence / name).write_text(json.dumps(document, indent=2) + "\n")
    controller = {
        "schema": 1, "passed": True, "guest_booted": True,
        "graphical_desktop_observed": True, "artifact_retained": True,
        "independent_reboot_passed": True, "os_qualified": False,
        "release_qualified": False, "signature_qualified": False,
        "source_binding": source, "artifact": disk,
        "producer_result_sha256": hashlib.sha256(
            (evidence / "producer-result.json").read_bytes()).hexdigest(),
        "guest_report_sha256": hashlib.sha256(
            (evidence / "guest-report.json").read_bytes()).hexdigest(),
        "reboot_result_sha256": hashlib.sha256(
            (evidence / "reboot-result.json").read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(
            (evidence / "manifest.json").read_bytes()).hexdigest(),
        "screenshot_sha256": hashlib.sha256(screenshot_path.read_bytes()).hexdigest(),
        "scope": SCOPE,
    }
    (evidence / "result.json").write_text(json.dumps(controller, indent=2) + "\n")
    write_outer_systemd_result(evidence / "systemd-result.txt")
    for name in SUCCESS_EVIDENCE_FILES:
        if not (evidence / name).exists():
            (evidence / name).write_bytes(b"")
    public = root / ".cache/interactive-appliance-artifact"
    public.mkdir()
    (public / ARTIFACT_NAME).write_bytes(qcow_bytes)
    (public / "manifest.json").write_bytes((evidence / "manifest.json").read_bytes())
    (public / "display.ppm").write_bytes(screenshot_path.read_bytes())
    return evidence, expected


def validate_fixture(root, expected, checkout=None, expiry=EXPECTED_EXPIRY):
    source = expected["source_binding"]
    checkout = checkout or {
        "source_commit": source["source_commit"], "source_tree": source["source_tree"],
    }
    with mock.patch("image.appliance.hosted._expected_guest_contract", return_value=expected), \
            mock.patch("image.appliance.hosted._checkout_binding", return_value=checkout):
        return validate_retained_evidence(root, expiry)


def validate_public_fixture(root, expected, checkout=None, expiry=EXPECTED_EXPIRY):
    source = expected["source_binding"]
    checkout = checkout or {
        "source_commit": source["source_commit"], "source_tree": source["source_tree"],
    }
    with mock.patch("image.appliance.hosted._expected_guest_contract", return_value=expected), \
            mock.patch("image.appliance.hosted._checkout_binding", return_value=checkout):
        return validate_public_artifact(root, expiry)


def validate_failure_fixture(root, source=None):
    source = source or source_binding()
    checkout = {
        "source_commit": source["source_commit"], "source_tree": source["source_tree"],
    }
    with mock.patch("image.appliance.hosted._checkout_binding", return_value=checkout):
        return validate_retained_evidence(root)


def validate_outer_failure_fixture(root):
    checkout = {
        "source_commit": OUTER_ENVIRONMENT["GITHUB_SHA"],
        "source_tree": OUTER_ENVIRONMENT["SYMBI_APPLIANCE_SOURCE_TREE"],
    }
    with mock.patch.dict(os.environ, OUTER_ENVIRONMENT), \
            mock.patch("image.appliance.hosted._checkout_binding", return_value=checkout):
        return validate_retained_evidence(root)


def write_atomic_outer_failure(root, commands, **values):
    evidence = root / ".cache/atomic-disk-evidence"
    evidence.mkdir(parents=True)
    lock = root / "image/desktop-images.lock.json"
    lock.parent.mkdir(parents=True)
    image_source_commit = "b" * 40
    rewrite_json(lock, {
        "images": {"generic": {"tested_commit": image_source_commit}},
    })
    record = {
        "schema": 1,
        "passed": False,
        "qualification": "appliance",
        "source_commit": OUTER_ENVIRONMENT["GITHUB_SHA"],
        "image_source_commit": image_source_commit,
        "commands": commands,
        **values,
    }
    rewrite_json(evidence / "result.json", record)


def rewrite_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def rebind_controller_hash(evidence, filename, field):
    controller = json.loads((evidence / "result.json").read_text())
    controller[field] = hashlib.sha256((evidence / filename).read_bytes()).hexdigest()
    rewrite_json(evidence / "result.json", controller)


class InteractiveApplianceContract(unittest.TestCase):
    def test_retained_success_evidence_is_exact_and_independently_verifiable(self):
        self.assertEqual(MAX_RETAINED_EVIDENCE_BYTES, 32 * 1024**2)
        self.assertEqual(SUCCESS_EVIDENCE_FILES, {
            "compress-qcow2.log", "convert-raw.log", "display.ppm",
            "guest-report.json", "manifest.json", "producer-result.json",
            "provision-qemu.log", "provision-serial.log", "reboot-qemu.log",
            "reboot-result.json", "reboot-serial.log", "result.json",
            "systemd-result.txt",
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            total = validate_fixture(root, expected)
            self.assertEqual(total, sum(path.stat().st_size for path in evidence.iterdir()))
            self.assertLess(total, MAX_RETAINED_EVIDENCE_BYTES)

            (evidence / "unexpected.log").write_text("extra")
            with self.assertRaisesRegex(ValueError, "Unsafe appliance evidence file"):
                validate_fixture(root, expected)

    def test_public_artifact_is_exact_secret_free_and_cross_bound(self):
        self.assertEqual(PUBLIC_ARTIFACT_FILES, {
            ARTIFACT_NAME, "manifest.json", "display.ppm",
        })
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, expected = retained_success_evidence(root)
            public = root / ".cache/interactive-appliance-artifact"
            total = validate_public_fixture(root, expected)
            self.assertEqual(total, sum(path.stat().st_size for path in public.iterdir()))

        for mutation, message in (
            ("extra", "inventory changed"),
            ("link", "Unsafe public appliance artifact file"),
            ("credential", "Credential-like material"),
            ("qcow", "Public qcow2 differs"),
            ("manifest", "Public manifest differs"),
            ("screenshot", "Public screenshot differs"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence, expected = retained_success_evidence(root)
                public = root / ".cache/interactive-appliance-artifact"
                if mutation == "extra":
                    (public / "workflow-token.txt").write_text("unexpected")
                elif mutation == "link":
                    (public / "manifest.json").unlink()
                    (public / "manifest.json").symlink_to(evidence / "manifest.json")
                elif mutation == "credential":
                    (public / ARTIFACT_NAME).write_bytes(b"PRIVATE KEY-----")
                elif mutation == "qcow":
                    with (public / ARTIFACT_NAME).open("ab") as stream:
                        stream.write(b"changed")
                elif mutation == "manifest":
                    with (public / "manifest.json").open("ab") as stream:
                        stream.write(b"\n")
                else:
                    data = bytearray((public / "display.ppm").read_bytes())
                    data[-1] ^= 1
                    (public / "display.ppm").write_bytes(data)
                with self.assertRaisesRegex(ValueError, message):
                    validate_public_fixture(root, expected)

    def test_manifest_expiry_is_bound_to_the_workflow_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            manifest = json.loads((evidence / "manifest.json").read_text())
            manifest["expires_at"] = "2099-01-01T00:00:00Z"
            rewrite_json(evidence / "manifest.json", manifest)
            rebind_controller_hash(evidence, "manifest.json", "manifest_sha256")
            with self.assertRaisesRegex(ValueError, "workflow binding"):
                validate_fixture(root, expected)

    def test_source_commit_and_tree_are_bound_to_the_checkout(self):
        for field in ("source_commit", "source_tree"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, expected = retained_success_evidence(root)
                source = expected["source_binding"]
                checkout = {
                    "source_commit": source["source_commit"],
                    "source_tree": source["source_tree"],
                }
                checkout[field] = "8" * 40
                with self.assertRaisesRegex(ValueError, "checkout commit or tree"):
                    validate_fixture(root, expected, checkout=checkout)

    def test_retained_evidence_aggregate_ceiling_precedes_content_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            evidence.mkdir(parents=True)
            for name, maximum in EVIDENCE_FILE_LIMITS.items():
                with (evidence / name).open("wb") as stream:
                    stream.truncate(maximum)
            self.assertGreater(
                sum(path.stat().st_size for path in evidence.iterdir()),
                MAX_RETAINED_EVIDENCE_BYTES,
            )
            with self.assertRaisesRegex(ValueError, "aggregate byte ceiling"):
                validate_retained_evidence(root)

    def test_retained_evidence_rejects_cross_binding_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            result = json.loads((evidence / "reboot-result.json").read_text())
            result["source_binding"]["source_commit"] = "8" * 40
            rewrite_json(evidence / "reboot-result.json", result)
            rebind_controller_hash(
                evidence, "reboot-result.json", "reboot_result_sha256")
            with self.assertRaisesRegex(ValueError, "reboot did not pass"):
                validate_fixture(root, expected)

    def test_retained_evidence_rejects_extra_positive_claims_in_every_child_schema(self):
        for filename, message in (
            ("producer-result.json", "producer success receipt"),
            ("guest-report.json", "guest report schema"),
            ("reboot-result.json", "reboot success receipt"),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence, expected = retained_success_evidence(root)
                document = json.loads((evidence / filename).read_text())
                document["security_qualified"] = True
                rewrite_json(evidence / filename, document)
                if filename == "producer-result.json":
                    rebind_controller_hash(
                        evidence, filename, "producer_result_sha256")
                elif filename == "guest-report.json":
                    producer = json.loads((evidence / "producer-result.json").read_text())
                    producer["guest_report_sha256"] = hashlib.sha256(
                        (evidence / filename).read_bytes()).hexdigest()
                    rewrite_json(evidence / "producer-result.json", producer)
                    rebind_controller_hash(evidence, filename, "guest_report_sha256")
                    rebind_controller_hash(
                        evidence, "producer-result.json", "producer_result_sha256")
                else:
                    rebind_controller_hash(
                        evidence, filename, "reboot_result_sha256")
                with self.assertRaisesRegex(ValueError, message):
                    validate_fixture(root, expected)

    def test_boolean_schema_values_never_count_as_integer_one(self):
        targets = (
            ("result.json", None),
            ("producer-result.json", "producer_result_sha256"),
            ("guest-report.json", "guest_report_sha256"),
            ("reboot-result.json", "reboot_result_sha256"),
            ("manifest.json", "manifest_sha256"),
        )
        for filename, controller_field in targets:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence, expected = retained_success_evidence(root)
                document = json.loads((evidence / filename).read_text())
                document["schema"] = True
                rewrite_json(evidence / filename, document)
                if filename == "guest-report.json":
                    producer = json.loads((evidence / "producer-result.json").read_text())
                    producer["guest_report_sha256"] = hashlib.sha256(
                        (evidence / filename).read_bytes()).hexdigest()
                    rewrite_json(evidence / "producer-result.json", producer)
                    rebind_controller_hash(
                        evidence, "producer-result.json", "producer_result_sha256")
                if controller_field is not None:
                    rebind_controller_hash(evidence, filename, controller_field)
                with self.assertRaises(ValueError):
                    validate_fixture(root, expected)

    def test_retained_evidence_rejects_unbound_guest_and_producer_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            guest_result = json.loads((evidence / "guest-report.json").read_text())
            guest_result["expected_sha256"] = "7" * 64
            rewrite_json(evidence / "guest-report.json", guest_result)
            producer = json.loads((evidence / "producer-result.json").read_text())
            producer["guest_report_sha256"] = hashlib.sha256(
                (evidence / "guest-report.json").read_bytes()).hexdigest()
            rewrite_json(evidence / "producer-result.json", producer)
            rebind_controller_hash(evidence, "guest-report.json", "guest_report_sha256")
            rebind_controller_hash(
                evidence, "producer-result.json", "producer_result_sha256")
            with self.assertRaisesRegex(ValueError, "(?i)guest.*unbound"):
                validate_fixture(root, expected)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            producer = json.loads((evidence / "producer-result.json").read_text())
            producer["artifact"]["sha256"] = "7" * 64
            rewrite_json(evidence / "producer-result.json", producer)
            rebind_controller_hash(
                evidence, "producer-result.json", "producer_result_sha256")
            with self.assertRaisesRegex(ValueError, "producer success receipt"):
                validate_fixture(root, expected)

    def test_retained_evidence_rejects_invalid_systemd_and_oom_facts(self):
        replacements = (
            ("MemoryPeak=1", "MemoryPeak=unknown", "numeric"),
            ("MemoryPeak=1", f"MemoryPeak={999 * 1024**3}", "Out-of-range"),
            ("MemorySwapPeak=0", "MemorySwapPeak=1", "used swap"),
            ("ExecMainStatus=0", "ExecMainStatus=True", "numeric"),
            ("ExecMainStatus=0", "ExecMainStatus=00", "Non-canonical"),
            ("ExecMainCode=1", "ExecMainCode=exited", "numeric"),
            ("ExecMainCode=1", "ExecMainCode=0", "child code"),
            ("Type=oneshot", "Type=simple", "unit contract"),
            ("RemainAfterExit=yes", "RemainAfterExit=no", "unit contract"),
            ("Result=success", "Result=exit-code", "exact systemd success"),
            ("OOMPolicy=stop", "OOMPolicy=continue", "OOM policy"),
        )
        for old, new, message in replacements:
            with self.subTest(replacement=new), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence, expected = retained_success_evidence(root)
                systemd_path = evidence / "systemd-result.txt"
                systemd_path.write_text(systemd_path.read_text().replace(old, new))
                with self.assertRaisesRegex(ValueError, message):
                    validate_fixture(root, expected)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            systemd_path = evidence / "systemd-result.txt"
            systemd = systemd_path.read_text()
            systemd = systemd.replace("Result=success", "Result=signal")
            systemd = systemd.replace("ActiveState=active", "ActiveState=failed")
            systemd = systemd.replace("SubState=exited", "SubState=failed")
            systemd = systemd.replace("ExecMainCode=1", "ExecMainCode=2")
            systemd = systemd.replace("ExecMainStatus=0", "ExecMainStatus=9")
            systemd_path.write_text(systemd)
            with self.assertRaisesRegex(ValueError, "exact systemd success"):
                validate_fixture(root, expected)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            write_outer_systemd_result(
                evidence / "systemd-result.txt", Result="oom-kill",
                ActiveState="failed", SubState="failed", ExecMainCode="2",
                ExecMainStatus="9",
            )
            with self.assertRaisesRegex(ValueError, "OOM evidence is not uploadable"):
                validate_fixture(root, expected)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            producer = json.loads((evidence / "producer-result.json").read_text())
            producer["cgroup_final"]["memory.events"] = (
                "low 0\nhigh 0\nmax 0\noom 1\noom_kill 0\noom_group_kill 0\n")
            rewrite_json(evidence / "producer-result.json", producer)
            rebind_controller_hash(
                evidence, "producer-result.json", "producer_result_sha256")
            with self.assertRaisesRegex(ValueError, "OOM event"):
                validate_fixture(root, expected)

    def test_outer_failure_receipt_captures_only_fixed_stage_status_and_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_atomic_outer_failure(
                root,
                [
                    {"name": "load-image", "exit_code": 0},
                    {"name": "sign-source", "exit_code": 0},
                    {"name": "install", "exit_code": 1},
                ],
                failure="RuntimeError: bearer must-not-be-retained",
                active_command={
                    "name": "install",
                    "command": ["--password", "must-not-be-retained"],
                },
                installation_attempted=True,
            )
            stage = root / ".cache/interactive-appliance-stage"
            artifact = root / ".cache/interactive-appliance-artifact"
            stage.mkdir(parents=True)
            artifact.mkdir()
            (stage / "private.log").write_text("must-not-be-retained")
            (artifact / "unverified.qcow2").write_bytes(b"unverified")
            with mock.patch.dict(os.environ, OUTER_ENVIRONMENT):
                self.assertTrue(create_outer_failure_evidence(root))
                expected = outer_failure_record(root)
            evidence = root / ".cache/interactive-appliance-evidence"
            retained = json.loads((evidence / "result.json").read_text())
            self.assertEqual(retained, expected)
            self.assertEqual(retained["evidence_kind"], "outer-systemd-failure")
            self.assertEqual(retained["stage"], "installation")
            self.assertEqual(retained["failed_command"], "install")
            self.assertFalse(retained["inner_evidence_available"])
            for claim in (
                "passed", "guest_booted", "graphical_desktop_observed",
                "artifact_retained", "independent_reboot_passed", "os_qualified",
                "release_qualified", "signature_qualified",
            ):
                self.assertIs(retained[claim], False)
            retained_bytes = (evidence / "result.json").read_bytes()
            self.assertNotIn(b"must-not-be-retained", retained_bytes)
            self.assertFalse(stage.exists())
            self.assertFalse(artifact.exists())
            write_outer_systemd_result(
                evidence / "systemd-result.txt",
                Result="exit-code", ActiveState="failed", SubState="failed",
                ExecMainStatus="1", MemoryPeak=str(3 * 1024**3),
                CPUUsageNSec="1234567",
            )
            self.assertGreater(validate_outer_failure_fixture(root), 0)

    def test_outer_failure_falls_back_without_reading_malformed_atomic_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_atomic_outer_failure(
                root,
                [{"name": "install", "exit_code": 1, "command": "secret"}],
                failure="token=must-not-be-retained",
            )
            with mock.patch.dict(os.environ, OUTER_ENVIRONMENT):
                self.assertTrue(create_outer_failure_evidence(root))
            evidence = root / ".cache/interactive-appliance-evidence"
            retained = json.loads((evidence / "result.json").read_text())
            self.assertEqual(retained["stage"], "outer-controller")
            self.assertEqual(retained["failed_command"], "unknown")
            self.assertNotIn(
                b"must-not-be-retained", (evidence / "result.json").read_bytes())
            write_outer_systemd_result(
                evidence / "systemd-result.txt",
                Result="exit-code", ActiveState="failed", SubState="failed",
                ExecMainStatus="1",
            )
            self.assertGreater(validate_outer_failure_fixture(root), 0)

    def test_outer_failure_never_relabels_existing_inner_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_atomic_outer_failure(
                root, [{"name": "install", "exit_code": 1}],
                installation_attempted=True,
            )
            evidence = root / ".cache/interactive-appliance-evidence"
            evidence.mkdir(parents=True)
            original = b'{"schema":1,"passed":true,"malformed":true}\n'
            (evidence / "result.json").write_bytes(original)
            with mock.patch.dict(os.environ, OUTER_ENVIRONMENT):
                self.assertFalse(create_outer_failure_evidence(root))
            self.assertEqual((evidence / "result.json").read_bytes(), original)
            self.assertEqual({path.name for path in evidence.iterdir()}, {"result.json"})

    def test_outer_failure_requires_exact_checkout_and_terminal_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_atomic_outer_failure(
                root, [{"name": "install", "exit_code": 1}],
                installation_attempted=True,
            )
            with mock.patch.dict(os.environ, OUTER_ENVIRONMENT):
                self.assertTrue(create_outer_failure_evidence(root))
            evidence = root / ".cache/interactive-appliance-evidence"
            write_outer_systemd_result(
                evidence / "systemd-result.txt",
                Result="exit-code", ActiveState="failed", SubState="failed",
                ExecMainStatus="1",
            )
            wrong = {
                "source_commit": "b" * 40,
                "source_tree": OUTER_ENVIRONMENT["SYMBI_APPLIANCE_SOURCE_TREE"],
            }
            with mock.patch.dict(os.environ, OUTER_ENVIRONMENT), \
                    mock.patch("image.appliance.hosted._checkout_binding", return_value=wrong), \
                    self.assertRaisesRegex(ValueError, "checkout"):
                validate_retained_evidence(root)
            write_outer_systemd_result(evidence / "systemd-result.txt")
            with self.assertRaisesRegex(ValueError, "systemd success"):
                validate_outer_failure_fixture(root)

    def test_retained_failure_evidence_has_only_controller_and_systemd_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            evidence.mkdir(parents=True)
            cleanup = {
                "stage_directory_removed": True, "user_artifact_absent": True,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            }
            result = controller_failure_record(
                source_binding(), "cleanup", "AtomicControllerFailure", cleanup, {},
            )
            (evidence / "result.json").write_text(json.dumps(result))
            write_outer_systemd_result(
                evidence / "systemd-result.txt", Result="exit-code",
                ActiveState="failed", SubState="failed", ExecMainStatus="1",
            )
            self.assertGreater(validate_failure_fixture(root), 0)
            (evidence / "display.ppm").write_bytes(b"stale")
            with self.assertRaisesRegex(ValueError, "non-controller evidence"):
                validate_failure_fixture(root)

    def test_retained_failure_preserves_observed_outer_peak_above_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            evidence.mkdir(parents=True)
            cleanup = {
                "stage_directory_removed": True, "user_artifact_absent": True,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            }
            result = controller_failure_record(
                source_binding(), "initialization", "ValueError", cleanup, {},
            )
            rewrite_json(evidence / "result.json", result)
            write_outer_systemd_result(
                evidence / "systemd-result.txt", Result="exit-code",
                ActiveState="failed", SubState="failed", ExecMainStatus="1",
                MemoryPeak=str(5 * 1024**3 + 4096),
            )
            self.assertGreater(validate_failure_fixture(root), 0)
            write_outer_systemd_result(
                evidence / "systemd-result.txt", Result="exit-code",
                ActiveState="failed", SubState="failed", ExecMainStatus="1",
                MemoryPeak=str(1 << 64),
            )
            with self.assertRaisesRegex(ValueError, "Out-of-range"):
                validate_failure_fixture(root)

    def test_retained_success_rejects_outer_peak_above_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, expected = retained_success_evidence(root)
            write_outer_systemd_result(
                evidence / "systemd-result.txt",
                MemoryPeak=str(5 * 1024**3 + 4096),
            )
            with self.assertRaisesRegex(ValueError, "memory limit"):
                validate_fixture(root, expected)

    def test_retained_failure_cannot_claim_unrelated_systemd_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            evidence.mkdir(parents=True)
            cleanup = {
                "stage_directory_removed": True, "user_artifact_absent": True,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            }
            result = controller_failure_record(
                source_binding(), "initialization", "ValueError", cleanup, {},
            )
            rewrite_json(evidence / "result.json", result)
            write_outer_systemd_result(evidence / "systemd-result.txt")
            with self.assertRaisesRegex(ValueError, "contradicts systemd success"):
                validate_failure_fixture(root)

    def test_real_systemd_interface_outcomes_use_numeric_wait_statuses(self):
        cases = (
            ("nonzero-exit", {"Result": "exit-code", "ExecMainCode": "1",
                              "ExecMainStatus": "7"}, None),
            ("signal", {"Result": "signal", "ExecMainCode": "2",
                        "ExecMainStatus": "15"}, None),
            ("core-dump", {"Result": "core-dump", "ExecMainCode": "3",
                           "ExecMainStatus": "6"}, None),
            ("timeout", {"Result": "timeout", "ExecMainCode": "2",
                         "ExecMainStatus": "15"}, None),
            ("oom", {"Result": "oom-kill",
                     "ExecMainCode": "2", "ExecMainStatus": "9"},
             "OOM evidence is not uploadable"),
            ("exit-code-killed", {"Result": "exit-code", "ExecMainCode": "2",
                                  "ExecMainStatus": "7"}, "systemd failure"),
            ("timeout-exited", {"Result": "timeout", "ExecMainCode": "1",
                                "ExecMainStatus": "124"}, "systemd failure"),
            ("oom-wrong-status", {"Result": "oom-kill", "ExecMainCode": "2",
                                  "ExecMainStatus": "15"}, "OOM outcome"),
        )
        for name, changes, error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / ".cache/interactive-appliance-evidence"
                evidence.mkdir(parents=True)
                cleanup = {
                    "stage_directory_removed": True, "user_artifact_absent": True,
                    "screenshot_artifact_absent": True,
                    "non_controller_evidence_removed": True,
                }
                result = controller_failure_record(
                    source_binding(), "initialization", "ValueError", cleanup, {},
                )
                rewrite_json(evidence / "result.json", result)
                terminal = changes | {"ActiveState": "failed", "SubState": "failed"}
                write_outer_systemd_result(evidence / "systemd-result.txt", **terminal)
                if error is None:
                    self.assertGreater(validate_failure_fixture(root), 0)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        validate_failure_fixture(root)

    def test_installer_selects_graphical_target_and_ephemeral_units(self):
        command = installer_arguments("sha256:" + "a"*64)
        self.assertIn("--karg=systemd.unit=graphical.target", command)
        self.assertNotIn("--karg=systemd.wants=p.service", command)
        self.assertNotIn("--karg=systemd.wants=v.service", command)
        self.assertNotIn("--karg=systemd.unit=multi-user.target", command)
        self.assertEqual(command[-1], "/output/atomic.raw")
        for bad in ("latest", "sha256:abc", "sha256:" + "z"*64):
            with self.assertRaises(ValueError):
                installer_arguments(bad)

    def test_firmware_fixture_is_bounded_and_has_no_login_secret(self):
        arguments = firmware_arguments()
        text = " ".join(arguments)
        for name in ("p.service", "v.service", "provision.py", "verify.py", "expected.json"):
            self.assertIn(name, text)
        for forbidden in ("password", "authorized_keys", "private-key", "ssh-key"):
            self.assertNotIn(forbidden, text.lower())
        self.assertEqual(len(arguments), 10)

    def test_transient_boot_units_are_exactly_credential_bound(self):
        arguments = transient_boot_arguments()
        self.assertEqual(arguments[0], "-smbios")
        prefix = "type=11,value=io.systemd.credential.binary:"
        self.assertTrue(arguments[1].startswith(prefix))
        name, encoded = arguments[1][len(prefix):].split("=", 1)
        self.assertEqual(name, TRANSIENT_BOOT_CREDENTIAL)
        self.assertEqual(base64.b64decode(encoded, validate=True), TRANSIENT_BOOT_DROPIN)
        self.assertEqual(TRANSIENT_BOOT_DROPIN, b"[Unit]\nWants=p.service v.service\n")
        provision = provision_qemu_arguments()
        self.assertEqual(provision.count(arguments[1]), 1)
        self.assertNotIn(arguments[1], reboot_qemu_arguments())
        self.assertNotIn(arguments[1], user_launch_arguments())

    def test_transient_boot_dropin_is_exactly_loaded_and_runtime_only(self):
        from image.appliance import verify

        self.assertEqual(verify.TRANSIENT_BOOT_DROPIN, TRANSIENT_BOOT_DROPIN)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "run/systemd/generator.early/graphical.target.d"
            runtime.mkdir(parents=True)
            for directory in (
                    root / "run", root / "run/systemd",
                    root / "run/systemd/generator.early", runtime):
                directory.chmod(0o755)
            dropin = runtime / "symbi-appliance.conf"
            dropin.write_bytes(TRANSIENT_BOOT_DROPIN)
            dropin.chmod(0o644)
            persistent = root / "etc/systemd/system"
            persistent.mkdir(parents=True)
            loaded = subprocess.CompletedProcess(
                [], 0, stdout=os.fspath(dropin) + "\n", stderr="")
            with mock.patch("image.appliance.verify.run", side_effect=[loaded, loaded]):
                self.assertTrue(transient_boot_dropin_is_exact(
                    time.monotonic() + 10, path=dropin,
                    persistent_roots=(persistent,), owner_uid=os.geteuid(),
                    runtime_root=root / "run"))

            other = root / "usr/lib/systemd/system/graphical.target.d/90-other.conf"
            other.parent.mkdir(parents=True)
            other.write_text("[Unit]\nRequires=p.service\n")
            other.chmod(0o644)
            graphical = subprocess.CompletedProcess(
                [], 0, stdout=f"{dropin} {other}\n", stderr="")
            with mock.patch("image.appliance.verify.run",
                            side_effect=[graphical, loaded]):
                self.assertFalse(transient_boot_dropin_is_exact(
                    time.monotonic() + 10, path=dropin,
                    persistent_roots=(persistent,), owner_uid=os.geteuid(),
                    runtime_root=root / "run"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_root = root / "run"
            runtime_root.mkdir()
            outside = root / "persistent/systemd/generator.early/graphical.target.d"
            outside.mkdir(parents=True)
            (outside / "symbi-appliance.conf").write_bytes(TRANSIENT_BOOT_DROPIN)
            (outside / "symbi-appliance.conf").chmod(0o644)
            (runtime_root / "systemd").symlink_to(root / "persistent/systemd")
            dropin = runtime_root / (
                "systemd/generator.early/graphical.target.d/symbi-appliance.conf")
            persistent = root / "etc/systemd/system"
            persistent.mkdir(parents=True)
            loaded = subprocess.CompletedProcess(
                [], 0, stdout=os.fspath(dropin) + "\n", stderr="")
            with mock.patch("image.appliance.verify.run", side_effect=[loaded, loaded]):
                self.assertFalse(transient_boot_dropin_is_exact(
                    time.monotonic() + 10, path=dropin,
                    persistent_roots=(persistent,), owner_uid=os.geteuid(),
                    runtime_root=runtime_root))

    def test_persistent_fixture_boot_references_are_rejected(self):
        cases = (
            ("p.service", b"[Unit]\nDescription=fixture\n"),
            ("graphical.target.d/symbi-appliance.conf",
             b"[Unit]\nDescription=shadow\n"),
            ("multi-user.target.d/90-fixture.conf",
             b"[Unit]\nWants=v.service\n"),
            ("multi-user.target.d/91-escaped.conf",
             b"[Unit]\nWants=\\x70\\x2eservice\n"),
            ("multi-user.target.d/92-quoted.conf",
             b"[Unit]\nWants=\"v\"\".service\"\n"),
            ("graphical.target", b"[Unit]\nRequires=p.service\n"),
            ("basic.target.wants/p.service", None),
        )
        for relative, content in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "system"
                root.mkdir()
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if content is None:
                    target.symlink_to("/run/systemd/generator.early/p.service")
                else:
                    target.write_bytes(content)
                    target.chmod(0o644)
                self.assertFalse(persistent_fixture_boot_references_absent(
                    (root,), os.geteuid()))

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "system"
            root.mkdir()
            hidden = base / "hidden-fragment"
            hidden.write_text("[Unit]\nWants=p.service\n")
            hidden.chmod(0o644)
            (root / "graphical.target").symlink_to(hidden)
            self.assertFalse(persistent_fixture_boot_references_absent(
                (root,), os.geteuid()))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "system"
            wants = root / "graphical.target.wants"
            wants.mkdir(parents=True)
            fixture = root / "p.service"
            fixture.write_text("[Service]\nExecStart=/bin/true\n")
            fixture.chmod(0o644)
            (wants / "fixture.service").symlink_to(fixture)
            self.assertFalse(persistent_fixture_boot_references_absent(
                (root,), os.geteuid()))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "system"
            dropin = root / "graphical.target.d/90-safe.conf"
            dropin.parent.mkdir(parents=True)
            dropin.write_text("[Unit]\nWants=sddm.service\n")
            dropin.chmod(0o644)
            (root / "default.target").symlink_to("../system/graphical.target")
            (root / "graphical.target").write_text(
                "[Unit]\nWants=multi-user.target\n")
            (root / "graphical.target").chmod(0o644)
            service = root / "sddm.service"
            service.write_text("[Service]\nExecStart=/usr/bin/sddm\n")
            service.chmod(0o644)
            wants = root / "graphical.target.wants"
            wants.mkdir()
            (wants / "sddm.service").symlink_to(service)
            self.assertTrue(persistent_fixture_boot_references_absent(
                (root,), os.geteuid()))

    def test_persistent_systemd_aliases_are_exact_and_direct(self):
        owner_uid = os.geteuid()

        def fixture(base, alias_name="default.target",
                    target_name="graphical.target"):
            config = base / "etc/systemd/system"
            vendor = base / "usr/lib/systemd/system"
            config.mkdir(parents=True)
            vendor.mkdir(parents=True)
            for directory in (
                    base / "etc", base / "etc/systemd", config,
                    base / "usr", base / "usr/lib", vendor.parent, vendor):
                directory.chmod(0o755)
            target = vendor / target_name
            target.write_text("[Unit]\nDescription=Graphical Interface\n")
            target.chmod(0o644)
            alias = config / alias_name
            alias.symlink_to(target)
            return config, vendor, alias, target

        for alias_name, target_name in (
                ("default.target", "graphical.target"),
                ("display-manager.service", "sddm.service")):
            with self.subTest(alias_name=alias_name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                config, vendor, _, _ = fixture(
                    base, alias_name, target_name)
                self.assertTrue(persistent_systemd_alias_is_exact(
                    alias_name, target_name, config_root=config,
                    vendor_root=vendor, anchor=base, owner_uid=owner_uid))

        cases = (
            "regular-alias", "relative-alias", "same-basename-shadow",
            "missing-target", "symlink-target", "directory-target",
            "fifo-target", "empty-target", "writable-target",
            "writable-config-ancestor", "writable-vendor-ancestor",
            "symlink-config-ancestor", "symlink-vendor-ancestor",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                config, vendor, alias, target = fixture(base)
                if case == "regular-alias":
                    alias.unlink()
                    alias.write_text(os.fspath(target))
                elif case == "relative-alias":
                    alias.unlink()
                    alias.symlink_to("graphical.target")
                elif case == "same-basename-shadow":
                    shadow = base / "shadow/graphical.target"
                    shadow.parent.mkdir()
                    shadow.write_text("[Unit]\nDescription=Shadow\n")
                    shadow.chmod(0o644)
                    alias.unlink()
                    alias.symlink_to(shadow)
                elif case == "missing-target":
                    target.unlink()
                elif case == "symlink-target":
                    actual = base / "actual.target"
                    actual.write_text("[Unit]\nDescription=Actual\n")
                    actual.chmod(0o644)
                    target.unlink()
                    target.symlink_to(actual)
                elif case == "directory-target":
                    target.unlink()
                    target.mkdir()
                elif case == "fifo-target":
                    target.unlink()
                    os.mkfifo(target)
                elif case == "empty-target":
                    target.write_text("")
                elif case == "writable-target":
                    target.chmod(0o664)
                elif case == "writable-config-ancestor":
                    config.parent.chmod(0o775)
                elif case == "writable-vendor-ancestor":
                    vendor.parent.chmod(0o775)
                elif case == "symlink-config-ancestor":
                    systemd = config.parent
                    relocated = base / "systemd-relocated"
                    systemd.rename(relocated)
                    systemd.symlink_to(relocated)
                elif case == "symlink-vendor-ancestor":
                    systemd = vendor.parent
                    relocated = base / "vendor-systemd-relocated"
                    systemd.rename(relocated)
                    systemd.symlink_to(relocated)
                self.assertFalse(persistent_systemd_alias_is_exact(
                    "default.target", "graphical.target", config_root=config,
                    vendor_root=vendor, anchor=base, owner_uid=owner_uid))

    def test_both_boots_have_interactive_devices_and_no_network(self):
        for command in (provision_qemu_arguments(), reboot_qemu_arguments(), user_launch_arguments()):
            joined = " ".join(command)
            self.assertIn("virtio-vga,id=symbi-display", joined)
            self.assertIn("virtio-keyboard-pci,id=symbi-keyboard", joined)
            self.assertIn("virtio-tablet-pci,id=symbi-pointer", joined)
            self.assertIn("-net none", joined)
            self.assertNotIn("-nic ", joined)
            self.assertNotIn("user,", joined)
        self.assertIn("gtk,gl=off", user_launch_arguments())

    def test_both_hosted_boots_use_reviewed_tcg_topology(self):
        for command in (provision_qemu_arguments(), reboot_qemu_arguments()):
            self.assertEqual(command[command.index("-accel") + 1], "tcg,thread=multi")
            self.assertEqual(
                command[command.index("-smp") + 1],
                "cpus=2,sockets=1,cores=2,threads=1",
            )
            self.assertNotIn("tcg,thread=single", command)

    def test_reboot_uses_overlay_instead_of_writable_retained_disk(self):
        joined = " ".join(reboot_qemu_arguments())
        self.assertIn("file=/output/reboot-overlay.qcow2", joined)
        self.assertNotIn("retained.qcow2", joined)
        hosted = (ROOT / "image/appliance/hosted.py").read_text()
        self.assertIn("dst=/inputs/retained.qcow2,ro", hosted)
        self.assertIn("artifact_before != artifact_after", hosted)

    def test_locked_non_admin_fixture_is_appliance_only(self):
        provision = (ROOT / "image/appliance/provision.py").read_text()
        verify = (ROOT / "image/appliance/verify.py").read_text()
        verifier_unit = (ROOT / "image/appliance/v.service").read_text()
        self.assertIn('"--lock", USERNAME', provision)
        self.assertNotIn("chpasswd", provision)
        self.assertNotIn("authorized_keys", provision)
        self.assertIn('USERNAME not in wheel.gr_mem', verify)
        self.assertIn("wheel.gr_gid not in group_ids", verify)
        self.assertIn("path_absent(ssh_directory)", verify)
        self.assertIn('matches[0] in {"!", "!!", "*", "!*"}', verify)
        self.assertIn(
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID",
            verifier_unit,
        )
        self.assertNotIn("CAP_SYS_ADMIN", verifier_unit)
        self.assertIn("persistent_scripts_absent", verify)
        self.assertIn("persistent_units_absent", verify)
        self.assertIn(
            "observe_bounded_walker(account.pw_uid, application_deadline)",
            verify,
        )
        self.assertIn('"/usr/bin/systemd-run", "--user", "--collect"', verify)
        self.assertIn(
            "executable in user_executables(uid, application_deadline)",
            verify,
        )
        self.assertNotIn('"Walker": True', verify)
        self.assertIn("HIGHLY EXPERIMENTAL disposable development appliance only", SDDM_CONFIGURATION)
        self.assertIn("no password or key", SDDM_CONFIGURATION)

    def test_provision_uses_no_persistent_fixture_boot_transaction(self):
        from image.appliance import provision

        unit = (ROOT / "image/appliance/p.service").read_text()
        self.assertIn("Before=display-manager.service sddm.service upgrade-on-boot.service", unit)
        source = (ROOT / "image/appliance/provision.py").read_text()
        self.assertNotIn("rpm-ostree", source)
        self.assertNotIn("systemd.wants=", source)
        self.assertNotIn("daemon-reload", source)
        self.assertIn("transient_boot_units", source)
        self.assertEqual(provision.SYSTEMCTL_OFFLINE, (
            "/usr/bin/systemctl", "--root=/", "--no-reload", "--quiet",
        ))
        self.assertEqual(provision.SELECT_GRAPHICAL_TARGET_COMMAND, (
            *provision.SYSTEMCTL_OFFLINE, "set-default", "graphical.target",
        ))
        self.assertEqual(provision.ENABLE_DISPLAY_MANAGER_COMMAND, (
            *provision.SYSTEMCTL_OFFLINE, "enable", "--force", "sddm.service",
        ))

    def test_provision_and_first_boot_time_budgets_are_statically_closed(self):
        from image.appliance import contract, provision, verify

        self.assertEqual(provision.PROVISION_COMMAND_TIMEOUTS, {
            "selinux-enforcement": 5,
            "create-fixture-account": 20,
            "lock-fixture-account": 10,
            "select-graphical-target": 10,
            "enable-display-manager": 15,
        })
        self.assertEqual(provision.PROVISION_SUBPROCESS_BUDGET_SECONDS, 60)
        self.assertEqual(provision.PROVISION_LOCAL_WORK_BUDGET_SECONDS, 30)
        self.assertEqual(provision.PROVISION_PHASE_BUDGET_SECONDS, 90)
        self.assertEqual(provision.PROVISION_SERVICE_TIMEOUT_SECONDS, 120)
        self.assertEqual(provision.PROVISION_SERVICE_MARGIN_SECONDS, 30)
        self.assertEqual(provision.VERIFIER_SERVICE_TIMEOUT_SECONDS, 420)
        self.assertEqual(verify.VERIFIER_SERVICE_TIMEOUT_SECONDS, 420)
        self.assertEqual(verify.VERIFIER_APPLICATION_BUDGET_SECONDS, 400)
        self.assertEqual(verify.VERIFIER_SERVICE_MARGIN_SECONDS, 20)
        self.assertEqual(verify.VERIFIER_PHASE_BUDGETS, {
            "graphical-session-and-portal": 260,
            "fixed-commands": 55,
            "walker-lifecycle": 70,
            "local-validation-and-report": 15,
        })
        self.assertEqual(verify.FIXED_COMMAND_TIMEOUTS, {
            "get-default": 5,
            "package-query": 2,
            "package-verify": 8,
            "kargs": 10,
            "graphical-dropin-paths": 5,
            "default-dropin-paths": 5,
        })
        self.assertEqual(
            verify.FIXED_COMMAND_TIMEOUTS["get-default"]
            + 3 * (verify.FIXED_COMMAND_TIMEOUTS["package-query"]
                   + verify.FIXED_COMMAND_TIMEOUTS["package-verify"])
            + verify.FIXED_COMMAND_TIMEOUTS["kargs"]
            + verify.FIXED_COMMAND_TIMEOUTS["graphical-dropin-paths"]
            + verify.FIXED_COMMAND_TIMEOUTS["default-dropin-paths"],
            verify.VERIFIER_PHASE_BUDGETS["fixed-commands"],
        )
        self.assertEqual(verify.WALKER_STEP_TIMEOUTS, {
            "reset-before": 5,
            "launch": 10,
            "observe": 20,
            "stop": 10,
            "observe-stopped": 20,
            "reset-after": 5,
        })
        self.assertEqual(sum(verify.WALKER_STEP_TIMEOUTS.values()),
                         verify.VERIFIER_PHASE_BUDGETS["walker-lifecycle"])
        self.assertEqual(sum(verify.VERIFIER_PHASE_BUDGETS.values()),
                         verify.VERIFIER_APPLICATION_BUDGET_SECONDS)
        self.assertEqual(verify.VERIFIER_APPLICATION_BUDGET_SECONDS
                         + verify.VERIFIER_SERVICE_MARGIN_SECONDS,
                         verify.VERIFIER_SERVICE_TIMEOUT_SECONDS)
        self.assertEqual(provision.FIRST_BOOT_ORCHESTRATION_BUDGET_SECONDS, 180)
        self.assertEqual(provision.FIRST_BOOT_CONTROLLER_MARGIN_SECONDS, 480)
        self.assertEqual(provision.FIRST_BOOT_TIMEOUT_SECONDS, 1200)
        self.assertEqual(
            provision.FIRST_BOOT_TIMEOUT_SECONDS,
            contract.FIRST_BOOT_TIMEOUT_SECONDS,
        )

        def unit_timeout(name, field="TimeoutStartSec"):
            unit = (ROOT / "image/appliance" / name).read_text()
            match = re.search(r"(?m)^" + re.escape(field) + r"=([0-9]+)$", unit)
            self.assertIsNotNone(match)
            return int(match.group(1))

        self.assertEqual(unit_timeout("p.service"),
                         provision.PROVISION_SERVICE_TIMEOUT_SECONDS)
        self.assertEqual(unit_timeout("v.service"),
                         provision.VERIFIER_SERVICE_TIMEOUT_SECONDS)
        self.assertEqual(unit_timeout("v.service", "TimeoutStopSec"), 15)
        self.assertLessEqual(unit_timeout("v.service", "TimeoutStopSec"),
                             provision.FIRST_BOOT_ORCHESTRATION_BUDGET_SECONDS)
        self.assertLessEqual(
            provision.PROVISION_PHASE_BUDGET_SECONDS,
            provision.PROVISION_SERVICE_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            provision.PROVISION_SERVICE_TIMEOUT_SECONDS
            + provision.VERIFIER_SERVICE_TIMEOUT_SECONDS
            + provision.FIRST_BOOT_ORCHESTRATION_BUDGET_SECONDS
            + provision.FIRST_BOOT_CONTROLLER_MARGIN_SECONDS,
            provision.FIRST_BOOT_TIMEOUT_SECONDS,
        )

        provision_tree = ast.parse(
            (ROOT / "image/appliance/provision.py").read_text())
        named_phases = [
            node.args[0].value
            for node in ast.walk(provision_tree)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "run_phase" and node.args
                and isinstance(node.args[0], ast.Constant))
        ]
        self.assertCountEqual(named_phases, provision.PROVISION_COMMAND_TIMEOUTS)
        producer = (ROOT / "image/appliance/producer.py").read_text()
        self.assertIn(
            "time.monotonic() - start >= FIRST_BOOT_TIMEOUT_SECONDS",
            producer,
        )

    def test_late_qemu_exit_is_rejected_before_guest_report_read(self):
        from image.appliance import producer

        child = mock.Mock(returncode=0)
        child.poll.return_value = 0
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            (evidence / "guest-report.json").write_text('{"complete": true}\n')
            with (mock.patch.object(
                    producer.time, "monotonic",
                    return_value=float(producer.FIRST_BOOT_TIMEOUT_SECONDS)),
                  mock.patch.object(producer, "load_guest_report") as load_report):
                with self.assertRaisesRegex(TimeoutError, "20 minutes"):
                    producer.await_first_boot_report(child, 0.0, evidence)
            load_report.assert_not_called()

    def test_complete_report_from_failed_verifier_cannot_power_off_or_be_accepted(self):
        from image.appliance import producer, verify

        verifier_unit = (ROOT / "image/appliance/v.service").read_text()
        provisioner_unit = (ROOT / "image/appliance/p.service").read_text()
        self.assertIn("SyslogIdentifier=symbi-appliance-provision", provisioner_unit)
        self.assertIn("SyslogIdentifier=symbi-appliance-verify", verifier_unit)
        self.assertIn("Requires=p.service", verifier_unit)
        self.assertIn("After=p.service", verifier_unit)
        self.assertIn("After=p.service sddm.service", verifier_unit)
        self.assertNotIn("graphical.target", next(
            line for line in verifier_unit.splitlines() if line.startswith("After=")
        ))
        self.assertIn("SuccessAction=poweroff", verifier_unit)
        self.assertNotIn("OnFailure=poweroff.target", verifier_unit)
        self.assertNotIn("ExecStopPost=", verifier_unit)
        self.assertEqual(verifier_unit.count("poweroff"), 1)
        self.assertIn("OnFailure=poweroff.target", provisioner_unit)
        self.assertNotIn("SuccessAction=poweroff", provisioner_unit)
        poweroff_paths = {
            path.name: [line for line in path.read_text().splitlines()
                        if "poweroff" in line]
            for path in (ROOT / "image/appliance").glob("*.service")
        }
        self.assertEqual(poweroff_paths, {
            "p.service": ["OnFailure=poweroff.target"],
            "v.service": ["SuccessAction=poweroff"],
        })

        raw = b'{"complete":true}\n'
        clock = [0.0]
        written = bytearray()
        poller = mock.Mock()
        poller.poll.return_value = [(7, select.POLLOUT)]

        def late_complete_write(_descriptor, value):
            written.extend(value)
            clock[0] = 16.0
            return len(value)

        with (mock.patch.object(verify.time, "monotonic",
                                side_effect=lambda: clock[0]),
              mock.patch.object(verify.os, "lstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.os, "open", return_value=7),
              mock.patch.object(verify.os, "fstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.select, "poll", return_value=poller),
              mock.patch.object(verify.os, "write", side_effect=late_complete_write),
              mock.patch.object(verify.os, "close")):
            with self.assertRaises(TimeoutError):
                verify.write_guest_report("/dev/fake", raw, 15.0)
        self.assertEqual(bytes(written), raw)

        clock[0] = 0.0
        child = mock.Mock(returncode=None)
        child.poll.return_value = None

        def reach_controller_deadline(_seconds):
            clock[0] = float(producer.FIRST_BOOT_TIMEOUT_SECONDS)

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            (evidence / "guest-report.json").write_bytes(raw)
            with (mock.patch.object(producer.time, "monotonic",
                                    side_effect=lambda: clock[0]),
                  mock.patch.object(producer.time, "sleep",
                                    side_effect=reach_controller_deadline),
                  mock.patch.object(producer, "load_guest_report") as load_report):
                with self.assertRaisesRegex(TimeoutError, "20 minutes"):
                    producer.await_first_boot_report(child, 0.0, evidence)
            load_report.assert_not_called()

    def test_provisioner_failure_poweroff_cannot_be_accepted_without_report(self):
        from image.appliance import producer

        child = mock.Mock(returncode=0)
        child.poll.return_value = 0
        with tempfile.TemporaryDirectory() as temporary:
            with (mock.patch.object(producer.time, "monotonic", return_value=1.0),
                  self.assertRaisesRegex(
                      RuntimeError, "emitted no bounded guest report")):
                producer.await_first_boot_report(child, 0.0, Path(temporary))

    def test_producer_failure_status_is_typed_and_consistent(self):
        from image.appliance import producer

        clean = mock.Mock(returncode=0)
        failed = mock.Mock(returncode=23)
        cases = (
            (
                "guest-report", producer.producer_failure_status(
                    "first-boot", RuntimeError("private"), clean),
                producer_status(),
            ),
            (
                "qemu-exit", producer.producer_failure_status(
                    "first-boot", RuntimeError("private"), failed),
                producer_status(
                    phase="first-boot", kind="qemu-exit", exit_code=23,
                    qemu_exit_code=23,
                ),
            ),
            (
                "subprocess-exit", producer.producer_failure_status(
                    "raw-conversion", subprocess.CalledProcessError(7, ["private"]),
                    None,
                ),
                producer_status(
                    phase="raw-conversion", kind="subprocess-exit", exit_code=7,
                    qemu_exit_code=None,
                ),
            ),
            (
                "subprocess-timeout", producer.producer_failure_status(
                    "input-validation", subprocess.TimeoutExpired(["private"], 15),
                    None,
                ),
                producer_status(
                    phase="input-validation", kind="subprocess-timeout",
                    timeout_seconds=15, qemu_exit_code=None,
                ),
            ),
            (
                "controller-timeout", producer.producer_failure_status(
                    "first-boot", TimeoutError("private"), None),
                producer_status(
                    phase="first-boot", kind="controller-timeout",
                    timeout_seconds=producer.FIRST_BOOT_TIMEOUT_SECONDS,
                    qemu_exit_code=None,
                ),
            ),
            (
                "late-clean-exit", producer.producer_failure_status(
                    "first-boot", TimeoutError("private"), clean),
                producer_status(
                    phase="first-boot", kind="controller-timeout",
                    timeout_seconds=producer.FIRST_BOOT_TIMEOUT_SECONDS,
                    qemu_exit_code=0,
                ),
            ),
        )
        for name, actual, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(actual, expected)
                self.assertTrue(validate_producer_failure_status(actual))
                self.assertNotIn("private", json.dumps(actual))

        contradictory = (
            producer_status(kind="qemu-exit", exit_code=0),
            producer_status(kind="qemu-exit", exit_code=4, qemu_exit_code=5),
            producer_status(kind="controller-timeout", timeout_seconds=10),
            producer_status(phase="guest-report", kind="subprocess-timeout",
                            timeout_seconds=10),
            producer_status(phase="initialization", kind="subprocess-exit",
                            exit_code=7, qemu_exit_code=None),
            producer_status(phase="initialization", kind="subprocess-timeout",
                            timeout_seconds=10, qemu_exit_code=None),
            producer_status(phase="input-validation", kind="subprocess-timeout",
                            timeout_seconds=999, qemu_exit_code=None),
            producer_status(phase="raw-conversion", kind="subprocess-timeout",
                            timeout_seconds=1.5, qemu_exit_code=None),
            producer_status(phase="artifact-validation", kind="subprocess-timeout",
                            timeout_seconds=1200, qemu_exit_code=0),
            producer_status(phase="first-boot", kind="controller-timeout",
                            timeout_seconds=1, qemu_exit_code=None),
            producer_status(phase="first-boot", qemu_exit_code=0),
        )
        for value in contradictory:
            with self.subTest(value=value):
                self.assertFalse(validate_producer_failure_status(value))

        for value in (
            producer_status(
                phase="raw-conversion", kind="subprocess-timeout",
                timeout_seconds=1200, qemu_exit_code=None,
            ),
            producer_status(
                phase="artifact-compression", kind="subprocess-timeout",
                timeout_seconds=300, qemu_exit_code=0,
            ),
            producer_status(
                phase="artifact-validation", kind="subprocess-timeout",
                timeout_seconds=30, qemu_exit_code=0,
            ),
        ):
            with self.subTest(valid_timeout=value):
                self.assertTrue(validate_producer_failure_status(value))

    def test_guest_status_sentinels_are_fixed_and_allowlisted(self):
        from image.appliance import provision

        emitted = []
        all_emitted = []
        phase = "selinux-enforcement"
        with (mock.patch.object(provision, "status", side_effect=emitted.append),
              mock.patch.object(provision, "run", return_value="ok")):
            self.assertEqual(provision.run_phase(phase, ["private"]), "ok")
        self.assertEqual(emitted, [
            "provision-phase-start:selinux-enforcement",
            "provision-phase-complete:selinux-enforcement",
        ])
        all_emitted.extend(emitted)
        for error, outcome in (
            (subprocess.TimeoutExpired(["private"], 1), "timeout"),
            (subprocess.CalledProcessError(1, ["private"]), "exit"),
            (ValueError("private"), "error"),
        ):
            emitted = []
            with (self.subTest(outcome=outcome),
                  mock.patch.object(provision, "status", side_effect=emitted.append),
                  mock.patch.object(provision, "run", side_effect=error),
                  self.assertRaises(type(error))):
                provision.run_phase(phase, ["private"])
            self.assertEqual(emitted, [
                "provision-phase-start:selinux-enforcement",
                f"provision-phase-{outcome}:selinux-enforcement",
            ])
            all_emitted.extend(emitted)
        for name in all_emitted:
            self.assertIn(name, FAILURE_STATUS_SENTINELS)
        self.assertEqual(set(provision.PROVISION_COMMAND_TIMEOUTS),
                         set(PROVISION_STATUS_PHASES))
        for phase_name in PROVISION_STATUS_PHASES:
            for outcome in ("start", "complete", "exit", "timeout", "error"):
                self.assertIn(
                    f"provision-phase-{outcome}:{phase_name}",
                    FAILURE_STATUS_SENTINELS,
                )

        for filename, expected in (
            ("provision.py", {
                "provision-start", "provision-complete", "provision-failed",
            }),
            ("verify.py", {
                "verifier-start", "verifier-provision-receipt-accepted",
                "verifier-graphical-session-observed", "verifier-walker-observed",
                "verifier-report-write-start", "verifier-report-write-complete",
                "verifier-failed",
            }),
        ):
            tree = ast.parse((ROOT / "image/appliance" / filename).read_text())
            observed = {
                call.args[0].value
                for call in ast.walk(tree)
                if (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "status" and len(call.args) == 1
                    and isinstance(call.args[0], ast.Constant)
                    and isinstance(call.args[0].value, str))
            }
            self.assertEqual(observed, expected)
            self.assertTrue(observed.issubset(FAILURE_STATUS_SENTINELS))

    def test_verifier_has_no_implicit_or_unbounded_subprocess_deadline(self):
        from image.appliance import verify

        source = (ROOT / "image/appliance/verify.py").read_text()
        tree = ast.parse(source)
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }
        for name in ("run", "user_systemctl"):
            function = functions[name]
            self.assertEqual([item.arg for item in function.args.kwonlyargs],
                             ["check", "timeout"])
            self.assertIsNone(function.args.kw_defaults[1])

        calls = [
            node
            for node in ast.walk(tree)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {"run", "user_systemctl"})
        ]
        self.assertEqual(len(calls), 12)
        for call in calls:
            with self.subTest(line=call.lineno, function=call.func.id):
                keywords = {item.arg for item in call.keywords}
                self.assertIn("timeout", keywords)
                self.assertNotIn(None, keywords)

        timeout_expressions = [
            ast.unparse(next(item.value for item in call.keywords
                             if item.arg == "timeout"))
            for call in calls
        ]
        self.assertCountEqual(timeout_expressions, [
            "remaining_timeout(application_deadline, FIXED_COMMAND_TIMEOUTS['package-query'])",
            "remaining_timeout(application_deadline, FIXED_COMMAND_TIMEOUTS['package-verify'])",
            "timeout",
            "remaining_timeout(launch_deadline, WALKER_STEP_TIMEOUTS['reset-before'])",
            "remaining_timeout(launch_deadline, WALKER_STEP_TIMEOUTS['launch'])",
            "remaining_timeout(cleanup_deadline, WALKER_STEP_TIMEOUTS['stop'])",
            "remaining_timeout(cleanup_deadline, WALKER_STEP_TIMEOUTS['reset-after'])",
            "remaining_timeout(phase_deadline, GRAPHICAL_COMMAND_TIMEOUT_SECONDS)",
            "remaining_timeout(phase_deadline, PORTAL_START_TIMEOUT_SECONDS)",
            "remaining_timeout(application_deadline, FIXED_COMMAND_TIMEOUTS['get-default'])",
            "remaining_timeout(application_deadline, FIXED_COMMAND_TIMEOUTS['kargs'])",
            "remaining_timeout(deadline, FIXED_COMMAND_TIMEOUTS[timeout_name])",
        ])
        self.assertEqual(source.count("subprocess.run("), 1)

        process_scans = [
            node
            for node in ast.walk(tree)
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "user_executables")
        ]
        self.assertGreater(len(process_scans), 0)
        self.assertTrue(all(len(call.args) == 2 for call in process_scans))
        self.assertIn("local_deadline = min(", source)
        self.assertIn(
            "write_guest_report(CHANNEL, raw, local_deadline)", source)

        self.assertNotIn("while time.monotonic()", source)
        self.assertIn(
            "attempts=GRAPHICAL_SESSION_POLL_ATTEMPTS",
            source,
        )
        self.assertIn("attempts=PORTAL_POLL_ATTEMPTS", source)
        self.assertIn('attempts=WALKER_STEP_TIMEOUTS["observe"]', source)
        self.assertIn('attempts=WALKER_STEP_TIMEOUTS["observe-stopped"]', source)
        self.assertEqual(verify.GRAPHICAL_SESSION_POLL_ATTEMPTS, 130)
        self.assertEqual(verify.PORTAL_POLL_ATTEMPTS, 260)

    def test_verifier_poll_and_command_deadlines_fail_closed_with_fake_clock(self):
        from image.appliance import verify

        clock = [0.0]
        probes = []

        def monotonic():
            return clock[0]

        def sleep(seconds):
            self.assertGreater(seconds, 0)
            clock[0] += seconds

        def never_ready():
            probes.append(clock[0])
            return False

        with (mock.patch.object(verify.time, "monotonic", side_effect=monotonic),
              mock.patch.object(verify.time, "sleep", side_effect=sleep)):
            self.assertFalse(verify.bounded_poll(
                never_ready, deadline=260.0, interval=2,
                attempts=verify.GRAPHICAL_SESSION_POLL_ATTEMPTS,
            ))
            self.assertEqual(len(probes), 130)
            self.assertEqual(clock[0], 260.0)
            clock[0] = 255.0
            self.assertEqual(verify.remaining_timeout(260.0, 10), 5.0)
            clock[0] = 260.0
            with self.assertRaises(TimeoutError):
                verify.remaining_timeout(260.0, 10)

        clock[0] = 0.0
        probes.clear()

        def third_probe_ready():
            probes.append(clock[0])
            return len(probes) == 3

        with (mock.patch.object(verify.time, "monotonic", side_effect=monotonic),
              mock.patch.object(verify.time, "sleep", side_effect=sleep)):
            self.assertTrue(verify.bounded_poll(
                third_probe_ready, deadline=260.0, interval=2,
                attempts=verify.GRAPHICAL_SESSION_POLL_ATTEMPTS,
            ))
        self.assertEqual(probes, [0.0, 2.0, 4.0])

        clock[0] = 0.0
        probes.clear()

        def late_ready():
            probes.append(clock[0])
            clock[0] = 261.0
            return True

        with mock.patch.object(verify.time, "monotonic", side_effect=monotonic):
            self.assertFalse(verify.bounded_poll(
                late_ready, deadline=260.0, interval=2, attempts=1,
            ))
        self.assertEqual(probes, [0.0])

    def test_user_process_scan_fails_when_deadline_expires_during_entry(self):
        from image.appliance import verify

        clock = [0.0]
        entry = mock.Mock()
        entry.name = "123"

        def entry_stat():
            clock[0] = 2.0
            return mock.Mock(st_uid=1000)

        entry.stat.side_effect = entry_stat
        with (mock.patch.object(verify.time, "monotonic",
                                side_effect=lambda: clock[0]),
              mock.patch.object(verify.os, "geteuid", return_value=0),
              mock.patch.object(verify.os, "seteuid") as seteuid,
              mock.patch.object(verify.Path, "iterdir", return_value=[entry]),
              mock.patch.object(verify.os, "readlink") as readlink):
            with self.assertRaises(TimeoutError):
                verify.user_executables(1000, 1.0)
        seteuid.assert_has_calls([mock.call(1000), mock.call(0)])
        readlink.assert_not_called()

    def test_guest_report_writer_retries_nonblocking_partial_writes(self):
        from image.appliance import verify

        poller = mock.Mock()
        poller.poll.return_value = [(7, select.POLLOUT)]
        writes = []

        def write(_fd, raw):
            writes.append(bytes(raw))
            if len(writes) == 1:
                raise BlockingIOError(errno.EAGAIN, "full")
            return 2 if len(writes) == 2 else len(raw)

        with (mock.patch.object(verify.time, "monotonic", return_value=0.0),
              mock.patch.object(verify.os, "lstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.os, "open", return_value=7) as opened,
              mock.patch.object(verify.os, "fstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.select, "poll", return_value=poller),
              mock.patch.object(verify.os, "write", side_effect=write),
              mock.patch.object(verify.os, "close") as closed):
            self.assertEqual(
                verify.write_guest_report("/dev/fake", b"hello", 15.0), 5)
        opened.assert_called_once_with(
            "/dev/fake",
            os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        poller.register.assert_called_once_with(
            7, select.POLLOUT | select.POLLERR | select.POLLHUP | select.POLLNVAL)
        self.assertEqual(writes, [b"hello", b"hello", b"llo"])
        closed.assert_called_once_with(7)

    def test_guest_report_writer_fails_closed_on_no_reader_and_zero_write(self):
        from image.appliance import verify

        for events, write_result, exception in (
                ([], 1, TimeoutError),
                ([(7, select.POLLOUT)], 0, ValueError)):
            poller = mock.Mock()
            poller.poll.return_value = events
            with (self.subTest(events=events),
                  mock.patch.object(verify.time, "monotonic", return_value=0.0),
                  mock.patch.object(verify.os, "lstat",
                                    return_value=mock.Mock(st_mode=stat.S_IFCHR)),
                  mock.patch.object(verify.os, "open", return_value=7),
                  mock.patch.object(verify.os, "fstat",
                                    return_value=mock.Mock(st_mode=stat.S_IFCHR)),
                  mock.patch.object(verify.select, "poll", return_value=poller),
                  mock.patch.object(verify.os, "write", return_value=write_result),
                  mock.patch.object(verify.os, "close") as closed):
                with self.assertRaises(exception):
                    verify.write_guest_report("/dev/fake", b"report", 15.0)
                closed.assert_called_once_with(7)

    def test_guest_report_writer_rejects_non_character_and_late_write(self):
        from image.appliance import verify

        with (mock.patch.object(verify.time, "monotonic", return_value=0.0),
              mock.patch.object(verify.os, "lstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.os, "open", return_value=7),
              mock.patch.object(verify.os, "fstat",
                                return_value=mock.Mock(st_mode=stat.S_IFREG)),
              mock.patch.object(verify.select, "poll") as poll_factory,
              mock.patch.object(verify.os, "close") as closed):
            with self.assertRaisesRegex(ValueError, "character device"):
                verify.write_guest_report("/dev/fake", b"report", 15.0)
        poll_factory.assert_not_called()
        closed.assert_called_once_with(7)

        clock = [0.0]
        poller = mock.Mock()
        poller.poll.return_value = [(7, select.POLLOUT)]

        def late_write(_fd, raw):
            clock[0] = 16.0
            return len(raw)

        with (mock.patch.object(verify.time, "monotonic",
                                side_effect=lambda: clock[0]),
              mock.patch.object(verify.os, "lstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.os, "open", return_value=7),
              mock.patch.object(verify.os, "fstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.select, "poll", return_value=poller),
              mock.patch.object(verify.os, "write", side_effect=late_write),
              mock.patch.object(verify.os, "close") as closed):
            with self.assertRaises(TimeoutError):
                verify.write_guest_report("/dev/fake", b"report", 15.0)
        closed.assert_called_once_with(7)

    def test_guest_report_writer_opens_only_reviewed_udev_link_target(self):
        from image.appliance import verify

        poller = mock.Mock()
        poller.poll.return_value = [(7, select.POLLOUT)]
        flags = os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
        with (mock.patch.object(verify.time, "monotonic", return_value=0.0),
              mock.patch.object(verify.os, "lstat",
                                return_value=mock.Mock(st_mode=stat.S_IFLNK)),
              mock.patch.object(verify.os, "readlink",
                                return_value="../vport7p2"),
              mock.patch.object(verify.os, "open", return_value=7) as opened,
              mock.patch.object(verify.os, "fstat",
                                return_value=mock.Mock(st_mode=stat.S_IFCHR)),
              mock.patch.object(verify.select, "poll", return_value=poller),
              mock.patch.object(verify.os, "write", return_value=6),
              mock.patch.object(verify.os, "close")):
            self.assertEqual(verify.write_guest_report(
                "/dev/virtio-ports/org.symbi.appliance", b"report", 15.0), 6)
        opened.assert_called_once_with("/dev/vport7p2", flags)

        with (mock.patch.object(verify.time, "monotonic", return_value=0.0),
              mock.patch.object(verify.os, "lstat",
                                return_value=mock.Mock(st_mode=stat.S_IFLNK)),
              mock.patch.object(verify.os, "readlink",
                                return_value="../../etc/passwd"),
              mock.patch.object(verify.os, "open") as opened):
            with self.assertRaisesRegex(ValueError, "reviewed device path"):
                verify.write_guest_report(
                    "/dev/virtio-ports/org.symbi.appliance", b"report", 15.0)
        opened.assert_not_called()

    def test_absent_guest_report_preserves_a_specific_failure(self):
        from image.appliance.producer import load_guest_report

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "guest-report.json"
            for contents in (None, b""):
                if contents is not None:
                    report.write_bytes(contents)
                with self.subTest(contents=contents), self.assertRaisesRegex(
                        RuntimeError, "emitted no bounded guest report"):
                    load_guest_report(report)
                if report.exists():
                    report.unlink()

    def test_walker_acceptance_launches_observes_and_stops_bounded_unit(self):
        processes = [set(), {"/usr/bin/walker"}, set()]
        with mock.patch("image.appliance.verify.user_executables",
                        side_effect=processes), \
                mock.patch("image.appliance.verify.run") as launch, \
                mock.patch("image.appliance.verify.user_systemctl",
                           return_value=mock.Mock(returncode=0)) as systemctl:
            evidence = observe_bounded_walker(1000, float("inf"))
        command = launch.call_args.args[0]
        for argument in ("--collect", "--service-type=exec", "--property=MemoryMax=512M",
                         "--property=MemorySwapMax=0", "--property=CPUQuota=100%",
                         "--property=TasksMax=64", "--property=RuntimeMaxSec=60",
                         "--property=NoNewPrivileges=yes", "/usr/bin/walker"):
            self.assertIn(argument, command)
        self.assertTrue(evidence["observed"])
        self.assertTrue(evidence["stop_succeeded"])
        self.assertTrue(evidence["stopped"])
        self.assertEqual(systemctl.call_args_list[1].args,
                         ("stop", "symbi-appliance-walker.service"))

        with mock.patch("image.appliance.verify.user_executables",
                        return_value={"/usr/bin/walker"}), \
                mock.patch("image.appliance.verify.run") as no_launch:
            with self.assertRaisesRegex(ValueError, "already running"):
                observe_bounded_walker(1000, float("inf"))
        no_launch.assert_not_called()

    def test_walker_rejects_nonzero_stop_even_after_process_absence(self):
        processes = [set(), {"/usr/bin/walker"}, set()]
        results = [mock.Mock(returncode=0), mock.Mock(returncode=1),
                   mock.Mock(returncode=0)]
        with mock.patch("image.appliance.verify.user_executables",
                        side_effect=processes) as executables, \
                mock.patch("image.appliance.verify.run"), \
                mock.patch("image.appliance.verify.user_systemctl",
                           side_effect=results) as systemctl:
            with self.assertRaisesRegex(ValueError, "did not stop successfully"):
                observe_bounded_walker(1000, float("inf"))
        self.assertEqual(executables.call_count, 3)
        self.assertEqual(systemctl.call_args_list[1].args,
                         ("stop", "symbi-appliance-walker.service"))

    def test_walker_stop_exception_still_resets_inside_shared_deadline(self):
        from image.appliance import verify

        clock = [0.0]
        calls = []

        def systemctl(*arguments, check=True, timeout):
            calls.append((arguments[0], timeout, clock[0]))
            clock[0] += timeout
            if arguments[0] == "stop":
                raise subprocess.TimeoutExpired(arguments, timeout)
            return mock.Mock(returncode=0)

        with (mock.patch.object(verify.time, "monotonic",
                                side_effect=lambda: clock[0]),
              mock.patch("image.appliance.verify.user_executables",
                         side_effect=[set(), {"/usr/bin/walker"}]),
              mock.patch("image.appliance.verify.run"),
              mock.patch("image.appliance.verify.user_systemctl",
                         side_effect=systemctl)):
            with self.assertRaisesRegex(ValueError, "Walker cleanup failed"):
                observe_bounded_walker(1000, 70.0)
        self.assertEqual([name for name, _, _ in calls],
                         ["reset-failed", "stop", "reset-failed"])
        self.assertLessEqual(clock[0], 70.0)
        self.assertLessEqual(calls[-1][1], 5.0)

    def test_source_binding_rejects_every_identity_change(self):
        original = source_binding()
        validate_source_binding(original)
        for key in original:
            changed = copy.deepcopy(original)
            changed[key] = 0 if isinstance(changed[key], int) else "wrong"
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_source_binding(changed)

    def test_guest_report_is_bound_to_all_desktop_and_cleanup_claims(self):
        expected = {"nonce": "0"*32, "source_binding": source_binding()}
        report = guest(expected)
        validate_guest_report(report, expected, "1"*64, "2"*64)
        changes = [
            ("network_interfaces", ["eth0", "lo"]),
            ("default_target", "multi-user.target"),
            ("display_manager", "gdm.service"),
            ("session", "other.desktop"),
            ("interactive_devices", {**report["interactive_devices"], "virtio_pointer": False}),
            ("fixture_user", {**report["fixture_user"], "password_locked": False}),
            ("fixture_cleanup", {**report["fixture_cleanup"], "persistent_units_absent": False}),
            ("desktop_components", {**report["desktop_components"], "portal": False}),
            ("walker_launch", {**report["walker_launch"], "observed": False}),
            ("walker_launch", {**report["walker_launch"], "stop_succeeded": False}),
            ("walker_launch", {**report["walker_launch"], "stopped": False}),
            ("walker_launch", {**report["walker_launch"], "limits": {
                **report["walker_launch"]["limits"], "memory_max": "1G"}}),
        ]
        for key, value in changes:
            changed = copy.deepcopy(report); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_guest_report(changed, expected, "1"*64, "2"*64)

    def test_failure_record_keeps_every_claim_false(self):
        record = failure_record(source_binding(), "fixture failure")
        for key in ("passed", "guest_booted", "graphical_desktop_observed",
                    "artifact_retained", "independent_reboot_passed", "os_qualified",
                    "release_qualified", "signature_qualified"):
            self.assertIs(record[key], False, key)

    def test_appliance_containers_use_exact_four_gib_with_outer_margin(self):
        self.assertEqual(APPLIANCE_CONTAINER_MEMORY_BYTES, 4 * 1024**3)
        self.assertEqual(APPLIANCE_CONTROLLER_MEMORY_BYTES, 5 * 1024**3)
        self.assertEqual(APPLIANCE_CONTROLLER_MARGIN_BYTES, 1024**3)
        self.assertEqual(APPLIANCE_CONTAINER_LIMITS, {
            "memory.max": "4294967296", "memory.swap.max": "0",
            "cpu.max": "200000 100000", "pids.max": "64",
        })
        hosted = (ROOT / "image/appliance/hosted.py").read_text()
        self.assertIn('"--memory=4g", "--memory-swap=4g"', hosted)
        for name in ("producer.py", "reboot.py"):
            source = (ROOT / "image/appliance" / name).read_text()
            self.assertIn("limits != APPLIANCE_CONTAINER_LIMITS", source)
        wrapper = (ROOT / "scripts/check-interactive-appliance.sh").read_text()
        self.assertIn("--property=MemoryMax=5G", wrapper)
        self.assertIn("--property=MemorySwapMax=0", wrapper)
        atomic = (ROOT / "image/atomic/hosted.py").read_text()
        self.assertIn("'memory.max':'5368709120'", atomic)

    def test_child_failure_retains_only_allowlisted_structured_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            result = child_failure(
                "RuntimeError: failed at /home/runner/private token=topsecret "
                "https://example.invalid/private"
            )
            raw_result = (json.dumps(result, indent=2) + "\n").encode()
            (output / "result.json").write_bytes(raw_result)
            qemu = (
                b"qemu-system-x86_64: cannot allocate RAM at /home/runner/private "
                b"password=hunter2\nMemoryError: secret diagnostic\n"
            )
            serial = (
                b"SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"SYMBI_APPLIANCE_STATUS:provision-phase-start:selinux-enforcement\n"
                b"subprocess.CalledProcessError: token=serial-secret\n"
                b"SYMBI_APPLIANCE_STATUS:provision-phase-exit:selinux-enforcement\n"
            )
            guest_report = b'{"private":"guest-report-secret"}\n'
            (evidence / "provision-qemu.log").write_bytes(qemu)
            (evidence / "provision-serial.log").write_bytes(serial)
            (evidence / "guest-report.json").write_bytes(guest_report)
            (evidence / "unapproved.log").write_text("must not be retained")

            diagnostic, receipt = _failure_diagnostic(output, "producer", source_binding())
            self.assertIsNotNone(diagnostic)
            self.assertEqual(receipt, {
                "limits": result["limits"], "cgroup_final": result["cgroup_final"],
            })
            retained = json.dumps(diagnostic)
            for forbidden in ("/home/runner", "topsecret", "hunter2",
                              "example.invalid", "serial-secret",
                              "guest-report-secret", "unapproved"):
                self.assertNotIn(forbidden, retained)
            self.assertEqual(diagnostic["result"]["failure_type"], "RuntimeError")
            self.assertEqual(diagnostic["result"]["producer_status"],
                             producer_status())
            self.assertEqual(diagnostic["result"], {
                "failure_type": "RuntimeError",
                "producer_status": producer_status(),
            })
            self.assertEqual(diagnostic["logs"]["provision-qemu.log"], {
                "bytes": len(qemu), "authority": "untrusted-log-observation",
                "observed_sentinels": [],
                "observed_error_classes": ["MemoryError"],
            })
            self.assertEqual(diagnostic["logs"]["provision-serial.log"], {
                "bytes": len(serial), "authority": "untrusted-log-observation",
                "observed_sentinels": [
                    "provision-phase-exit:selinux-enforcement",
                    "provision-phase-start:selinux-enforcement",
                    "provision-start",
                ],
                "observed_error_classes": ["CalledProcessError"],
            })
            self.assertEqual(diagnostic["guest_report"], {
                "state": "bounded", "bytes": len(guest_report),
            })
            self.assertEqual(diagnostic["rejected"], {})

            cleanup = {
                "stage_directory_removed": True, "user_artifact_absent": True,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            }
            resources = {"producer": {
                "limits": result["limits"], "cgroup_final": result["cgroup_final"],
            }}
            controller = controller_failure_record(
                source_binding(), "producer", "CalledProcessError", cleanup,
                resources, {"producer": diagnostic},
            )
            self.assertEqual(controller["diagnostics"]["producer"], diagnostic)
            self.assertTrue(all(controller[name] is False for name in (
                "passed", "guest_booted", "graphical_desktop_observed",
                "artifact_retained", "independent_reboot_passed", "os_qualified",
                "release_qualified", "signature_qualified",
            )))
            unsafe = copy.deepcopy(diagnostic)
            unsafe["result"]["message"] = "token=must-not-escape"
            with self.assertRaisesRegex(ValueError, "failure diagnostics"):
                controller_failure_record(
                    source_binding(), "producer", "CalledProcessError", cleanup,
                    resources, {"producer": unsafe},
                )
            unsafe = copy.deepcopy(diagnostic)
            unsafe["logs"]["provision-qemu.log"]["observed_sentinels"] = [[]]
            with self.assertRaisesRegex(ValueError, "failure diagnostics"):
                controller_failure_record(
                    source_binding(), "producer", "CalledProcessError", cleanup,
                    resources, {"producer": unsafe},
                )
            for mutate in (
                lambda value: value["logs"].pop("provision-qemu.log"),
                lambda value: value["logs"].update({"unapproved.log": {
                    "bytes": 1, "authority": "untrusted-log-observation",
                    "observed_sentinels": [], "observed_error_classes": [],
                }}),
                lambda value: value.update({"unknown": False}),
            ):
                unsafe = copy.deepcopy(diagnostic)
                mutate(unsafe)
                with self.assertRaisesRegex(ValueError, "failure diagnostics"):
                    controller_failure_record(
                        source_binding(), "producer", "CalledProcessError", cleanup,
                        resources, {"producer": unsafe},
                    )
            with self.assertRaisesRegex(ValueError, "failure diagnostics"):
                controller_failure_record(
                    source_binding(), "producer", "CalledProcessError", cleanup,
                    {}, {"producer": diagnostic},
                )

    def test_child_failure_preserves_causal_classes_before_a_long_shutdown_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
            raw = (
                b"SYMBI_APPLIANCE_STATUS:verifier-report-write-start\n"
                b"subprocess.TimeoutExpired: timed out before report write\n"
                + b"shutdown-noise-with-private-value " * 2000
            )
            (evidence / "provision-serial.log").write_bytes(raw)

            diagnostic, receipt = _failure_diagnostic(
                output, "producer", source_binding()
            )
            self.assertIsNotNone(receipt)
            item = diagnostic["logs"]["provision-serial.log"]
            self.assertEqual(item["bytes"], len(raw))
            self.assertEqual(item["observed_sentinels"], [
                "verifier-report-write-start",
            ])
            self.assertEqual(item["observed_error_classes"], ["TimeoutExpired"])
            self.assertEqual(diagnostic["rejected"], {
                "provision-qemu.log": "missing",
            })
            self.assertNotIn("shutdown-noise", json.dumps(diagnostic))

    def test_child_failure_accepts_only_exact_python_console_framing(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
            raw = (
                b"[  255.123456] symbi-appliance-provision[686]: "
                b"SYMBI_APPLIANCE_STATUS:provision-phase-timeout:"
                b"enable-display-manager\n"
                b"[  255.123457] symbi-appliance-provision[686]: "
                b"subprocess.TimeoutExpired: private detail\n"
                b"[  255.123458] symbi-appliance-verify[700]: "
                b"SYMBI_APPLIANCE_STATUS:verifier-failed\n"
            )
            (evidence / "provision-serial.log").write_bytes(raw)

            diagnostic, receipt = _failure_diagnostic(
                output, "producer", source_binding()
            )
            self.assertIsNotNone(receipt)
            item = diagnostic["logs"]["provision-serial.log"]
            self.assertEqual(item["observed_sentinels"], [
                "provision-phase-timeout:enable-display-manager",
                "verifier-failed",
            ])
            self.assertEqual(item["observed_error_classes"], ["TimeoutExpired"])
            serialized = json.dumps(diagnostic)
            self.assertNotIn("255.123456", serialized)
            self.assertNotIn("686", serialized)
            self.assertNotIn("private detail", serialized)

    def test_child_failure_ignores_unknown_or_malformed_log_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            result = child_failure()
            (output / "result.json").write_text(json.dumps(result) + "\n")
            raw = (
                b"xSYMBI_APPLIANCE_STATUS:provision-start\n"
                b"SYMBI_APPLIANCE_STATUS:unknown-event\n"
                b"SYMBI_APPLIANCE_STATUS:provision-start extra\n"
                b"print('SYMBI_APPLIANCE_STATUS:provision-start')\n"
                b"TimeoutExpired without a reviewed traceback signature\n"
                b"MemoryError without a colon\n"
                b"not really ValueError: forged\n"
                b"SYMBI_APPLIANCE_STATUS:\xff\xfe\n"
                b"[  255.123456] sh[686]: SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"[  255.123456] python3[0]: SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"[  255.12345] python3[686]: SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"[  255.123456] python3[686]: \x1b[0mSYMBI_APPLIANCE_STATUS:provision-start\n"
                b"prefix [  255.123456] python3[686]: SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"[  255.123456] python3[686]: SYMBI_APPLIANCE_STATUS:provision-start suffix\n"
                b"[  255.123456] symbi-appliance-provision[0]: "
                b"SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"[  255.123456] symbi-appliance-provision[686]: \x1b[0m"
                b"SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"prefix [  255.123456] symbi-appliance-provision[686]: "
                b"SYMBI_APPLIANCE_STATUS:provision-start\n"
                b"[  255.123456] symbi-appliance-provision[686]: "
                b"SYMBI_APPLIANCE_STATUS:provision-start suffix\n"
                b"[  255.123456] symbi-appliance-provision[686]: "
                b"[  1.000000] symbi-appliance-provision[1]: "
                b"SYMBI_APPLIANCE_STATUS:provision-start\n"
            )
            (evidence / "provision-qemu.log").write_bytes(raw)

            diagnostic, receipt = _failure_diagnostic(
                output, "producer", source_binding()
            )
            self.assertIsNotNone(receipt)
            item = diagnostic["logs"]["provision-qemu.log"]
            self.assertEqual(item["observed_sentinels"], [])
            self.assertEqual(item["observed_error_classes"], [])
            self.assertNotIn("unknown-event", json.dumps(diagnostic))

    def test_child_failure_guest_report_state_is_content_free_and_typed(self):
        cases = {
            "absent": "absent", "empty": "empty", "bounded": "bounded",
            "oversized": "oversized", "symlink": "unsafe", "hardlink": "unsafe",
        }
        for case, state in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                evidence = output / "evidence"
                evidence.mkdir(parents=True)
                (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
                report = evidence / "guest-report.json"
                raw = b'{"private":"must-not-escape"}\n'
                if case == "empty":
                    report.touch()
                elif case == "bounded":
                    report.write_bytes(raw)
                elif case == "oversized":
                    report.write_bytes(b"x" * (128 * 1024 + 1))
                elif case == "symlink":
                    target = evidence / "private-report"
                    target.write_bytes(raw)
                    report.symlink_to(target.name)
                elif case == "hardlink":
                    target = evidence / "private-report"
                    target.write_bytes(raw)
                    os.link(target, report)
                diagnostic, receipt = _failure_diagnostic(
                    output, "producer", source_binding()
                )
                self.assertIsNotNone(receipt)
                self.assertEqual(diagnostic["guest_report"]["state"], state)
                self.assertNotIn("must-not-escape", json.dumps(diagnostic))
                if state == "bounded":
                    self.assertEqual(diagnostic["guest_report"], {
                        "state": "bounded", "bytes": len(raw),
                    })
                else:
                    self.assertEqual(diagnostic["guest_report"], {"state": state})

    def test_child_failure_rejects_untyped_resource_text(self):
        cases = (
            ("memory.peak", 17),
            ("memory.events", 17),
            ("cpu.stat", 17),
            ("memory.peak", "9" * 5000),
        )
        for name, value in cases:
            with self.subTest(name=name, kind=type(value).__name__), \
                    tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                evidence = output / "evidence"
                evidence.mkdir(parents=True)
                result = child_failure()
                result["cgroup_final"][name] = value
                (output / "result.json").write_text(json.dumps(result) + "\n")
                self.assertEqual(
                    _failure_diagnostic(output, "producer", source_binding()),
                    (None, None),
                )

    def test_child_failure_types_every_refused_log_without_reading_it(self):
        cases = {
            "symlink": "unsafe", "hardlink": "unsafe",
            "linked-directory": "unsafe", "fifo": "unsafe",
            "oversized": "oversized", "empty": "empty", "missing": "missing",
        }
        for case, reason in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                evidence = output / "evidence"
                evidence.mkdir(parents=True)
                (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
                log = evidence / "provision-qemu.log"
                if case == "symlink":
                    target = evidence / "target.log"
                    target.write_text("private")
                    log.symlink_to(target.name)
                elif case == "hardlink":
                    target = evidence / "target.log"
                    target.write_text("private")
                    os.link(target, log)
                elif case == "linked-directory":
                    evidence.rmdir()
                    target = output / "linked-evidence"
                    target.mkdir()
                    (target / log.name).write_text("private")
                    evidence.symlink_to(target.name)
                elif case == "fifo":
                    os.mkfifo(log)
                elif case == "oversized":
                    log.write_bytes(b"x" * (2 * 1024**2 + 1))
                elif case == "empty":
                    log.touch()
                diagnostic, receipt = _failure_diagnostic(
                    output, "producer", source_binding()
                )
                self.assertIsNotNone(receipt)
                self.assertEqual(diagnostic["logs"], {})
                expected = {
                    "provision-qemu.log": reason,
                    "provision-serial.log": (
                        "unsafe" if case == "linked-directory" else "missing"
                    ),
                }
                self.assertEqual(diagnostic["rejected"], expected)
                self.assertEqual(
                    diagnostic["guest_report"],
                    {"state": "unsafe" if case == "linked-directory" else "absent"},
                )
                self.assertNotIn("private", json.dumps(diagnostic))

    def test_child_failure_types_changed_and_unreadable_log_reads(self):
        from image.appliance import hosted

        for error, reason in ((ValueError("changed"), "changed"),
                              (OSError("unreadable"), "unreadable")):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                evidence = output / "evidence"
                evidence.mkdir(parents=True)
                (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
                (evidence / "provision-qemu.log").write_text("private qemu content")
                (evidence / "provision-serial.log").write_text(
                    "SYMBI_APPLIANCE_STATUS:provision-start\n"
                )
                original = hosted._bounded_regular

                def fail_selected(path, maximum):
                    if path.name == "provision-qemu.log":
                        raise error
                    return original(path, maximum)

                with mock.patch.object(
                    hosted, "_bounded_regular", side_effect=fail_selected,
                ):
                    diagnostic, receipt = hosted._failure_diagnostic(
                        output, "producer", source_binding()
                    )
                self.assertIsNotNone(receipt)
                self.assertEqual(diagnostic["rejected"], {
                    "provision-qemu.log": reason,
                })
                self.assertIn("provision-serial.log", diagnostic["logs"])
                self.assertNotIn("private qemu content", json.dumps(diagnostic))

    def test_reboot_failure_diagnostic_uses_the_same_content_free_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "reboot-output"
            output.mkdir()
            result = child_failure("RuntimeError: private reboot failure")
            result.pop("producer_status")
            raw_result = (json.dumps(result) + "\n").encode()
            (output / "result.json").write_bytes(raw_result)
            qemu = b"private qemu detail\n"
            serial = b"RuntimeError: private serial detail\n"
            (output / "reboot-qemu.log").write_bytes(qemu)
            (output / "reboot-serial.log").write_bytes(serial)

            diagnostic, receipt = _failure_diagnostic(
                output, "reboot", source_binding()
            )
            self.assertIsNotNone(receipt)
            self.assertEqual(diagnostic["result"], {
                "failure_type": "RuntimeError", "producer_status": None,
            })
            self.assertEqual(diagnostic["rejected"], {})
            self.assertIsNone(diagnostic["guest_report"])
            self.assertEqual(
                diagnostic["logs"]["reboot-serial.log"]["observed_error_classes"],
                ["RuntimeError"],
            )
            serialized = json.dumps(diagnostic)
            self.assertNotIn("private qemu detail", serialized)
            self.assertNotIn("private serial detail", serialized)

    def test_child_failure_rejects_unsafe_result_file_itself(self):
        for case in ("symlink", "fifo", "oversized"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                output.mkdir()
                result = output / "result.json"
                if case == "symlink":
                    target = output / "target.json"
                    target.write_text(json.dumps(child_failure()))
                    result.symlink_to(target.name)
                elif case == "fifo":
                    os.mkfifo(result)
                else:
                    result.write_bytes(b"x" * (256 * 1024 + 1))
                self.assertEqual(
                    _failure_diagnostic(output, "producer", source_binding()),
                    (None, None),
                )

    def test_child_failure_requires_exact_source_result_and_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            result = child_failure()
            result["source_binding"]["source_commit"] = "0" * 40
            (output / "result.json").write_text(json.dumps(result) + "\n")
            (evidence / "provision-qemu.log").write_text("must not escape")
            diagnostic, receipt = _failure_diagnostic(
                output, "producer", source_binding()
            )
            self.assertIsNone(diagnostic)
            self.assertIsNotNone(receipt)

        cleanup = {
            "stage_directory_removed": True, "user_artifact_absent": True,
            "screenshot_artifact_absent": True, "non_controller_evidence_removed": True,
        }
        result = child_failure()
        resources = {"producer": {
            "limits": dict(result["limits"]),
            "cgroup_final": dict(result["cgroup_final"]),
        }}
        resources["producer"]["limits"]["memory.max"] = "1"
        resources["producer"]["cgroup_final"]["memory.max"] = "1"
        with self.assertRaisesRegex(ValueError, "resource receipt"):
            controller_failure_record(
                source_binding(), "producer", "CalledProcessError", cleanup, resources,
            )

    def test_controller_captures_child_cause_before_removing_private_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def failed_producer(*arguments):
                stage, progress = arguments[9], arguments[11]
                output = stage / "output"
                evidence = output / "evidence"
                evidence.mkdir(parents=True)
                progress["stage"] = "producer"
                (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
                (evidence / "provision-qemu.log").write_text(
                    "MemoryError: cannot allocate guest RAM private-detail\n"
                )
                (evidence / "provision-serial.log").write_text(
                    "SYMBI_APPLIANCE_STATUS:verifier-report-write-start\n"
                    "private serial content\n"
                )
                raise subprocess.CalledProcessError(1, ["podman", "run"])

            with mock.patch("image.appliance.hosted._produce_appliance",
                            side_effect=failed_producer):
                with self.assertRaises(subprocess.CalledProcessError):
                    produce_appliance(
                        root, Path("/sys/fs/cgroup/test"), ["podman"], "image",
                        Path("disk"), source_binding(), [], mock.Mock(),
                    )
            retained = json.loads(
                (root / ".cache/interactive-appliance-evidence/result.json").read_text()
            )
            self.assertEqual(retained["stage"], "producer")
            self.assertIn("producer", retained["resources"])
            self.assertEqual(
                retained["diagnostics"]["producer"]["result"]["failure_type"],
                "RuntimeError",
            )
            diagnostic = retained["diagnostics"]["producer"]
            self.assertEqual(
                diagnostic["logs"]["provision-qemu.log"]["observed_error_classes"],
                ["MemoryError"],
            )
            self.assertEqual(
                diagnostic["logs"]["provision-serial.log"]["observed_sentinels"],
                ["verifier-report-write-start"],
            )
            self.assertEqual(diagnostic["guest_report"], {"state": "absent"})
            serialized = json.dumps(retained)
            self.assertNotIn("private-detail", serialized)
            self.assertNotIn("private serial content", serialized)
            self.assertFalse((root / ".cache/interactive-appliance-stage").exists())
            evidence = root / ".cache/interactive-appliance-evidence"
            self.assertEqual(sorted(path.name for path in evidence.iterdir()),
                             ["result.json"])
            from image.appliance.hosted import finalize_failed_appliance_evidence
            self.assertTrue(finalize_failed_appliance_evidence(root))
            self.assertEqual(
                json.loads(
                    (root / ".cache/interactive-appliance-evidence/result.json").read_text()
                ),
                retained,
            )
            write_outer_systemd_result(
                evidence / "systemd-result.txt",
                Result="exit-code", ActiveState="failed", SubState="failed",
                ExecMainStatus="1",
            )
            self.assertEqual(sorted(path.name for path in evidence.iterdir()),
                             ["result.json", "systemd-result.txt"])
            self.assertGreater(validate_failure_fixture(root), 0)

    def test_malformed_child_diagnostic_cannot_interrupt_cleanup(self):
        def scalar(result):
            result["cgroup_final"]["memory.events"] = 17

        def container(result):
            result["cgroup_final"] = []

        def surrogate(result):
            result["failure"] = "RuntimeError: invalid surrogate \ud800"

        def mismatched_status(result):
            result["producer_status"] = producer_status(
                phase="raw-conversion", kind="subprocess-exit", exit_code=7,
                qemu_exit_code=None,
            )

        for name, corrupt in (
            ("scalar-resource", scalar),
            ("container-resource", container),
            ("surrogate-message", surrogate),
            ("mismatched-status", mismatched_status),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)

                def failed_producer(*arguments):
                    stage, progress = arguments[9], arguments[11]
                    output = stage / "output"
                    (output / "evidence").mkdir(parents=True)
                    progress["stage"] = "producer"
                    result = child_failure()
                    corrupt(result)
                    (output / "result.json").write_text(
                        json.dumps(result, ensure_ascii=True) + "\n"
                    )
                    raise subprocess.CalledProcessError(1, ["podman", "run"])

                with mock.patch(
                    "image.appliance.hosted._produce_appliance",
                    side_effect=failed_producer,
                ):
                    with self.assertRaises(subprocess.CalledProcessError):
                        produce_appliance(
                            root, Path("/sys/fs/cgroup/test"), ["podman"], "image",
                            Path("disk"), source_binding(), [], mock.Mock(),
                        )
                retained = json.loads(
                    (root / ".cache/interactive-appliance-evidence/result.json").read_text()
                )
                self.assertEqual(retained["stage"], "producer")
                self.assertEqual(
                    set(retained["resources"]),
                    {"producer"}
                    if name in {"surrogate-message", "mismatched-status"}
                    else set(),
                )
                self.assertEqual(retained["diagnostics"], {})
                self.assertTrue(all(retained["cleanup"].values()))
                self.assertFalse((root / ".cache/interactive-appliance-stage").exists())

    def test_early_controller_failure_is_source_bound_path_free_and_all_false(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def partial_output(*arguments):
                evidence, stage, artifact_output = arguments[8:11]
                stage.mkdir(parents=True)
                artifact_output.mkdir(parents=True)
                (artifact_output / ARTIFACT_NAME).write_bytes(b"partial")
                (evidence / "display.ppm").write_bytes(b"stale screenshot")
                raise ValueError("/home/runner/private/fixture")

            with mock.patch("image.appliance.hosted._produce_appliance",
                            side_effect=partial_output):
                with self.assertRaises(ValueError):
                    produce_appliance(root, Path("/sys/fs/cgroup/test"), ["podman"],
                                      "image", Path("disk"), source_binding(), [], mock.Mock())
            result = json.loads(
                (root / ".cache/interactive-appliance-evidence/result.json").read_text())
            for key in ("passed", "guest_booted", "graphical_desktop_observed",
                        "artifact_retained", "independent_reboot_passed", "os_qualified",
                        "release_qualified", "signature_qualified"):
                self.assertIs(result[key], False, key)
            self.assertEqual(result["stage"], "initialization")
            self.assertEqual(result["source"], {
                "commit": source_binding()["source_commit"],
                "tree": source_binding()["source_tree"],
            })
            self.assertEqual(result["failure"], "ValueError")
            self.assertNotIn("/home/runner", json.dumps(result))
            self.assertEqual(result["cleanup"], {
                "stage_directory_removed": True, "user_artifact_absent": True,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            })
            self.assertEqual(result["resources"], {})
            self.assertEqual(result["diagnostics"], {})
            self.assertFalse((root / ".cache/interactive-appliance-artifact").exists())
            self.assertFalse((root / ".cache/interactive-appliance-evidence/display.ppm").exists())

    def test_outer_failure_revokes_success_artifacts_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            artifact_output = root / ".cache/interactive-appliance-artifact"
            evidence.mkdir(parents=True)
            artifact_output.mkdir()
            (evidence / "result.json").write_text('{"passed":true}\n')
            (evidence / "display.ppm").write_bytes(b"screenshot")
            (artifact_output / ARTIFACT_NAME).write_bytes(b"qcow2")
            result = invalidate_appliance_output(root, source_binding())
            self.assertFalse(result["passed"])
            self.assertEqual(result["stage"], "cleanup")
            self.assertFalse(artifact_output.exists())
            self.assertFalse((evidence / "display.ppm").exists())
            retained = json.loads((evidence / "result.json").read_text())
            self.assertEqual(retained, result)
            self.assertTrue(all(retained["cleanup"].values()))
            self.assertEqual([path.name for path in evidence.iterdir()], ["result.json"])

    def test_failure_sanitizer_replaces_stale_positive_child_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            artifact_output = root / ".cache/interactive-appliance-artifact"
            evidence.mkdir(parents=True)
            artifact_output.mkdir()
            stale = {"passed": True, "source_binding": source_binding(),
                     "host_path": "/home/runner/private"}
            (evidence / "result.json").write_text(json.dumps(stale))
            (evidence / "producer-result.json").write_text('{"passed":true}')
            (artifact_output / ARTIFACT_NAME).write_bytes(b"qcow2")
            from image.appliance.hosted import finalize_failed_appliance_evidence
            self.assertTrue(finalize_failed_appliance_evidence(root))
            retained = json.loads((evidence / "result.json").read_text())
            self.assertFalse(retained["passed"])
            self.assertNotIn("/home/runner", json.dumps(retained))
            self.assertEqual([path.name for path in evidence.iterdir()], ["result.json"])
            self.assertFalse(artifact_output.exists())

    def test_outer_finally_failure_cancels_pending_success_return(self):
        def pending_return(record):
            try:
                return "should-not-escape"
            finally:
                enforce_appliance_final_status("appliance", record)

        with self.assertRaises(RuntimeError):
            pending_return({"passed": False})
        self.assertEqual(pending_return({"passed": True}), "should-not-escape")
        enforce_appliance_final_status("", {"passed": False})

    def test_failed_qcow_removal_retains_no_positive_claim(self):
        from image.appliance import hosted as appliance_hosted
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            artifact_output = root / ".cache/interactive-appliance-artifact"
            evidence.mkdir(parents=True)
            artifact_output.mkdir()
            (artifact_output / ARTIFACT_NAME).write_bytes(b"qcow2")
            original_remove = appliance_hosted._remove_local_output

            def fail_artifact_removal(path):
                if path == artifact_output:
                    return False
                return original_remove(path)

            with mock.patch.object(appliance_hosted, "_remove_local_output",
                                   side_effect=fail_artifact_removal):
                result = invalidate_appliance_output(root, source_binding())
            self.assertFalse(result["passed"])
            self.assertFalse(result["cleanup"]["user_artifact_absent"])
            self.assertTrue(artifact_output.exists())
            with self.assertRaises(RuntimeError):
                enforce_appliance_final_status("appliance", result)

    def test_failure_sanitizer_discards_every_output_after_any_false_cleanup(self):
        from image.appliance import hosted as appliance_hosted
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / ".cache"
            evidence = cache / "interactive-appliance-evidence"
            stage = cache / "interactive-appliance-stage"
            artifact_output = cache / "interactive-appliance-artifact"
            ready = cache / "interactive-appliance-evidence.ready"
            evidence.mkdir(parents=True)
            stage.mkdir()
            artifact_output.mkdir()
            ready.write_text("stale upload authorization\n")
            cleanup = {
                "stage_directory_removed": False,
                "user_artifact_absent": False,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            }
            failure = controller_failure_record(
                source_binding(), "cleanup", "AtomicControllerFailure", cleanup, {},
            )
            (evidence / "result.json").write_text(json.dumps(failure) + "\n")
            (artifact_output / ARTIFACT_NAME).write_bytes(b"surviving public output")
            original_remove = appliance_hosted._remove_local_output
            artifact_attempts = 0

            def fail_first_artifact_removal(path):
                nonlocal artifact_attempts
                if path == artifact_output:
                    artifact_attempts += 1
                    if artifact_attempts == 1:
                        return False
                return original_remove(path)

            with mock.patch.object(
                appliance_hosted, "_remove_local_output",
                side_effect=fail_first_artifact_removal,
            ):
                self.assertFalse(appliance_hosted.finalize_failed_appliance_evidence(root))
            self.assertGreaterEqual(artifact_attempts, 2)
            for path in (evidence, stage, artifact_output, ready):
                self.assertFalse(path.exists() or path.is_symlink(), path)

    def test_failure_sanitizer_rejects_public_output_despite_true_cleanup_claims(self):
        from image.appliance.hosted import finalize_failed_appliance_evidence
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / ".cache/interactive-appliance-evidence"
            artifact_output = root / ".cache/interactive-appliance-artifact"
            evidence.mkdir(parents=True)
            artifact_output.mkdir()
            cleanup = {
                "stage_directory_removed": True,
                "user_artifact_absent": True,
                "screenshot_artifact_absent": True,
                "non_controller_evidence_removed": True,
            }
            failure = controller_failure_record(
                source_binding(), "cleanup", "AtomicControllerFailure", cleanup, {},
            )
            (evidence / "result.json").write_text(json.dumps(failure) + "\n")
            (artifact_output / ARTIFACT_NAME).write_bytes(b"surviving public output")
            self.assertFalse(finalize_failed_appliance_evidence(root))
            self.assertFalse(evidence.exists() or evidence.is_symlink())
            self.assertFalse(artifact_output.exists() or artifact_output.is_symlink())

    def test_failure_validation_rejects_false_cleanup_or_surviving_public_output(self):
        for case in ("false-cleanup", "public-output"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = root / ".cache/interactive-appliance-evidence"
                evidence.mkdir(parents=True)
                ready = root / ".cache/interactive-appliance-evidence.ready"
                cleanup = {
                    "stage_directory_removed": True,
                    "user_artifact_absent": True,
                    "screenshot_artifact_absent": True,
                    "non_controller_evidence_removed": True,
                }
                if case == "false-cleanup":
                    cleanup["user_artifact_absent"] = False
                    ready.write_text("stale upload authorization\n")
                else:
                    artifact_output = root / ".cache/interactive-appliance-artifact"
                    artifact_output.mkdir()
                    (artifact_output / ARTIFACT_NAME).write_bytes(b"surviving public output")
                failure = controller_failure_record(
                    source_binding(), "cleanup", "AtomicControllerFailure", cleanup, {},
                )
                (evidence / "result.json").write_text(json.dumps(failure) + "\n")
                write_outer_systemd_result(evidence / "systemd-result.txt")
                with self.assertRaisesRegex(ValueError, "cleanup is incomplete"):
                    validate_failure_fixture(root)
                self.assertFalse(evidence.exists() or evidence.is_symlink())
                self.assertFalse(ready.exists() or ready.is_symlink())
                self.assertFalse(
                    (root / ".cache/interactive-appliance-artifact").exists()
                    or (root / ".cache/interactive-appliance-artifact").is_symlink()
                )

    def test_source_bound_nonblank_reboot_is_required(self):
        source, disk = source_binding(), artifact()
        report = reboot(source, disk)
        validate_reboot_report(report, source, disk)
        cases = []
        changed = copy.deepcopy(report); changed["source_binding"]["source_commit"] = "9"*40; cases.append(changed)
        changed = copy.deepcopy(report); changed["artifact_after"]["sha256"] = "8"*64; cases.append(changed)
        changed = copy.deepcopy(report); changed["screenshot"]["sampled_colors"] = 1; cases.append(changed)
        changed = copy.deepcopy(report); changed["screenshot"]["boot_elapsed_seconds"] = 89; cases.append(changed)
        changed = copy.deepcopy(report); changed["command"] = ["qemu-system-x86_64"]; cases.append(changed)
        changed = copy.deepcopy(report); changed["artifact_retained"] = False; cases.append(changed)
        changed = copy.deepcopy(report); changed["independent_reboot_passed"] = False; cases.append(changed)
        for index, changed in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                validate_reboot_report(changed, source, disk)

    def test_ppm_observation_rejects_blank_display(self):
        path = Path("/unopened/reboot.ppm")
        blank = b"P6\n320 200\n255\n" + b"\0\0\0"*(320*200)
        with mock.patch.object(Path, "read_bytes", return_value=blank):
            with self.assertRaises(ValueError):
                ppm_observation(path)
        pixels = bytearray(b"\0\0\0"*(320*200)); pixels[:3] = b"\xff\xff\xff"
        with mock.patch.object(Path, "read_bytes",
                               return_value=b"P6\n320 200\n255\n" + pixels):
            self.assertGreaterEqual(ppm_observation(path)["sampled_colors"], 2)

    def test_reboot_refuses_stale_outputs_and_oversized_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            require_empty_output(output)
            stale = output / "reboot.ppm"
            stale.write_bytes(b"old")
            with self.assertRaises(ValueError):
                require_empty_output(output)
            stale.unlink()
            log = output / "reboot-qemu.log"
            log.write_bytes(b"x" * 17)
            bounded_log(log, 17, required=True)
            with self.assertRaises(ValueError):
                bounded_log(log, 16, required=True)

    def test_reviewed_launcher_cannot_escape_or_change_target(self):
        binding = {"sha256": "", "bytes": 7, "mode": 0o755}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            launcher = root / "usr/bin/Hyprland"
            target = root / "usr/lib/symbi/hyprland/bin/Hyprland"
            launcher.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            target.write_bytes(b"desktop")
            target.chmod(0o755)
            binding["sha256"] = hashlib.sha256(b"desktop").hexdigest()
            launcher.symlink_to("../lib/symbi/hyprland/bin/Hyprland")
            expected = {"link": "../lib/symbi/hyprland/bin/Hyprland"}
            self.assertTrue(reviewed_launcher(root, expected))
            self.assertTrue(bound_regular(target, binding, os.getuid()))
            target.write_bytes(b"changed")
            self.assertFalse(bound_regular(target, binding, os.getuid()))
            launcher.unlink(); target.write_bytes(b"desktop")
            launcher.symlink_to("/etc/passwd")
            self.assertFalse(reviewed_launcher(root, expected))
            launcher.unlink(); target.unlink()
            target.symlink_to("/etc/passwd")
            launcher.symlink_to("../lib/symbi/hyprland/bin/Hyprland")
            self.assertFalse(reviewed_launcher(root, expected))

    def test_broken_key_link_is_not_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authorized_keys"
            self.assertTrue(path_absent(path))
            path.symlink_to("missing")
            self.assertFalse(path_absent(path))

    def test_component_bindings_come_from_exact_retained_image(self):
        lock = json.loads((ROOT / "image/desktop-images.lock.json").read_text())
        selected = lock["images"]["generic"]
        source = source_binding()
        source.update({
            "image_source_commit": selected["tested_commit"],
            "image_run_id": selected["run_id"],
            "image_artifact_id": selected["artifact"]["id"],
            "image_artifact_sha256": selected["artifact"]["sha256"],
        })
        bindings = _installed_desktop_bindings(ROOT, source)
        self.assertEqual(
            bindings["files"]["/usr/bin/Hyprland"],
            {"link": "../lib/symbi/hyprland/bin/Hyprland"},
        )
        self.assertEqual(
            bindings["files"]["/usr/lib/symbi/hyprland/bin/Hyprland"]["sha256"],
            "0f5dc9a3bb14265516a1a7c16a90ff0ad54fda94c7caed5defb4b234ecb7f34a",
        )
        self.assertEqual(bindings["packages"]["waybar"], "waybar\t0\t0.16.0\t1.fc45\tx86_64")

    def test_manifest_is_short_lived_unsigned_and_exact(self):
        source, disk = source_binding(), artifact()
        producer = {"passed": True, "guest_booted": True, "graphical_desktop_observed": True,
                    "artifact_retained": True, "os_qualified": False,
                    "independent_reboot_passed": False,
                    "release_qualified": False, "signature_qualified": False,
                    "source_binding": source}
        manifest = build_manifest(source, disk, producer, reboot(source, disk),
                                  datetime(2026, 11, 27, tzinfo=timezone.utc))
        self.assertTrue(manifest["highly_experimental"])
        self.assertEqual(manifest["expires_at"], "2026-11-29T00:00:00Z")
        self.assertEqual(manifest["retention_days"], 2)
        self.assertEqual(manifest["network"], "none")
        self.assertFalse(manifest["signed"])
        for key in ("os_qualified", "release_qualified", "signature_qualified"):
            self.assertIs(manifest[key], False)

    def test_manifest_refuses_any_artifact_or_reboot_mismatch(self):
        source, disk = source_binding(), artifact()
        producer = {"passed": True, "guest_booted": True, "graphical_desktop_observed": True,
                    "artifact_retained": True, "os_qualified": False,
                    "independent_reboot_passed": False,
                    "release_qualified": False, "signature_qualified": False,
                    "source_binding": source}
        for mutation in ("name", "sha256", "virtual_bytes"):
            changed = copy.deepcopy(disk)
            changed[mutation] = "wrong" if mutation != "virtual_bytes" else 1
            with self.subTest(field=mutation), self.assertRaises(ValueError):
                build_manifest(source, changed, producer, reboot(source, disk))

    def test_workflow_is_manual_only_source_checked_and_short_lived(self):
        path = ROOT / ".github/workflows/interactive-appliance.yml"
        document = yaml.safe_load(path.read_text())
        self.assertEqual(set(document[True]), {"workflow_dispatch"})
        self.assertEqual(document["permissions"], {"contents": "read", "actions": "read"})
        workflow = path.read_text()
        self.assertIn("sha256sum --check --strict", workflow)
        self.assertIn("retention-days: 2", workflow)
        self.assertIn("if: success()", workflow)
        self.assertIn("SYMBI_QUALIFICATION: appliance", workflow)
        self.assertNotIn("!.cache/interactive-appliance-evidence/display.ppm", workflow)
        self.assertNotIn("hashFiles('.cache/interactive-appliance-evidence.ready')", workflow)
        self.assertIn("steps.appliance.outputs.evidence_ready == 'true'", workflow)
        self.assertIn("SYMBI_APPLIANCE_EXPECTED_EXPIRY", workflow)
        self.assertIn("date --utc --date='now + 2 days'", workflow)
        self.assertIn("--validate-public-artifact", workflow)
        self.assertNotIn(".cache/interactive-appliance-hosted.log", workflow)
        self.assertNotIn(".cache/atomic-disk-evidence/", workflow)
        self.assertNotIn(".cache/atomic-image-evidence/", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:", workflow)
        steps = document["jobs"]["produce"]["steps"]
        self.assertEqual(document["jobs"]["produce"]["timeout-minutes"], 240)
        expected_timeouts = {
            "Check out the explicitly selected producer revision": 5,
            "Bind appliance expiry to the hosted workflow clock": 1,
            "Require reviewed preflight and runner capacity before download": 2,
            "Download the exact retained generic development OCI": 20,
            "Verify metadata and stream the exact retained OCI": 20,
            "Install and independently reboot the offline graphical appliance": 130,
            "Retain bounded appliance evidence including failures": 10,
            "Revalidate the exact public appliance artifact before upload": 10,
            "Retain the compressed HIGHLY EXPERIMENTAL qcow2 for two days": 30,
        }
        self.assertEqual({step["name"]: step["timeout-minutes"] for step in steps},
                         expected_timeouts)
        self.assertEqual(sum(expected_timeouts.values()), 228)
        self.assertEqual(240 - sum(expected_timeouts.values()), 12)
        gate = workflow.index("python3 -m image.appliance.prerequisite")
        download = workflow.index("Download the exact retained generic development OCI")
        self.assertLess(gate, download)
        self.assertIn("timeout 30 gh api", workflow)
        self.assertIn("timeout 900 gh api", workflow)
        evidence_step = workflow.index("Retain bounded appliance evidence including failures")
        public_validation = workflow.index(
            "Revalidate the exact public appliance artifact before upload")
        qcow2_step = workflow.index("Retain the compressed HIGHLY EXPERIMENTAL qcow2")
        self.assertLess(evidence_step, public_validation)
        self.assertLess(public_validation, qcow2_step)
        install_step = next(
            step for step in steps
            if step["name"] == "Install and independently reboot the offline graphical appliance")
        self.assertEqual(install_step["id"], "appliance")
        evidence_upload = next(
            step for step in steps
            if step["name"] == "Retain bounded appliance evidence including failures")
        self.assertEqual(
            evidence_upload["if"],
            "${{ always() && steps.appliance.outputs.evidence_ready == 'true' }}",
        )
        for name in (
            "Revalidate the exact public appliance artifact before upload",
            "Retain the compressed HIGHLY EXPERIMENTAL qcow2 for two days",
        ):
            public_step = next(step for step in steps if step["name"] == name)
            self.assertEqual(public_step["if"], "success()")
        script = (ROOT / "scripts/check-interactive-appliance.sh").read_text()
        self.assertNotIn("| tee", script)
        self.assertIn("--sanitize-failure", script)
        self.assertIn("--create-outer-failure", script)
        self.assertIn("--validate-evidence", script)
        self.assertNotIn("validated-small-evidence", script)
        self.assertIn("rm -f -- \"$evidence_ready\"", script)
        self.assertIn("printf 'evidence_ready=true\\n' >> \"$GITHUB_OUTPUT\"", script)
        self.assertLess(
            script.index("rm -f -- \"$evidence_ready\""),
            script.index('[[ "${GITHUB_ACTIONS:-}" == true'),
        )
        self.assertIn("> 4096", script)
        self.assertIn("RuntimeMaxSec=115min", script)
        self.assertIn('--unit="$unit" --no-block', script)
        self.assertIn("--property=Type=oneshot --property=RemainAfterExit=yes", script)
        self.assertNotIn("--wait --pipe", script)
        self.assertIn("deadline=$((SECONDS + 7020))", script)
        self.assertIn("--property=TimeoutStartSec=115min", script)
        self.assertIn("--property=TimeoutStopSec=30s", script)
        self.assertIn("--property=ActiveState --property=SubState", script)
        self.assertIn("--property=Result --property=OOMPolicy", script)
        self.assertIn("--property=ControlGroup", script)
        self.assertIn("--property=OOMPolicy=stop", script)
        self.assertIn('/usr/bin/sync -f "$resource"', script)
        self.assertIn('cgroup_path="/sys/fs/cgroup${expected_control_group}"', script)
        self.assertIn('[[ -n $value && $value != "$expected_control_group" ]]', script)
        self.assertIn('! capture_control_group && (( unit_terminal == 0 ))', script)
        self.assertIn("if ! discard_appliance_output", script)
        self.assertIn("--property=MemoryMax", script)
        self.assertIn("--property=MemorySwapMax", script)
        self.assertIn("SYMBI_APPLIANCE_EXPECTED_EXPIRY", script)
        self.assertIn("SYMBI_APPLIANCE_SOURCE_TREE", script)
        self.assertIn('source_tree=$(git rev-parse \'HEAD^{tree}\')', script)
        collect = script.index("capture_systemd_result || true")
        cleanup = script.index("if ! stop_and_reset_unit", collect)
        create = script.index("if ! create_outer_evidence", cleanup)
        write = script.index("if ! write_systemd_result", create)
        validate = script.index("elif ! validate_evidence", cleanup)
        output = script.index("printf 'evidence_ready=true", validate)
        self.assertLess(cleanup, output)
        self.assertLess(collect, cleanup)
        self.assertLess(cleanup, create)
        self.assertLess(create, write)
        self.assertLess(write, validate)
        self.assertLess(validate, output)
        prepare = (ROOT / "scripts/check-atomic-image.sh").read_text()
        self.assertIn("RuntimeMaxSec=15min", prepare)

    def test_pre_download_gate_accepts_the_reviewed_selector_before_capacity(self):
        available = 10**15
        result = validate_appliance_prerequisites(
            ROOT, available_bytes=available)
        self.assertEqual(result["schema"], 1)
        self.assertEqual(result["variant"], "generic")
        self.assertEqual(result["preflight_run"], 46125049529)
        self.assertEqual(result["desktop_images_lock_sha256"],
                         "1a268651cccc61a5693ec9c3a519680b9cffc1844ffeda852f4d151b4b7d670c")
        self.assertEqual(result["artifact_bytes"], 4177421526)
        self.assertEqual(result["available_bytes"], available)
        self.assertEqual(result["required_bytes"], 69675672790)
        self.assertIs(result["os_qualified"], False)
        self.assertIs(result["release_qualified"], False)

    def test_pre_download_capacity_has_controller_floor_and_working_margin(self):
        lock = json.loads((ROOT / "image/desktop-images.lock.json").read_text())
        selected = lock["images"]["generic"]
        self.assertEqual(selected["artifact"]["bytes"], 4177421526)
        expected = (MINIMUM_DISK_FREE_BYTES + selected["artifact"]["bytes"]
                    + DOWNLOAD_WORKING_MARGIN_BYTES)
        self.assertEqual(expected, 69675672790)
        self.assertEqual(required_free_before_download(selected), expected)
        self.assertEqual(require_download_capacity(selected, expected), expected)
        with self.assertRaisesRegex(ValueError, "before downloading"):
            require_download_capacity(selected, expected - 1)

    def test_hosted_hook_never_changes_the_production_oci(self):
        hosted = (ROOT / "image/atomic/hosted.py").read_text()
        appliance = (ROOT / "image/appliance/hosted.py").read_text()
        self.assertIn("image/appliance/install.py", hosted)
        self.assertIn("os.chmod(disk,0o444", hosted)
        self.assertIn("production_oci_before", hosted)
        self.assertIn("production_oci_after", hosted)
        self.assertIn("Retained production OCI bytes changed", hosted)
        self.assertIn(
            "save()\n        enforce_appliance_final_status(qualification,record)", hosted)
        self.assertIn("dst=/inputs/atomic.raw,ro", appliance)
        self.assertIn("sha256(disk) != raw_before", appliance)
        self.assertNotIn("image/overlay", (ROOT / "image/appliance/producer.py").read_text())

    def test_documentation_never_overstates_runtime_evidence(self):
        readme = (ROOT / "image/appliance/README.md").read_text()
        card = (ROOT / "docs/cards/P0-06.md").read_text()
        readme_flat = " ".join(readme.split())
        for text in (readme, card):
            self.assertIn("HIGHLY EXPERIMENTAL", text)
            self.assertIn("no NIC", text)
        self.assertIn("Hosted runtime evidence is\nstill required", card)
        self.assertIn(
            "Failures before the unit starts or reaches a captured terminal state",
            readme,
        )
        self.assertIn("content-free outer receipt", readme)
        self.assertIn("`inner_evidence_available=false`", readme)
        self.assertIn("content-free outer receipt", card)
        self.assertIn("unit start or captured termination", " ".join(card.split()))
        self.assertIn("Immediately before the successful download upload", readme)
        self.assertIn("already uploaded diagnostic evidence can remain", readme_flat)
        self.assertIn("already\n  uploaded diagnostic evidence may remain", card)
        self.assertIn("preflight run `46125049529`", readme)
        self.assertNotIn("pending integrated-head preflight", readme)

    def test_documented_verifier_rejects_tampering_when_optimized(self):
        readme = (ROOT / "image/appliance/README.md").read_text()
        marker = "python3 - <<'PY'\n"
        start = readme.index(marker) + len(marker)
        verifier = readme[start:readme.index("\nPY\n```", start)]
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(verifier))))

        source = source_binding()
        disk_bytes = b"qcow2-fixture"
        screenshot_bytes = b"P6\n1 1\n255\n\x00\x01\x02"
        disk = {
            "name": ARTIFACT_NAME, "bytes": len(disk_bytes),
            "sha256": hashlib.sha256(disk_bytes).hexdigest(), "format": "qcow2",
            "compression": "qcow2-zlib-clusters", "virtual_bytes": VIRTUAL_DISK_BYTES,
        }
        producer = {
            "passed": True, "guest_booted": True, "graphical_desktop_observed": True,
            "artifact_retained": True, "independent_reboot_passed": False,
            "os_qualified": False, "release_qualified": False,
            "signature_qualified": False, "source_binding": source,
        }
        reboot_report = reboot(source, disk)
        reboot_report["screenshot"].update({
            "bytes": len(screenshot_bytes),
            "sha256": hashlib.sha256(screenshot_bytes).hexdigest(),
        })
        manifest = build_manifest(source, disk, producer, reboot_report)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            script = directory / "verify-download.py"
            script.write_text(verifier)
            (directory / "manifest.json").write_text(json.dumps(manifest))
            disk_path = directory / ARTIFACT_NAME
            screenshot_path = directory / "display.ppm"
            disk_path.write_bytes(disk_bytes)
            screenshot_path.write_bytes(screenshot_bytes)
            environment = dict(os.environ, PYTHONOPTIMIZE="1", PYTHONDONTWRITEBYTECODE="1")

            def execute():
                return subprocess.run(
                    [sys.executable, str(script)], cwd=directory, env=environment,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    timeout=10, check=False,
                )

            valid = execute()
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("validated", valid.stdout)

            disk_path.write_bytes(b"X" + disk_bytes[1:])
            tampered_disk = execute()
            self.assertNotEqual(tampered_disk.returncode, 0)
            self.assertNotIn("validated", tampered_disk.stdout)
            self.assertIn("qcow2 SHA-256 changed", tampered_disk.stderr)

            disk_path.write_bytes(disk_bytes)
            screenshot_path.write_bytes(b"X" + screenshot_bytes[1:])
            tampered_screenshot = execute()
            self.assertNotEqual(tampered_screenshot.returncode, 0)
            self.assertNotIn("validated", tampered_screenshot.stdout)
            self.assertIn("screenshot SHA-256 changed", tampered_screenshot.stderr)


if __name__ == "__main__":
    unittest.main()
