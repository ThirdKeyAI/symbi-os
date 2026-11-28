"""Offline contract tests for the HIGHLY EXPERIMENTAL graphical appliance."""
import ast
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
import unittest
from unittest import mock

import yaml

from image.appliance.contract import (APPLIANCE_CONTAINER_LIMITS,
    APPLIANCE_CONTAINER_MEMORY_BYTES, APPLIANCE_CONTROLLER_MARGIN_BYTES,
    APPLIANCE_CONTROLLER_MEMORY_BYTES, ARTIFACT_NAME, FAILURE_EXCERPT_BYTES,
    SCOPE, SDDM_CONFIGURATION,
    VIRTUAL_DISK_BYTES, build_manifest, controller_failure_record, failure_record,
    firmware_arguments, installer_arguments, provision_qemu_arguments,
    reboot_qemu_arguments, user_launch_arguments, validate_guest_report,
    validate_reboot_report, validate_source_binding)
from image.appliance.hosted import (_failure_diagnostic, _installed_desktop_bindings,
                                    _sanitize_diagnostic,
                                    invalidate_appliance_output, produce_appliance)
from image.appliance.prerequisite import (DOWNLOAD_WORKING_MARGIN_BYTES,
    require_download_capacity, required_free_before_download,
    validate_appliance_prerequisites)
from image.appliance.reboot import (bounded_log, ppm_observation,
                                    require_empty_output)
from image.appliance.verify import (bound_regular, observe_bounded_walker,
                                    path_absent, reviewed_launcher)
from image.atomic.hosted import MINIMUM_DISK_FREE_BYTES, enforce_appliance_final_status


ROOT = Path(__file__).resolve().parents[2]


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


def child_failure(reason="RuntimeError: QEMU could not allocate guest memory"):
    source = source_binding()
    result = failure_record(source, reason)
    result.update({
        "limits": dict(APPLIANCE_CONTAINER_LIMITS),
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
        "fixture_cleanup": {"boot_wants_removed": True, "persistent_scripts_absent": True,
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
        "scope": SCOPE,
    }


class InteractiveApplianceContract(unittest.TestCase):
    def test_installer_selects_graphical_target_and_ephemeral_units(self):
        command = installer_arguments("sha256:" + "a"*64)
        self.assertIn("--karg=systemd.unit=graphical.target", command)
        self.assertIn("--karg=systemd.wants=p.service", command)
        self.assertIn("--karg=systemd.wants=v.service", command)
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

    def test_provision_serializes_one_karg_transaction_before_background_update(self):
        from image.appliance import provision

        unit = (ROOT / "image/appliance/p.service").read_text()
        self.assertIn("Before=display-manager.service sddm.service upgrade-on-boot.service", unit)
        with mock.patch.object(provision, "run") as execute:
            provision.remove_fixture_boot_wants()
        execute.assert_called_once_with([
            "/usr/bin/rpm-ostree", "kargs",
            "--delete-if-present=systemd.wants=p.service",
            "--delete-if-present=systemd.wants=v.service",
        ], timeout=provision.PROVISION_COMMAND_TIMEOUTS[
            "remove-fixture-boot-wants"])

    def test_provision_and_first_boot_time_budgets_are_statically_closed(self):
        from image.appliance import contract, provision, verify

        self.assertEqual(provision.PROVISION_COMMAND_TIMEOUTS, {
            "selinux-enforcement": 5,
            "create-fixture-account": 20,
            "lock-fixture-account": 10,
            "select-graphical-target": 10,
            "enable-display-manager": 15,
            "remove-fixture-boot-wants": 240,
        })
        self.assertEqual(provision.PROVISION_SUBPROCESS_BUDGET_SECONDS, 300)
        self.assertEqual(provision.PROVISION_LOCAL_WORK_BUDGET_SECONDS, 30)
        self.assertEqual(provision.PROVISION_PHASE_BUDGET_SECONDS, 330)
        self.assertEqual(provision.PROVISION_SERVICE_TIMEOUT_SECONDS, 360)
        self.assertEqual(provision.PROVISION_SERVICE_MARGIN_SECONDS, 30)
        self.assertEqual(provision.VERIFIER_SERVICE_TIMEOUT_SECONDS, 420)
        self.assertEqual(verify.VERIFIER_SERVICE_TIMEOUT_SECONDS, 420)
        self.assertEqual(verify.VERIFIER_APPLICATION_BUDGET_SECONDS, 390)
        self.assertEqual(verify.VERIFIER_SERVICE_MARGIN_SECONDS, 30)
        self.assertEqual(verify.VERIFIER_PHASE_BUDGETS, {
            "graphical-session-and-portal": 260,
            "fixed-commands": 45,
            "walker-lifecycle": 70,
            "local-validation-and-report": 15,
        })
        self.assertEqual(verify.FIXED_COMMAND_TIMEOUTS, {
            "get-default": 5,
            "package-query": 2,
            "package-verify": 8,
            "kargs": 10,
        })
        self.assertEqual(
            verify.FIXED_COMMAND_TIMEOUTS["get-default"]
            + 3 * (verify.FIXED_COMMAND_TIMEOUTS["package-query"]
                   + verify.FIXED_COMMAND_TIMEOUTS["package-verify"])
            + verify.FIXED_COMMAND_TIMEOUTS["kargs"],
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
        self.assertEqual(provision.FIRST_BOOT_CONTROLLER_MARGIN_SECONDS, 240)
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
        self.assertIn("Requires=p.service", verifier_unit)
        self.assertIn("After=p.service", verifier_unit)
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
        self.assertEqual(len(calls), 11)
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
        self.assertNotIn('"--memory=3g", "--memory-swap=3g"', hosted)
        for name in ("producer.py", "reboot.py"):
            source = (ROOT / "image/appliance" / name).read_text()
            self.assertIn("limits != APPLIANCE_CONTAINER_LIMITS", source)
            self.assertNotIn("3221225472", source)
        wrapper = (ROOT / "scripts/check-interactive-appliance.sh").read_text()
        self.assertIn("--property=MemoryMax=5G", wrapper)
        self.assertIn("--property=MemorySwapMax=0", wrapper)
        atomic = (ROOT / "image/atomic/hosted.py").read_text()
        self.assertIn("'memory.max':'5368709120'", atomic)

    def test_child_failure_retains_only_redacted_digest_bound_diagnostics(self):
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
                b"password=hunter2\n"
            )
            serial = b"kernel: memory allocation failed without OOM kill\n"
            (evidence / "provision-qemu.log").write_bytes(qemu)
            (evidence / "provision-serial.log").write_bytes(serial)
            (evidence / "unapproved.log").write_text("must not be retained")

            diagnostic, receipt = _failure_diagnostic(output, "producer", source_binding())
            self.assertIsNotNone(diagnostic)
            self.assertEqual(receipt, {
                "limits": result["limits"], "cgroup_final": result["cgroup_final"],
            })
            retained = json.dumps(diagnostic)
            for forbidden in ("/home/runner", "topsecret", "hunter2",
                              "example.invalid", "unapproved"):
                self.assertNotIn(forbidden, retained)
            self.assertTrue(diagnostic["result"]["redacted"])
            self.assertEqual(diagnostic["result"]["sha256"],
                             hashlib.sha256(raw_result).hexdigest())
            self.assertEqual(diagnostic["logs"]["provision-qemu.log"]["sha256"],
                             hashlib.sha256(qemu).hexdigest())
            self.assertTrue(diagnostic["logs"]["provision-qemu.log"]["redacted"])
            self.assertEqual(diagnostic["rejected"], [])

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
            with self.assertRaisesRegex(ValueError, "failure diagnostics"):
                controller_failure_record(
                    source_binding(), "producer", "CalledProcessError", cleanup,
                    {}, {"producer": diagnostic},
                )

    def test_child_failure_redacts_before_tail_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            (output / "result.json").write_text(json.dumps(child_failure()) + "\n")
            secret = b"s" * (FAILURE_EXCERPT_BYTES + 1024)
            raw = (
                b"AWS_SECRET_ACCESS_KEY=\"" + secret + b"\"\n"
                b"password='two word secret'\n"
                b"Authorization: Bearer bearer-value\n"
                b"safe final diagnostic\n"
            )
            (evidence / "provision-qemu.log").write_bytes(raw)

            diagnostic, receipt = _failure_diagnostic(
                output, "producer", source_binding()
            )
            self.assertIsNotNone(receipt)
            item = diagnostic["logs"]["provision-qemu.log"]
            self.assertTrue(item["truncated"])
            self.assertTrue(item["redacted"])
            self.assertIn("safe final diagnostic", item["excerpt"])
            retained = json.dumps(item)
            for forbidden in (
                "AWS_SECRET_ACCESS_KEY", "two word secret", "bearer-value",
                "s" * 256,
            ):
                self.assertNotIn(forbidden, retained)

    def test_child_failure_excerpt_is_utf8_bounded_and_control_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            result = child_failure()
            (output / "result.json").write_text(json.dumps(result) + "\n")
            raw = (
                b"prefix\n" + "😀".encode("utf-8") * 5000
                + b"\x7f\xc2\x80safe-end\n"
            )
            (evidence / "provision-qemu.log").write_bytes(raw)

            diagnostic, receipt = _failure_diagnostic(
                output, "producer", source_binding()
            )
            self.assertIsNotNone(receipt)
            item = diagnostic["logs"]["provision-qemu.log"]
            excerpt = item["excerpt"]
            self.assertLessEqual(len(excerpt.encode("utf-8")), FAILURE_EXCERPT_BYTES)
            self.assertNotIn("\ufffd", excerpt)
            self.assertNotIn("\x7f", excerpt)
            self.assertNotIn("\x80", excerpt)
            self.assertIn("??safe-end", excerpt)

        for character, suffix in (("¢", "x"), ("€", "xy"), ("😀", "x")):
            with self.subTest(character=character):
                width = len(character.encode("utf-8"))
                raw = (
                    character.encode("utf-8")
                    * (FAILURE_EXCERPT_BYTES // width + 16)
                    + suffix.encode("ascii")
                )
                excerpt, redacted = _sanitize_diagnostic(
                    raw, FAILURE_EXCERPT_BYTES
                )
                self.assertTrue(redacted)
                self.assertLessEqual(
                    len(excerpt.encode("utf-8")), FAILURE_EXCERPT_BYTES
                )
                self.assertNotIn("\ufffd", excerpt)
                self.assertTrue(excerpt.endswith(suffix))

        invalid, redacted = _sanitize_diagnostic(
            b"invalid-utf8:\xff\xfe\xf0\x28\x8c\x28", FAILURE_EXCERPT_BYTES
        )
        self.assertTrue(redacted)
        self.assertNotIn("\ufffd", invalid)
        self.assertEqual(invalid, "invalid-utf8:???(?(")

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

    def test_child_failure_rejects_links_specials_and_oversized_logs(self):
        cases = ("symlink", "hardlink", "linked-directory", "fifo", "oversized")
        for case in cases:
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
                else:
                    log.write_bytes(b"x" * (2 * 1024**2 + 1))
                diagnostic, receipt = _failure_diagnostic(
                    output, "producer", source_binding()
                )
                self.assertIsNotNone(receipt)
                self.assertEqual(diagnostic["logs"], {})
                self.assertEqual(diagnostic["rejected"], ["provision-qemu.log"])
                self.assertNotIn("private", json.dumps(diagnostic))

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
        resources["producer"]["limits"]["memory.max"] = "3221225472"
        resources["producer"]["cgroup_final"]["memory.max"] = "3221225472"
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
                    "qemu-system-x86_64: cannot allocate guest RAM\n"
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
            self.assertIn(
                "cannot allocate guest RAM",
                retained["diagnostics"]["producer"]["logs"]["provision-qemu.log"]["excerpt"],
            )
            self.assertFalse((root / ".cache/interactive-appliance-stage").exists())
            from image.appliance.hosted import finalize_failed_appliance_evidence
            self.assertTrue(finalize_failed_appliance_evidence(root))
            self.assertEqual(
                json.loads(
                    (root / ".cache/interactive-appliance-evidence/result.json").read_text()
                ),
                retained,
            )

    def test_malformed_child_diagnostic_cannot_interrupt_cleanup(self):
        def scalar(result):
            result["cgroup_final"]["memory.events"] = 17

        def container(result):
            result["cgroup_final"] = []

        def surrogate(result):
            result["failure"] = "RuntimeError: invalid surrogate \ud800"

        for name, corrupt in (
            ("scalar-resource", scalar),
            ("container-resource", container),
            ("surrogate-message", surrogate),
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
                    {"producer"} if name == "surrogate-message" else set(),
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
        self.assertIn("!.cache/interactive-appliance-evidence/display.ppm", workflow)
        self.assertNotIn(".cache/interactive-appliance-hosted.log", workflow)
        self.assertNotIn(".cache/atomic-disk-evidence/", workflow)
        self.assertNotIn(".cache/atomic-image-evidence/", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:", workflow)
        steps = document["jobs"]["produce"]["steps"]
        self.assertEqual(document["jobs"]["produce"]["timeout-minutes"], 240)
        expected_timeouts = {
            "Check out the explicitly selected producer revision": 5,
            "Require reviewed preflight and runner capacity before download": 2,
            "Download the exact retained generic development OCI": 20,
            "Verify metadata and stream the exact retained OCI": 20,
            "Install and independently reboot the offline graphical appliance": 130,
            "Retain bounded appliance evidence including failures": 10,
            "Retain the compressed HIGHLY EXPERIMENTAL qcow2 for two days": 30,
        }
        self.assertEqual({step["name"]: step["timeout-minutes"] for step in steps},
                         expected_timeouts)
        self.assertEqual(sum(expected_timeouts.values()), 217)
        self.assertEqual(240 - sum(expected_timeouts.values()), 23)
        gate = workflow.index("python3 -m image.appliance.prerequisite")
        download = workflow.index("Download the exact retained generic development OCI")
        self.assertLess(gate, download)
        self.assertIn("timeout 30 gh api", workflow)
        self.assertIn("timeout 900 gh api", workflow)
        evidence_step = workflow.index("Retain bounded appliance evidence including failures")
        qcow2_step = workflow.index("Retain the compressed HIGHLY EXPERIMENTAL qcow2")
        self.assertLess(evidence_step, qcow2_step)
        script = (ROOT / "scripts/check-interactive-appliance.sh").read_text()
        self.assertNotIn("| tee", script)
        self.assertIn("--sanitize-failure", script)
        self.assertIn("> 4096", script)
        self.assertIn("RuntimeMaxSec=115min", script)
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
        for text in (readme, card):
            self.assertIn("HIGHLY EXPERIMENTAL", text)
            self.assertIn("no NIC", text)
        self.assertIn("Hosted runtime evidence is\nstill required", card)

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
