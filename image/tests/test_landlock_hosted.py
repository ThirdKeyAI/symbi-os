"""Inert acceptance tests for the offline hosted Landlock qualification boot."""
import base64
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

from image.atomic.hosted import LANDLOCK_PARENT_LIMITS, run_hosted_command
from image.launcher.probes.bounded_process import run_bounded
from image.qualification import landlock as landlock_driver
from image.qualification.boot import (MAX_QMP_MESSAGE_BYTES,
                                      discard_control_socket, discard_overlay,
                                      firmware_arguments, overlay_command,
                                      path_identity, qemu_command, qmp_request,
                                      stop_child, validate_guest_report,
                                      validate_peer_credentials,
                                      validate_process_state,
                                      validate_socket_info,
                                      write_progress_sample)
from image.qualification.guest import collect_public_artifacts
from image.qualification.hosted import (QUALIFICATION_FILES,
                                        retain_deferred_landlock_output,
                                        validate_source_checkout)
from image.qualification.hosted_process import (TIMEOUT_SECONDS,
                                                validate_landlock_controller_command)
from image.qualification.symbi_mountinfo import (observe_mountinfo,
                                                 observe_visible_mount,
                                                 parse_visible_mount_id,
                                                 read_mountinfo,
                                                 read_visible_mount_id,
                                                 validate_mount_observation)
from image.qualification.source_mount import validate_source_identity


ROOT = Path(__file__).resolve().parents[2]


def settings(name):
    result = {}
    for line in (ROOT / "image/qualification" / name).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result.setdefault(key, []).append(value)
    return result


class HostedLandlock(unittest.TestCase):
    landlock_unit = "symbi-landlock-123456-1"
    landlock_cgroup = "/system.slice/" + landlock_unit + ".service"
    landlock_image = "sha256:" + "9" * 64

    def landlock_controller_command(self):
        storage = ROOT / ".cache/atomic-disk-storage"
        return [
            "podman", "--cgroup-manager=cgroupfs", "--root", str(storage / "root"),
            "--runroot", "/run/" + self.landlock_unit, "run", "--rm",
            "--name=symbi-landlock-qemu", "--pull=never", "--network=none",
            "--pid=private", "--cgroup-parent=" + self.landlock_cgroup,
            "--env=LANG=C.UTF-8", "--env=PYTHONDONTWRITEBYTECODE=1", "--read-only",
            "--user=10001:10001", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--memory=3g", "--memory-swap=3g",
            "--cpus=2", "--pids-limit=64",
            "--mount", f"type=bind,src={storage / 'landlock-input'},dst=/inputs,ro",
            "--mount", f"type=bind,src={storage / 'disk/atomic.raw'},dst=/inputs/atomic.raw,ro",
            "--mount", f"type=bind,src={storage / 'landlock-source.raw'},dst=/inputs/source.raw,ro",
            "--mount", f"type=bind,src={storage / 'landlock-output'},dst=/output",
            "--entrypoint=/usr/bin/python3", self.landlock_image, "/inputs/boot.py",
        ]

    def expected(self):
        return {
            "nonce": "a" * 32,
            "source_revision": "b" * 40,
            "binary_sha256": "c" * 64,
            "image_ref": "ghcr.io/thirdkeyai/symbiont-os@sha256:" + "d" * 64,
            "source_manifest_sha256": "e" * 64,
            "source_disk": {"filesystem": "ext4", "label": "SYMBIQUAL",
                            "uuid": "12345678-1234-1234-1234-123456789abc"},
        }

    def report(self, name="platform.json", content=b'{"passed":true}\n'):
        expected = self.expected()
        compressed = zlib.compress(content, level=9)
        return {
            "schema": 1,
            "passed": True,
            "qualified": True,
            "guest_booted": True,
            "os_qualified": False,
            "release_qualified": False,
            "product": "Symbi-Hosted-Landlock-Probe",
            "nonce": expected["nonce"],
            "expected_sha256": "f" * 64,
            "runner_sha256": "1" * 64,
            "driver_sha256": "2" * 64,
            "validator_sha256": "3" * 64,
            "source_revision": expected["source_revision"],
            "source_manifest_sha256": expected["source_manifest_sha256"],
            "binary_sha256": expected["binary_sha256"],
            "image_ref": expected["image_ref"],
            "landlock_abi": 6,
            "source_device": {"path": "/dev/vdb", "major_minor": "252:16",
                              "TYPE": "ext4",
                              "LABEL": "SYMBIQUAL",
                              "UUID": expected["source_disk"]["uuid"]},
            "source_mount_observation": {
                "path_match_count": 1, "selected_match_count": 1,
                "visible_mount_id": 36, "selected_mount_id": 36,
                "mountpoint": "/run/symbi-qualification/source", "root": "/",
                "fstype": "ext4", "source": "/dev/vdb",
                "major_minor": "252:16",
                "options": ["nodev", "noexec", "nosuid", "ro"],
                "super_options": ["rw"], "mountinfo_sha256": "a" * 64,
            },
            "summary": {"passed": True, "qualified": True,
                        "public_reports": {name: hashlib.sha256(content).hexdigest()}},
            "artifacts": {name: {"bytes": len(content),
                                  "sha256": hashlib.sha256(content).hexdigest(),
                                  "zlib_bytes": len(compressed),
                                  "zlib_base64": base64.b64encode(compressed).decode()}},
        }

    def test_firmware_transport_contains_only_fixed_units_and_inputs(self):
        args = firmware_arguments(Path("/inputs"))
        names = [args[index].split(",file=", 1)[0].removeprefix("name=")
                 for index in range(1, len(args), 2)]
        self.assertEqual(set(names), {
            "opt/io.systemd.credentials/fstab.extra",
            "opt/io.systemd.credentials/systemd.extra-unit.m.service",
            "opt/io.systemd.credentials/systemd.extra-unit.p.service",
            "opt/io.systemd.credentials/systemd.extra-unit.q.service",
            "opt/io.systemd.credentials/systemd.extra-unit.l.service",
            "opt/io.systemd.credentials/symbi-status-server.py",
            "opt/io.systemd.credentials/symbi-landlock.py",
            "opt/io.systemd.credentials/vertical_slice.py",
            "opt/io.systemd.credentials/symbi-runner.py",
            "opt/io.systemd.credentials/symbi-prepare.py",
            "opt/io.systemd.credentials/symbi-source-mount.py",
            "opt/io.systemd.credentials/symbi_mountinfo.py",
            "opt/io.systemd.credentials/symbi-expected.json",
            "opt/io.systemd.credentials/symbi-sysusers.conf",
        })
        self.assertTrue(all(len(name.encode("ascii")) < 56 for name in names))
        self.assertFalse(any(word in name for name in names for word in ("password", "ssh", "token", "key")))
        staged = {Path(args[index].split(",file=", 1)[1]).name
                  for index in range(1, len(args), 2)}
        self.assertEqual(staged - {"expected.json"},
                         set(QUALIFICATION_FILES) - {"boot.py"})

    def test_guest_units_have_fixed_user_mount_and_authority(self):
        fstab = (ROOT / "image/qualification/fstab.extra").read_text().split()
        self.assertEqual(fstab, ["/dev/disk/by-id/virtio-SYMBIQUAL",
                                 "/run/symbi-qualification/source", "ext4",
                                 "ro,nosuid,nodev,noexec,x-systemd.device-timeout=30s",
                                 "0", "0"])
        prepare = settings("p.service")
        self.assertEqual(prepare["Requires"], ["m.service"])
        self.assertEqual(prepare["After"], ["m.service"])
        self.assertEqual(set(prepare["ImportCredential"]),
                         {"symbi-sysusers.conf", "symbi-prepare.py"})
        self.assertTrue(all("/bin/sh" not in command and "/bin/bash" not in command
                            for command in prepare["ExecStart"]))
        self.assertEqual(prepare["ExecStart"],
                         ["/usr/bin/python3 %d/symbi-prepare.py %d/symbi-sysusers.conf"])
        mount = settings("m.service")
        self.assertEqual(mount["CapabilityBoundingSet"], [""])
        self.assertEqual(mount["RequiresMountsFor"],
                         ["/run/symbi-qualification/source"])
        self.assertEqual(mount["NoNewPrivileges"], ["yes"])
        self.assertEqual(mount["MemorySwapMax"], ["0"])
        self.assertEqual(set(mount["ImportCredential"]),
                         {"symbi-source-mount.py", "symbi_mountinfo.py",
                          "symbi-expected.json"})
        self.assertNotIn('"/usr/bin/mount"',
                         (ROOT / "image/qualification/source_mount.py").read_text())
        setup = (ROOT / "image/qualification/prepare.py").read_text()
        for control in ("pwd.getpwuid", "grp.getgrgid", "os.O_EXCL", "os.O_NOFOLLOW",
                        'user.pw_uid == UID', 'group.gr_gid == UID',
                        'not RUNTIME.exists()', 'stat.S_IMODE(runtime.st_mode) == 0o700'):
            self.assertIn(control, setup)
        guest = (ROOT / "image/qualification/guest.py").read_text()
        self.assertNotIn("stderr.decode", guest)
        self.assertIn('record["driver_stderr_sha256"]', guest)
        runner = settings("l.service")
        self.assertEqual(runner["User"], ["symbi-qual"])
        self.assertEqual(runner["CapabilityBoundingSet"], [""])
        self.assertEqual(runner["AmbientCapabilities"], [""])
        self.assertEqual(runner["NoNewPrivileges"], ["yes"])
        self.assertEqual(runner["MemorySwapMax"], ["0"])
        self.assertEqual(runner["SuccessAction"], ["poweroff"])
        self.assertEqual(runner["FailureAction"], ["poweroff"])
        self.assertNotIn("ExecStopPost", runner)
        self.assertEqual(set(runner["ImportCredential"]),
                         {"symbi-landlock.py", "vertical_slice.py", "symbi-runner.py",
                          "symbi_mountinfo.py", "symbi-expected.json"})
        self.assertEqual(runner["ExecStart"], [
            "/usr/bin/python3 %d/symbi-runner.py %d/symbi-landlock.py "
            "%d/vertical_slice.py %d/symbi-expected.json",
        ])

    def test_staged_driver_imports_validator_without_repository_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / "credentials"
            unrelated = root / "unrelated"
            credentials.mkdir()
            unrelated.mkdir()
            shutil.copyfile(ROOT / "image/qualification/landlock.py",
                            credentials / "symbi-landlock.py")
            shutil.copyfile(ROOT / "image/qualification/vertical_slice.py",
                            credentials / "vertical_slice.py")
            result = subprocess.run(
                [sys.executable, "-E", "-s", "-B", str(credentials / "symbi-landlock.py"),
                 "--help"],
                cwd=unrelated,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--expected-revision", result.stdout)

    def test_staged_driver_refuses_absent_or_non_sibling_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credentials = root / "credentials"
            unrelated = root / "unrelated"
            other = root / "other"
            credentials.mkdir()
            unrelated.mkdir()
            other.mkdir()
            driver = credentials / "symbi-landlock.py"
            shutil.copyfile(ROOT / "image/qualification/landlock.py", driver)

            absent = subprocess.run(
                [sys.executable, "-E", "-s", "-B", str(driver), "--help"],
                cwd=unrelated,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(absent.returncode, 0)
            self.assertIn("vertical_slice", absent.stderr)

            validator = other / "vertical_slice.py"
            validator.write_text("def validate_vertical_slice(*args):\n    return {}\n")
            non_sibling = subprocess.run(
                [sys.executable, "-E", "-s", "-B",
                 str(ROOT / "image/qualification/guest.py"), str(driver),
                 str(validator), str(credentials / "symbi-expected.json")],
                cwd=unrelated,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(non_sibling.returncode, 0)
            self.assertIn("fixed sibling qualification driver and validator", non_sibling.stderr)

    def test_guest_runner_passes_authenticated_revision_without_repository_state(self):
        driver = (ROOT / "image/qualification/landlock.py").read_text()
        runner = (ROOT / "image/qualification/guest.py").read_text()
        self.assertNotIn("upstream/symbiont.toml", driver)
        self.assertNotIn("import tomllib", driver)
        self.assertIn('"--expected-revision", expected["source_revision"]', runner)

    def test_driver_rejects_malformed_authenticated_revision_before_filesystem_use(self):
        arguments = [
            "symbi-landlock.py", "--source", "/unreachable/source",
            "--binary", "/unreachable/symbi", "--expected-revision", "B" * 40,
            "--expected-binary-sha256", "c" * 64,
            "--image-ref", "ghcr.io/thirdkeyai/symbiont-os@sha256:" + "d" * 64,
            "--expected-abi", "6", "--bootc-status-socket",
            "/run/symbi-qualification/status.sock", "--output", "/unreachable/output",
        ]
        output = io.StringIO()
        with mock.patch.object(landlock_driver, "host_details", return_value={"fixture": True}), \
                mock.patch.object(sys, "argv", arguments), redirect_stdout(output):
            self.assertEqual(landlock_driver.main(), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["error"], "invalid runtime source revision")
        self.assertNotIn("runtime_revision", report)

    def test_vertical_slice_report_crosses_the_guest_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            raw = b'{"passed":true}\n'
            (output / "vertical-slice.json").write_bytes(raw)
            (output / "vertical-slice.json").chmod(0o600)
            reports = collect_public_artifacts(output, {"public_reports": {
                "vertical-slice.json": hashlib.sha256(raw).hexdigest(),
            }})
            self.assertEqual(reports["vertical-slice.json"]["bytes"], len(raw))
            self.assertEqual(reports["vertical-slice.json"]["sha256"], hashlib.sha256(raw).hexdigest())

    def test_qemu_has_no_network_login_or_host_share(self):
        command = qemu_command(Path("/inputs"), Path("/output"))
        joined = " ".join(command)
        self.assertIn("-net none", joined)
        self.assertIn("-m 2048M", joined)
        self.assertIn("-smp 1", joined)
        self.assertIn("product=Symbi-Hosted-Landlock-Probe", joined)
        self.assertIn("file=/output/guest.qcow2,format=qcow2,if=virtio", joined)
        self.assertNotIn("snapshot=on", joined)
        self.assertNotIn("file=/inputs/atomic.raw", joined)
        self.assertIn("file=/inputs/source.raw,format=raw,if=none,id=symbi-qualification-source,readonly=on", joined)
        self.assertIn("virtio-blk-pci,drive=symbi-qualification-source,serial=SYMBIQUAL", joined)
        self.assertIn("-qmp unix:/output/qmp.sock,server=on,wait=off", joined)
        self.assertEqual(overlay_command(), [
            "/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
            "-b", "/inputs/atomic.raw", "/output/guest.qcow2",
        ])
        for forbidden in ("-virtfs", "-fsdev", "hostfwd", "-nic", "-kernel", "-initrd"):
            self.assertNotIn(forbidden, command)

    def test_source_identity_and_controller_cleanup_fail_closed(self):
        expected = self.expected()["source_disk"]
        raw = ("DEVNAME=/dev/vdb\nTYPE=ext4\nLABEL=SYMBIQUAL\nUUID="
               + expected["uuid"] + "\n")
        self.assertEqual(validate_source_identity(raw, expected), {
            "TYPE": "ext4", "LABEL": "SYMBIQUAL", "UUID": expected["uuid"],
        })
        for changed in (raw.replace("TYPE=ext4", "TYPE=xfs"),
                        raw.replace("LABEL=SYMBIQUAL", "LABEL=OTHER"),
                        raw.replace(expected["uuid"], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                validate_source_identity(changed, expected)

        identity = {"pid": 4242, "starttime": 777,
                    "executable_device": 8, "executable_inode": 9,
                    "uid": 10001, "gid": 10001, "pidfd": None}
        child = mock.Mock(pid=4242)
        child.poll.return_value = None
        child.terminate.side_effect = PermissionError("synthetic refusal")
        child.kill.side_effect = PermissionError("synthetic refusal")
        failure = "TimeoutError: Landlock guest did not report"
        qmp = mock.Mock(side_effect=FileNotFoundError("synthetic absent socket"))
        prove_exit = mock.Mock(return_value=False)
        record = {"failure": failure,
                  "child_cleanup": stop_child(
                      child, identity, {"path": Path("/output/qmp.sock")},
                      request=qmp, prove_exit=prove_exit,
                      verify=mock.Mock(return_value=None))}
        self.assertEqual(record["failure"], failure)
        self.assertTrue(record["child_cleanup"]["attempted"])
        self.assertFalse(record["child_cleanup"]["qmp_quit"])
        self.assertFalse(record["child_cleanup"]["exit_proven"])
        self.assertEqual(len(record["child_cleanup"]["errors"]), 3)
        qmp.assert_called_once_with({"path": Path("/output/qmp.sock")}, "quit")

        controlled = mock.Mock(pid=4242)
        controlled.poll.return_value = None
        qmp = mock.Mock(return_value={})
        cleanup = stop_child(
            controlled, identity, {"path": Path("/output/qmp.sock")},
            request=qmp, prove_exit=mock.Mock(side_effect=(False, True)),
            verify=mock.Mock(return_value=None))
        self.assertTrue(cleanup["qmp_quit"])
        self.assertTrue(cleanup["exit_proven"])
        self.assertFalse(cleanup["terminated"])
        self.assertFalse(cleanup["killed"])
        controlled.terminate.assert_not_called()
        controlled.kill.assert_not_called()

        reused = mock.Mock(pid=4242)
        reused.poll.return_value = None
        cleanup = stop_child(
            reused, identity, {"path": Path("/output/qmp.sock")},
            request=mock.Mock(), prove_exit=mock.Mock(return_value=False),
            verify=mock.Mock(side_effect=ValueError("PID identity changed")))
        self.assertFalse(cleanup["exit_proven"])
        reused.terminate.assert_not_called()
        reused.kill.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            qmp_path = Path(directory) / "qmp.sock"
            channel = socket.socket(socket.AF_UNIX)
            channel.bind(str(qmp_path))
            os.chmod(qmp_path, 0o700)
            qmp_identity = path_identity(qmp_path.lstat())
            overlay = Path(directory) / "guest.qcow2"
            overlay.write_bytes(b"synthetic overlay")
            overlay_identity = path_identity(overlay.stat())
            self.assertFalse(discard_control_socket(
                qmp_path, qmp_identity, exit_proven=False)["removed"])
            self.assertFalse(discard_overlay(
                overlay, overlay_identity, exit_proven=False)["removed"])
            self.assertTrue(qmp_path.exists())
            self.assertTrue(overlay.exists())
            channel.close()
            cleanup = discard_control_socket(
                qmp_path, qmp_identity, exit_proven=True)
            self.assertEqual(cleanup, {"attempted": True, "removed": True,
                                       "errors": []})
            cleanup = discard_overlay(
                overlay, overlay_identity, exit_proven=True)
            self.assertEqual(cleanup, {"attempted": True, "removed": True,
                                       "errors": []})
            self.assertFalse(overlay.exists())

    def test_qmp_protocol_is_exact_and_bounded(self):
        class Stream:
            def __init__(self, lines):
                self.lines = iter(lines)
                self.writes = []

            def readline(self, _maximum):
                value = next(self.lines, b"")
                if isinstance(value, Exception):
                    raise value
                return value

            def write(self, raw):
                self.writes.append(raw)

            def flush(self):
                pass

        greeting = (b'{"QMP":{"version":{"qemu":{"major":9,"minor":2,'
                    b'"micro":0},"package":""},"capabilities":["oob"]}}\n')
        capabilities = b'{"return":{},"id":"symbi-qmp-capabilities"}\n'
        status = (b'{"return":{"running":true,"singlestep":false,'
                  b'"status":"running"},"id":"symbi-query-status"}\n')
        stream = Stream([greeting, capabilities, status])
        self.assertEqual(qmp_request(stream, "query-status"),
                         {"running": True, "singlestep": False,
                          "status": "running"})
        self.assertEqual(len(stream.writes), 2)
        quit_stream = Stream([
            greeting, capabilities, b'{"return":{},"id":"symbi-quit"}\n'])
        self.assertEqual(qmp_request(quit_stream, "quit"), {})
        for forbidden in ("qmp_capabilities", "stop", "cont", "system_reset"):
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                qmp_request(Stream([]), forbidden)

        invalid = {
            "extra greeting field": (
                greeting.replace(b'"QMP":', b'"extra":1,"QMP":'),
                capabilities, status),
            "extra capabilities field": (
                greeting, b'{"return":{},"id":"symbi-qmp-capabilities","extra":1}\n',
                status),
            "wrong response id": (
                greeting, capabilities,
                status.replace(b"symbi-query-status", b"other")),
            "extra status field": (
                greeting, capabilities,
                status.replace(b'"status":"running"',
                               b'"status":"running","extra":1')),
            "inconsistent state": (
                greeting, capabilities,
                status.replace(b'"running":true', b'"running":false')),
            "malformed json": (b'{not-json}\n',),
            "truncated json": (greeting.removesuffix(b"\n"),),
            "oversized json": (b"{" + b"x" * MAX_QMP_MESSAGE_BYTES + b"}\n",),
            "timeout": (TimeoutError("synthetic timeout"),),
        }
        for name, lines in invalid.items():
            with self.subTest(name=name), self.assertRaises((ValueError, TimeoutError)):
                qmp_request(Stream(lines), "query-status")

    def test_qmp_peer_socket_and_process_identity_are_exact(self):
        identity = {"pid": 4242, "starttime": 777,
                    "executable_device": 8, "executable_inode": 9,
                    "uid": 10001, "gid": 10001, "pidfd": None}
        raw = struct.pack("=iII", 4242, 10001, 10001)
        self.assertEqual(validate_peer_credentials(raw, identity),
                         {"pid": 4242, "uid": 10001, "gid": 10001})
        for values in ((4243, 10001, 10001), (4242, 10002, 10001),
                       (4242, 10001, 10002)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_peer_credentials(struct.pack("=iII", *values), identity)
        validate_process_state(identity, {
            "pid": 4242, "starttime": 777,
            "executable_device": 8, "executable_inode": 9,
            "uid": 10001, "gid": 10001,
        })
        changed = {key: identity[key] for key in
                   ("pid", "starttime", "executable_device", "executable_inode",
                    "uid", "gid")}
        changed["starttime"] = 778
        with self.assertRaises(ValueError):
            validate_process_state(identity, changed)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qmp.sock"
            with socket.socket(socket.AF_UNIX) as channel:
                channel.bind(str(path))
                os.chmod(path, 0o700)
                info = path.lstat()
                expected = path_identity(info)
                self.assertEqual(validate_socket_info(
                    info, os.geteuid(), os.getegid(), expected), expected)
                os.chmod(path, 0o770)
                with self.assertRaises(ValueError):
                    validate_socket_info(path.lstat(), os.geteuid(),
                                         os.getegid(), expected)
                os.chmod(path, 0o700)
                swapped = tuple(value + 1 if index == 1 else value
                                for index, value in enumerate(expected))
                with self.assertRaises(ValueError):
                    validate_socket_info(path.lstat(), os.geteuid(),
                                         os.getegid(), swapped)

    def test_failed_cleanup_residue_does_not_hide_regular_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            evidence = Path(directory) / "evidence"
            destination = evidence / "guest"
            source.mkdir(mode=0o700)
            evidence.mkdir(mode=0o700)
            (evidence / "result.json").write_text(json.dumps({
                "passed": False,
                "retention_deferred_until_outer_container_absence": True,
            }))
            (source / "result.json").write_text('{"passed":false}\n')
            (source / "progress.jsonl").write_text('{"sample":0}\n')
            expected_bytes = sum((source / name).stat().st_size
                                 for name in ("result.json", "progress.jsonl"))
            (source / "guest.qcow2").write_bytes(b"private overlay")
            with socket.socket(socket.AF_UNIX) as channel:
                channel.bind(str(source / "qmp.sock"))
                retained = retain_deferred_landlock_output(source, evidence)
            self.assertTrue(retained["attempted"])
            self.assertEqual(retained["bytes"], expected_bytes)
            self.assertEqual(set(retained["cleanup_residue"]),
                             {"guest.qcow2", "qmp.sock"})
            self.assertTrue((destination / "result.json").is_file())
            self.assertTrue((destination / "progress.jsonl").is_file())
            self.assertFalse((destination / "guest.qcow2").exists())
            self.assertFalse((destination / "qmp.sock").exists())
            outer = json.loads((evidence / "result.json").read_text())
            self.assertTrue(outer["outer_container_absence_proven"])
            self.assertFalse(
                outer["retention_deferred_until_outer_container_absence"])

    def test_progress_evidence_is_bounded(self):

        progress = io.BytesIO()
        sample = {"schema": 1, "sample": 0, "elapsed_seconds": 0,
                  "qemu": {"status": "starting"}, "outputs": {}}
        write_progress_sample(progress, sample)
        self.assertLess(len(progress.getvalue()), 8192)
        with self.assertRaises(ValueError):
            write_progress_sample(progress, {"oversized": "x" * 8192})

    def test_landlock_parent_keeps_four_gib_pressure_threshold_with_headroom(self):
        self.assertEqual(LANDLOCK_PARENT_LIMITS, {
            "memory.high": "4294967296", "memory.max": "5368709120",
            "memory.swap.max": "0", "cpu.max": "200000 100000",
            "pids.max": "256",
        })
        wrapper = (ROOT / "scripts/check-landlock-qualification.sh").read_text()
        self.assertIn("MemoryHigh=4G", wrapper)
        self.assertIn("MemoryMax=5G", wrapper)

    def test_kernel_mountinfo_binds_the_exact_source_mount(self):
        raw = ("36 25 252:16 / /run/symbi-qualification/source "
               "ro,nosuid,nodev,noexec,relatime shared:7 - ext4 /dev/vdb rw\n")
        observed = observe_mountinfo(raw, "/run/symbi-qualification/source", 36)
        self.assertEqual(observed["path_match_count"], 1)
        self.assertEqual(observed["selected_match_count"], 1)
        self.assertEqual(observed["visible_mount_id"], 36)
        self.assertEqual(observed["selected_mount_id"], 36)
        self.assertEqual(observed["mountpoint"], "/run/symbi-qualification/source")
        self.assertEqual(observed["root"], "/")
        self.assertEqual(observed["fstype"], "ext4")
        self.assertEqual(observed["source"], "/dev/vdb")
        self.assertEqual(observed["major_minor"], "252:16")
        self.assertEqual(observed["options"],
                         ["nodev", "noexec", "nosuid", "relatime", "ro"])
        self.assertRegex(observed["mountinfo_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            validate_mount_observation(
                observed, mountpoint="/run/symbi-qualification/source",
                source="/dev/vdb", major_minor="252:16"),
            observed,
        )
        escaped = raw.replace("/run/symbi-qualification/source",
                              r"/run/symbi\040qualification/source")
        self.assertEqual(
            observe_mountinfo(escaped, "/run/symbi qualification/source", 36)["mountpoint"],
            "/run/symbi qualification/source",
        )

    def test_kernel_mountinfo_refuses_ambiguous_or_weakened_mounts(self):
        base = ("36 25 252:16 / /run/symbi-qualification/source "
                "ro,nosuid,nodev,noexec,relatime shared:7 - ext4 /dev/vdb rw\n")
        target = "/run/symbi-qualification/source"
        observations = [
            (base.replace("252:16", "252:17"), "/dev/vdb", "252:16"),
            (base.replace("252:16 / /run", "252:16 /sub /run"), "/dev/vdb", "252:16"),
            (base.replace(" - ext4 ", " - xfs "), "/dev/vdb", "252:16"),
            (base.replace(" /dev/vdb ", " /dev/vdc "), "/dev/vdb", "252:16"),
            (base.replace("ro,nosuid,nodev,noexec,relatime", "rw,nosuid,nodev,noexec"),
             "/dev/vdb", "252:16"),
        ]
        for raw, source, major_minor in observations:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                validate_mount_observation(
                    observe_mountinfo(raw, target, 36), mountpoint=target,
                    source=source, major_minor=major_minor)
        for option in ("ro", "nosuid", "nodev", "noexec"):
            raw = base.replace(option + ",", "")
            with self.subTest(option=option), self.assertRaises(ValueError):
                validate_mount_observation(
                    observe_mountinfo(raw, target, 36), mountpoint=target,
                    source="/dev/vdb", major_minor="252:16")
        for raw in (
            base.replace("/run/symbi-qualification/source", r"/run/symbi\\04xsource"),
            base.replace("/run/symbi-qualification/source", r"/run/symbi\\000source"),
            base.replace("source", "source\x00", 1),
            base.rstrip("\n"),
            base.replace("\n", "\r\n"),
            base.replace("36 25", "36  25"),
            base.replace("/dev/vdb rw\n", "/dev/vdb rw extra\n"),
            "1 1 0:1 / /other ro - tmpfs tmpfs rw\n" * 4097,
            "x" * (1024 * 1024 + 1),
        ):
            with self.subTest(raw=raw[:100]), self.assertRaises(ValueError):
                observe_mountinfo(raw, target, 36)
        with self.assertRaises(ValueError):
            observe_mountinfo(base, "/run/symbi-qualification/sourc\N{LATIN SMALL LETTER E WITH ACUTE}", 36)

    def test_kernel_mountinfo_selects_visible_stacked_row_without_guessing(self):
        target = "/run/symbi-qualification/source"
        visible = ("36 25 252:16 / " + target
                   + " ro,nosuid,nodev,noexec - ext4 /dev/vdb rw\n")
        hidden_with_larger_id = ("99 25 0:31 / " + target
                                 + " rw,nosuid,nodev - tmpfs tmpfs rw\n")
        observed = observe_mountinfo(hidden_with_larger_id + visible, target, 36)
        self.assertEqual(observed["path_match_count"], 2)
        self.assertEqual(observed["selected_mount_id"], 36)
        self.assertEqual(observed["source"], "/dev/vdb")
        self.assertEqual(validate_mount_observation(
            observed, mountpoint=target, source="/dev/vdb", major_minor="252:16"),
            observed)
        for raw, visible_id in (
            (visible + visible, 36),
            (visible, 37),
            (visible.replace(target, "/other"), 36),
        ):
            with self.subTest(visible_id=visible_id), self.assertRaises(ValueError):
                validate_mount_observation(
                    observe_mountinfo(raw, target, visible_id), mountpoint=target,
                    source="/dev/vdb", major_minor="252:16")

    def test_fdinfo_mount_id_parser_is_bounded_and_unambiguous(self):
        self.assertEqual(parse_visible_mount_id(b"pos:\t0\nflags:\t010000000\nmnt_id:\t36\n"), 36)
        for raw in (
            b"pos:\t0\n",
            b"mnt_id:\t36\nmnt_id:\t36\n",
            b"mnt_id:\t0\n",
            b"mnt_id:\t036\n",
            b"mnt_id:\t-1\n",
            b"mnt_id:\tbad\n",
            b"mnt_id:\t36\x00\n",
            b"mnt_id:\t36",
            b"x: y\n" * 65,
            b"x" * 4097,
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                parse_visible_mount_id(raw)

    def test_visible_mount_open_binds_fdinfo_mountinfo_and_named_path(self):
        target = Path("/run/symbi-qualification/source")
        raw = (b"36 25 252:16 / /run/symbi-qualification/source "
               b"ro,nosuid,nodev,noexec - ext4 /dev/vdb rw\n")
        directory = mock.Mock(st_mode=0o040755, st_dev=252, st_ino=7)
        observed = observe_visible_mount(
            target,
            opener=mock.Mock(return_value=9),
            descriptor_stat=mock.Mock(return_value=directory),
            path_lstat=mock.Mock(side_effect=[directory, directory]),
            closer=mock.Mock(),
            fdinfo_reader=mock.Mock(return_value=36),
            mountinfo_reader=mock.Mock(return_value=raw),
        )
        self.assertEqual(observed["selected_mount_id"], 36)
        opener = mock.Mock(return_value=9)
        observe_visible_mount(
            target, opener=opener,
            descriptor_stat=mock.Mock(return_value=directory),
            path_lstat=mock.Mock(side_effect=[directory, directory]),
            closer=mock.Mock(), fdinfo_reader=mock.Mock(return_value=36),
            mountinfo_reader=mock.Mock(return_value=raw))
        flags = opener.call_args.args[1]
        self.assertEqual(flags & os.O_DIRECTORY, os.O_DIRECTORY)
        self.assertEqual(flags & os.O_CLOEXEC, os.O_CLOEXEC)
        self.assertEqual(flags & os.O_PATH, os.O_PATH)
        self.assertEqual(flags & os.O_NOFOLLOW, os.O_NOFOLLOW)
        changed = mock.Mock(st_mode=0o040755, st_dev=252, st_ino=8)
        for before, after in ((changed, directory), (directory, changed)):
            with self.subTest(before=before.st_ino, after=after.st_ino), \
                    self.assertRaises(ValueError):
                observe_visible_mount(
                    target, opener=mock.Mock(return_value=9),
                    descriptor_stat=mock.Mock(return_value=directory),
                    path_lstat=mock.Mock(side_effect=[before, after]),
                    closer=mock.Mock(), fdinfo_reader=mock.Mock(return_value=36),
                    mountinfo_reader=mock.Mock(return_value=raw))
        symlink = mock.Mock(st_mode=0o120777, st_dev=252, st_ino=7)
        with self.assertRaises(ValueError):
            observe_visible_mount(
                target, opener=mock.Mock(return_value=9),
                descriptor_stat=mock.Mock(return_value=directory),
                path_lstat=mock.Mock(side_effect=[symlink, symlink]),
                closer=mock.Mock(), fdinfo_reader=mock.Mock(return_value=36),
                mountinfo_reader=mock.Mock(return_value=raw))

    def test_real_host_fdinfo_mount_id_selects_visible_root(self):
        descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
                             | os.O_NOFOLLOW)
        try:
            visible_mount_id = read_visible_mount_id(descriptor)
        finally:
            os.close(descriptor)
        observed = observe_mountinfo(
            read_mountinfo(), "/", visible_mount_id)
        self.assertGreaterEqual(observed["path_match_count"], 1)
        self.assertEqual(observed["selected_match_count"], 1)
        self.assertEqual(observed["selected_mount_id"], visible_mount_id)
        with self.assertRaises(ValueError):
            read_mountinfo(Path("/tmp/not-mountinfo"))

    def test_mountinfo_reader_uses_fixed_bounded_no_follow_descriptor(self):
        raw = b"1 1 0:1 / / ro - tmpfs tmpfs rw\n"
        with mock.patch("image.qualification.symbi_mountinfo.os.open",
                        return_value=8) as opener, \
                mock.patch("image.qualification.symbi_mountinfo.os.read",
                           side_effect=[raw, b""]), \
                mock.patch("image.qualification.symbi_mountinfo.os.close") as closer:
            self.assertEqual(read_mountinfo(), raw)
        self.assertEqual(opener.call_args.args[0], Path("/proc/self/mountinfo"))
        flags = opener.call_args.args[1]
        self.assertEqual(flags, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        closer.assert_called_once_with(8)

    def test_host_rejects_malformed_visible_mount_evidence(self):
        changes = {
            "path_match_count": True,
            "selected_match_count": True,
            "visible_mount_id": "36",
            "selected_mount_id": True,
            "options": ["ro", "nosuid", "nodev", "noexec", {}],
            "super_options": [],
            "mountinfo_sha256": 1,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                report = self.report()
                report["source_mount_observation"][field] = value
                with self.assertRaises(ValueError):
                    validate_guest_report(report, self.expected(), "f" * 64,
                                          "1" * 64, "2" * 64, "3" * 64)
        for options in (["ro", "nosuid", "nodev", "noexec"],
                        ["nodev", "noexec", "nosuid", "ro", "ro"]):
            with self.subTest(options=options):
                report = self.report()
                report["source_mount_observation"]["options"] = options
                with self.assertRaises(ValueError):
                    validate_guest_report(report, self.expected(), "f" * 64,
                                          "1" * 64, "2" * 64, "3" * 64)
        report = self.report()
        oversized = "12345678:16"
        report["source_device"]["major_minor"] = oversized
        report["source_mount_observation"]["major_minor"] = oversized
        with self.assertRaises(ValueError):
            validate_guest_report(report, self.expected(), "f" * 64,
                                  "1" * 64, "2" * 64, "3" * 64)

    def test_guest_source_device_binding_is_required(self):
        report = self.report()
        report["source_device"]["UUID"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(ValueError, "source-device"):
            validate_guest_report(report, self.expected(), "f" * 64, "1" * 64,
                                  "2" * 64, "3" * 64)

    def test_landlock_controller_uses_only_its_fixed_extended_runner(self):
        command = self.landlock_controller_command()
        self.assertEqual(validate_landlock_controller_command(
            command, self.landlock_cgroup, self.landlock_image), command)
        completed = subprocess.CompletedProcess(command, 0, "", "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                run_bounded(command, root / "shared-out", root / "shared-err",
                            TIMEOUT_SECONDS, 1024**2)
            with mock.patch("image.atomic.hosted.run_landlock_controller",
                            return_value=completed) as dedicated, \
                    mock.patch("image.atomic.hosted.run_bounded") as shared:
                observed = run_hosted_command(
                    "landlock", "landlock-qualification", command,
                    root / "out", root / "err", TIMEOUT_SECONDS,
                    self.landlock_cgroup, self.landlock_image)
            self.assertIs(observed, completed)
            dedicated.assert_called_once_with(
                command, root / "out", root / "err",
                self.landlock_cgroup, self.landlock_image)
            shared.assert_not_called()
            with self.assertRaises(ValueError):
                run_hosted_command("landlock", "landlock-qualification", command,
                                   root / "out", root / "err", TIMEOUT_SECONDS - 1,
                                   self.landlock_cgroup, self.landlock_image)
            with self.assertRaises(ValueError):
                run_hosted_command("", "landlock-qualification", command,
                                   root / "out", root / "err", TIMEOUT_SECONDS,
                                   self.landlock_cgroup, self.landlock_image)

    def test_landlock_extended_runner_rejects_command_shape_mutations(self):
        command = self.landlock_controller_command()
        mutations = []
        changed = copy.deepcopy(command)
        changed.insert(1, "--remote")
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed[3] = "/tmp/other/atomic-disk-storage/root"
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed[changed.index("--memory=3g")] = "--memory=4g"
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed.insert(changed.index("--entrypoint=/usr/bin/python3"), "--privileged")
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed[changed.index("--mount") + 1] = \
            "type=bind,src=/tmp/other,dst=/inputs,ro"
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed[-2] = "latest"
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed[changed.index("--cgroup-parent=" + self.landlock_cgroup)] = \
            "--cgroup-parent=/escape.slice/" + self.landlock_unit + ".service"
        mutations.append(changed)
        changed = copy.deepcopy(command)
        changed[-2] = "sha256:" + "8" * 64
        mutations.append(changed)
        completed = subprocess.CompletedProcess(command, 0, "", "")
        def validate_only(candidate, _stdout, _stderr, expected_cgroup, expected_image):
            validate_landlock_controller_command(candidate, expected_cgroup, expected_image)
            return completed
        for changed in mutations:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                validate_landlock_controller_command(
                    changed, self.landlock_cgroup, self.landlock_image)
            with mock.patch("image.atomic.hosted.run_landlock_controller",
                            side_effect=validate_only):
                with self.subTest(dispatch=changed), self.assertRaises(ValueError):
                    run_hosted_command(
                        "landlock", "landlock-qualification", changed,
                        Path("/tmp/out"), Path("/tmp/err"), TIMEOUT_SECONDS,
                        self.landlock_cgroup, self.landlock_image)

    def test_landlock_deadlines_remain_nested_and_bounded(self):
        self.assertEqual(TIMEOUT_SECONDS, 6000)
        boot = (ROOT / "image/qualification/boot.py").read_text()
        service = (ROOT / "image/qualification/l.service").read_text()
        wrapper = (ROOT / "scripts/check-landlock-qualification.sh").read_text()
        workflow = (ROOT / ".github/workflows/landlock-qualification.yml").read_text()
        self.assertIn("time.monotonic() - started >= 5700", boot)
        self.assertIn("RuntimeMaxSec=95min", service)
        self.assertIn("RuntimeMaxSec=145min", wrapper)
        self.assertIn("timeout-minutes: 165", workflow)

    def test_bounded_public_report_is_authenticated_and_expanded(self):
        report = self.report()
        files = validate_guest_report(report, self.expected(), "f" * 64, "1" * 64,
                                      "2" * 64, "3" * 64)
        self.assertEqual(files, {"platform.json": b'{"passed":true}\n'})

    def test_validator_hash_substitution_is_rejected(self):
        report = self.report()
        report["validator_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unbound, incomplete or falsely qualified"):
            validate_guest_report(report, self.expected(), "f" * 64, "1" * 64,
                                  "2" * 64, "3" * 64)

    def test_private_changed_or_excessive_report_is_rejected(self):
        cases = []
        private = self.report("release/private-actions/key.pem", b"private")
        cases.append(private)
        changed = self.report()
        changed["artifacts"]["platform.json"]["sha256"] = "0" * 64
        cases.append(changed)
        unlisted = self.report()
        unlisted["summary"]["public_reports"] = {}
        cases.append(unlisted)
        oversized = self.report(content=b"x" * (2 * 1024 * 1024 + 1))
        cases.append(oversized)
        for report in cases:
            with self.subTest(keys=list(report["artifacts"])), self.assertRaises(ValueError):
                validate_guest_report(report, self.expected(), "f" * 64, "1" * 64,
                                      "2" * 64, "3" * 64)

    def test_public_artifact_parent_symlink_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            outside = root / "outside"
            output.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            content = b"private fixture\n"
            (outside / "qualification.json").write_bytes(content)
            (output / "release").symlink_to(outside, target_is_directory=True)
            summary = {"public_reports": {
                "release/qualification.json": hashlib.sha256(content).hexdigest()}}
            with self.assertRaises((OSError, ValueError)):
                collect_public_artifacts(output, summary)

    def test_source_checkout_must_be_exact_clean_and_free_of_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=source, check=True)
            (source / "Cargo.lock").write_text("fixture lock\n")
            (source / "script.py").write_text("print('fixture')\n")
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=source, check=True)
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
            manifest = validate_source_checkout(source, revision)
            self.assertEqual(manifest["source_revision"], revision)
            self.assertEqual(manifest["cargo_lock_sha256"], hashlib.sha256(b"fixture lock\n").hexdigest())
            (source / "dirty").write_text("untracked")
            with self.assertRaises(ValueError):
                validate_source_checkout(source, revision)
            (source / "dirty").unlink()
            subprocess.run(["git", "config", "http.https://github.com/.extraheader",
                            "AUTHORIZATION: basic synthetic-secret"], cwd=source, check=True)
            with self.assertRaises(ValueError):
                validate_source_checkout(source, revision)
            subprocess.run(["git", "config", "--unset-all",
                            "http.https://github.com/.extraheader"], cwd=source, check=True)
            (source / ".git/config.synthetic").symlink_to("config")
            with self.assertRaises(ValueError):
                validate_source_checkout(source, revision)

    def test_workflow_is_read_only_and_uses_the_exact_runtime_revision(self):
        workflow = (ROOT / ".github/workflows/landlock-qualification.yml").read_text()
        self.assertIn("contents: read", workflow)
        self.assertIn("actions: read", workflow)
        self.assertNotIn("packages: write", workflow)
        self.assertIn("deddb9e997244d2289c217ad76b8fde0e9b0339b", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("SYMBI_QUALIFICATION: landlock", workflow)
        self.assertIn("branches: [main, card/P0-04-hosted-fix]", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("include-hidden-files: true", workflow)


if __name__ == "__main__":
    unittest.main()
