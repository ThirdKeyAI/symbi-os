"""Inert acceptance tests for the offline hosted Landlock qualification boot."""
import base64
import copy
from contextlib import redirect_stdout
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
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
                                      MAX_QMP_MESSAGES_PER_CALL,
                                      capture_process_identity,
                                      discard_control_socket, discard_overlay,
                                      firmware_arguments, overlay_command,
                                      observe_qmp_topology,
                                      path_identity, qemu_command, qmp_request,
                                      qmp_topology_observation,
                                      prepare_process_identity,
                                      retain_qmp_topology_failure,
                                      stop_child, validate_guest_report,
                                      validate_qmp_block_topology,
                                      validate_qmp_topology_observation,
                                      validate_qmp_topology_record,
                                      validate_peer_credentials,
                                      validate_process_state,
                                      validate_socket_info,
                                      unique_json,
                                      verify_process_identity,
                                      write_progress_sample)
from image.qualification.guest import collect_public_artifacts
from image.qualification.hosted import (QUALIFICATION_FILES,
                                        retain_deferred_landlock_output,
                                        validate_landlock_controller_result,
                                        validate_source_checkout)
from image.qualification.hosted_process import (TIMEOUT_SECONDS,
                                                validate_landlock_controller_command)
from image.qualification.symbi_mountinfo import (observe_mountinfo,
                                                 observe_visible_mount,
                                                 parse_visible_mount_id,
                                                 read_mountinfo,
                                                 read_visible_mount_id,
                                                 validate_mount_observation)
from image.qualification.source_mount import (EXPECTED_UDEV_RULE,
                                              observe_block_inventory,
                                              validate_block_identity,
                                              validate_installed_udev_rule,
                                              validate_source_identity,
                                              validate_udev_rule)


ROOT = Path(__file__).resolve().parents[2]
ROOT_BACKEND_QDEV = (
    "/machine/peripheral/symbi-atomic-root-device/virtio-backend")
SOURCE_BACKEND_QDEV = (
    "/machine/peripheral/symbi-qualification-source-device/virtio-backend")


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
            "source_device": {"link": "/dev/disk/by-id/virtio-SYMBIQUAL",
                              "link_target": "../../vdb",
                              "path": "/dev/vdb", "sysfs_name": "vdb",
                              "serial": "SYMBIQUAL", "major_minor": "252:16",
                              "read_only": True,
                              "transport_subsystem": "virtio",
                              "transport_driver": "virtio_blk",
                              "root_path": "/dev/vda", "root_sysfs_name": "vda",
                              "root_serial": "SYMBIROOT",
                              "root_major_minor": "252:0", "root_read_only": False,
                              "root_transport_subsystem": "virtio",
                              "root_transport_driver": "virtio_blk",
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

    def block_identity_fixture(self):
        row = lambda name, serial, major_minor, read_only: {
            "name": name,
            "path": "/dev/" + name,
            "serial": serial,
            "major_minor": major_minor,
            "node_major_minor": major_minor,
            "read_only": read_only,
            "whole_disk": True,
            "subsystem": "virtio",
            "driver": "virtio_blk",
            "node_block": True,
            "node_uid": 0,
            "node_nlink": 1,
        }
        inventory = [row("vda", "SYMBIROOT", "252:0", False),
                     row("vdb", "SYMBIQUAL", "252:16", True)]
        link = {"is_symlink": True, "uid": 0, "gid": 0, "nlink": 1,
                "target": "../../vdb", "resolved": "/dev/vdb"}
        return inventory, link

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
        self.assertIn("-accel tcg,thread=multi", joined)
        self.assertIn("-smp cpus=2,sockets=1,cores=2,threads=1", joined)
        self.assertNotIn("tcg,thread=single", joined)
        self.assertNotIn("-smp 1", joined)
        self.assertIn("product=Symbi-Hosted-Landlock-Probe", joined)
        self.assertIn("-boot strict=on", joined)
        root_drive = "file=/output/guest.qcow2,format=qcow2,if=none,id=symbi-atomic-root"
        root_device = ("virtio-blk-pci,drive=symbi-atomic-root,"
                       "id=symbi-atomic-root-device,serial=SYMBIROOT,bootindex=1")
        source_drive = ("file=/inputs/source.raw,format=raw,if=none,"
                        "id=symbi-qualification-source,readonly=on")
        source_device = ("virtio-blk-pci,drive=symbi-qualification-source,"
                         "id=symbi-qualification-source-device,serial=SYMBIQUAL")
        self.assertIn(root_drive, command)
        self.assertIn(root_device, command)
        self.assertIn(source_drive, command)
        self.assertIn(source_device, command)
        self.assertEqual(command.index("-boot") + 1,
                         command.index("strict=on"))
        self.assertLess(command.index(root_drive), command.index(root_device))
        self.assertLess(command.index(root_device), command.index(source_drive))
        self.assertLess(command.index(source_drive), command.index(source_device))
        self.assertNotIn("bootindex=", source_device)
        self.assertEqual(sum("bootindex=" in value for value in command), 1)
        self.assertNotIn("snapshot=on", joined)
        self.assertNotIn("file=/inputs/atomic.raw", joined)
        self.assertIn("-qmp unix:/output/qmp.sock,server=on,wait=off", joined)
        self.assertEqual(overlay_command(), [
            "/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "raw",
            "-b", "/inputs/atomic.raw", "/output/guest.qcow2",
        ])
        for forbidden in ("-virtfs", "-fsdev", "hostfwd", "-nic", "-kernel", "-initrd"):
            self.assertNotIn(forbidden, command)

    def test_guest_host_contract_requires_exactly_two_cpus(self):
        def inspect_host(cpu_count=2, system="Linux", machine="x86_64",
                         euid=10001, virt="qemu", container_return=1,
                         memory_kib=2 * 1024 * 1024, cgroup_v2=True,
                         selinux="Enforcing", release=None):
            release = (dict(landlock_driver.EXPECTED_OS_RELEASE)
                       if release is None else release)
            meminfo = mock.Mock()
            meminfo.read_text.return_value = f"MemTotal: {memory_kib} kB\n"
            controllers = mock.Mock()
            controllers.is_file.return_value = cgroup_v2

            def path(value):
                if value == "/proc/meminfo":
                    return meminfo
                if value == "/sys/fs/cgroup/cgroup.controllers":
                    return controllers
                raise AssertionError("unexpected host-details path: " + str(value))

            def output(command, cwd=None):
                self.assertIsNone(cwd)
                if command == ["systemd-detect-virt", "--vm"]:
                    return virt
                if command == ["getenforce"]:
                    return selinux
                raise AssertionError("unexpected host-details command: "
                                     + repr(command))

            def run(command, timeout):
                self.assertEqual(command, [
                    "systemd-detect-virt", "--container", "--quiet"])
                self.assertEqual(timeout, 10)
                return mock.Mock(returncode=container_return)

            observed_cpus = mock.Mock(return_value=cpu_count)
            with mock.patch.object(landlock_driver.platform, "system",
                                   return_value=system), \
                    mock.patch.object(landlock_driver.platform, "machine",
                                      return_value=machine), \
                    mock.patch.object(landlock_driver.platform,
                                      "freedesktop_os_release",
                                      return_value=release), \
                    mock.patch.object(landlock_driver.platform, "release",
                                      return_value="6.12.0-test"), \
                    mock.patch.object(landlock_driver.os, "geteuid",
                                      return_value=euid), \
                    mock.patch.object(landlock_driver.os, "cpu_count",
                                      observed_cpus), \
                    mock.patch.object(landlock_driver, "Path",
                                      side_effect=path), \
                    mock.patch.object(landlock_driver, "command_output",
                                      side_effect=output), \
                    mock.patch.object(landlock_driver.subprocess, "run",
                                      side_effect=run):
                try:
                    return landlock_driver.host_details()
                finally:
                    if system == "Linux" and machine == "x86_64" and euid != 0 \
                            and release == landlock_driver.EXPECTED_OS_RELEASE \
                            and virt in ("qemu", "kvm") and container_return == 1:
                        observed_cpus.assert_called_once_with()

        observed = inspect_host()
        self.assertEqual(observed["cpus"], 2)
        self.assertEqual(observed["memory_kib"], 2 * 1024 * 1024)
        self.assertEqual(observed["virtualization"], "qemu")
        self.assertEqual(observed["selinux"], "Enforcing")
        for value in (1, 3, 2.0, None, True, False):
            with self.subTest(cpu_count=value), self.assertRaisesRegex(
                    ValueError, "guest must expose exactly two CPUs"):
                inspect_host(cpu_count=value)

        prerequisites = (
            ({"system": "Darwin"}, "Linux x86-64 required"),
            ({"machine": "aarch64"}, "Linux x86-64 required"),
            ({"euid": 0}, "qualification must run as the non-root runtime user"),
            ({"release": {"ID": "fedora"}},
             "selected secureblue Fedora 45 generic image required"),
            ({"virt": "none"}, "disposable QEMU/KVM guest required"),
            ({"container_return": 0},
             "containers are not Fedora boot qualification"),
            ({"memory_kib": 2 * 1024 * 1024 + 1},
             "guest exceeds the 2 GiB memory ceiling"),
            ({"cgroup_v2": False}, "cgroup v2 required"),
            ({"selinux": "Permissive"}, "SELinux must remain enforcing"),
        )
        for changes, message in prerequisites:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    ValueError, message):
                inspect_host(**changes)

    def test_image_owned_source_rule_is_exact_and_required(self):
        rule_path = (ROOT / "image/overlay/usr/lib/udev/rules.d/"
                     "61-symbi-qualification-source.rules")
        raw = rule_path.read_text()
        self.assertEqual(validate_udev_rule(raw), EXPECTED_UDEV_RULE)
        hardener = (ROOT / "image/harden-image.sh").read_text()
        digest = hashlib.sha256(rule_path.read_bytes()).hexdigest()
        self.assertIn("61-symbi-qualification-source.rules", hardener)
        self.assertIn("qualification_rule_sha256=" + digest, hardener)
        self.assertIn('sha256sum < "$qualification_rule"', hardener)
        mutations = {
            "broad serial": raw.replace('ATTR{serial}=="SYMBIQUAL"',
                                        'ATTR{serial}=="?*"'),
            "parent serial": raw.replace('ATTR{serial}=="SYMBIQUAL"',
                                         'ATTRS{serial}=="SYMBIQUAL"'),
            "dynamic link": raw.replace("virtio-SYMBIQUAL", "virtio-$attr{serial}", 1),
            "all transports": raw.replace(', DRIVERS=="virtio_blk"', ""),
            "partitions": raw.replace('ENV{DEVTYPE}=="disk"', 'ENV{DEVTYPE}=="partition"'),
            "extra rule": raw + raw,
            "suffix without final newline": raw + "BROKEN",
        }
        for name, changed in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(hashlib.sha256(changed.encode()).hexdigest(), digest)
                with self.assertRaisesRegex(ValueError, "udev rule"):
                    validate_udev_rule(changed)
        with self.assertRaisesRegex(ValueError, "rule is absent"):
            validate_installed_udev_rule(
                Path("/usr/lib/udev/rules.d/61-symbi-missing-fixture.rules"))

    def test_source_block_identity_uses_exact_serial_not_device_order(self):
        inventory, link = self.block_identity_fixture()
        self.assertEqual(validate_block_identity(inventory, link), {
            "link": "/dev/disk/by-id/virtio-SYMBIQUAL",
            "link_target": "../../vdb",
            "path": "/dev/vdb",
            "sysfs_name": "vdb",
            "serial": "SYMBIQUAL",
            "major_minor": "252:16",
            "read_only": True,
            "transport_subsystem": "virtio",
            "transport_driver": "virtio_blk",
            "root_path": "/dev/vda",
            "root_sysfs_name": "vda",
            "root_serial": "SYMBIROOT",
            "root_major_minor": "252:0",
            "root_read_only": False,
            "root_transport_subsystem": "virtio",
            "root_transport_driver": "virtio_blk",
        })
        reversed_inventory = list(reversed(inventory))
        self.assertEqual(validate_block_identity(reversed_inventory, link)["path"],
                         "/dev/vdb")

    def test_source_inventory_reads_the_block_event_serial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sys_block = root / "sys/class/block"
            dev_root = root / "dev"
            entry = sys_block / "vda"
            (entry / "device").mkdir(parents=True)
            dev_root.mkdir()
            (entry / "serial").write_text("SYMBIROOT")
            (entry / "device/serial").write_text("WRONG-PARENT")
            (entry / "dev").write_text("252:0\n")
            (entry / "ro").write_text("0\n")
            (dev_root / "vda").touch()
            rows = observe_block_inventory(sys_block, dev_root)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["serial"], "SYMBIROOT")
            (entry / "serial").unlink()
            self.assertEqual(observe_block_inventory(sys_block, dev_root), [])

    def test_source_block_identity_rejects_adversarial_aliases(self):
        inventory, link = self.block_identity_fixture()
        cases = {}
        cases["absent source"] = (inventory[:1], link)
        duplicate = copy.deepcopy(inventory)
        duplicate.append({**duplicate[1], "name": "vdc", "path": "/dev/vdc",
                          "major_minor": "252:32", "node_major_minor": "252:32"})
        cases["duplicate source serial"] = (duplicate, link)
        wrong_serial = copy.deepcopy(inventory)
        wrong_serial[1]["serial"] = "WRONG"
        cases["wrong source serial"] = (wrong_serial, link)
        root_alias = copy.deepcopy(inventory)
        root_alias[1]["major_minor"] = root_alias[0]["major_minor"]
        root_alias[1]["node_major_minor"] = root_alias[0]["major_minor"]
        cases["root major alias"] = (root_alias, link)
        cases["link points at root"] = (
            inventory, {**link, "target": "../../vda", "resolved": "/dev/vda"})
        cases["absolute preexisting link"] = (
            inventory, {**link, "target": "/dev/vdb"})
        cases["non-symlink source path"] = (
            inventory, {**link, "is_symlink": False})
        non_block = copy.deepcopy(inventory)
        non_block[1]["node_block"] = False
        non_block[1]["node_major_minor"] = None
        cases["non-block target"] = (non_block, link)
        wrong_major = copy.deepcopy(inventory)
        wrong_major[1]["node_major_minor"] = "252:17"
        cases["mismatched major minor"] = (wrong_major, link)
        writable = copy.deepcopy(inventory)
        writable[1]["read_only"] = False
        cases["writable source"] = (writable, link)
        partition = copy.deepcopy(inventory)
        partition[1]["whole_disk"] = False
        cases["source partition"] = (partition, link)
        for name, (changed_inventory, changed_link) in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_block_identity(changed_inventory, changed_link)

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

        identity = {"pid": 4242, "ppid": 1, "starttime": 777,
                    "executable_device": 8, "executable_inode": 9,
                    "uid": 10001, "gid": 10001, "pidfd": 10}
        child = mock.Mock(pid=4242)
        child.poll.return_value = None
        send_signal = mock.Mock(side_effect=PermissionError(
            errno.EACCES, "Permission denied"))
        failure = "TimeoutError: Landlock guest did not report"
        qmp = mock.Mock(side_effect=ValueError(
            "unexpected QMP response schema"))
        prove_exit = mock.Mock(return_value=False)
        record = {"failure": failure,
                  "child_cleanup": stop_child(
                      child, identity, {"path": Path("/output/qmp.sock")},
                      request=qmp, prove_exit=prove_exit,
                      verify=mock.Mock(return_value=None),
                      send_signal=send_signal)}
        self.assertEqual(record["failure"], failure)
        self.assertTrue(record["child_cleanup"]["attempted"])
        self.assertFalse(record["child_cleanup"]["qmp_quit"])
        self.assertFalse(record["child_cleanup"]["exit_proven"])
        self.assertEqual(record["child_cleanup"]["errors"], [
            "ValueError: unexpected QMP response schema",
            "PermissionError: [Errno 13] Permission denied",
            "PermissionError: [Errno 13] Permission denied",
        ])
        qmp.assert_called_once_with({"path": Path("/output/qmp.sock")}, "quit")
        self.assertEqual(send_signal.call_args_list, [
            mock.call(identity, signal.SIGTERM),
            mock.call(identity, signal.SIGKILL),
        ])
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

        controlled = mock.Mock(pid=4242)
        controlled.poll.return_value = None
        qmp = mock.Mock(return_value={})
        cleanup = stop_child(
            controlled, identity, {"path": Path("/output/qmp.sock")},
            request=qmp, prove_exit=mock.Mock(side_effect=(False, True)),
            verify=mock.Mock(return_value=None), send_signal=mock.Mock())
        self.assertTrue(cleanup["qmp_quit"])
        self.assertTrue(cleanup["exit_proven"])
        self.assertFalse(cleanup["terminated"])
        self.assertFalse(cleanup["killed"])
        controlled.terminate.assert_not_called()
        controlled.kill.assert_not_called()

        # QEMU documents that quit may close QMP before returning a response.
        # Exact pidfd plus direct-child exit proof is sufficient for cleanup;
        # a signal fallback must not run after that proof succeeds.
        eof_child = mock.Mock(pid=4242)
        eof_child.poll.return_value = None
        qmp = mock.Mock(side_effect=EOFError("synthetic QMP close after quit"))
        send_signal = mock.Mock(side_effect=PermissionError("must not signal"))
        cleanup = stop_child(
            eof_child, identity, {"path": Path("/output/qmp.sock")},
            request=qmp, prove_exit=mock.Mock(side_effect=(False, True)),
            verify=mock.Mock(return_value=None), send_signal=send_signal)
        self.assertTrue(cleanup["exit_proven"])
        self.assertFalse(cleanup["qmp_quit"])
        self.assertFalse(cleanup["terminated"])
        self.assertFalse(cleanup["killed"])
        self.assertEqual(cleanup["errors"],
                         ["EOFError: synthetic QMP close after quit"])
        send_signal.assert_not_called()
        eof_child.terminate.assert_not_called()
        eof_child.kill.assert_not_called()

        reused = mock.Mock(pid=4242)
        reused.poll.return_value = None
        cleanup = stop_child(
            reused, identity, {"path": Path("/output/qmp.sock")},
            request=mock.Mock(), prove_exit=mock.Mock(return_value=False),
            verify=mock.Mock(side_effect=ValueError("PID identity changed")),
            send_signal=mock.Mock())
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
        legacy_status = (b'{"return":{"running":true,"singlestep":false,'
                         b'"status":"running"},"id":"symbi-query-status"}\n')
        current_status = (b'{"return":{"running":true,"status":"running"},'
                          b'"id":"symbi-query-status"}\n')
        running_event = (b'{"event":"RESUME","timestamp":{"seconds":1,'
                         b'"microseconds":2}}\n')
        for name, status, expected in (
            ("legacy singlestep", legacy_status,
             {"running": True, "singlestep": False, "status": "running"}),
            ("current", current_status,
             {"running": True, "status": "running"}),
        ):
            with self.subTest(name=name):
                stream = Stream([greeting, capabilities, status])
                self.assertEqual(qmp_request(stream, "query-status"), expected)
                self.assertEqual(len(stream.writes), 2)
        event_stream = Stream([
            greeting, capabilities, running_event, current_status])
        self.assertEqual(qmp_request(event_stream, "query-status"),
                         {"running": True, "status": "running"})
        bounded_stream = Stream([
            greeting, capabilities,
            *([running_event] * (MAX_QMP_MESSAGES_PER_CALL - 1)),
            current_status,
        ])
        self.assertEqual(qmp_request(bounded_stream, "query-status"),
                         {"running": True, "status": "running"})
        quit_stream = Stream([
            greeting, capabilities,
            b'{"event":"SHUTDOWN","data":{"guest":false,'
            b'"reason":"host-qmp-quit"},"timestamp":{"seconds":1,'
            b'"microseconds":3}}\n',
            b'{"return":{},"id":"symbi-quit"}\n'])
        self.assertEqual(qmp_request(quit_stream, "quit"), {})
        blocks = [
            {"device": "symbi-atomic-root", "qdev": ROOT_BACKEND_QDEV,
             "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                          "ro": False, "backing_file": "/inputs/atomic.raw"}},
            {"device": "symbi-qualification-source",
             "qdev": SOURCE_BACKEND_QDEV,
             "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                          "ro": True}},
        ]

        def response(value, request_id):
            return (json.dumps({"return": value, "id": request_id},
                               separators=(",", ":")) + "\n").encode()

        topology_stream = Stream([
            greeting, capabilities, response(blocks, "symbi-query-block"),
            response(1, "symbi-root-bootindex"),
            response(-1, "symbi-source-bootindex"),
        ])
        topology = qmp_request(topology_stream, "query-block-topology")
        self.assertEqual(topology, validate_qmp_topology_record(topology))
        self.assertEqual(topology_stream.writes, [
            b'{"execute":"qmp_capabilities","id":"symbi-qmp-capabilities"}\n',
            b'{"execute":"query-block","id":"symbi-query-block"}\n',
            (b'{"execute":"qom-get","id":"symbi-root-bootindex",'
             b'"arguments":{"path":"/machine/peripheral/'
             b'symbi-atomic-root-device","property":"bootindex"}}\n'),
            (b'{"execute":"qom-get","id":"symbi-source-bootindex",'
             b'"arguments":{"path":"/machine/peripheral/'
             b'symbi-qualification-source-device","property":"bootindex"}}\n'),
        ])
        for forbidden in ("qmp_capabilities", "stop", "cont", "system_reset"):
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                qmp_request(Stream([]), forbidden)

        expected = validate_qmp_block_topology(blocks, 1, -1)
        mutations = {
            "blocks not list": {},
            "missing source": blocks[:1],
            "duplicate root": [blocks[0], blocks[0]],
            "root drive": [{**blocks[0], "device": "other"}, blocks[1]],
            "root parent qdev": [
                {**blocks[0], "qdev": "symbi-atomic-root-device"}, blocks[1]],
            "root backend under another parent": [
                {**blocks[0], "qdev":
                 "/machine/peripheral/other/virtio-backend"}, blocks[1]],
            "root inserted": [{**blocks[0], "inserted": []}, blocks[1]],
            "root file": [{**blocks[0], "inserted": {
                **blocks[0]["inserted"], "file": "/inputs/source.raw"}}, blocks[1]],
            "root format": [{**blocks[0], "inserted": {
                **blocks[0]["inserted"], "drv": "raw"}}, blocks[1]],
            "root readonly": [{**blocks[0], "inserted": {
                **blocks[0]["inserted"], "ro": True}}, blocks[1]],
            "root backing": [{**blocks[0], "inserted": {
                **blocks[0]["inserted"], "backing_file": "/other"}}, blocks[1]],
            "source drive": [blocks[0], {**blocks[1], "device": "other"}],
            "source parent qdev": [
                blocks[0],
                {**blocks[1], "qdev": "symbi-qualification-source-device"}],
            "source backend under another parent": [
                blocks[0], {**blocks[1], "qdev":
                            "/machine/peripheral/other/virtio-backend"}],
            "source writable": [blocks[0], {**blocks[1], "inserted": {
                **blocks[1]["inserted"], "ro": False}}],
            "source backing": [blocks[0], {**blocks[1], "inserted": {
                **blocks[1]["inserted"], "backing_file": "/other"}}],
        }
        for name, changed in mutations.items():
            with self.subTest(topology_mutation=name), self.assertRaises(ValueError):
                validate_qmp_block_topology(changed, 1, -1)
        for name, root_index, source_index in (
            ("root bool", True, -1), ("root missing", None, -1),
            ("root wrong", 2, -1), ("source bool", 1, False),
            ("source included", 1, 2), ("source missing", 1, None),
        ):
            with self.subTest(bootindex_mutation=name), self.assertRaises(ValueError):
                validate_qmp_block_topology(blocks, root_index, source_index)
        for key, value in (("schema", True), ("strict_boot", 1),
                           ("root", []), ("source", None)):
            changed = copy.deepcopy(expected)
            changed[key] = value
            with self.subTest(record_mutation=key), self.assertRaises(ValueError):
                validate_qmp_topology_record(changed)
        changed = copy.deepcopy(expected)
        changed["root"]["bootindex"] = True
        with self.assertRaises(ValueError):
            validate_qmp_topology_record(changed)
        changed = copy.deepcopy(expected)
        changed["root"]["qdev"] = "symbi-atomic-root-device"
        with self.assertRaises(ValueError):
            validate_qmp_topology_record(changed)

        invalid = {
            "extra greeting field": (
                greeting.replace(b'"QMP":', b'"extra":1,"QMP":'),
                capabilities, current_status),
            "extra capabilities field": (
                greeting, b'{"return":{},"id":"symbi-qmp-capabilities","extra":1}\n',
                current_status),
            "event before capabilities": (
                greeting, running_event, capabilities, current_status),
            "wrong response id": (
                greeting, capabilities,
                current_status.replace(b"symbi-query-status", b"other")),
            "extra status field": (
                greeting, capabilities,
                current_status.replace(b'"status":"running"',
                                       b'"status":"running","extra":1')),
            "invalid legacy singlestep": (
                greeting, capabilities,
                legacy_status.replace(b'"singlestep":false',
                                      b'"singlestep":"false"')),
            "inconsistent state": (
                greeting, capabilities,
                current_status.replace(b'"running":true', b'"running":false')),
            "invalid event timestamp": (
                greeting, capabilities,
                running_event.replace(b'"microseconds":2',
                                      b'"microseconds":1000000'),
                current_status),
            "extra event field": (
                greeting, capabilities,
                running_event.replace(b'"event":"RESUME"',
                                      b'"event":"RESUME","extra":1'),
                current_status),
            "invalid event name": (
                greeting, capabilities,
                running_event.replace(b'"RESUME"', b'"resume"'),
                current_status),
            "invalid event data": (
                greeting, capabilities,
                running_event.replace(b'"timestamp":', b'"data":[],"timestamp":'),
                current_status),
            "too many events": (
                greeting, capabilities,
                *([running_event] * MAX_QMP_MESSAGES_PER_CALL),
                current_status),
            "malformed json": (b'{not-json}\n',),
            "truncated json": (greeting.removesuffix(b"\n"),),
            "oversized json": (b"{" + b"x" * MAX_QMP_MESSAGE_BYTES + b"}\n",),
            "timeout": (TimeoutError("synthetic timeout"),),
        }
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            invalid["event data " + constant.decode()] = (
                greeting, capabilities,
                running_event.replace(
                    b'"timestamp":',
                    b'"data":{"value":' + constant + b'},"timestamp":'),
                current_status,
            )
        for name, lines in invalid.items():
            with self.subTest(name=name), self.assertRaises((ValueError, TimeoutError)):
                qmp_request(Stream(lines), "query-status")

    def test_qmp_topology_observation_retries_only_socket_startup(self):
        topology = validate_qmp_block_topology([
            {"device": "symbi-atomic-root", "qdev": ROOT_BACKEND_QDEV,
             "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                          "ro": False, "backing_file": "/inputs/atomic.raw"}},
            {"device": "symbi-qualification-source",
             "qdev": SOURCE_BACKEND_QDEV,
             "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                          "ro": True}},
        ], 1, -1)
        request = mock.Mock(side_effect=(
            FileNotFoundError(errno.ENOENT, "synthetic absent socket"),
            ConnectionRefusedError(errno.ECONNREFUSED, "synthetic startup"),
            topology,
        ))
        clock = mock.Mock(side_effect=(0.0, 0.1, 0.2))
        sleep = mock.Mock()
        missing_socket = mock.Mock()
        missing_socket.lstat.side_effect = FileNotFoundError(
            errno.ENOENT, "synthetic absent socket")
        self.assertEqual(observe_qmp_topology(
            {"path": missing_socket}, clock=clock, sleep=sleep,
            request=request), topology)
        self.assertEqual(request.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(0.1), mock.call(0.1)])

        with self.assertRaisesRegex(ValueError, "synthetic malformed"):
            observe_qmp_topology(
                {}, request=mock.Mock(side_effect=ValueError("synthetic malformed")))
        with self.assertRaisesRegex(PermissionError, "synthetic denied"):
            observe_qmp_topology(
                {}, request=mock.Mock(side_effect=PermissionError(
                    errno.EACCES, "synthetic denied")))
        with self.assertRaisesRegex(TimeoutError, "within 30 seconds"):
            observe_qmp_topology(
                {"path": missing_socket},
                clock=mock.Mock(side_effect=(0.0, 30.0)),
                sleep=mock.Mock(), request=mock.Mock(side_effect=FileNotFoundError(
                    errno.ENOENT, "synthetic absent socket")))
        existing_socket = mock.Mock()
        existing_socket.lstat.return_value = mock.Mock()
        with self.assertRaisesRegex(FileNotFoundError, "synthetic process gone"):
            observe_qmp_topology(
                {"path": existing_socket}, request=mock.Mock(
                    side_effect=FileNotFoundError(
                        errno.ENOENT, "synthetic process gone")))

    def test_qmp_topology_failures_retain_only_fixed_predicate_results(self):
        blocks = [
            {"device": "symbi-atomic-root", "qdev": ROOT_BACKEND_QDEV,
             "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                          "ro": False, "backing_file": "/inputs/atomic.raw"}},
            {"device": "symbi-qualification-source",
             "qdev": SOURCE_BACKEND_QDEV,
             "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                          "ro": True}},
        ]
        expected = qmp_topology_observation(blocks, 1, -1)
        self.assertEqual(validate_qmp_topology_observation(expected), expected)
        for section in ("inventory", "root", "source"):
            self.assertEqual(set(expected[section].values()), {"pass"})

        mapping_mutations = {
            ("root", "qdev"): [
                {**blocks[0], "qdev": "unreviewed-sensitive-value"}, blocks[1]],
            ("root", "inserted"): [
                {**blocks[0], "inserted": []}, blocks[1]],
            ("root", "file"): [
                {**blocks[0], "inserted": {
                    **blocks[0]["inserted"], "file": "/unreviewed/root"}}, blocks[1]],
            ("root", "format"): [
                {**blocks[0], "inserted": {
                    **blocks[0]["inserted"], "drv": "unreviewed-format"}}, blocks[1]],
            ("root", "read_only_type"): [
                {**blocks[0], "inserted": {
                    **blocks[0]["inserted"], "ro": 0}}, blocks[1]],
            ("root", "read_only"): [
                {**blocks[0], "inserted": {
                    **blocks[0]["inserted"], "ro": True}}, blocks[1]],
            ("root", "backing_file"): [
                {**blocks[0], "inserted": {
                    **blocks[0]["inserted"],
                    "backing_file": "/unreviewed/backing"}}, blocks[1]],
            ("source", "qdev"): [
                blocks[0], {**blocks[1], "qdev": "unreviewed-sensitive-value"}],
            ("source", "inserted"): [
                blocks[0], {**blocks[1], "inserted": None}],
            ("source", "file"): [
                blocks[0], {**blocks[1], "inserted": {
                    **blocks[1]["inserted"], "file": "/unreviewed/source"}}],
            ("source", "format"): [
                blocks[0], {**blocks[1], "inserted": {
                    **blocks[1]["inserted"], "drv": "unreviewed-format"}}],
            ("source", "read_only_type"): [
                blocks[0], {**blocks[1], "inserted": {
                    **blocks[1]["inserted"], "ro": 1}}],
            ("source", "read_only"): [
                blocks[0], {**blocks[1], "inserted": {
                    **blocks[1]["inserted"], "ro": False}}],
            ("source", "backing_file"): [
                blocks[0], {**blocks[1], "inserted": {
                    **blocks[1]["inserted"],
                    "backing_file": "/unreviewed/backing"}}],
        }
        for (section, predicate), changed in mapping_mutations.items():
            with self.subTest(section=section, predicate=predicate):
                with self.assertRaisesRegex(ValueError, "mapping differs") as caught:
                    validate_qmp_block_topology(changed, 1, -1)
                observation = caught.exception.qmp_topology_observation
                self.assertEqual(observation[section][predicate], "fail")
                retained = json.dumps(observation, sort_keys=True)
                self.assertNotIn("unreviewed", retained)
                self.assertEqual(
                    validate_qmp_topology_observation(observation), observation)

        index_mutations = (
            ("root", "bootindex_type", True, -1),
            ("root", "bootindex", 2, -1),
            ("source", "bootindex_type", 1, False),
            ("source", "bootindex", 1, 2),
        )
        for section, predicate, root_index, source_index in index_mutations:
            with self.subTest(section=section, predicate=predicate):
                with self.assertRaisesRegex(ValueError, "boot indexes differ") as caught:
                    validate_qmp_block_topology(blocks, root_index, source_index)
                self.assertEqual(
                    caught.exception.qmp_topology_observation[section][predicate],
                    "fail")

    def test_qmp_topology_row_failures_are_distinct_and_content_free(self):
        root = {"device": "symbi-atomic-root",
                "qdev": ROOT_BACKEND_QDEV,
                "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                             "ro": False,
                             "backing_file": "/inputs/atomic.raw"}}
        source = {"device": "symbi-qualification-source",
                  "qdev": SOURCE_BACKEND_QDEV,
                  "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                               "ro": True}}
        cases = (
            ("not-list", {}, (("inventory", "is_list"),)),
            ("absent", [root], (
                ("inventory", "count"),
                ("inventory", "exact_devices"),
                ("source", "drive"),
            )),
            ("duplicate", [root, root], (
                ("inventory", "devices_unique"),
                ("inventory", "exact_devices"),
                ("root", "drive"),
                ("source", "drive"),
            )),
            ("unexpected", [root, {**source, "device": "unreviewed-device"}],
             (("inventory", "only_expected_devices"),
              ("inventory", "exact_devices"),
              ("source", "drive"))),
            ("non-object", [root, []],
             (("inventory", "rows_are_objects"),)),
            ("non-string-device", [root, {**source, "device": []}],
             (("inventory", "device_fields_are_strings"),)),
        )
        for name, changed, expected_failures in cases:
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as caught:
                    validate_qmp_block_topology(changed, 1, -1)
                observation = caught.exception.qmp_topology_observation
                for section, predicate in expected_failures:
                    self.assertEqual(observation[section][predicate], "fail")
                self.assertNotIn(
                    "unreviewed", json.dumps(observation, sort_keys=True))
                validate_qmp_topology_observation(observation)

    def test_qmp_topology_observation_schema_rejects_mutations(self):
        blocks = [
            {"device": "symbi-atomic-root", "qdev": ROOT_BACKEND_QDEV,
             "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                          "ro": False, "backing_file": "/inputs/atomic.raw"}},
            {"device": "symbi-qualification-source",
             "qdev": SOURCE_BACKEND_QDEV,
             "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                          "ro": True}},
        ]
        valid = qmp_topology_observation(blocks, 1, -1)
        mutations = (
            {**valid, "schema": True},
            {**valid, "extra": "fail"},
            {**valid, "inventory": {**valid["inventory"], "raw": "/secret"}},
            {**valid, "root": {**valid["root"], "file": True}},
            {**valid, "source": {**valid["source"], "format": "unknown"}},
        )
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_qmp_topology_observation(changed)

    def test_qmp_topology_failure_is_retained_before_result_write(self):
        blocks = [
            {"device": "symbi-atomic-root", "qdev": "changed-qdev",
             "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                          "ro": False, "backing_file": "/inputs/atomic.raw"}},
            {"device": "symbi-qualification-source",
             "qdev": SOURCE_BACKEND_QDEV,
             "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                          "ro": True}},
        ]
        with self.assertRaisesRegex(ValueError, "mapping differs") as caught:
            validate_qmp_block_topology(blocks, 1, -1)
        record = {"passed": False}
        self.assertTrue(retain_qmp_topology_failure(record, caught.exception))
        self.assertEqual(record["block_topology_observation"]["root"]["qdev"],
                         "fail")
        self.assertNotIn("changed-qdev", json.dumps(record, sort_keys=True))
        self.assertFalse(retain_qmp_topology_failure({}, ValueError("other")))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            retain_qmp_topology_failure(record, caught.exception)
        caught.exception.qmp_topology_observation["root"]["qdev"] = []
        with self.assertRaisesRegex(ValueError, "invalid QMP topology"):
            retain_qmp_topology_failure({}, caught.exception)

    def test_host_acceptance_requires_exact_qmp_boot_topology(self):
        source_revision = "a" * 40
        binary_sha256 = "b" * 64
        topology = validate_qmp_block_topology([
            {"device": "symbi-atomic-root", "qdev": ROOT_BACKEND_QDEV,
             "inserted": {"file": "/output/guest.qcow2", "drv": "qcow2",
                          "ro": False, "backing_file": "/inputs/atomic.raw"}},
            {"device": "symbi-qualification-source",
             "qdev": SOURCE_BACKEND_QDEV,
             "inserted": {"file": "/inputs/source.raw", "drv": "raw",
                          "ro": True}},
        ], 1, -1)
        controller = {"passed": True, "qualification_qualified": True,
                      "source_revision": source_revision,
                      "binary_sha256": binary_sha256,
                      "block_topology": topology}
        self.assertIsNone(validate_landlock_controller_result(
            0, controller, source_revision, binary_sha256))
        mutations = (
            ("exit", 1, controller),
            ("bool exit", False, controller),
            ("missing topology", 0, {key: value for key, value in controller.items()
                                     if key != "block_topology"}),
            ("wrong topology", 0, {**controller, "block_topology": {
                **topology, "strict_boot": False}}),
            ("unqualified", 0, {**controller, "qualification_qualified": False}),
        )
        for name, exit_code, changed in mutations:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_landlock_controller_result(
                    exit_code, changed, source_revision, binary_sha256)

    def test_unique_json_rejects_constants_and_duplicate_keys(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), self.assertRaisesRegex(
                    ValueError, "non-RFC JSON constant"):
                unique_json('{"nested":[{"value":' + constant + '}]}')
        with self.assertRaisesRegex(ValueError,
                                    "duplicate qualification report key"):
            unique_json('{"nested":{"value":1,"value":2}}')

    def test_qmp_peer_socket_and_process_identity_are_exact(self):
        identity = {"pid": 4242, "ppid": 1, "starttime": 777,
                    "executable_device": 8, "executable_inode": 9,
                    "executable": "/usr/bin/qemu-system-x86_64",
                    "cmdline_sha256": "a" * 64, "cmdline_bytes": 128,
                    "cgroup": "0::/qualification", "uid": 10001,
                    "gid": 10001, "pidfd": 10,
                    "proc_exe_verified": False}
        raw = struct.pack("=iII", 4242, 10001, 10001)
        self.assertEqual(validate_peer_credentials(raw, identity),
                         {"pid": 4242, "uid": 10001, "gid": 10001})
        for values in ((4243, 10001, 10001), (4242, 10002, 10001),
                       (4242, 10001, 10002)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_peer_credentials(struct.pack("=iII", *values), identity)
        validate_process_state(identity, {
            "pid": 4242, "ppid": 1, "starttime": 777,
            "cmdline_sha256": "a" * 64, "cmdline_bytes": 128,
            "cgroup": "0::/qualification", "uid": 10001, "gid": 10001,
            "proc_exe_verified": False,
        })
        changed = {key: identity[key] for key in
                   ("pid", "ppid", "starttime", "cmdline_sha256", "cmdline_bytes",
                    "cgroup", "uid", "gid", "proc_exe_verified")}
        for key, value in (("ppid", 2), ("starttime", 778),
                           ("cmdline_sha256", "b" * 64),
                           ("cmdline_bytes", 129),
                           ("cgroup", "0::/reused"), ("uid", 10002)):
            candidate = dict(changed)
            candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_process_state(identity, candidate)
        executable_denied = dict(changed)
        executable_denied["proc_exe_verified"] = False
        executable_verified = dict(identity, proc_exe_verified=True)
        with self.assertRaises(ValueError):
            validate_process_state(executable_verified, executable_denied)
        unavailable = dict(identity, pidfd=None)
        reader = mock.Mock()
        with self.assertRaisesRegex(ValueError, "pidfd"):
            verify_process_identity(unavailable, reader=reader)
        reader.assert_not_called()

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

    def test_process_identity_survives_proc_exe_denial_and_rejects_pid_reuse(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]
        cgroup = Path("/proc/self/cgroup").read_text().strip()
        prepared = prepare_process_identity(command, cgroup)
        child = subprocess.Popen(command)
        identity = None
        try:
            with mock.patch("image.qualification.boot.os.pidfd_open", None):
                with self.assertRaisesRegex(ValueError, "pidfd"):
                    capture_process_identity(child, prepared)
            with mock.patch("image.qualification.boot.signal.getsignal",
                            return_value=signal.SIG_IGN):
                with self.assertRaisesRegex(ValueError, "pidfd"):
                    capture_process_identity(child, prepared)

            changed = dict(prepared)
            changed["cmdline_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "identity changed"):
                capture_process_identity(child, changed)

            changed = dict(prepared)
            changed["executable_inode"] += 1
            with self.assertRaisesRegex(ValueError, "executable identity changed"):
                capture_process_identity(child, changed)

            proc_exe = Path("/proc") / str(child.pid) / "exe"
            original_stat = Path.stat

            def deny_proc_exe(path, *args, **kwargs):
                if path == proc_exe:
                    raise PermissionError(errno.EACCES, "synthetic proc denial",
                                          str(path))
                return original_stat(path, *args, **kwargs)

            def forbid_proc_exe(path, *args, **kwargs):
                if path == proc_exe:
                    raise PermissionError(errno.EPERM, "synthetic proc refusal",
                                          str(path))
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(Path, "stat", forbid_proc_exe):
                with self.assertRaises(PermissionError):
                    capture_process_identity(child, prepared)

            with mock.patch.object(Path, "stat", deny_proc_exe):
                identity = capture_process_identity(child, prepared)
                self.assertFalse(identity["proc_exe_verified"])
                self.assertIsInstance(identity["pidfd"], int)
                verify_process_identity(identity)

            cleanup = stop_child(child, identity)
            self.assertTrue(cleanup["terminated"])
            self.assertFalse(cleanup["killed"])
            self.assertTrue(cleanup["exit_proven"])
            self.assertEqual(cleanup["errors"], [])
            observed = {key: identity[key] for key in
                        ("pid", "ppid", "starttime", "cmdline_sha256", "cmdline_bytes",
                         "cgroup", "uid", "gid", "proc_exe_verified")}
            reader = mock.Mock(return_value=observed)
            with self.assertRaisesRegex(ValueError, "exited"):
                verify_process_identity(identity, reader=reader)
            reader.assert_not_called()
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            if identity is not None and identity["pidfd"] is not None:
                os.close(identity["pidfd"])

    def test_process_identity_opens_pidfd_before_poll_or_proc_reads(self):
        command = [sys.executable, "-c", "pass"]
        prepared = prepare_process_identity(
            command, Path("/proc/self/cgroup").read_text().strip())
        events = []
        child = mock.Mock(pid=4242, args=command)
        child.poll.side_effect = lambda: events.append("poll")
        observed = {"pid": 4242, "ppid": os.getpid(), "starttime": 777,
                    "cmdline_sha256": prepared["cmdline_sha256"],
                    "cmdline_bytes": prepared["cmdline_bytes"],
                    "cgroup": prepared["cgroup"], "uid": os.geteuid(),
                    "gid": os.getegid(), "proc_exe_verified": False}
        observations = [observed, dict(observed, proc_exe_verified=True)]
        reader = mock.Mock(
            side_effect=lambda *_: (events.append("proc"), observations.pop(0))[1])
        real_pidfd_open = os.pidfd_open

        def open_pidfd(pid, flags):
            self.assertEqual((pid, flags), (4242, 0))
            events.append("pidfd")
            return real_pidfd_open(os.getpid(), 0)

        identity = None
        try:
            with mock.patch("image.qualification.boot.os.pidfd_open", open_pidfd):
                identity = capture_process_identity(child, prepared, reader=reader)
            self.assertEqual(events, ["pidfd", "proc", "proc", "poll"])
            self.assertTrue(identity["proc_exe_verified"])
        finally:
            if identity is not None:
                os.close(identity["pidfd"])

    def test_process_identity_rejects_changed_popen_argv_before_proc_reads(self):
        command = [sys.executable, "-c", "pass"]
        prepared = prepare_process_identity(
            command, Path("/proc/self/cgroup").read_text().strip())
        child = mock.Mock(pid=4242,
                          args=[sys.executable, "-c", "raise SystemExit(1)"])
        reader = mock.Mock()
        real_pidfd_open = os.pidfd_open

        def open_pidfd(pid, flags):
            self.assertEqual((pid, flags), (4242, 0))
            return real_pidfd_open(os.getpid(), 0)

        with mock.patch("image.qualification.boot.os.pidfd_open", open_pidfd), \
                self.assertRaisesRegex(ValueError,
                                       "QEMU Popen command identity changed"):
            capture_process_identity(child, prepared, reader=reader)
        reader.assert_not_called()
        child.poll.assert_not_called()

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
        mutations = {
            "filesystem UUID": ("UUID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "source serial": ("serial", "OTHER"),
            "root serial": ("root_serial", "OTHER"),
            "source read only": ("read_only", False),
            "root alias": ("root_major_minor", "252:16"),
            "link target": ("link_target", "../../vda"),
            "transport": ("transport_driver", "other"),
            "root transport": ("root_transport_driver", "other"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                report = self.report()
                report["source_device"][field] = value
                with self.assertRaisesRegex(ValueError, "source-device"):
                    validate_guest_report(report, self.expected(), "f" * 64,
                                          "1" * 64, "2" * 64, "3" * 64)

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
