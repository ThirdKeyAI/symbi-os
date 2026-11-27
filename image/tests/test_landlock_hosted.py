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
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

from image.atomic.hosted import run_hosted_command
from image.launcher.probes.bounded_process import run_bounded
from image.qualification import landlock as landlock_driver
from image.qualification.boot import (firmware_arguments, qemu_command,
                                      validate_guest_report)
from image.qualification.guest import collect_public_artifacts
from image.qualification.hosted import validate_source_checkout
from image.qualification.hosted_process import (TIMEOUT_SECONDS,
                                                validate_landlock_controller_command)


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
            "opt/io.systemd.credentials/systemd.extra-unit.p.service",
            "opt/io.systemd.credentials/systemd.extra-unit.q.service",
            "opt/io.systemd.credentials/systemd.extra-unit.l.service",
            "opt/io.systemd.credentials/symbi-status-server.py",
            "opt/io.systemd.credentials/symbi-landlock.py",
            "opt/io.systemd.credentials/vertical_slice.py",
            "opt/io.systemd.credentials/symbi-runner.py",
            "opt/io.systemd.credentials/symbi-prepare.py",
            "opt/io.systemd.credentials/symbi-expected.json",
            "opt/io.systemd.credentials/symbi-sysusers.conf",
        })
        self.assertTrue(all(len(name.encode("ascii")) < 56 for name in names))
        self.assertFalse(any(word in name for name in names for word in ("password", "ssh", "token", "key")))

    def test_guest_units_have_fixed_user_mount_and_authority(self):
        fstab = (ROOT / "image/qualification/fstab.extra").read_text().split()
        self.assertEqual(fstab, ["LABEL=SYMBIQUAL", "/var/lib/symbi-qualification/source",
                                 "ext4", "ro,nosuid,nodev,noexec", "0", "0"])
        prepare = settings("p.service")
        self.assertEqual(prepare["RequiresMountsFor"], ["/var/lib/symbi-qualification/source"])
        self.assertEqual(set(prepare["ImportCredential"]),
                         {"symbi-sysusers.conf", "symbi-prepare.py"})
        self.assertTrue(all("/bin/sh" not in command and "/bin/bash" not in command
                            for command in prepare["ExecStart"]))
        self.assertEqual(prepare["ExecStart"],
                         ["/usr/bin/python3 %d/symbi-prepare.py %d/symbi-sysusers.conf"])
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
                          "symbi-expected.json"})
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
        self.assertIn("file=/inputs/atomic.raw,format=raw,if=virtio", joined)
        self.assertIn("file=/inputs/source.raw,format=raw,if=virtio,readonly=on", joined)
        for forbidden in ("-virtfs", "-fsdev", "hostfwd", "-nic", "-kernel", "-initrd"):
            self.assertNotIn(forbidden, command)

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
