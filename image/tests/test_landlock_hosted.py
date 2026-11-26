"""Inert acceptance tests for the offline hosted Landlock qualification boot."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zlib

from image.qualification.boot import (firmware_arguments, qemu_command,
                                      validate_guest_report)
from image.qualification.guest import collect_public_artifacts
from image.qualification.hosted import validate_source_checkout


ROOT = Path(__file__).resolve().parents[2]


def settings(name):
    result = {}
    for line in (ROOT / "image/qualification" / name).read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result.setdefault(key, []).append(value)
    return result


class HostedLandlock(unittest.TestCase):
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
                         {"symbi-landlock.py", "symbi-runner.py", "symbi-expected.json"})

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

    def test_bounded_public_report_is_authenticated_and_expanded(self):
        report = self.report()
        files = validate_guest_report(report, self.expected(), "f" * 64, "1" * 64, "2" * 64)
        self.assertEqual(files, {"platform.json": b'{"passed":true}\n'})

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
                validate_guest_report(report, self.expected(), "f" * 64, "1" * 64, "2" * 64)

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
        self.assertIn("branches: [main]", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("include-hidden-files: true", workflow)


if __name__ == "__main__":
    unittest.main()
