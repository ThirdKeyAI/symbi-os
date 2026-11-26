"""Synthetic report validation tests, never runtime qualification evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]


class Qualification(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("landlock", ROOT / "image/qualification/landlock.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        status_spec = importlib.util.spec_from_file_location(
            "qualification_status", ROOT / "image/qualification/status_server.py")
        self.status = importlib.util.module_from_spec(status_spec)
        status_spec.loader.exec_module(self.status)
        self.binary_hash = "a" * 64
        self.revision = "b" * 40
        self.platform = {"passed": True, "qualified": True, "expected": "usable",
                         "binary_sha256": self.binary_hash, "landlock_abi": 6,
                         "cleanup_confirmed": True, "binary_unchanged": True,
                         "policy_unchanged": True}
        self.release = {"passed": True, "profile": "full-linux", "dirty": False,
                        "sha": self.revision, "binary_sha256": self.binary_hash,
                        "binary_unchanged": True, "cases": [
                            {"name": name, "passed": True, "exit_code": 0}
                            for name in self.module.REQUIRED_CASES]}
        for row in self.release["cases"]:
            if row["name"] in ("broker", "lifecycle", "external-effects"):
                row.update(verification_exit_code=0, integrity_exit_code=0)

    def validate(self):
        self.module.validate_results(self.platform, self.release, self.binary_hash, self.revision, 6)

    def test_complete_synthetic_reports_validate(self):
        self.validate()

    def test_host_identity_requires_the_selected_secureblue_fedora_image(self):
        selected = {"ID": "secureblue", "ID_LIKE": "fedora", "VERSION_ID": "45",
                    "VARIANT_ID": "sericea-main-hardened", "IMAGE_ID": "sericea-main-hardened"}
        self.module.validate_os_release(selected)
        changes = [
            {**selected, "ID": "fedora"},
            {**selected, "ID": "unrelated", "ID_LIKE": "fedora"},
            {**selected, "ID_LIKE": "ubuntu fedora"},
            {**selected, "VERSION_ID": "46"},
            {**selected, "VARIANT_ID": "sericea-nvidia-hardened"},
            {**selected, "IMAGE_ID": "sericea-main-userns-hardened"},
        ]
        for release in changes:
            with self.subTest(release=release), self.assertRaises(ValueError):
                self.module.validate_os_release(release)

    def test_fixed_status_socket_supplies_two_bounded_unique_reports(self):
        report = {"apiVersion": "org.containers.bootc/v1", "kind": "BootcHost"}
        raw = (json.dumps(report) + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.sock"
            errors = []
            def server():
                try:
                    self.status.serve(path, lambda: raw, expected_requests=2,
                                      required_peer_uid=os.geteuid())
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=server)
            thread.start()
            deadline = time.monotonic() + 2
            while not path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.module.read_bootc_status(path), report)
            self.assertEqual(self.module.read_bootc_status(path), report)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(path.exists())

    def test_status_socket_rejects_input_invalid_json_duplicates_and_oversize(self):
        cases = [b"{}{}", b'{"kind":"a","kind":"b"}', b"x" * (128 * 1024 + 1)]
        for raw in cases:
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "status.sock"
                errors = []
                def server():
                    try:
                        self.status.serve(path, lambda: raw, expected_requests=1,
                                          required_peer_uid=os.geteuid())
                    except Exception as error:
                        errors.append(error)
                thread = threading.Thread(target=server)
                thread.start()
                deadline = time.monotonic() + 2
                while not path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                with self.assertRaises((ValueError, ConnectionError)):
                    self.module.read_bootc_status(path)
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(errors), 1)

    def test_root_status_service_has_one_fixed_command_and_bounded_authority(self):
        settings = {}
        for line in (ROOT / "image/qualification/q.service").read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                settings.setdefault(key, []).append(value)
        self.assertEqual(settings["ExecStart"],
                         ["/usr/bin/python3 %d/symbi-status-server.py"])
        self.assertEqual(settings["ImportCredential"], ["symbi-status-server.py"])
        self.assertEqual(settings["CapabilityBoundingSet"], ["CAP_SYS_ADMIN"])
        self.assertEqual(settings["AmbientCapabilities"], [""])
        self.assertEqual(settings["NoNewPrivileges"], ["yes"])
        self.assertEqual(settings["PrivatePIDs"], ["yes"])
        self.assertEqual(settings["PrivateMounts"], ["yes"])
        self.assertEqual(settings["PrivateNetwork"], ["yes"])
        self.assertEqual(settings["MemoryMax"], ["256M"])
        self.assertEqual(settings["MemorySwapMax"], ["0"])
        self.assertEqual(settings["TasksMax"], ["32"])

    def test_successful_namespace_refusal_is_not_qualification(self):
        self.platform.update(expected="namespace-refused", qualified=False)
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_and_duplicate_suites_fail(self):
        original = copy.deepcopy(self.release["cases"])
        self.release["cases"].pop()
        with self.assertRaises(ValueError):
            self.validate()
        self.release["cases"] = original + [original[0]]
        with self.assertRaises(ValueError):
            self.validate()

    def test_top_level_pass_does_not_hide_failed_case(self):
        self.release["cases"][0]["exit_code"] = 1
        with self.assertRaises(ValueError):
            self.validate()

    def test_evidence_only_is_not_full_release_qualification(self):
        self.release["profile"] = "containment-evidence"
        with self.assertRaises(ValueError):
            self.validate()

    def test_failed_independent_verifier_is_not_hidden_by_pass(self):
        next(row for row in self.release["cases"] if row["name"] == "broker")["verification_exit_code"] = 1
        with self.assertRaises(ValueError):
            self.validate()

    def test_binary_source_and_cleanup_must_match(self):
        for report, field, bad in [(self.platform, "binary_sha256", "c" * 64),
                                   (self.release, "sha", "c" * 40),
                                   (self.platform, "cleanup_confirmed", False),
                                   (self.platform, "policy_unchanged", False),
                                   (self.release, "dirty", True)]:
            with self.subTest(field=field):
                old = report[field]
                report[field] = bad
                with self.assertRaises(ValueError):
                    self.validate()
                report[field] = old

    def test_unsigned_wrong_or_mutable_deployment_fails(self):
        ref = "ghcr.io/example/test@sha256:" + "d" * 64
        status = {"status": {"booted": {"incompatible": False,
                  "ostree": {"checksum": "e" * 64}, "image": {
                  "imageDigest": "sha256:" + "d" * 64,
                  "image": {"image": ref, "transport": "registry", "signature": "containerPolicy"}}}}}
        self.module.validate_deployment(status, ref)
        for field, bad in [("signature", "insecure"), ("image", "ghcr.io/example/test:latest")]:
            candidate = copy.deepcopy(status)
            candidate["status"]["booted"]["image"]["image"][field] = bad
            with self.assertRaises(ValueError):
                self.module.validate_deployment(candidate, ref)
        status["status"]["booted"]["image"]["imageDigest"] = "sha256:" + "e" * 64
        with self.assertRaises(ValueError):
            self.module.validate_deployment(status, ref)

    def test_private_action_files_are_never_selected_for_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release/private-actions").mkdir(parents=True)
            (root / "release/private-actions/private.pem").write_text("fake secret")
            (root / "release/qualification.json").write_text("{}")
            paths = self.module.public_reports(root)
            self.assertEqual(paths, [root / "release/qualification.json"])


if __name__ == "__main__":
    unittest.main()
