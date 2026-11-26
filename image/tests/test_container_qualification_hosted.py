"""Offline contracts for the fail-closed Fedora container qualification controller."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


class FedoraContainerController(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "container_hosted", ROOT / "image/qualification/container_hosted.py"
        )
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_authenticated_repository_metadata_selects_exact_runsc_bytes(self):
        calls = []
        identity = self.module.load_authenticated_runsc(
            ROOT, verify=lambda *arguments: calls.append(arguments)
        )
        self.assertEqual(identity["package_version"], "20261123.0")
        self.assertEqual(identity["package_sha256"],
                         "3b78fe64d212d0d1a753660b0a9e95488e5e264d36dce04c36e7245b81151e18")
        self.assertEqual(identity["runsc_sha256"],
                         "fcf27497492d44de3d1406d64bd72e038822bed74dea429efb338edf0b2ceeb8")
        self.assertEqual(identity["signing_fingerprint"],
                         "6F1DF85E3A71C24918E727D56FC6D554E32BD943")
        self.assertFalse(identity["selected_for_release"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], identity["signing_fingerprint"])

    def test_repository_metadata_rejects_changed_signature_package_or_inventory(self):
        base = ROOT / "image/container/hosted"
        lock = json.loads((base / "inputs.lock.json").read_text())
        metadata = json.loads((base / "gvisor/verified-metadata.json").read_text())
        inventory = json.loads((base / "gvisor/package-inventory.json").read_text())
        hashes = self.module.retained_input_hashes(ROOT)
        candidates = []
        candidate = copy.deepcopy(metadata)
        candidate["signature_verified"] = False
        candidates.append((candidate, inventory))
        candidate = copy.deepcopy(metadata)
        candidate["package"]["SHA256"] = "0" * 64
        candidates.append((candidate, inventory))
        candidate_inventory = copy.deepcopy(inventory)
        next(row for row in candidate_inventory["entries"] if row["path"] == "usr/bin/runsc")["sha256"] = "0" * 64
        candidates.append((metadata, candidate_inventory))
        for changed_metadata, changed_inventory in candidates:
            with self.subTest(package=changed_metadata["package"]["SHA256"]), self.assertRaises(ValueError):
                self.module.validate_runsc_records(lock, changed_metadata, changed_inventory, hashes)

    def test_fedora_image_contract_requires_selected_signed_packages_and_exact_files(self):
        identity = self.module.load_authenticated_runsc(ROOT, verify=lambda *arguments: None)
        contract = {
            "schema": 1,
            "selected": True,
            "installed": True,
            "packages": {
                name: {"nevra": name + "-1-1.x86_64", "rpm_sha256": index * 64,
                       "signature_verified": True, "signing_fingerprint": "d" * 40,
                       "repository_metadata_sha256": "e" * 64}
                for name, index in (("moby-engine", "a"), ("docker-cli", "b"),
                                    ("container-selinux", "c"))
            },
            "files": {path: {"sha256": value} for path, value in identity["package_files"].items()},
            "runsc_package_sha256": identity["package_sha256"],
            "runsc_repository_fingerprint": identity["signing_fingerprint"],
        }
        self.module.validate_fedora_contract(contract, identity)
        changes = [
            ("selected", False),
            ("installed", False),
            ("runsc_package_sha256", "0" * 64),
            ("runsc_repository_fingerprint", "0" * 40),
        ]
        for field, value in changes:
            candidate = copy.deepcopy(contract)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_fedora_contract(candidate, identity)
        candidate = copy.deepcopy(contract)
        del candidate["packages"]["container-selinux"]
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(candidate, identity)
        candidate = copy.deepcopy(contract)
        candidate["packages"]["moby-engine"]["signature_verified"] = False
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(candidate, identity)
        candidate = copy.deepcopy(contract)
        candidate["files"]["usr/bin/runsc"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(candidate, identity)

    def test_preflight_stays_unqualified_and_hash_binds_shared_boot_status_inputs(self):
        result = self.module.build_preflight(ROOT, "1" * 40, "2" * 40,
                                             verify=lambda *arguments: None)
        self.assertFalse(result["passed"])
        self.assertFalse(result["qualified"])
        self.assertFalse(result["native_fixture_matrix_passed"])
        self.assertFalse(result["managed_route_qualified"])
        self.assertFalse(result["escape_suite_qualified"])
        self.assertIn("missing-fedora-runtime-lock", result["blockers"])
        self.assertEqual(set(result["shared_boot_status_inputs"]),
                         set(self.module.SHARED_BOOT_STATUS_INPUTS))
        self.assertTrue(all(len(value) == 64 for value in result["shared_boot_status_inputs"].values()))
        self.assertNotIn("gvisor-inputs.json", json.dumps(result))
        self.assertEqual(result["fixture_source"]["revision"],
                         "be3bef1dababb49a68450a883dc1ba97fa6322b0")
        self.assertEqual(result["fixture_source"]["tree"],
                         "207616f4326f83b00c2c8717294f4689c969d093")
        self.assertEqual(result["fixture_source"]["runtime_source_revision"],
                         "deddb9e997244d2289c217ad76b8fde0e9b0339b")

    def test_reviewed_fixture_checkout_requires_merge_revision_tree_and_driver_hashes(self):
        pin = self.module.load_fixture_pin(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "scripts").mkdir()
            for driver in pin["drivers"]:
                (source / "scripts" / driver).write_text(driver)
            values = {("rev-parse", "HEAD"): pin["revision"],
                      ("rev-parse", "HEAD^{tree}"): pin["tree"],
                      ("status", "--porcelain", "--untracked-files=all"): ""}
            with mock.patch.object(self.module, "_git", side_effect=lambda unused, *args: values[args]), \
                    mock.patch.object(self.module, "sha256",
                                      side_effect=lambda path: pin["drivers"][Path(path).name]):
                observed = self.module.validate_fixture_checkout(source, pin)
        self.assertEqual(observed["revision"], pin["revision"])
        self.assertEqual(observed["tree"], pin["tree"])
        self.assertEqual(observed["drivers"], pin["drivers"])

    def test_manual_workflow_is_bounded_and_cannot_claim_qualification(self):
        workflow = (ROOT / ".github/workflows/landlock-qualification.yml").read_text()
        script = (ROOT / "scripts/check-container-qualification.sh").read_text()
        atomic = (ROOT / "image/atomic/hosted.py").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("options:\n          - landlock\n          - containers", workflow)
        self.assertIn("permissions:\n  contents: read\n  actions: read", workflow)
        self.assertIn("inputs.qualification", workflow)
        self.assertIn("check-container-qualification.sh", workflow)
        self.assertIn("be3bef1dababb49a68450a883dc1ba97fa6322b0", workflow)
        self.assertIn("path: .cache/container-fixture-source", workflow)
        self.assertIn("MemoryMax=4G", script)
        self.assertIn("MemorySwapMax=0", script)
        self.assertIn("CPUQuota=200%", script)
        self.assertIn("SYMBI_QUALIFICATION=containers", script)
        self.assertIn("qualification not in ('','landlock','update','containers')", atomic)
        self.assertIn("run_container_preflight", atomic)


if __name__ == "__main__":
    unittest.main()
