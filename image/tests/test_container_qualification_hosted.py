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
        requirements = json.loads(
            (ROOT / "image/container/runtime-requirements.json").read_text())
        base = json.loads((ROOT / "image/base-images.json").read_text())
        repository = json.loads(
            (ROOT / "image/hyprland/package-repository-inputs.json").read_text())
        desktop = json.loads((ROOT / "image/desktop-images.lock.json").read_text())
        selected_image = desktop["images"]["generic"]
        candidate_lock = json.loads(
            (ROOT / "image/container/fedora-runtime-candidates.lock.json").read_text())
        source_plan = candidate_lock["source_package_plan"]
        package_names = [*requirements["packages"], "libcontainer-support"] + [
            f"dependency-{index:03}" for index in range(candidate_lock["package_count"] - 4)
        ]
        sizes = [1024 + index for index in range(len(package_names))]
        sizes[-1] += candidate_lock["package_bytes"] - sum(sizes)
        packages = [
            {
                "filename": name + "-1-1.x86_64.rpm",
                "bytes": sizes[index],
                "sha256": f"{index + 1:064x}",
                "nevra": source_plan["requested_root_nevras"].get(
                    name, name + "-1-1.x86_64"),
                "vendor": "Fedora Project",
                "license": "Apache-2.0",
                "signature_verified": True,
                "key_fingerprint": "4F50A6114CD5C6976A7F1179655A4B02F577861E",
            }
            for index, name in enumerate(package_names)
        ]
        contract = {
            "schema": 1,
            "selected": True,
            "installed": True,
            "qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "requested_packages": requirements["packages"],
            "discovery": {
                "repository": candidate_lock["repository"],
                "workflow": candidate_lock["workflow"],
                "profile": candidate_lock["profile"],
                "run_id": candidate_lock["run_id"],
                "run_attempt": candidate_lock["run_attempt"],
                "source_commit": candidate_lock["source_commit"],
                "base": base["variants"]["generic"]["image"],
                "requirements_sha256": self.module.sha256(
                    ROOT / "image/container/runtime-requirements.json"),
                "repository_configuration_sha256": repository[
                    "selected_configuration_sha256"],
                "rpm_manifest_sha256": "a" * 64,
                "input_bindings_sha256": "b" * 64,
                "package_count": candidate_lock["package_count"],
                "artifact": candidate_lock["candidate_artifact"],
            },
            "packages": packages,
            "installation": {
                "image_source_commit": selected_image["tested_commit"],
                "image_manifest_sha256": selected_image["manifest_sha256"],
                "image_producer": candidate_lock["source_image_producer"],
                "before_inventory_sha256": source_plan["inventory"]["canonical_sha256"],
                "after_inventory_sha256": source_plan["inventory"]["canonical_sha256"],
                "source_inventory_sha256": source_plan["inventory"]["canonical_sha256"],
                "requested_root_nevras": source_plan["requested_root_nevras"],
                "added_nevras": [],
                "rpm_transaction_empty": True,
                "daemon_configuration_sha256": self.module.sha256(
                    ROOT / "image/container/daemon.json"),
            },
            "files": {path: {"sha256": value} for path, value in identity["package_files"].items()},
            "runsc_package_sha256": identity["package_sha256"],
            "runsc_repository_fingerprint": identity["signing_fingerprint"],
        }
        self.module.validate_fedora_contract(
            contract, identity, ROOT, selected_image["tested_commit"])
        changes = [
            ("selected", False),
            ("installed", False),
            ("qualified", True),
            ("os_qualified", True),
            ("release_qualified", True),
            ("runsc_package_sha256", "0" * 64),
            ("runsc_repository_fingerprint", "0" * 40),
        ]
        for field, value in changes:
            candidate = copy.deepcopy(contract)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.validate_fedora_contract(
                    candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        candidate["packages"] = [
            row for row in candidate["packages"]
            if not row["nevra"].startswith("container-selinux-")]
        candidate["discovery"]["package_count"] = len(candidate["packages"])
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        candidate["packages"][0]["signature_verified"] = False
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        candidate["packages"][0]["key_fingerprint"] = "d" * 40
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        # Fedora's selected repositories use repo_gpgcheck=0. There is no
        # per-package repository_metadata_sha256 to synthesize; the contract
        # must preserve the RPM signature evidence the discovery job produced.
        candidate["packages"][0]["repository_metadata_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        candidate["packages"].append(copy.deepcopy(candidate["packages"][0]))
        candidate["discovery"]["package_count"] = len(candidate["packages"])
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        package = next(row for row in candidate["packages"]
                       if row["nevra"].startswith("container-selinux-"))
        package["filename"] = "container-selinux-evil-1-1.x86_64.rpm"
        package["nevra"] = "container-selinux-evil-1-1.x86_64"
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])
        for field, value in (
            ("source_inventory_sha256", "0" * 64),
            ("before_inventory_sha256", "0" * 64),
            ("added_nevras", ["libzstd-1.6.0-1.fc45.x86_64"]),
            ("rpm_transaction_empty", False),
            ("requested_root_nevras", {
                **source_plan["requested_root_nevras"],
                "moby-engine": "moby-engine-0-0.fc45.x86_64",
            }),
        ):
            candidate = copy.deepcopy(contract)
            candidate["installation"][field] = value
            with self.subTest(installation=field), self.assertRaises(ValueError):
                self.module.validate_fedora_contract(
                    candidate, identity, ROOT, selected_image["tested_commit"])
        candidate = copy.deepcopy(contract)
        candidate["files"]["usr/bin/runsc"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.module.validate_fedora_contract(
                candidate, identity, ROOT, selected_image["tested_commit"])

    def test_preflight_stays_unqualified_and_hash_binds_shared_boot_status_inputs(self):
        result = self.module.build_preflight(ROOT, "1" * 40, "2" * 40,
                                             verify=lambda *arguments: None)
        self.assertFalse(result["passed"])
        self.assertFalse(result["qualified"])
        self.assertFalse(result["native_fixture_matrix_passed"])
        self.assertFalse(result["managed_route_qualified"])
        self.assertFalse(result["escape_suite_qualified"])
        self.assertIn("pending-container-runtime-image", result["blockers"])
        self.assertEqual(set(result["shared_boot_status_inputs"]),
                         set(self.module.SHARED_BOOT_STATUS_INPUTS))
        self.assertTrue(all(len(value) == 64 for value in result["shared_boot_status_inputs"].values()))
        self.assertNotIn("gvisor-inputs.json", json.dumps(result))
        self.assertEqual(result["fixture_source"]["revision"],
                         "cd4b34282ade880c8ac3d5136d31ff80cde92794")
        self.assertEqual(result["fixture_source"]["tree"],
                         "2b2379d0de4eaaf4a57cf52c96355015bb3dc25d")
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

    def test_ready_input_preflight_passes_without_claiming_qualification(self):
        prepared = {
            "schema": 1,
            "card": "P0-05",
            "passed": False,
            "qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "native_fixture_matrix_passed": False,
            "managed_route_qualified": False,
            "escape_suite_qualified": False,
            "fedora_runtime_ready": True,
            "container_boot": {
                "qualified": False,
                "os_qualified": False,
                "release_qualified": False,
                "remaining_blocker": "native-fedora-six-run-matrix",
            },
            "fixture_source": {"revision": "a" * 40},
            "blockers": ["native-fedora-six-run-matrix", "managed-route-evidence",
                         "escape-suite-evidence", "required-review"],
        }
        checkout = {"revision": "a" * 40, "tree": "b" * 40, "drivers": {}}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(self.module, "build_preflight", return_value=prepared), \
                mock.patch.object(self.module, "validate_fixture_checkout", return_value=checkout):
            root = Path(directory)
            result = self.module.run_container_preflight(root, "1" * 40, "2" * 40)
            retained = json.loads(
                (root / ".cache/container-qualification-evidence/result.json").read_text())
        self.assertTrue(result["passed"])
        self.assertEqual(retained, result)
        self.assertEqual(result["fixture_checkout"], checkout)
        self.assertFalse(result["qualified"])
        self.assertFalse(result["os_qualified"])
        self.assertFalse(result["release_qualified"])
        self.assertFalse(result["native_fixture_matrix_passed"])
        self.assertIn("native-fedora-six-run-matrix", result["blockers"])

    def test_ready_input_without_candidate_boot_binding_stays_failed(self):
        prepared = {
            "schema": 1,
            "card": "P0-05",
            "passed": False,
            "qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "native_fixture_matrix_passed": False,
            "managed_route_qualified": False,
            "escape_suite_qualified": False,
            "fedora_runtime_ready": True,
            "fixture_source": {"revision": "a" * 40},
            "blockers": ["native-fedora-six-run-matrix", "managed-route-evidence",
                         "escape-suite-evidence", "required-review"],
        }
        checkout = {"revision": "a" * 40, "tree": "b" * 40, "drivers": {}}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(self.module, "build_preflight", return_value=prepared), \
                mock.patch.object(self.module, "validate_fixture_checkout", return_value=checkout):
            result = self.module.run_container_preflight(
                Path(directory), "1" * 40, "2" * 40)
        self.assertFalse(result["passed"])
        self.assertNotIn("container_boot", result)

    def test_candidate_boot_binding_uses_exact_generated_contract_and_image(self):
        archive = {
            "name": "symbi-container-runtime-generic.oci.tar.gz",
            "bytes": 123456,
            "sha256": "a" * 64,
            "image_id": "sha256:" + "b" * 64,
            "manifest_digest": "sha256:" + "c" * 64,
        }
        candidate = {
            "selection": {
                "manifest": {
                    "sha256": "d" * 64,
                    "contract_sha256": "e" * 64,
                    "archive": copy.deepcopy(archive),
                },
            },
            "manifest": {"archive": copy.deepcopy(archive), "contract_sha256": "e" * 64},
        }
        contract = {
            "qualified": False,
            "os_qualified": False,
            "release_qualified": False,
            "files": {
                "usr/bin/runsc": {"sha256": "f" * 64},
                "etc/containerd/runsc.toml": {"sha256": "1" * 64},
            },
            "installation": {
                "after_inventory_sha256": "2" * 64,
                "source_inventory_sha256": "2" * 64,
                "daemon_configuration_sha256": "3" * 64,
            },
        }
        binding = self.module.build_container_boot_binding(candidate, contract)
        self.assertEqual(binding["archive"], archive)
        self.assertEqual(binding["generated_manifest_sha256"], "d" * 64)
        self.assertEqual(binding["contract_sha256"], "e" * 64)
        self.assertEqual(binding["runsc_files"], {
            "usr/bin/runsc": "f" * 64,
            "etc/containerd/runsc.toml": "1" * 64,
        })
        self.assertEqual(binding["daemon_configuration_sha256"], "3" * 64)
        self.assertEqual(binding["remaining_blocker"], "native-fedora-six-run-matrix")
        self.assertFalse(binding["qualified"])
        self.assertFalse(binding["os_qualified"])
        self.assertFalse(binding["release_qualified"])

        changes = []
        changed = copy.deepcopy(candidate)
        changed["manifest"]["archive"]["image_id"] = "sha256:" + "0" * 64
        changes.append((changed, contract))
        changed_contract = copy.deepcopy(contract)
        changed_contract["qualified"] = True
        changes.append((candidate, changed_contract))
        changed_contract = copy.deepcopy(contract)
        changed_contract["files"]["../runsc"] = changed_contract["files"].pop("usr/bin/runsc")
        changes.append((candidate, changed_contract))
        changed_contract = copy.deepcopy(contract)
        changed_contract["installation"]["after_inventory_sha256"] = "4" * 64
        changes.append((candidate, changed_contract))
        for changed_candidate, changed_contract in changes:
            with self.subTest(change=changed_contract), self.assertRaises(ValueError):
                self.module.build_container_boot_binding(changed_candidate, changed_contract)

    def test_pending_runtime_image_preflight_fails_before_native_image_work(self):
        prepared = {
            "schema": 1,
            "card": "P0-05",
            "passed": False,
            "qualified": False,
            "fedora_runtime_ready": False,
            "fixture_source": {"revision": "a" * 40},
            "blockers": ["pending-container-runtime-image", "native-fedora-six-run-matrix"],
        }
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(self.module, "build_preflight", return_value=prepared), \
                mock.patch.object(self.module, "validate_fixture_checkout", return_value={}):
            result = self.module.run_container_preflight(
                Path(directory), "1" * 40, "2" * 40)
        self.assertFalse(result["passed"])
        self.assertIn("pending-container-runtime-image", result["blockers"])

    def test_manual_workflow_is_bounded_and_cannot_claim_qualification(self):
        workflow = (ROOT / ".github/workflows/landlock-qualification.yml").read_text()
        preflight_script = (ROOT / "scripts/check-container-preflight.sh").read_text()
        script = (ROOT / "scripts/check-container-qualification.sh").read_text()
        atomic = (ROOT / "image/atomic/hosted.py").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("options:\n          - landlock\n          - containers", workflow)
        self.assertIn("permissions:\n  contents: read\n  actions: read", workflow)
        self.assertIn("inputs.qualification", workflow)
        self.assertIn("check-container-qualification.sh", workflow)
        self.assertIn("cd4b34282ade880c8ac3d5136d31ff80cde92794", workflow)
        self.assertIn("path: .cache/container-fixture-source", workflow)
        self.assertLess(
            workflow.index("Validate and download the exact retained container-runtime image"),
            workflow.index("Authenticate and stream the exact retained container-runtime image"),
        )
        self.assertIn("bash scripts/check-container-runtime-native-transfer.sh", workflow)
        self.assertIn("bash scripts/check-container-preflight.sh", workflow)
        self.assertIn("bash scripts/check-container-runtime-native-input.sh", workflow)
        self.assertIn("env.SYMBI_REQUESTED_QUALIFICATION == 'containers'", workflow)
        self.assertIn("run_container_preflight", preflight_script)
        self.assertIn('result.get("passed") is not True', preflight_script)
        self.assertIn('result.get("qualified") is not False', preflight_script)
        self.assertNotIn("gh api", preflight_script)
        self.assertIn("MemoryMax=4G", script)
        self.assertIn("MemorySwapMax=0", script)
        self.assertIn("CPUQuota=200%", script)
        self.assertIn("SYMBI_QUALIFICATION=containers", script)
        self.assertIn('exit "$status"', script)
        self.assertIn("qualification not in ('','landlock','update','containers')", atomic)
        self.assertIn("qualification in ('landlock','containers')", atomic)
        self.assertIn("'4294967296'", atomic)
        self.assertIn("'5368709120'", atomic)
        self.assertIn("run_container_preflight", atomic)
        self.assertIn("native-fedora-six-run-matrix", atomic)
        self.assertIn("container_candidate", atomic)
        self.assertIn("container-runtime-native-inputs", atomic)
        self.assertIn(
            "stop_after_container_candidate_boot(record,report['container_candidate'])",
            atomic,
        )
        self.assertIn("'candidate_boot_passed':True", atomic)
        self.assertIn("qualification remains blocked", atomic)
        self.assertNotIn("Fedora container native six-run controller is not yet bound", atomic)


if __name__ == "__main__":
    unittest.main()
