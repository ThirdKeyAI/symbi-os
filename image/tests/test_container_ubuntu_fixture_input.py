"""Pending-lock and public-entry tests for offline Ubuntu fixture inputs."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

from image.container import ubuntu_fixture_inputs as inputs
from image.container import ubuntu_fixture_packages as packages


ROOT = Path(__file__).resolve().parents[2]


class UbuntuFixtureInputContract(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "image/container/ubuntu-fixture-packages.lock.json"
        self.lock = packages.unique_json(self.path)

    def test_committed_pending_contract_is_complete_but_not_usable(self):
        result = inputs.validate_pending_lock(ROOT, copy.deepcopy(self.lock))
        self.assertEqual(result, {
            "ready": False,
            "status": "pending",
            "blocker": "offline-ubuntu-package-closure",
        })
        for flag in inputs.CLAIM_FIELDS:
            self.assertIs(self.lock[flag], False)
        self.assertEqual(self.lock["release_metadata"], [])
        self.assertEqual(self.lock["package_indexes"], [])
        self.assertEqual(self.lock["packages"], [])
        self.assertEqual(self.lock["package_count"], 0)
        self.assertEqual(self.lock["package_bytes"], 0)
        self.assertIsNone(self.lock["producer"]["run_id"])
        self.assertIsNone(self.lock["artifact"]["id"])

    def test_runtime_and_fixture_sources_remain_distinct_and_exact(self):
        source = self.lock["fixture_source"]
        self.assertEqual(
            source["runtime_source_revision"],
            "deddb9e997244d2289c217ad76b8fde0e9b0339b",
        )
        self.assertEqual(
            source["fixture_revision"],
            "cd4b34282ade880c8ac3d5136d31ff80cde92794",
        )
        self.assertEqual(
            source["fixture_tree"],
            "2b2379d0de4eaaf4a57cf52c96355015bb3dc25d",
        )
        self.assertNotEqual(
            source["runtime_source_revision"], source["fixture_revision"])

    def test_unexpected_fields_wrong_anchors_and_source_mutations_fail(self):
        cases = []
        changed = copy.deepcopy(self.lock)
        changed["unexpected"] = True
        cases.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["artifact"]["unexpected"] = True
        cases.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["fixture_source"]["fixture_tree"] = "0" * 40
        cases.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["fixture_source"]["runtime_source_revision"] = \
            changed["fixture_source"]["fixture_revision"]
        cases.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["package_request"]["roots"].reverse()
        cases.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["sources"][0]["metadata"]["signer_fingerprint"] = None
        cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inputs.validate_pending_lock(ROOT, changed)

    def test_every_claim_status_and_readiness_mutation_fails_closed(self):
        for flag in inputs.CLAIM_FIELDS:
            changed = copy.deepcopy(self.lock)
            changed[flag] = True
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                inputs.validate_pending_lock(ROOT, changed)
        for status in ("ready", "selected", "complete"):
            changed = copy.deepcopy(self.lock)
            changed["status"] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                inputs.validate_pending_lock(ROOT, changed)

    def test_pending_lock_rejects_run_artifact_metadata_and_payload_rows(self):
        mutations = []
        for field, value in (
            ("workflow", ".github/workflows/container-fixtures.yml"),
            ("run_id", 123), ("run_attempt", 1), ("head_sha", "a" * 40),
        ):
            changed = copy.deepcopy(self.lock)
            changed["producer"][field] = value
            mutations.append(changed)
        for field, value in (
            ("id", 123), ("bytes", 4096), ("sha256", "a" * 64),
        ):
            changed = copy.deepcopy(self.lock)
            changed["artifact"][field] = value
            mutations.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["release_metadata"] = [{}]
        mutations.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["package_indexes"] = [{}]
        mutations.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["packages"] = [{}]
        mutations.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["package_count"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(self.lock)
        changed["package_bytes"] = 1
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                inputs.validate_pending_lock(ROOT, changed)

    def test_artifact_selection_and_all_use_modes_are_blocked_while_pending(self):
        candidate = {
            "selected": False,
            "id": 123,
            "name": packages.ARTIFACT_NAME,
            "bytes": 4096,
            "sha256": "a" * 64,
            "run": {"id": 456, "attempt": 1, "head_sha": "b" * 40},
        }
        metadata = {
            "id": 123,
            "name": packages.ARTIFACT_NAME,
            "size_in_bytes": 4096,
            "digest": "sha256:" + "a" * 64,
            "expired": False,
            "workflow_run": {
                "id": 456,
                "head_sha": "b" * 40,
                "repository_id": packages.REPOSITORY["id"],
                "head_repository_id": packages.REPOSITORY["id"],
            },
        }
        with self.assertRaises(ValueError):
            inputs.validate_artifact_for_use(ROOT, self.lock, candidate, metadata)
        for mode in ("consume", "build", "materialize"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                inputs.require_mode(ROOT, self.lock, mode)

    def test_duplicate_keys_in_committed_shape_fail_before_validation(self):
        raw = self.path.read_text()
        duplicate = raw.replace('"schema": 1,', '"schema": 1,\n  "schema": 1,', 1)
        with self.assertRaises(ValueError):
            packages.unique_json_bytes(duplicate.encode())

    def test_public_check_passes_only_pending_schema_validation(self):
        script = ROOT / "scripts/check-container-ubuntu-packages.sh"
        checked = subprocess.run(
            ["bash", str(script), "check"], cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('"ready": false', checked.stdout)
        for mode in ("consume", "build", "materialize"):
            blocked = subprocess.run(
                ["bash", str(script), mode], cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            with self.subTest(mode=mode):
                self.assertNotEqual(blocked.returncode, 0)
                self.assertIn("pending", blocked.stderr.lower())

    def test_producer_workflow_and_native_build_remain_unwired(self):
        workflow = (ROOT / ".github/workflows/container-fixtures.yml").read_text()
        producer = (ROOT / "image/container/native_fixture_build.py").read_text()
        prerequisites = json.loads(
            (ROOT / "image/container/native-fixture-build.lock.json").read_text())
        self.assertNotIn("ubuntu_fixture_inputs", workflow)
        self.assertNotIn("ubuntu_fixture_packages", workflow)
        self.assertNotIn("ubuntu_fixture_inputs", producer)
        self.assertIn("offline-ubuntu-package-closure", prerequisites["blockers"])


if __name__ == "__main__":
    unittest.main()
