#!/usr/bin/env python3
"""Focused fail-closed tests for the OS security-control catalogue."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-security-controls.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("security_controls", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load security-control checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CommittedCatalogue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = load_checker()
        cls.catalogue = json.loads(
            (ROOT / "docs/security/controls.json").read_text(encoding="utf-8")
        )

    def test_exact_os_control_set_is_valid(self):
        self.assertEqual(self.checker.validate(ROOT, self.catalogue), 14)

    def test_missing_or_renamed_control_is_rejected(self):
        for mutate in ("missing", "old-prefix"):
            with self.subTest(mutate=mutate):
                catalogue = copy.deepcopy(self.catalogue)
                if mutate == "missing":
                    catalogue["controls"].pop()
                else:
                    catalogue["controls"][0]["id"] = "OS-INV-01"
                with self.assertRaisesRegex(ValueError, "exactly OSI-001 through OSI-014"):
                    self.checker.validate(ROOT, catalogue)

    def test_unknown_fields_are_rejected(self):
        catalogue = copy.deepcopy(self.catalogue)
        catalogue["controls"][0]["claim"] = "qualified"
        with self.assertRaisesRegex(ValueError, "invalid control fields"):
            self.checker.validate(ROOT, catalogue)

    def test_unqualified_validation_claim_is_rejected(self):
        catalogue = copy.deepcopy(self.catalogue)
        catalogue["controls"][0]["validation_status"] = "partial"
        with self.assertRaisesRegex(ValueError, "requires passing exact runtime evidence"):
            self.checker.validate(ROOT, catalogue)

    def test_implemented_claim_requires_exact_runtime_evidence(self):
        catalogue = copy.deepcopy(self.catalogue)
        catalogue["controls"][0]["implementation_status"] = "implemented"
        with self.assertRaisesRegex(ValueError, "implemented control requires"):
            self.checker.validate(ROOT, catalogue)

    def test_parent_source_reference_is_rejected(self):
        catalogue = copy.deepcopy(self.catalogue)
        catalogue["controls"][0]["sources"] = ["../outside"]
        with self.assertRaisesRegex(ValueError, "repository-relative"):
            self.checker.validate(ROOT, catalogue)


class RuntimeEvidence(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "source.txt").write_text("fixture\n", encoding="utf-8")
        self.report = {
            "schema_version": 1,
            "control_ids": ["OSI-001"],
            "source_revision": "a" * 40,
            "image_digest": "sha256:" + "b" * 64,
            "configuration_digest": "c" * 64,
            "driver_sha256": "d" * 64,
            "verifier_sha256": "e" * 64,
            "platform": "fixture",
            "timestamp": "2026-11-27T00:00:00Z",
            "routes": ["fixture_route"],
            "backends": ["fixture_backend"],
            "checks": [{"name": "runtime observation", "passed": True}],
            "passed": True,
            "errors": [],
        }
        self.reference = {
            "report": "report.json",
            "sha256": "",
            "routes": ["fixture_route"],
            "backends": ["fixture_backend"],
        }
        self.control = {
            "id": "OSI-001",
            "title": "fixture",
            "threat": "fixture",
            "invariant": "INV-1: fixture",
            "owner": "fixture owner",
            "implementation_status": "partial",
            "validation_status": "partial",
            "routes": ["fixture_route"],
            "backends": ["fixture_backend"],
            "sources": ["source.txt"],
            "tests": [],
            "limitations": ["fixture only"],
            "qualifications": [self.reference],
        }
        self.save_report()

    def save_report(self):
        path = self.root / "report.json"
        path.write_text(json.dumps(self.report), encoding="utf-8")
        self.reference["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    def test_exact_passing_report_can_support_partial_validation(self):
        self.assertTrue(self.checker.validate_control(self.root, self.control))

    def test_changed_report_is_rejected(self):
        (self.root / "report.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.checker.validate_control(self.root, self.control)

    def test_duplicate_report_field_is_rejected(self):
        (self.root / "report.json").write_text(
            '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
        )
        self.reference["sha256"] = hashlib.sha256(
            (self.root / "report.json").read_bytes()
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            self.checker.validate_control(self.root, self.control)

    def test_passing_flag_cannot_hide_failed_check(self):
        self.report["checks"][0]["passed"] = False
        self.save_report()
        with self.assertRaisesRegex(ValueError, "failed checks"):
            self.checker.validate_control(self.root, self.control)

    def test_report_cannot_claim_another_control(self):
        self.report["control_ids"] = ["OSI-002"]
        self.save_report()
        with self.assertRaisesRegex(ValueError, "does not cover"):
            self.checker.validate_control(self.root, self.control)

    def test_untested_control_cannot_attach_qualification(self):
        self.control["validation_status"] = "untested"
        with self.assertRaisesRegex(ValueError, "must not attach qualification"):
            self.checker.validate_control(self.root, self.control)


if __name__ == "__main__":
    unittest.main()
