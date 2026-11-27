"""Acceptance tests for the P0 vertical-slice evidence summary."""
import unittest

from image.qualification.vertical_slice import validate_vertical_slice


class VerticalSliceTests(unittest.TestCase):
    binary = "a" * 64
    drivers = {
        "managed": "b" * 64,
        "external_effects": "c" * 64,
        "external_effects_verifier": "d" * 64,
        "external_effects_integrity": "e" * 64,
    }

    def setUp(self):
        self.release = {
            "passed": True,
            "binary_sha256": self.binary,
            "cases": [
                {"name": "managed", "passed": True, "exit_code": 0,
                 "driver": "test-landlock-managed.py",
                 "driver_sha256": self.drivers["managed"]},
                {"name": "external-effects", "passed": True, "exit_code": 0,
                 "verification_exit_code": 0, "integrity_exit_code": 0,
                 "driver": "test-external-effect-recovery.py",
                 "driver_sha256": self.drivers["external_effects"],
                 "verifier_sha256": self.drivers["external_effects_verifier"],
                 "integrity_sha256": self.drivers["external_effects_integrity"]},
            ],
        }
        self.managed = {
            "passed": True,
            "binary_sha256": self.binary,
            "cases": [
                {"name": "allowed", "passed": True, "exit_code": 0,
                 "provider_requests": [{}, {}],
                 "journal": {"sha256": "1" * 64, "public_key": "2" * 64}},
                {"name": "denied", "passed": True, "exit_code": 0,
                 "provider_requests": [{}, {}],
                 "journal": {"sha256": "3" * 64, "public_key": "4" * 64}},
            ],
        }
        self.effects = {"passed": True, "complete_suite": True, "cases": 5,
                        "receiver_effects": 5, "binary_sha256": self.binary,
                        "manifest_sha256": "5" * 64}
        self.integrity = {"passed": True, "original_cases": 5,
                          "rejected": ["missing_case", "receiver_substitution",
                                       "approval_substitution", "resolution_substitution",
                                       "resolution_signature"],
                          "optimization_refused": True}

    def validate(self):
        return validate_vertical_slice(self.release, self.managed, self.effects,
                                       self.integrity, self.binary, self.drivers)

    def test_accepts_explicit_cedar_and_journal_before_effect_proof(self):
        result = self.validate()
        self.assertTrue(result["passed"])
        self.assertEqual(result["cedar"]["decisions"], ["allowed", "denied"])
        self.assertEqual(result["journal_before_effect"]["receiver_effects"], 5)
        self.assertTrue(result["journal_before_effect"]["independently_verified"])

    def test_rejects_missing_cedar_deny_case(self):
        self.managed["cases"].pop()
        with self.assertRaisesRegex(ValueError, "Cedar allow/deny"):
            self.validate()

    def test_rejects_unverified_effect_ordering(self):
        self.effects["complete_suite"] = False
        with self.assertRaisesRegex(ValueError, "journal-before-effect"):
            self.validate()

    def test_rejects_changed_pinned_driver(self):
        self.release["cases"][0]["driver_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "managed driver"):
            self.validate()

    def test_rejects_binary_mismatch(self):
        self.managed["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binary"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
