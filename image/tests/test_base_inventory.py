"""Reject unbound or absent signature results before executing a base image."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("inventory", Path(__file__).parents[1] / "hyprland/inventory.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class BaseSignature(unittest.TestCase):
    image = "ghcr.io/secureblue/sericea-main-hardened@sha256:" + "1" * 64

    def payload(self):
        return [{"critical": {"type": "cosign container image signature",
                "identity": {"docker-reference": self.image.split("@")[0]},
                "image": {"docker-manifest-digest": self.image.split("@")[1]}}}]

    def test_accept_exact_verified_subject(self):
        inventory.require_subject(self.payload(), self.image)

    def test_reject_no_verified_signatures(self):
        with self.assertRaises(ValueError):
            inventory.require_subject([], self.image)

    def test_reject_different_digest(self):
        data = self.payload()
        data[0]["critical"]["image"]["docker-manifest-digest"] = "sha256:" + "2" * 64
        with self.assertRaises(ValueError):
            inventory.require_subject(data, self.image)

    def test_reject_different_repository(self):
        data = self.payload()
        data[0]["critical"]["identity"]["docker-reference"] = "ghcr.io/example/other"
        with self.assertRaises(ValueError):
            inventory.require_subject(data, self.image)

    def test_reject_malformed_evidence(self):
        for value in ({}, [{}], [{"critical": {}}], [False]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                inventory.require_subject(value, self.image)


if __name__ == "__main__":
    unittest.main()
