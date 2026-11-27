"""Recognize the selected secureblue derivative without accepting arbitrary ID_LIKE."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("guest_inventory", Path(__file__).parents[1] / "hyprland/guest_inventory.py")
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


class FedoraIdentity(unittest.TestCase):
    def test_accept_fedora(self):
        guest.require_fedora_family({"ID": "fedora"})

    def test_accept_selected_secureblue_family(self):
        guest.require_fedora_family({"ID": "secureblue", "ID_LIKE": "fedora"})

    def test_reject_unknown_derivative(self):
        with self.assertRaises(ValueError):
            guest.require_fedora_family({"ID": "unrelated", "ID_LIKE": "fedora"})

    def test_reject_secureblue_without_fedora_base(self):
        for fields in ({"ID": "secureblue"}, {"ID": "secureblue", "ID_LIKE": "not-fedora"}, {}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                guest.require_fedora_family(fields)


if __name__ == "__main__":
    unittest.main()
