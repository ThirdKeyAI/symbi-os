"""An empty /etc inventory must not satisfy package-input discovery."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("guest_inventory", Path(__file__).parents[1] / "hyprland/guest_inventory.py")
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)
HOST_SPEC = importlib.util.spec_from_file_location("inventory", Path(__file__).parents[1] / "hyprland/inventory.py")
host = importlib.util.module_from_spec(HOST_SPEC)
HOST_SPEC.loader.exec_module(host)


class PackageInputDiscovery(unittest.TestCase):
    def test_distribution_owned_dnf5_paths(self):
        owned = ["/usr/share/dnf5/repos.d/fedora.repo",
                 "/usr/share/pki/rpm-gpg/RPM-GPG-KEY-fedora-45-primary",
                 "/usr/share/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary",
                 "/etc/shadow", "/home/private.repo"]
        selected = guest.package_metadata_paths(owned, "45")
        self.assertEqual(selected, [Path(name) for name in owned[:2]])
        result = guest.require_package_inputs({str(p): {} for p in selected}, "45")
        self.assertEqual(result["repository_files"], [owned[0]])
        self.assertFalse(result["rpm_signatures_verified"])

    def test_empty_configuration_is_incomplete(self):
        with self.assertRaises(ValueError):
            guest.require_package_inputs({}, "45")

    def test_wrong_release_key_is_incomplete(self):
        files = {"/usr/etc/yum.repos.d/fedora.repo": {},
                 "/usr/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary": {}}
        with self.assertRaises(ValueError):
            guest.require_package_inputs(files, "45")

    def test_record_bootc_and_backup_paths_without_claiming_authentication(self):
        files = {"/usr/etc/yum.repos.d/fedora.repo": {},
                 "/usr/share/secureblue/etc/yum.repos.d/fedora-updates.repo": {},
                 "/usr/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-45-primary": {}}
        result = guest.require_package_inputs(files, "45")
        self.assertEqual(result["repository_files"], sorted(list(files)[:2]))
        self.assertEqual(result["fedora_release_key_files"], [list(files)[2]])
        self.assertFalse(result["rpm_signatures_verified"])


class PartialInventoryEvidence(unittest.TestCase):
    def test_failure_retains_child_output_and_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "inventory.json"
            script = 'print(\'{"package_inputs_complete": false}\'); raise SystemExit(1)'
            with self.assertRaises(subprocess.CalledProcessError):
                host.collect_inventory([sys.executable, "-"], script, output)
            self.assertEqual(output.read_text(), '{"package_inputs_complete": false}\n')

    def test_success_must_have_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                host.collect_inventory([sys.executable, "-"], 'print("not json")', Path(directory) / "inventory.json")


if __name__ == "__main__":
    unittest.main()
