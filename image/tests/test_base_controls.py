"""Inventory admin tools and public controls without reading unrelated files."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("guest_inventory", Path(__file__).parents[1] / "hyprland/guest_inventory.py")
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


class BaseControlDiscovery(unittest.TestCase):
    def test_admin_executable_is_found_outside_bin_and_environment_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("bin", "sbin", "untrusted"):
                (root / name).mkdir()
            executable = root / "sbin/visudo"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            (root / "bin/sudo").write_text("not executable")
            (root / "untrusted/sudo").write_text("#!/bin/sh\nexit 0\n")
            (root / "untrusted/sudo").chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(root / "untrusted")}):
                result = guest.discover_tools(("sudo", "visudo"), (root / "bin", root / "sbin"))
            self.assertIsNone(result["sudo"])
            self.assertEqual(result["visudo"], str(executable))

    def test_public_control_selection_records_links_without_reading_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "greetd").mkdir()
            (root / "greetd/config.toml").write_text("[default_session]\n")
            (root / "shadow").write_text("not public")
            (root / "sysctl.d").mkdir()
            (root / "sysctl.d/50-test.conf").write_text("user.max_user_namespaces=0\n")
            (root / "sysctl.d/51-linked.conf").symlink_to(root / "shadow")
            (root / "sysctl.d/unrelated.txt").write_text("not configuration")
            result = guest.discover_controls((root,))
            self.assertEqual(result["files"][str(root / "greetd/config.toml")]["text"], "[default_session]\n")
            self.assertIn(str(root / "sysctl.d/50-test.conf"), result["files"])
            self.assertNotIn(str(root / "sysctl.d/51-linked.conf"), result["files"])
            self.assertEqual(result["links"][str(root / "sysctl.d/51-linked.conf")], str(root / "shadow"))
            self.assertNotIn("not public", str(result))
            self.assertNotIn("not configuration", str(result))
            self.assertIn(str(root / "sudoers"), result["missing_fixed_paths"])

    def test_oversized_control_refuses_without_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (root / "sudoers").open("wb") as stream:
                stream.truncate(262145)
            with self.assertRaisesRegex(ValueError, "too large"):
                guest.discover_controls((root,))

    def test_linked_configuration_directory_is_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            target = Path(directory) / "private"
            root.mkdir()
            target.mkdir()
            (target / "secret.rules").write_text("do not read this")
            (root / "polkit-1").symlink_to(target, target_is_directory=True)
            (target / "rules.d").symlink_to(target, target_is_directory=True)
            result = guest.discover_controls((root,))
            self.assertEqual(result["links"][str(root / "polkit-1")], str(target))
            self.assertNotIn("do not read this", str(result))


if __name__ == "__main__":
    unittest.main()
