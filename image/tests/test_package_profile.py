"""Keep launcher discovery separate from the authenticated compositor lock."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('package_inventory', Path(__file__).parents[1] / 'hyprland/package_inventory.py')
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class PackageProfiles(unittest.TestCase):
    def test_profiles_select_separate_fixed_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for profile, relative in [('hyprland', 'image/hyprland/build-requirements.json'),
                                      ('launcher', 'image/launcher/runtime-requirements.json')]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"packages": ["' + profile + '"]}')
                self.assertEqual(inventory.requirements_input(root, profile), relative)

    def test_unknown_or_path_profile_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            for profile in ('', '../hyprland', '/etc/shadow', 'unreviewed'):
                with self.subTest(profile=profile), self.assertRaises(ValueError):
                    inventory.requirements_input(Path(directory), profile)

    def test_selected_input_cannot_follow_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'image/launcher/runtime-requirements.json'
            path.parent.mkdir(parents=True)
            other = root / 'unreviewed.json'
            other.write_text('{"packages": ["unexpected"]}')
            path.symlink_to(other)
            with self.assertRaises(ValueError):
                inventory.requirements_input(root, 'launcher')


if __name__ == '__main__':
    unittest.main()
