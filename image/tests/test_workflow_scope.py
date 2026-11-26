"""Keep expensive hosted image work off ordinary feature-branch pushes."""
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
HEAVY = {
    "assembly-inputs.yml", "atomic-boot.yml", "atomic-preflight.yml",
    "desktop-image.yml", "desktop-packages.yml", "elephant-build.yml",
    "elephant-packages.yml", "elephant-runtime.yml", "fedora-base.yml",
    "fedora-packages.yml", "font-intake.yml", "graphics-cloud-boot.yml",
    "graphics-preflight.yml", "hyprland-build.yml",
    "hyprland-runtime-packages.yml", "hyprland-runtime.yml", "image-tools.yml",
    "kitty-bundle.yml", "launcher-packages.yml", "portal-build.yml",
    "portal-consent.yml", "portal-packages.yml", "portal-runtime.yml",
    "runtime-packages.yml", "walker-build.yml", "walker-packages.yml",
}


class WorkflowScopeTests(unittest.TestCase):
    def test_heavy_workflows_are_main_or_manual(self):
        root = ROOT / ".github/workflows"
        for name in sorted(HEAVY):
            with self.subTest(workflow=name):
                document = yaml.safe_load((root / name).read_text())
                triggers = document[True]
                self.assertIn("workflow_dispatch", triggers)
                self.assertEqual(triggers["push"]["branches"], ["main"])


if __name__ == "__main__":
    unittest.main()
