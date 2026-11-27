"""Keep expensive hosted image work off ordinary feature-branch pushes."""
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
HEAVY = {
    "assembly-inputs.yml", "atomic-boot.yml", "atomic-preflight.yml",
    "desktop-image.yml", "desktop-packages.yml", "elephant-build.yml",
    "elephant-packages.yml", "elephant-runtime.yml", "fedora-base.yml",
    "font-intake.yml", "graphics-cloud-boot.yml",
    "graphics-preflight.yml", "hyprland-build.yml",
    "hyprland-runtime-packages.yml", "hyprland-runtime.yml", "image-tools.yml",
    "kitty-bundle.yml", "launcher-packages.yml", "portal-build.yml",
    "portal-consent.yml", "portal-packages.yml", "portal-runtime.yml",
    "runtime-packages.yml", "walker-build.yml", "walker-packages.yml",
}
P0_05_PASSIVE_INPUTS = {"fedora-packages.yml", "gvisor-intake.yml"}
P0_05_PREP_BRANCH = "card/P0-05-native-prep"


class WorkflowScopeTests(unittest.TestCase):
    def test_heavy_workflows_are_main_or_manual(self):
        root = ROOT / ".github/workflows"
        for name in sorted(HEAVY):
            with self.subTest(workflow=name):
                document = yaml.safe_load((root / name).read_text())
                triggers = document[True]
                self.assertIn("workflow_dispatch", triggers)
                self.assertEqual(triggers["push"]["branches"], ["main"])

    def test_only_passive_input_workflows_run_on_p0_05_prep_branch(self):
        root = ROOT / ".github/workflows"
        selected = set()
        for path in sorted(root.glob("*.yml")):
            document = yaml.safe_load(path.read_text())
            triggers = document[True]
            if not isinstance(triggers, dict) or "push" not in triggers:
                continue
            push = triggers["push"]
            self.assertIsInstance(
                push, dict, f"{path.name} must not push on every branch")
            self.assertIn(
                "branches", push, f"{path.name} must scope its push branches")
            branches = push["branches"]
            if P0_05_PREP_BRANCH in branches:
                selected.add(path.name)
                self.assertEqual(branches, ["main", P0_05_PREP_BRANCH])
                self.assertEqual(document.get("permissions"), {"contents": "read"})
        self.assertEqual(selected, P0_05_PASSIVE_INPUTS)


if __name__ == "__main__":
    unittest.main()
