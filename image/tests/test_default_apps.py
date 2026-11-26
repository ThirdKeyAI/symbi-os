"""Fail-closed requirements for the owner-selected terminal applications."""
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DefaultApplicationRequirements(unittest.TestCase):
    def test_candidates_are_exact_unqualified_and_keep_security_blockers(self):
        data = json.loads((ROOT / "image/default_apps/requirements.json").read_text())
        self.assertEqual(set(data), {"schema", "qualified", "installed", "applications", "scope"})
        self.assertEqual(data["schema"], 1)
        self.assertIs(data["qualified"], False)
        self.assertIs(data["installed"], False)
        self.assertEqual(set(data["applications"]), {"yazi", "glum", "tootles"})
        expected = {
            "yazi": ("v26.9.1", "8dd895c695a5950330c2623eb43debf323b60654"),
            "glum": ("v0.4.1", "9cc45ced6ee0fc0bb5c6d90db65b453e6c2e650b"),
            "tootles": ("v0.2.0", "40d7a63c5ec0e08cb3eb8241b50a2af6cf76c98a"),
        }
        for name, app in data["applications"].items():
            with self.subTest(name=name):
                self.assertRegex(app["version"], r"^v[0-9]+(?:\.[0-9]+)+$")
                self.assertTrue(re.fullmatch(r"[a-f0-9]{40}", app["revision"]))
                self.assertEqual(app["repository"], {
                    "yazi": "https://github.com/sxyazi/yazi",
                    "glum": "https://github.com/jaschadub/glum",
                    "tootles": "https://github.com/tootles-dev/tootles",
                }[name])
                self.assertGreaterEqual(len(app["blockers"]), 3)
                self.assertEqual((app["version"], app["revision"]), expected[name])
        self.assertTrue(any("runtime package" in item
                            for item in data["applications"]["yazi"]["blockers"]))
        self.assertTrue(any("secret storage" in item
                            for item in data["applications"]["tootles"]["blockers"]))


if __name__ == "__main__":
    unittest.main()
