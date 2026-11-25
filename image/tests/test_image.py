"""Small, offline acceptance tests; these are not Fedora VM qualification."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / "image/overlay"


class Defaults(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "defaults"
        self.target = self.root / "config"
        (self.source / "hypr").mkdir(parents=True)
        (self.source / "hypr/with spaces.conf").write_text("default\n")

    def run_copy(self):
        return subprocess.run(
            ["bash", str(OVERLAY / "usr/libexec/symbi-seed-config"),
             str(self.source), str(self.target)],
            text=True, capture_output=True, timeout=5)

    def test_first_login_and_repeat_preserve_user_edits(self):
        self.assertEqual(self.run_copy().returncode, 0)
        target = self.target / "hypr/with spaces.conf"
        self.assertEqual(target.read_text(), "default\n")
        target.write_text("my settings\n")
        (self.source / "hypr/new.conf").write_text("new\n")
        self.assertEqual(self.run_copy().returncode, 0)
        self.assertEqual(target.read_text(), "my settings\n")
        self.assertEqual((self.target / "hypr/new.conf").read_text(), "new\n")

    def test_existing_symlink_is_neither_replaced_nor_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.target.mkdir()
        (self.target / "hypr").symlink_to(outside, target_is_directory=True)
        result = self.run_copy()
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((self.target / "hypr").is_symlink())

    def test_root_symlink_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.target.symlink_to(outside, target_is_directory=True)
        result = self.run_copy()
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(list(outside.iterdir()), [])

    def test_source_symlinks_are_rejected(self):
        (self.source / "escape").symlink_to("/etc/passwd")
        result = self.run_copy()
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlink", result.stderr)
        self.assertFalse((self.target / "escape").exists())

    def test_existing_file_symlink_is_preserved(self):
        (self.target / "hypr").mkdir(parents=True)
        outside = self.root / "user-settings"
        outside.write_text("my linked settings\n")
        target = self.target / "hypr/with spaces.conf"
        target.symlink_to(outside)
        self.assertEqual(self.run_copy().returncode, 0)
        self.assertTrue(target.is_symlink())
        self.assertEqual(outside.read_text(), "my linked settings\n")


class RecipePins(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("image_recipe", ROOT / "image/recipe.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "image/keys").mkdir(parents=True)
        self.key = self.root / "image/keys/test.pub"
        # A schema fixture, never a signature verification or release key.
        self.key.write_text("test fixture public key\n")
        self.config = {
            "schema": 1,
            "variants": {"generic": {
                "image": "ghcr.io/example/test@sha256:" + "a" * 64,
                "public_key": "image/keys/test.pub",
                "public_key_sha256": hashlib.sha256(self.key.read_bytes()).hexdigest(),
            }},
        }

    def test_committed_configuration_has_no_fabricated_base(self):
        config = json.loads((ROOT / "image/base-images.json").read_text())
        if not config["variants"]:
            with self.assertRaisesRegex(ValueError, "base selection"):
                self.module.render(config, "generic", ROOT)
        else:
            for variant in config["variants"]:
                self.module.render(config, variant, ROOT)

    def test_recipe_uses_digest_and_local_public_key(self):
        recipe = self.module.render(self.config, "generic", self.root)
        self.assertEqual(recipe["version"], 2)
        self.assertEqual(recipe["base"]["image"]["digest"], "sha256:" + "a" * 64)
        self.assertNotIn("tag", recipe["base"]["image"])
        self.assertEqual(recipe["base"]["public-key"], "image/keys/test.pub")
        self.assertEqual(recipe["spec"]["tool-versions"]["bluebuild"], "none")

    def test_mutable_or_malformed_base_is_rejected(self):
        for ref in ["ghcr.io/example/test:latest", "ghcr.io/example/test@sha256:abc",
                    "ghcr.io/example/test@sha256:" + "0" * 64,
                    "ghcr.io/example/test:latest@sha256:" + "a" * 64,
                    "ghcr.io/example/test@sha256:" + "a" * 64 + "\nRUN false"]:
            with self.subTest(ref=ref):
                config = copy.deepcopy(self.config)
                config["variants"]["generic"]["image"] = ref
                with self.assertRaises(ValueError):
                    self.module.render(config, "generic", self.root)

    def test_changed_or_outside_trust_key_is_rejected(self):
        self.key.write_text("changed key\n")
        with self.assertRaisesRegex(ValueError, "key hash"):
            self.module.render(self.config, "generic", self.root)
        self.config["variants"]["generic"]["public_key"] = "../outside.pub"
        with self.assertRaises(ValueError):
            self.module.render(self.config, "generic", self.root)


class PrivacyDefaults(unittest.TestCase):
    def test_telemetry_off_without_turning_off_browser_security_updates(self):
        chromium = json.loads((OVERLAY / "etc/chromium/policies/managed/symbi-privacy.json").read_text())
        self.assertIs(chromium["MetricsReportingEnabled"], False)
        self.assertIs(chromium["UrlKeyedAnonymizedDataCollectionEnabled"], False)
        self.assertNotIn("SafeBrowsingProtectionLevel", chromium)
        firefox = json.loads((OVERLAY / "etc/firefox/policies/policies.json").read_text())["policies"]
        self.assertIs(firefox["DisableTelemetry"], True)
        self.assertIs(firefox["DisableFirefoxStudies"], True)
        self.assertNotIn("DisableAppUpdate", firefox)

    def test_portal_and_connectivity_defaults(self):
        portal = (OVERLAY / "usr/share/symbiont/defaults/hypr/xdph.conf").read_text()
        self.assertIn("allow_token_by_default = false", portal)
        self.assertNotIn("custom_picker_binary", portal)
        nm = (OVERLAY / "etc/NetworkManager/conf.d/99-symbi-no-connectivity-check.conf").read_text()
        self.assertIn("enabled=false", nm)

    def test_shipped_config_does_not_invoke_omarchy_installers_or_plugins(self):
        defaults = OVERLAY / "usr/share/symbiont/defaults"
        self.assertTrue(defaults.is_dir())
        for path in defaults.rglob("*"):
            if path.is_file():
                text = path.read_text()
                for forbidden in ["omarchy-", "hyprpm", "plugin =", "curl ", "wget "]:
                    self.assertNotIn(forbidden, text, str(path))


if __name__ == "__main__":
    unittest.main()
