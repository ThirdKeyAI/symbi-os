"""Trust-policy generation checks; no fixture is a verified image signature."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SigningPolicy(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("signing", ROOT / "image/signing.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "image/keys").mkdir(parents=True)
        # Deliberately synthetic key text tests configuration binding only.
        # A real containers/image verifier must reject it as an invalid key.
        self.key = b"-----BEGIN PUBLIC KEY-----\nconfiguration-fixture\n-----END PUBLIC KEY-----\n"
        (self.root / "image/keys/test.pub").write_bytes(self.key)
        pin = {"public_key": "image/keys/test.pub", "public_key_sha256": hashlib.sha256(self.key).hexdigest()}
        self.release = {"schema": 1, "repositories": {"generic": "ghcr.io/example/symbi"}, **pin}
        self.base_ref = "ghcr.io/example/base@sha256:" + "a" * 64
        self.bases = {"schema": 1, "variants": {"generic": {"image": self.base_ref, **pin}}}

    def bundle(self):
        return self.module.render(self.release, self.bases, self.root)

    def test_unconfigured_release_trust_fails(self):
        config = json.loads((ROOT / "image/release-trust.json").read_text())
        if not config["repositories"]:
            with self.assertRaisesRegex(ValueError, "release trust setup"):
                self.module.render(config, self.bases, ROOT)

    def test_default_reject_and_explicit_key_repository_bindings(self):
        bundle = self.bundle()
        self.assertEqual(bundle["policy"]["default"], [{"type": "reject"}])
        scopes = bundle["policy"]["transports"]["docker"]
        self.assertEqual(set(scopes), {"ghcr.io/example/symbi", self.base_ref})
        for scope, rules in scopes.items():
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["type"], "sigstoreSigned")
            self.assertEqual(base64.b64decode(rules[0]["keyData"]), self.key)
            self.assertEqual(rules[0]["signedIdentity"], {
                "type": "exactRepository", "dockerRepository": scope.split("@")[0]})
        self.assertNotIn("insecureAcceptAnything", json.dumps(bundle))
        self.assertEqual(set(bundle["registries"]["docker"]), set(scopes))
        self.assertTrue(all(v["use-sigstore-attachments"] for v in bundle["registries"]["docker"].values()))

    def test_bad_repository_scopes_are_refused(self):
        for value in ["ghcr.io", "ghcr.io/*", "https://ghcr.io/example/repo", "ghcr.io/example/repo:latest",
                      "ghcr.io/example/../repo", "ghcr.io/Example/repo", "user@ghcr.io/example/repo"]:
            with self.subTest(value=value):
                candidate = copy.deepcopy(self.release)
                candidate["repositories"]["generic"] = value
                with self.assertRaises(ValueError):
                    self.module.render(candidate, self.bases, self.root)

    def test_changed_key_or_key_outside_trust_directory_is_refused(self):
        self.release["public_key_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "key hash"):
            self.bundle()
        self.release["public_key"] = "../private.key"
        with self.assertRaises(ValueError):
            self.bundle()

    def test_symlinked_trust_directory_cannot_escape(self):
        keys = self.root / "image/keys"
        outside = self.root / "outside-keys"
        keys.rename(outside)
        keys.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.bundle()

    def test_private_key_material_is_never_embedded(self):
        key = b"-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"
        (self.root / "image/keys/test.pub").write_bytes(key)
        self.release["public_key_sha256"] = hashlib.sha256(key).hexdigest()
        with self.assertRaisesRegex(ValueError, "public key"):
            self.bundle()

    def test_missing_variant_and_base_release_collision_fail(self):
        self.release["repositories"]["nvidia"] = "ghcr.io/example/symbi-nvidia"
        with self.assertRaises(ValueError):
            self.bundle()
        del self.release["repositories"]["nvidia"]
        self.release["repositories"]["generic"] = "ghcr.io/example/base"
        with self.assertRaises(ValueError):
            self.bundle()

    def test_only_approved_digest_rebases_are_emitted(self):
        ref = "ghcr.io/example/symbi@sha256:" + "b" * 64
        self.assertEqual(self.module.rebase_command(self.bundle(), ref),
                         ["rpm-ostree", "rebase", "ostree-image-signed:docker://" + ref])
        self.module.rebase_command(self.bundle(), self.base_ref)
        for bad in ["ghcr.io/example/symbi:latest", "ghcr.io/example/evil@sha256:" + "b" * 64,
                    "ghcr.io/example/base@sha256:" + "c" * 64,
                    "ghcr.io/example/symbi/child@sha256:" + "b" * 64]:
            with self.subTest(ref=bad), self.assertRaises(ValueError):
                self.module.rebase_command(self.bundle(), bad)

    def test_policy_bundle_cannot_overwrite_existing_output(self):
        output = self.root / "output"
        self.module.write_bundle(self.bundle(), output)
        self.assertEqual(json.loads((output / "policy.json").read_text()), self.bundle()["policy"])
        with self.assertRaises(FileExistsError):
            self.module.write_bundle(self.bundle(), output)


if __name__ == "__main__":
    unittest.main()
