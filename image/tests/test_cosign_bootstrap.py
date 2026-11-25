"""Offline authentication regressions using disposable, explicitly synthetic keys."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bootstrap_cosign", ROOT / "image/toolchain/bootstrap_cosign.py")
bootstrap_cosign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap_cosign)


class CosignBootstrap(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        private = self.root / "synthetic.key"
        self.public = self.root / "synthetic.pub"
        self.binary = self.root / "inert-fixture"
        self.binary.write_bytes(b"This fixture is data, not an executable.\n")
        signature = self.root / "synthetic.sig"
        for command in (
            ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(private)],
            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(self.public)],
            ["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(self.binary)],
        ):
            subprocess.run(command, capture_output=True, check=True, timeout=10)
        self.key_hash = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.value = {"messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(hashlib.sha256(self.binary.read_bytes()).digest()).decode()},
            "signature": base64.b64encode(signature.read_bytes()).decode()}}
        self.bundle = self.root / "bundle.json"
        self.bundle.write_text(json.dumps(self.value))

    def verify(self):
        return bootstrap_cosign.verify_signature(self.binary, self.bundle, self.public,
                                                  self.key_hash, self.root / "verification.sig")

    def test_authenticates_signature_without_executing_payload(self):
        self.assertEqual(self.verify().strip(), "Verified OK")
        self.assertEqual(self.binary.stat().st_mode & 0o111, 0)

    def test_changed_payload_rejected_even_if_bundle_digest_is_rewritten(self):
        self.binary.write_bytes(b"Changed payload\n")
        with self.assertRaisesRegex(ValueError, "bundle digest mismatch"):
            self.verify()
        value = copy.deepcopy(self.value)
        value["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(hashlib.sha256(self.binary.read_bytes()).digest()).decode()
        self.bundle.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.verify()

    def test_changed_key_and_changed_signature_rejected(self):
        self.key_hash = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.verify()
        self.key_hash = hashlib.sha256(self.public.read_bytes()).hexdigest()
        self.value["messageSignature"]["signature"] = base64.b64encode(b"invalid signature").decode()
        self.bundle.write_text(json.dumps(self.value))
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.verify()

    def test_download_hash_and_size_must_match(self):
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.assertEqual(bootstrap_cosign.verify_hash(self.binary, digest, self.binary.stat().st_size), digest)
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            bootstrap_cosign.verify_hash(self.binary, digest, 1)
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            bootstrap_cosign.verify_hash(self.binary, "0" * 64)

    def test_local_bootstrap_refused_before_any_download(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "hosted runner"):
                bootstrap_cosign.bootstrap(self.root, self.root)
