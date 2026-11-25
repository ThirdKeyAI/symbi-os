"""Parser checks are separate from the hosted real RPM verification controls."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("rpm_inputs", Path(__file__).parents[1] / "hyprland/resolve_packages.py")
rpm_inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rpm_inputs)
FINGERPRINT = "4F50A6114CD5C6976A7F1179655A4B02F577861E"
GOOD = "sample.rpm:\n    Header V4 RSA/SHA256 Signature, key ID f577861e: OK\n    Header SHA256 digest: OK\n    Payload SHA256 digest: OK\n"


class SignatureOutput(unittest.TestCase):
    def test_requires_signature_and_payload_digest(self):
        rpm_inputs.require_verified_rpm(0, GOOD, FINGERPRINT)

    def test_unsigned_digest_success_is_refused(self):
        with self.assertRaises(ValueError):
            rpm_inputs.require_verified_rpm(0, "sample.rpm:\n    Payload SHA256 digest: OK\n", FINGERPRINT)

    def test_failure_bad_missing_or_wrong_key_is_refused(self):
        for status, text in ((1, GOOD), (0, GOOD.replace('digest: OK', 'digest: BAD')),
                             (0, GOOD.replace('f577861e', 'deadbeef')),
                             (0, GOOD.replace(': OK', ': NOTFOUND')),
                             (0, GOOD.split('    Payload')[0])):
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                rpm_inputs.require_verified_rpm(status, text, FINGERPRINT)

    def test_keyring_contains_exactly_one_expected_key(self):
        rpm_inputs.require_keyring(FINGERPRINT.lower() + ' Fedora (45) public key\n', FINGERPRINT)
        for text in ('', '0000000000000000000000000000000000000000 other key\n',
                     FINGERPRINT + ' expected\n' + FINGERPRINT + ' duplicate\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                rpm_inputs.require_keyring(text, FINGERPRINT)


if __name__ == '__main__':
    unittest.main()
