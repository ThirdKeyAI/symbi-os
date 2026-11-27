"""Image payload must contain the reviewed enforcing release policy."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from image.desktop.trust import prepare_trust


class DesktopTrust(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root/'payload'
        self.payload.mkdir()
        keys = self.root/'image/keys'
        keys.mkdir(parents=True)
        # Configuration fixtures only; these are not valid signing keys.
        self.release_key = b'-----BEGIN PUBLIC KEY-----\nrelease-fixture\n-----END PUBLIC KEY-----\n'
        self.base_key = b'-----BEGIN PUBLIC KEY-----\nbase-fixture\n-----END PUBLIC KEY-----\n'
        (keys/'release.pub').write_bytes(self.release_key)
        (keys/'base.pub').write_bytes(self.base_key)
        self.release = {'schema': 1, 'repositories': {'generic': 'ghcr.io/example/os'},
                        'public_key': 'image/keys/release.pub',
                        'public_key_sha256': hashlib.sha256(self.release_key).hexdigest()}
        self.base = 'ghcr.io/example/base@sha256:'+'a'*64
        self.bases = {'schema': 1, 'variants': {'generic': {'image': self.base,
                     'public_key': 'image/keys/base.pub',
                     'public_key_sha256': hashlib.sha256(self.base_key).hexdigest()}}}
        (self.root/'image/release-trust.json').write_text(json.dumps(self.release))
        (self.root/'image/base-images.json').write_text(json.dumps(self.bases))

    def test_payload_installs_default_reject_and_exact_release_base_trust(self):
        record = prepare_trust(self.root, self.payload)
        policy = json.loads((self.payload/'etc/containers/policy.json').read_text())
        registries = json.loads((self.payload/'etc/containers/registries.d/symbiont.yaml').read_text())
        self.assertEqual(policy['default'], [{'type': 'reject'}])
        self.assertEqual(set(policy['transports']), {'docker'})
        rules = policy['transports']['docker']
        self.assertEqual(set(rules), {'ghcr.io/example/os', self.base})
        for scope, key in [('ghcr.io/example/os', self.release_key), (self.base, self.base_key)]:
            self.assertEqual(len(rules[scope]), 1)
            self.assertEqual(rules[scope][0]['type'], 'sigstoreSigned')
            self.assertEqual(base64.b64decode(rules[scope][0]['keyData']), key)
            self.assertEqual(rules[scope][0]['signedIdentity'],
                             {'type': 'exactRepository', 'dockerRepository': scope.split('@')[0]})
        self.assertEqual(set(registries['docker']), set(rules))
        self.assertTrue(all(v == {'use-sigstore-attachments': True} for v in registries['docker'].values()))
        self.assertEqual(set(record['files']), {'etc/containers/policy.json', 'etc/containers/registries.d/symbiont.yaml'})
        self.assertFalse(record['signature_qualified'])
        for relative, pin in record['files'].items():
            path = self.payload/relative
            self.assertEqual(pin['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_changed_public_key_is_refused_before_creating_policy(self):
        (self.root/'image/keys/release.pub').write_bytes(self.base_key)
        with self.assertRaisesRegex(ValueError, 'key hash'):
            prepare_trust(self.root, self.payload)
        self.assertFalse((self.payload/'etc').exists())

    def test_linked_payload_or_parent_cannot_redirect_policy(self):
        outside = self.root/'outside'; outside.mkdir()
        linked = self.root/'linked'; linked.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): prepare_trust(self.root, linked)
        (self.payload/'etc').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): prepare_trust(self.root, self.payload)
        self.assertEqual(list(outside.iterdir()), [])

    def test_existing_policy_is_not_overwritten(self):
        target = self.payload/'etc/containers/policy.json'
        target.parent.mkdir(parents=True)
        target.write_text('existing policy')
        with self.assertRaises(FileExistsError): prepare_trust(self.root, self.payload)
        self.assertEqual(target.read_text(), 'existing policy')
