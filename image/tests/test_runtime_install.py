"""Compatibility installation must stay tied to reviewed additive inputs."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from image.assembly.runtime_install import require_runtime_rpms, snapshot_crypto_configuration


class RuntimeInstallation(unittest.TestCase):
    def fixture(self):
        requirements = {'packages': ['libssl.so.3()(64bit)', 'libcrypto.so.3()(64bit)'],
                        'expected_provider': 'openssl3-libs'}
        key = {'fingerprint': 'A'*40, 'sha256': 'b'*64}
        row = {'filename': 'openssl3-libs-3.5.9-1.fc45.x86_64.rpm',
               'nevra': 'openssl3-libs-1:3.5.9-1.fc45.x86_64', 'signature_verified': True,
               'key_fingerprint': key['fingerprint'], 'bytes': 1234, 'sha256': 'c'*64}
        lock = {'schema': 1, 'qualified': False, 'product_installation': False,
                'base': 'pinned-base', 'requirements': copy.deepcopy(requirements),
                'key': copy.deepcopy(key), 'packages': [row]}
        return lock, 'pinned-base', requirements, {'source': {'image': 'pinned-base'}, 'key': key}

    def test_exact_compatibility_input_is_accepted(self):
        require_runtime_rpms(*self.fixture())

    def test_changed_base_key_requirements_or_replacement_package_is_refused(self):
        for change in ('base', 'key', 'requirements', 'qualified', 'signature', 'replacement', 'extra'):
            with self.subTest(change=change):
                args = list(self.fixture());lock = args[0]
                if change == 'base':lock['base'] = 'changed'
                elif change == 'key':lock['key']['fingerprint'] = 'B'*40
                elif change == 'requirements':lock['requirements']['packages'].append('unrelated')
                elif change == 'qualified':lock['qualified'] = True
                elif change == 'signature':lock['packages'][0]['signature_verified'] = False
                elif change == 'replacement':lock['packages'][0]['nevra'] = 'openssl-libs-1:4.0.3-1.fc45.x86_64'
                else:lock['packages'].append(copy.deepcopy(lock['packages'][0]))
                with self.assertRaises(ValueError):require_runtime_rpms(*args)

    def test_crypto_snapshot_tracks_file_content_link_target_and_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root/'etc/crypto-policies/config';config.parent.mkdir(parents=True)
            config.write_text('FUTURE\n')
            target = root/'usr/share/crypto-policies/FUTURE/opensslcnf.txt';target.parent.mkdir(parents=True)
            target.write_text('MinProtocol = TLSv1.2\n')
            link = root/'etc/pki/tls/openssl.cnf';link.parent.mkdir(parents=True)
            link.symlink_to('../../../usr/share/crypto-policies/FUTURE/opensslcnf.txt')
            before = snapshot_crypto_configuration(root)
            self.assertEqual(before['etc/crypto-policies/config']['sha256'], hashlib.sha256(config.read_bytes()).hexdigest())
            self.assertEqual(before['etc/pki/tls/openssl.cnf']['link'], '../../../usr/share/crypto-policies/FUTURE/opensslcnf.txt')
            self.assertIsNone(before['usr/etc/pki/tls/openssl.cnf'])
            target.write_text('MinProtocol = TLSv1\n')
            self.assertNotEqual(before, snapshot_crypto_configuration(root))
            target.write_text('MinProtocol = TLSv1.2\n')
            self.assertEqual(before, snapshot_crypto_configuration(root))
            config.unlink()
            self.assertNotEqual(before, snapshot_crypto_configuration(root))

    def test_crypto_snapshot_refuses_escaping_link_or_oversized_configuration(self):
        for change in ('link', 'large'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory);path = root/'etc/pki/tls/openssl.cnf';path.parent.mkdir(parents=True)
                if change == 'link':path.symlink_to('/etc/passwd')
                else:path.write_bytes(b'x'*65537)
                with self.assertRaises(ValueError):snapshot_crypto_configuration(root)
