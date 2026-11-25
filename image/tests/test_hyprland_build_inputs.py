"""Reject changed and unexpected package-bundle contents before installation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile


SPEC = importlib.util.spec_from_file_location('build_inputs', Path(__file__).parents[1] / 'hyprland/build_inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class PackageBundle(unittest.TestCase):
    def bundle(self, directory, changes=None):
        package = b'package fixture, never executed'
        rows = [{'filename': 'fixture.rpm', 'bytes': len(package),
                 'sha256': hashlib.sha256(package).hexdigest(), 'signature_verified': True,
                 'key_fingerprint': 'A' * 40}]
        manifest = {'passed': True, 'installed_packages_unchanged': True, 'packages': rows,
                    'base': 'example@sha256:' + 'b' * 64,
                    'negative_controls': {'missing_key_rejected': True, 'tampered_package_rejected': True}}
        encoded = json.dumps(manifest).encode()
        members = [('rpms/fixture.rpm', package), ('evidence/result.json', encoded)]
        if changes:
            members = changes(members)
        archive = directory / 'inputs.zip'
        with zipfile.ZipFile(archive, 'w') as stream:
            for name, value in members:
                with warnings.catch_warnings():
                    warnings.filterwarnings('ignore', 'Duplicate name:', UserWarning)
                    stream.writestr(name, value)
        lock = {'schema': 1, 'artifact': {'bytes': archive.stat().st_size, 'sha256': inputs.digest(archive)},
                'manifest_sha256': hashlib.sha256(encoded).hexdigest(), 'packages': rows,
                'base': manifest['base'], 'key': {'fingerprint': 'A' * 40}}
        return archive, lock

    def test_exact_bundle_is_extracted(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, lock = self.bundle(directory)
            result = inputs.unpack_rpms(archive, lock, directory / 'out')
            self.assertEqual(result['packages'], lock['packages'])
            self.assertEqual((directory / 'out/rpms/fixture.rpm').read_bytes(), b'package fixture, never executed')

    def test_modified_archive_refused_before_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, lock = self.bundle(directory)
            with archive.open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaises(ValueError):
                inputs.unpack_rpms(archive, lock, directory / 'out')
            self.assertFalse((directory / 'out').exists())

    def test_missing_extra_traversal_and_duplicate_members_refused(self):
        changes = [lambda rows: rows[:-1], lambda rows: rows + [('rpms/extra.rpm', b'x')],
                   lambda rows: rows + [('../escape', b'x')], lambda rows: rows + [rows[0]]]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                archive, lock = self.bundle(directory, change)
                with self.assertRaises(ValueError):
                    inputs.unpack_rpms(archive, lock, directory / 'out')
                self.assertFalse((directory / 'out').exists())

    def test_package_bytes_must_match_manifest_even_with_matching_zip_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, lock = self.bundle(directory, lambda rows: [(rows[0][0], b'tampered'), rows[1]])
            with self.assertRaises(ValueError):
                inputs.unpack_rpms(archive, lock, directory / 'out')

    def test_symlink_member_refused(self):
        def linked(rows):
            info = zipfile.ZipInfo(rows[0][0])
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            return [(info, rows[0][1]), rows[1]]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, lock = self.bundle(directory, linked)
            with self.assertRaises(ValueError):
                inputs.unpack_rpms(archive, lock, directory / 'out')
            self.assertFalse((directory / 'out').exists())

    def test_manifest_cannot_weaken_signature_requirement(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, lock = self.bundle(directory)
            lock['packages'][0]['signature_verified'] = False
            with self.assertRaises(ValueError):
                inputs.unpack_rpms(archive, lock, directory / 'out')

    def test_real_negative_controls_are_required_even_for_pinned_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, lock = self.bundle(directory)
            with zipfile.ZipFile(archive) as stream:
                package = stream.read('rpms/fixture.rpm')
                manifest = json.loads(stream.read('evidence/result.json'))
            manifest['negative_controls']['tampered_package_rejected'] = False
            encoded = json.dumps(manifest).encode()
            with zipfile.ZipFile(archive, 'w') as stream:
                stream.writestr('rpms/fixture.rpm', package)
                stream.writestr('evidence/result.json', encoded)
            lock['artifact'] = {'bytes': archive.stat().st_size, 'sha256': inputs.digest(archive)}
            lock['manifest_sha256'] = hashlib.sha256(encoded).hexdigest()
            with self.assertRaises(ValueError):
                inputs.unpack_rpms(archive, lock, directory / 'out')
            self.assertFalse((directory / 'out').exists())


if __name__ == '__main__':
    unittest.main()
