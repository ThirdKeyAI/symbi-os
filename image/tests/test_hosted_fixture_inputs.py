"""Fail closed before executing reused runtime binaries or signed inputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile


SPEC = importlib.util.spec_from_file_location('fixture_inputs', Path(__file__).parents[1] / 'container/hosted/inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class RuntimeArchive(unittest.TestCase):
    def fixture(self, directory, extra=None):
        payload = b'fixture bytes; not an executable'
        archive = directory / 'binaries.zip'
        with zipfile.ZipFile(archive, 'w') as stream:
            stream.writestr('symbi', payload)
            if extra:
                with warnings.catch_warnings():
                    warnings.filterwarnings('ignore', 'Duplicate name:', UserWarning)
                    stream.writestr(extra, payload)
        lock = {'artifact': {'bytes': archive.stat().st_size, 'sha256': inputs.digest(archive)},
                'binaries': {'symbi': {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}}}
        return archive, lock

    def test_verified_bytes_become_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, lock = self.fixture(root)
            inputs.unpack_runtime(archive, lock, root / 'bin')
            self.assertEqual((root / 'bin/symbi').stat().st_mode & 0o777, 0o755)

    def test_modified_or_unexpected_archive_members_are_refused(self):
        for extra in ('../escape', 'another-binary', 'symbi'):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive, lock = self.fixture(root, extra)
                with self.assertRaises(ValueError):
                    inputs.unpack_runtime(archive, lock, root / 'bin')
                self.assertFalse((root / 'bin').exists())

    def test_binary_hash_mismatch_never_creates_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, lock = self.fixture(root)
            lock['binaries']['symbi']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                inputs.unpack_runtime(archive, lock, root / 'bin')
            self.assertFalse((root / 'bin/symbi').stat().st_mode & 0o111)

    def test_archive_digest_mismatch_prevents_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, lock = self.fixture(root)
            lock['artifact']['sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                inputs.unpack_runtime(archive, lock, root / 'bin')
            self.assertFalse((root / 'bin').exists())

    def test_signature_status_requires_exact_valid_signer(self):
        fingerprint = '1' * 40
        inputs.require_signature(0, '[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-11-25 rest\n', fingerprint)
        for status, text in [(1, '[GNUPG:] VALIDSIG ' + fingerprint),
                             (0, '[GNUPG:] GOODSIG short-id example'),
                             (0, '[GNUPG:] VALIDSIG ' + '2' * 40),
                             (0, '[GNUPG:] VALIDSIG ' + fingerprint + '\n[GNUPG:] BADSIG x y')]:
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                inputs.require_signature(status, text, fingerprint)

    def test_public_evidence_refuses_links_to_private_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'public'
            source.mkdir()
            (root / 'private-key').write_text('synthetic private fixture')
            (source / 'report.log').symlink_to(root / 'private-key')
            with self.assertRaises(ValueError):
                inputs.collect_public(source, root / 'retained')
            self.assertFalse((root / 'retained').exists())

    def test_public_evidence_refuses_private_pem_but_copies_public_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'public'
            source.mkdir()
            report = source / 'result.json'
            report.write_text(json.dumps({'qualified': False, 'passed': False}) + '\n')
            (source / 'diagnostic.log').write_text('-----BEGIN PRIVATE KEY-----\nfixture\n')
            with self.assertRaises(ValueError):
                inputs.collect_public(source, root / 'retained')
            self.assertFalse((root / 'retained').exists())
            (source / 'diagnostic.log').unlink()
            inputs.collect_public(source, root / 'retained')
            self.assertEqual((root / 'retained/result.json').read_bytes(), report.read_bytes())


if __name__ == '__main__':
    unittest.main()
