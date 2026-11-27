"""Fail closed before executing reused runtime binaries or signed inputs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'fixture_inputs', ROOT / 'image/container/hosted/inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class RuntimeArchive(unittest.TestCase):
    def test_hosted_source_exactly_matches_native_lock(self):
        hosted = json.loads((
            ROOT / 'image/container/hosted/inputs.lock.json').read_text())
        native = json.loads((
            ROOT / 'image/container/native-fixture.lock.json').read_text())
        selected = inputs.validate_fixture_source_lock(hosted, native)
        self.assertEqual(selected['revision'], native['revision'])
        self.assertEqual(selected['tree'], native['tree'])
        self.assertEqual(selected['drivers'], native['drivers'])
        self.assertEqual(hosted['fixture_execution'], {
            'state': 'passed',
            'event': 'pull_request',
            'pull_request': 6,
            'conclusion': 'success',
            'run_id': 45995824985,
            'run_attempt': 1,
            'head': 'cdd8e7d931ddf90f1fe8afb22d12df9c539320b4',
            'checked_merge': '2189acad039387cd48116c11934da383bea8e653',
            'job_id': 140494839919,
            'source_revision': native['revision'],
            'source_tree': native['tree'],
            'artifact': {
                'id': 15196575712,
                'name': 'container-fixture-evidence',
                'bytes': 293698,
                'sha256': '8b9d8f59f66348ff42625cb313bffc21cead77bb0b152563c6b236313aa99ad0',
            },
            'passed': True,
            'qualified': False,
        })

        pending = copy.deepcopy(hosted)
        pending['fixture_execution'] = {
            'state': 'pending',
            'run_id': None,
            'head': None,
            'source_revision': native['revision'],
            'source_tree': native['tree'],
        }
        inputs.validate_fixture_source_lock(pending, native)

        variants = []
        for field in ('fixture_commit', 'fixture_tree', 'source_revision'):
            changed = copy.deepcopy(hosted)
            changed[field] = '0' * 40
            variants.append((changed, native))
        changed = copy.deepcopy(hosted)
        changed['fixture_drivers']['test-git-source.py'] = '0' * 64
        variants.append((changed, native))
        changed_native = copy.deepcopy(native)
        changed_native['qualified'] = True
        variants.append((hosted, changed_native))
        changed_native = copy.deepcopy(native)
        changed_native['drivers']['extra.py'] = '0' * 64
        variants.append((hosted, changed_native))
        changed = copy.deepcopy(hosted)
        changed['runtime_artifact_validation']['run_id'] = 0
        variants.append((changed, native))

        execution_mutations = (
            (('state',), 'pending'),
            (('event',), 'push'),
            (('pull_request',), 7),
            (('conclusion',), 'failure'),
            (('run_id',), 45995824986),
            (('run_attempt',), 2),
            (('head',), '0' * 40),
            (('checked_merge',), '0' * 40),
            (('job_id',), 140494839920),
            (('source_revision',), '0' * 40),
            (('source_tree',), '0' * 40),
            (('artifact', 'id'), 15196575713),
            (('artifact', 'name'), 'other-evidence'),
            (('artifact', 'bytes'), 293699),
            (('artifact', 'sha256'), '0' * 64),
            (('passed',), False),
            (('passed',), 1),
            (('qualified',), True),
            (('qualified',), 0),
        )
        for path, value in execution_mutations:
            changed = copy.deepcopy(hosted)
            target = changed['fixture_execution']
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            variants.append((changed, native))

        changed = copy.deepcopy(pending)
        changed['fixture_execution']['unexpected'] = None
        variants.append((changed, native))
        changed = copy.deepcopy(hosted)
        changed['fixture_execution']['unexpected'] = None
        variants.append((changed, native))
        for changed_hosted, changed_native in variants:
            with self.subTest(hosted=changed_hosted, native=changed_native), \
                    self.assertRaises(ValueError):
                inputs.validate_fixture_source_lock(
                    changed_hosted, changed_native)

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
