"""Retained runtime bytes must stay bound to the tested, pinned source."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

from image.assembly.inputs import require_runtime, unpack_runtime


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class RuntimeInputs(unittest.TestCase):
    def fixture(self, root):
        source = root/'source.toml'
        source.write_text('repository = "https://github.com/thirdkeyai/symbiont"\nrevision = "'+40*'a'+'"\nversion = "3.0.0"\n')
        binaries = {'symbi': b'not executable runtime', 'symbi-sandbox-supervisor': b'not executable supervisor'}
        identities = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in binaries.items()}
        checks = [{'phase': phase, 'name': name, 'exit_code': 0, 'timeout': False, 'passed': True}
                  for phase, names in (('baseline', ('build', 'test', 'clippy', 'fmt')),
                                       ('fixture', ('python', 'build', 'test', 'clippy', 'fmt'))) for name in names]
        result = {'schema': 1, 'source_revision': 'a'*40, 'source_commit': 'b'*40,
                  'source_clean_before': True, 'baseline_passed': True, 'patched_workspace_passed': True,
                  'patch_applied': True, 'patch_sha256': 'c'*64, 'cargo_lock_sha256': 'd'*64,
                  'os_qualified': False, 'binaries': identities, 'checks': checks}
        result_path = root/'result.json'
        result_path.write_text(json.dumps(result)+'\n')
        lock = {'schema': 1, 'qualified': False, 'product_installation': False,
                'validation_run': 123, 'validation_head': 'e'*40, 'validation_checked_merge': 'b'*40,
                'source_revision': 'a'*40, 'source_pin_sha256': sha(source.read_bytes()),
                'patch_sha256': 'c'*64, 'cargo_lock_sha256': 'd'*64, 'binaries': identities,
                'build_result_sha256': sha(result_path.read_bytes())}
        archive = root/'runtime.zip'
        members = [(name, raw, stat.S_IFREG | 0o755) for name, raw in binaries.items()]
        self.archive(archive, members, lock)
        return dict(archive=archive, lock=lock, source_pin=source, build_result=result_path,
                    destination=root/'unpacked'), members

    def archive(self, path, members, lock):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as bundle:
                for name, raw, mode in members:
                    info = zipfile.ZipInfo(name)
                    info.external_attr = mode << 16
                    bundle.writestr(info, raw)
        lock['artifact'] = {'id': 456, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}

    def test_exact_reviewed_bytes_extracted_without_executing(self):
        with tempfile.TemporaryDirectory() as directory:
            args, members = self.fixture(Path(directory))
            unpack_runtime(**args)
            for name, raw, _ in members:
                self.assertEqual((args['destination']/name).read_bytes(), raw)
                self.assertEqual((args['destination']/name).stat().st_mode & 0o777, 0o755)

    def test_changed_source_evidence_or_incomplete_acceptance_refused(self):
        for change in ('source', 'result', 'build', 'tests', 'merge', 'binary', 'qualified'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                args, _ = self.fixture(Path(directory))
                if change in ('source', 'result'):
                    path = args['source_pin' if change == 'source' else 'build_result']
                    path.write_text(path.read_text()+' ')
                elif change == 'merge':args['lock']['validation_checked_merge'] = 'f'*40
                elif change == 'qualified':args['lock']['qualified'] = True
                elif change == 'binary':args['lock']['binaries']['symbi']['sha256'] = 'f'*64
                else:
                    result = json.loads(args['build_result'].read_text())
                    if change == 'build':result['baseline_passed'] = False
                    else:result['checks'][1]['passed'] = False
                    args['build_result'].write_text(json.dumps(result))
                    args['lock']['build_result_sha256'] = sha(args['build_result'].read_bytes())
                with self.assertRaises(ValueError):unpack_runtime(**args)
                self.assertFalse(args['destination'].exists())

    def test_archive_and_payload_corruption_leave_no_output(self):
        for change in ('archive', 'payload'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                args, members = self.fixture(Path(directory))
                if change == 'archive':
                    with args['archive'].open('ab') as stream:stream.write(b'changed')
                else:
                    name, raw, mode = members[1]
                    members[1] = (name, b'x'+raw[1:], mode)
                    self.archive(args['archive'], members, args['lock'])
                with self.assertRaises(ValueError):unpack_runtime(**args)
                self.assertFalse(args['destination'].exists())

    def test_duplicate_missing_traversal_and_nonregular_members_refused(self):
        for change in ('duplicate', 'missing', 'traversal', 'symlink', 'fifo'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                args, members = self.fixture(Path(directory))
                if change == 'duplicate':members.append(members[0])
                elif change == 'missing':members.pop()
                else:
                    name, raw, mode = members[0]
                    if change == 'traversal':name = '../'+name
                    else:mode = (stat.S_IFLNK if change == 'symlink' else stat.S_IFIFO) | 0o755
                    members[0] = (name, raw, mode)
                self.archive(args['archive'], members, args['lock'])
                with self.assertRaises(ValueError):unpack_runtime(**args)
                self.assertFalse(args['destination'].exists())

    def test_limits_and_existing_or_linked_paths_refused(self):
        for change in ('oversize', 'extra-binary', 'destination', 'parent-link', 'archive-link'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args, _ = self.fixture(root)
                if change == 'oversize':args['lock']['artifact']['bytes'] = 601*1024**2
                elif change == 'extra-binary':args['lock']['binaries']['unexpected'] = copy.deepcopy(args['lock']['binaries']['symbi'])
                elif change == 'destination':args['destination'].mkdir()
                elif change == 'parent-link':
                    (root/'linked').symlink_to(root, target_is_directory=True)
                    args['destination'] = root/'linked/unpacked'
                else:
                    (root/'linked').symlink_to(args['archive'])
                    args['archive'] = root/'linked'
                with self.assertRaises(ValueError):unpack_runtime(**args)


if __name__ == '__main__':
    unittest.main()
