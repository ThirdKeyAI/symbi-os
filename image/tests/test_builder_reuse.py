"""Retained native tools are executable only after exact artifact/input checks."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

SPEC = importlib.util.spec_from_file_location('builder_reuse', Path(__file__).parents[1]/'toolchain/reuse.py')
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class BuilderReuse(unittest.TestCase):
    def fixture(self, root):
        binary, license_data = b'non-executable binary fixture', b'original license\n'
        config = {'schema': 1, 'repository': 'https://github.com/blue-build/cli', 'revision': '1'*40,
                  'rust': '1.100.0', 'features': ['v1_0_0'], 'profile': 'dev', 'qualified': False,
                  'patches': [{'path': 'image/toolchain/patches/validator.patch', 'sha256': '2'*64}]}
        config_path = root/'bluebuild.json'
        config_path.write_text(json.dumps(config)+'\n')
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False, 'cli_acceptance_qualified': False,
                    'scope': 'Compiled development builder only', 'source_commit': '3'*40,
                    'upstream_revision': config['revision'], 'tool_config_sha256': sha(config_path.read_bytes()),
                    'cargo_lock_sha256': '4'*64, 'applied_diff_sha256': '5'*64, 'patches': config['patches'],
                    'rust': config['rust'], 'rustc': 'rustc 1.100.0 (fixture)',
                    'features': config['features'], 'profile': config['profile'],
                    'binary': {'name': 'bluebuild', 'bytes': len(binary), 'sha256': sha(binary)},
                    'license': {'name': 'LICENSE', 'bytes': len(license_data), 'sha256': sha(license_data)}}
        raw = (json.dumps(manifest)+'\n').encode()
        members = [('bluebuild', binary, stat.S_IFREG | 0o755),
                   ('LICENSE', license_data, stat.S_IFREG | 0o644),
                   ('manifest.json', raw, stat.S_IFREG | 0o644)]
        lock = {'schema': 1, 'qualified': False, 'product_installation': False,
                'cli_acceptance_passed': True, 'upstream_tests_passed': True,
                'tested_commit': manifest['source_commit'], 'manifest_sha256': sha(raw), 'manifest': manifest}
        archive = root/'tool.zip'
        self.archive(archive, members, lock)
        return {'archive': archive, 'lock': lock, 'config_path': config_path, 'destination': root/'unpacked'}, members

    def archive(self, path, members, lock):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as bundle:
                for name, data, mode in members:
                    info = zipfile.ZipInfo(name)
                    info.external_attr = mode << 16
                    bundle.writestr(info, data)
        lock['artifact'] = {'id': 123, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}

    def test_exact_binary_and_license_are_preserved_without_executing_them(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments, members = self.fixture(Path(directory))
            manifest = reuse.unpack_tool(**arguments)
            destination = arguments['destination']
            self.assertEqual({p.name for p in destination.iterdir()}, {'bluebuild', 'LICENSE', 'manifest.json'})
            for name, content, mode in members:
                self.assertEqual((destination/name).read_bytes(), content)
                self.assertEqual((destination/name).stat().st_mode & 0o777, mode & 0o777)
            self.assertEqual(manifest, arguments['lock']['manifest'])
            self.assertFalse(manifest['os_qualified'])

    def test_unreviewed_acceptance_source_or_changed_current_config_is_refused(self):
        for mutation in ('cli', 'upstream', 'qualified', 'installed', 'commit', 'config', 'manifest-hash'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                arguments, _ = self.fixture(Path(directory))
                lock = arguments['lock']
                if mutation == 'cli':lock['cli_acceptance_passed'] = False
                elif mutation == 'upstream':lock['upstream_tests_passed'] = False
                elif mutation == 'qualified':lock['qualified'] = True
                elif mutation == 'installed':lock['product_installation'] = True
                elif mutation == 'commit':lock['tested_commit'] = '6'*40
                elif mutation == 'manifest-hash':lock['manifest_sha256'] = '0'*64
                else:arguments['config_path'].write_text(arguments['config_path'].read_text()+' ')
                with self.assertRaises(ValueError):reuse.unpack_tool(**arguments)
                self.assertFalse(arguments['destination'].exists())

    def test_tampered_archive_or_payload_is_refused_and_partial_output_removed(self):
        for mutation in ('archive', 'binary', 'license', 'manifest'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                arguments, members = self.fixture(Path(directory))
                if mutation == 'archive':
                    with arguments['archive'].open('ab') as stream:stream.write(b'changed')
                else:
                    index = {'binary': 0, 'license': 1, 'manifest': 2}[mutation]
                    name, content, mode = members[index]
                    members[index] = (name, b'x'+content[1:], mode)
                    self.archive(arguments['archive'], members, arguments['lock'])
                with self.assertRaises(ValueError):reuse.unpack_tool(**arguments)
                self.assertFalse(arguments['destination'].exists())

    def test_duplicate_link_special_and_escaping_members_are_refused(self):
        for mutation in ('duplicate', 'link', 'fifo', 'escape', 'directory'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                arguments, members = self.fixture(Path(directory))
                if mutation == 'duplicate':members.append(members[0])
                elif mutation in ('link', 'fifo', 'directory'):
                    name, content, _ = members[0]
                    kind = {'link': stat.S_IFLNK, 'fifo': stat.S_IFIFO, 'directory': stat.S_IFDIR}[mutation]
                    members[0] = (name, content, kind | 0o755)
                else:members[0] = ('../bluebuild', members[0][1], members[0][2])
                self.archive(arguments['archive'], members, arguments['lock'])
                with self.assertRaises(ValueError):reuse.unpack_tool(**arguments)
                self.assertFalse(arguments['destination'].exists())

    def test_existing_output_or_linked_input_and_parent_are_refused(self):
        for mutation in ('archive-link', 'config-link', 'destination', 'linked-parent'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                arguments, _ = self.fixture(root)
                if mutation.endswith('-link'):
                    key = 'archive' if mutation == 'archive-link' else 'config_path'
                    linked = root/'linked'
                    linked.symlink_to(arguments[key])
                    arguments[key] = linked
                elif mutation == 'destination':arguments['destination'].mkdir()
                else:
                    linked = root/'linked'
                    linked.symlink_to(root, target_is_directory=True)
                    arguments['destination'] = linked/'unpacked'
                with self.assertRaises(ValueError):reuse.unpack_tool(**arguments)

    def test_rewritten_lock_cannot_change_current_source_compiler_or_manifest_scope(self):
        for field, value in (('compiled', False), ('os_qualified', True), ('cli_acceptance_qualified', True),
                             ('upstream_revision', '6'*40), ('rust', '1.101.0'), ('rustc', 'rustc 1.101.0'),
                             ('features', []), ('profile', 'release'), ('patches', []),
                             ('cargo_lock_sha256', ''), ('binary', {'name': '../tool', 'bytes': 1, 'sha256': '0'*64})):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                arguments, members = self.fixture(Path(directory))
                lock = arguments['lock']
                manifest = copy.deepcopy(lock['manifest'])
                manifest[field] = value
                raw = (json.dumps(manifest)+'\n').encode()
                lock.update(manifest=manifest, manifest_sha256=sha(raw))
                members[2] = ('manifest.json', raw, stat.S_IFREG | 0o644)
                self.archive(arguments['archive'], members, lock)
                with self.assertRaises(ValueError):reuse.unpack_tool(**arguments)
                self.assertFalse(arguments['destination'].exists())

    def test_oversized_or_ambiguous_metadata_is_refused_before_extraction(self):
        for mutation in ('archive-size', 'binary-size', 'manifest-size', 'config-duplicate', 'manifest-duplicate'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                arguments, members = self.fixture(Path(directory))
                lock = arguments['lock']
                if mutation == 'archive-size':lock['artifact']['bytes'] = 129*1024**2+1
                elif mutation == 'binary-size':lock['manifest']['binary']['bytes'] = 128*1024**2+1
                elif mutation == 'config-duplicate':
                    path = arguments['config_path']
                    path.write_text('{"schema": 1, '+path.read_text()[1:])
                    lock['manifest']['tool_config_sha256'] = sha(path.read_bytes())
                else:
                    raw = (b' ' * 65537 if mutation == 'manifest-size'
                           else b'{"schema": 1, '+members[2][1][1:])
                    lock['manifest_sha256'] = sha(raw)
                    members[2] = ('manifest.json', raw, stat.S_IFREG | 0o644)
                    self.archive(arguments['archive'], members, lock)
                with self.assertRaises(ValueError):reuse.unpack_tool(**arguments)
                self.assertFalse(arguments['destination'].exists())


if __name__ == '__main__':
    unittest.main()
