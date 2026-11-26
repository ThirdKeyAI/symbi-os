"""Authenticate exact ZIP bytes and source bindings before executable reuse."""
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

SPEC = importlib.util.spec_from_file_location('binary_inputs', Path(__file__).parents[1] / 'launcher/binary_inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class BinaryInputs(unittest.TestCase):
    def fixture(self, root, extra=(), replaced=None, mode=None, manifest_change=None):
        payloads = {name: b'synthetic non-executable fixture '+name.encode()
                    for name in ('baseline', 'patched', 'desktopapplications', 'marker')}
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False,
                    'provider_loading_qualified': False, 'source_commit': '1'*40,
                    'base': 'base@sha256:'+'2'*64, 'upstream_revision': '3'*40,
                    'rpm_lock_sha256': '4'*64, 'patch_sha256': '5'*64,
                    'go_mod_sha256': '6'*64, 'go_sum_sha256': '7'*64,
                    'source_variants': {'baseline': 'unmodified', 'marker': 'unmodified',
                                        'patched': 'provider-patched', 'desktopapplications': 'provider-patched'},
                    'binaries': {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}}
        expected = copy.deepcopy(manifest)
        raw = json.dumps(manifest).encode()
        lock = {'schema': 1, 'tested_commit': '1'*40, 'manifest': expected,
                'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'marker_source_sha256': '8'*64}
        if manifest_change:
            manifest.update(manifest_change)
            raw = json.dumps(manifest).encode()
        if replaced:
            payloads.update(replaced)
        archive = root/'inputs.zip'
        with zipfile.ZipFile(archive, 'w') as bundle, warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            bundle.writestr('manifest.json', raw)
            for name, data in [*payloads.items(), *extra]:
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = ((mode if mode is not None and name == 'marker' else stat.S_IFREG|0o755)<<16)
                bundle.writestr(member, data)
        lock['artifact'] = {'bytes': archive.stat().st_size, 'sha256': inputs.digest(archive)}
        return archive, lock, payloads

    def test_exact_fixture_unpacks_only_bound_binaries_with_fixed_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, lock, payloads = self.fixture(root)
            actual = inputs.unpack_binaries(archive, lock, root/'unpacked')
            self.assertEqual(actual, lock['manifest'])
            self.assertEqual({p.name for p in (root/'unpacked').iterdir()}, set(payloads))
            for name, data in payloads.items():
                self.assertEqual((root/'unpacked'/name).read_bytes(), data)
                self.assertEqual((root/'unpacked'/name).stat().st_mode & 0o777,
                                 0o755 if name in ('baseline', 'patched') else 0o644)

    def test_changed_archive_manifest_or_binary_is_refused(self):
        for mutation in ('archive', 'manifest', 'binary'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = {'manifest_change': {'upstream_revision': 'a'*40}} if mutation == 'manifest' else {}
                if mutation == 'binary':args['replaced'] = {'patched': b'tampered'}
                archive, lock, _ = self.fixture(root, **args)
                if mutation == 'archive':archive.write_bytes(archive.read_bytes()+b'changed')
                with self.assertRaises(ValueError):inputs.unpack_binaries(archive, lock, root/'unpacked')

    def test_duplicate_extra_and_escaping_members_are_refused(self):
        for name in ('marker', '../outside', '/tmp/outside', 'nested/marker', 'extra'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, lock, _ = self.fixture(root, extra=[(name, b'unexpected')])
                with self.assertRaises(ValueError):inputs.unpack_binaries(archive, lock, root/'unpacked')
                self.assertFalse((root/'unpacked').exists())

    def test_link_special_member_and_preexisting_destination_are_refused(self):
        for mode in (stat.S_IFLNK|0o777, stat.S_IFIFO|0o600, stat.S_IFDIR|0o755):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, lock, _ = self.fixture(root, mode=mode)
                with self.assertRaises(ValueError):inputs.unpack_binaries(archive, lock, root/'unpacked')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, lock, _ = self.fixture(root)
            (root/'unpacked').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):inputs.unpack_binaries(archive, lock, root/'unpacked')

    def test_current_source_patch_compiler_and_marker_bindings_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            _, lock, _ = self.fixture(Path(directory))
            manifest = lock['manifest']
            source = {'revision': '3'*40, 'go_mod_sha256': '6'*64, 'go_sum_sha256': '7'*64}
            arguments = {'manifest': manifest, 'lock': lock, 'base': manifest['base'],
                         'source': source, 'rpm_lock_sha256': '4'*64,
                         'patch_sha256': '5'*64, 'marker_sha256': '8'*64}
            inputs.require_bindings(**arguments)
            for field in ('base', 'rpm_lock_sha256', 'patch_sha256', 'marker_sha256'):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    inputs.require_bindings(**{**arguments, field: 'changed'})
            for field in source:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    inputs.require_bindings(**{**arguments, 'source': {**source, field: 'changed'}})


    def binding_arguments(self, root):
        _, lock, _ = self.fixture(root)
        return {'manifest': lock['manifest'], 'lock': lock, 'base': lock['manifest']['base'],
                'source': {'revision': '3'*40, 'go_mod_sha256': '6'*64, 'go_sum_sha256': '7'*64},
                'rpm_lock_sha256': '4'*64, 'patch_sha256': '5'*64, 'marker_sha256': '8'*64}

    def test_tested_commit_must_be_exact_and_match_the_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments = self.binding_arguments(Path(directory))
            inputs.require_bindings(**arguments)
            for commit in (None, '', '1'*39, 'g'*40, '2'*40, 1):
                with self.subTest(commit=commit), self.assertRaises(ValueError):
                    lock = {**arguments['lock'], 'tested_commit': commit}
                    inputs.require_bindings(**{**arguments, 'lock': lock})
            lock = dict(arguments['lock'])
            del lock['tested_commit']
            with self.assertRaises(ValueError):
                inputs.require_bindings(**{**arguments, 'lock': lock})

    def test_provider_and_executable_must_share_the_patched_source(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments = self.binding_arguments(Path(directory))
            for variants in (None, {}, {'baseline': 'unmodified', 'marker': 'unmodified',
                                       'patched': 'provider-patched', 'desktopapplications': 'unmodified'}):
                with self.subTest(variants=variants), self.assertRaises(ValueError):
                    manifest = {**arguments['manifest'], 'source_variants': variants}
                    inputs.require_bindings(**{**arguments, 'manifest': manifest,
                                              'lock': {**arguments['lock'], 'manifest': manifest}})


if __name__ == '__main__':
    unittest.main()
