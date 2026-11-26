"""Reuse the tested launcher only with its exact current source and RPM inputs."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

from image.launcher.walker_binary_inputs import unpack_walker


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class WalkerReuse(unittest.TestCase):
    def fixture(self, root):
        launcher = root/'image/launcher';(launcher/'licenses').mkdir(parents=True)
        source = {'schema': 1, 'repository': 'https://github.com/abenz1267/walker',
                  'revision': 'a'*40, 'version': '2.17.2', 'os_qualified': False,
                  'cargo_toml_sha256': 'b'*64, 'cargo_lock_sha256': 'c'*64, 'build_rs_sha256': 'd'*64}
        (launcher/'walker-source.json').write_text(json.dumps(source))
        (launcher/'walker-build-rpms.lock.json').write_text('{"build": "fixture"}\n')
        (launcher/'runtime-rpms.lock.json').write_text('{"runtime": "fixture"}\n')
        license_bytes = b'non-executable license fixture\n'
        (launcher/'licenses/walker.LICENSE').write_bytes(license_bytes)
        binary = b'non-executable walker fixture'
        manifest = {'schema': 1, 'compiled': True, 'gui_qualified': False, 'os_qualified': False,
                    'base': 'pinned-build-base', 'source_commit': 'e'*40, 'upstream_revision': source['revision'],
                    'version': source['version'], 'binary_bytes': len(binary), 'binary_sha256': sha(binary),
                    'build_rpm_lock_sha256': sha((launcher/'walker-build-rpms.lock.json').read_bytes()),
                    **{name: source[name] for name in ('cargo_toml_sha256', 'cargo_lock_sha256', 'build_rs_sha256')}}
        raw = json.dumps(manifest).encode()
        lock = {'schema': 1, 'qualified': False, 'product_installation': False, 'upstream_tests_passed': True,
                'upstream_tests': 14, 'cli_acceptance_passed': True, 'tested_commit': 'e'*40,
                'manifest': manifest, 'manifest_sha256': sha(raw),
                'runtime_rpm_lock_sha256': sha((launcher/'runtime-rpms.lock.json').read_bytes()),
                'source_license': {'path': 'image/launcher/licenses/walker.LICENSE', 'bytes': len(license_bytes),
                                   'sha256': sha(license_bytes),
                                   'git_blob': hashlib.sha1(b'blob '+str(len(license_bytes)).encode()+b'\0'+license_bytes).hexdigest()}}
        archive = root/'walker.zip';members = [('walker', binary, stat.S_IFREG | 0o755), ('manifest.json', raw, stat.S_IFREG | 0o644)]
        self.archive(archive, members, lock)
        return dict(archive=archive, lock=lock, root=root, build_base='pinned-build-base', destination=root/'output'), members

    def archive(self, path, members, lock):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as bundle:
                for name, raw, mode in members:
                    info = zipfile.ZipInfo(name);info.external_attr = mode << 16;bundle.writestr(info, raw)
        lock['artifact'] = {'id': 1, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}

    def test_exact_retained_binary_manifest_and_original_license_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            args, members = self.fixture(Path(directory));unpack_walker(**args)
            for name, raw, _ in members:self.assertEqual((args['destination']/name).read_bytes(), raw)
            self.assertEqual((args['destination']/'walker.LICENSE').read_bytes(), (args['root']/'image/launcher/licenses/walker.LICENSE').read_bytes())
            self.assertEqual((args['destination']/'walker').stat().st_mode & 0o777, 0o755)

    def test_stale_source_rpm_inputs_license_and_unreviewed_acceptance_are_refused(self):
        for change in ('source', 'build-rpms', 'runtime-rpms', 'license', 'base', 'commit', 'acceptance', 'qualified'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                args, _ = self.fixture(Path(directory))
                paths = {'source': 'walker-source.json', 'build-rpms': 'walker-build-rpms.lock.json',
                         'runtime-rpms': 'runtime-rpms.lock.json', 'license': 'licenses/walker.LICENSE'}
                if change in paths:
                    path = args['root']/'image/launcher'/paths[change]
                    if change == 'source':
                        source = json.loads(path.read_text());source['revision'] = 'f'*40;path.write_text(json.dumps(source))
                    else:path.write_bytes(path.read_bytes()+b'changed')
                elif change == 'base':args['build_base'] = 'different'
                elif change == 'commit':args['lock']['tested_commit'] = 'f'*40
                elif change == 'acceptance':args['lock']['upstream_tests_passed'] = False
                else:args['lock']['qualified'] = True
                with self.assertRaises(ValueError):unpack_walker(**args)
                self.assertFalse(args['destination'].exists())

    def test_payload_or_manifest_corruption_is_refused_and_output_removed(self):
        for index in (0, 1):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                args, members = self.fixture(Path(directory));name, raw, mode = members[index]
                members[index] = (name, b'x'+raw[1:], mode);self.archive(args['archive'], members, args['lock'])
                with self.assertRaises(ValueError):unpack_walker(**args)
                self.assertFalse(args['destination'].exists())

    def test_duplicate_link_traversal_or_oversize_archive_is_refused(self):
        for change in ('duplicate', 'link', 'traversal', 'size'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                args, members = self.fixture(Path(directory))
                if change == 'size':args['lock']['artifact']['bytes'] = 200*1024**2
                else:
                    if change == 'duplicate':members.append(members[0])
                    elif change == 'link':members[0] = ('walker', members[0][1], stat.S_IFLNK | 0o755)
                    else:members[0] = ('../walker', members[0][1], members[0][2])
                    self.archive(args['archive'], members, args['lock'])
                with self.assertRaises(ValueError):unpack_walker(**args)

    def test_existing_destination_or_linked_parent_is_refused(self):
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as directory:
                root = Path(directory);args, _ = self.fixture(root)
                if linked:
                    (root/'link').symlink_to(root, target_is_directory=True);args['destination'] = root/'link/output'
                else:args['destination'].mkdir()
                with self.assertRaises(ValueError):unpack_walker(**args)
