"""The patched prefix must retain its exact parent, native controls and bytes."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

import image.tests.test_portal_prefix as original_tests
from image.portal.consent_prefix import require_consent_manifest, unpack_consent_portal


def sha(data): return hashlib.sha256(data).hexdigest()


class ConsentPrefix(unittest.TestCase):
    def fixture(self, root, mutate=None):
        old = root/'old'; old.mkdir()
        parent_args = original_tests.PortalPrefix().fixture(old)
        parent = parent_args[1]
        with zipfile.ZipFile(parent_args[0]) as bundle:
            data = bundle.read('portal-prefix.tar.gz')
        members = []
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as bundle:
            for info in bundle:
                raw = bundle.extractfile(info).read() if info.isfile() else None
                members.append((copy.copy(info), raw))
        manifest = copy.deepcopy(parent['manifest'])
        license = {'installed_path': 'share/licenses/symbi-os-portal-patch/LICENSE', 'sha256': sha(b'patch license'), 'bytes': 13}
        consent = {'upstream_revision': 'b'*40, 'patch_license': license}
        manifest.update(consent_inputs=consent, parent_prefix_manifest_sha256=parent['manifest_sha256'],
                        native_negative_controls={'original_native_test_failed': True, 'allow-token_rejected': True, 'unknown-option_rejected': True})
        manifest['test_suites'] = {'portal-tests': manifest['test_suites']['portal-tests']}
        for name in ('bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland'):
            for info, raw in members:
                if info.name == 'portal/'+name:
                    changed = raw+b' patched'
                    members[members.index((info, raw))] = (info, changed)
                    info.size = len(changed)
                    manifest['files'][name] = {'sha256': sha(changed), 'bytes': len(changed), 'mode': 0o755}
                    break
        info = tarfile.TarInfo('portal/share/licenses/symbi-os-portal-patch'); info.type = tarfile.DIRTYPE; info.mode = 0o755
        members.append((info, None))
        info = tarfile.TarInfo('portal/'+license['installed_path']); info.mode = 0o644; info.size = license['bytes']
        members.append((info, b'patch license'))
        manifest['files'][license['installed_path']] = {'sha256': license['sha256'], 'bytes': license['bytes'], 'mode': 0o644}
        manifest['unchanged_retained_files'] = sorted(set(parent['manifest']['files'])-{'bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland'})
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as bundle:
            for info, raw in members:
                if mutate: mutate(info)
                bundle.addfile(info, io.BytesIO(raw) if raw is not None else None)
        payload = output.getvalue()
        manifest.update(payload_bytes=len(payload), payload_sha256=sha(payload))
        raw = (json.dumps(manifest)+'\n').encode()
        archive = root/'consent.zip'
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('manifest.json', raw); bundle.writestr('portal-prefix.tar.gz', payload)
        lock = {'schema': 1, 'qualified': False, 'product_installation': False, 'consent_qualified': False,
                'tested_commit': manifest['source_commit'], 'run_id': 1, 'manifest': manifest, 'manifest_sha256': sha(raw),
                'artifact': {'id': 2, 'name': 'portal-consent-prefix', 'bytes': archive.stat().st_size, 'sha256': sha(archive.read_bytes())}}
        return archive, lock, parent_args[2], consent, parent, *parent_args[3:]

    def test_exact_patched_files_and_original_toolkit_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); args = self.fixture(root)
            actual = unpack_consent_portal(*args, root/'out')
            self.assertEqual(actual, args[1]['manifest'])
            self.assertEqual((root/'out/portal/bin/hyprland-share-picker').read_bytes(), b'picker fixture patched')
            self.assertEqual((root/'out/portal/lib/libhyprtoolkit.so').read_bytes(), b'library fixture')
            self.assertEqual((root/'out/portal/share/licenses/symbi-os-portal-patch/LICENSE').read_bytes(), b'patch license')
            self.assertEqual((root/'out').stat().st_mode & 0o777, 0o700)

    def test_changed_parent_patch_native_controls_or_claims_are_refused(self):
        for kind in ('parent', 'patch', 'tests', 'controls', 'toolkit', 'old-binary', 'license', 'accounting', 'qualified', 'artifact', 'run'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                args = list(self.fixture(Path(directory).resolve())); lock = args[1]; manifest = copy.deepcopy(lock['manifest'])
                if kind == 'parent': manifest['parent_prefix_manifest_sha256'] = '9'*64
                elif kind == 'patch': manifest['consent_inputs']['upstream_revision'] = '9'*40
                elif kind == 'tests': manifest['test_suites']['portal-tests']['cases'] = ['substitute']
                elif kind == 'controls': manifest['native_negative_controls']['original_native_test_failed'] = False
                elif kind == 'toolkit': manifest['files']['lib/libhyprtoolkit.so.0.6.0']['sha256'] = '9'*64
                elif kind == 'old-binary': manifest['files']['bin/hyprland-share-picker'] = copy.deepcopy(args[4]['manifest']['files']['bin/hyprland-share-picker'])
                elif kind == 'license': del manifest['files']['share/licenses/symbi-os-portal-patch/LICENSE']
                elif kind == 'accounting': manifest['unchanged_retained_files'] = []
                elif kind == 'qualified': manifest['consent_qualified'] = True
                elif kind == 'artifact': lock['artifact']['name'] = 'portal-development-prefix'
                else: lock['run_id'] = True
                lock['manifest'] = manifest
                with self.assertRaises(ValueError): require_consent_manifest(manifest, *args[1:])

    def test_original_test_suite_cannot_be_substituted_for_patched_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory).resolve()); args[1]['manifest']['test_suites'] = copy.deepcopy(args[4]['manifest']['test_suites'])
            with self.assertRaises(ValueError): require_consent_manifest(args[1]['manifest'], *args[1:])

    def test_archive_manifest_and_payload_tampering_leave_no_destination(self):
        for member in ('archive', 'manifest.json', 'portal-prefix.tar.gz'):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); args = self.fixture(root); archive, lock = args[:2]
                if member == 'archive': archive.write_bytes(archive.read_bytes()+b'changed')
                else:
                    with zipfile.ZipFile(archive) as bundle: content = {name: bundle.read(name) for name in bundle.namelist()}
                    content[member] += b'changed'
                    with zipfile.ZipFile(archive, 'w') as bundle:
                        for name, data in content.items(): bundle.writestr(name, data)
                    lock['artifact'].update(bytes=archive.stat().st_size, sha256=sha(archive.read_bytes()))
                with self.assertRaises(ValueError): unpack_consent_portal(*args, root/'out')
                self.assertFalse((root/'out').exists())

    def test_escaping_paths_links_special_files_modes_and_missing_members_are_refused(self):
        for kind in ('traversal', 'absolute', 'link', 'extra', 'mode', 'hardlink', 'fifo', 'directory'):
            def mutate(info):
                if info.name == 'portal/bin/hyprland-share-picker':
                    if kind == 'traversal': info.name = 'portal/../escape'
                    elif kind == 'absolute': info.name = '/portal/bin/hyprland-share-picker'
                    elif kind == 'extra': info.name = 'portal/bin/unreviewed'
                    elif kind == 'mode': info.mode = 0o4755
                    elif kind == 'hardlink': info.type = tarfile.LNKTYPE; info.linkname = 'portal/lib/libhyprtoolkit.so.0.6.0'
                    elif kind == 'fifo': info.type = tarfile.FIFOTYPE
                if kind == 'directory' and info.name == 'portal/bin': info.mode = 0o777
                if kind == 'link' and info.name == 'portal/lib/libhyprtoolkit.so': info.linkname = '/etc/passwd'
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); args = self.fixture(root, mutate)
                with self.assertRaises(ValueError): unpack_consent_portal(*args, root/'out')
                self.assertFalse((root/'out').exists())

    def test_existing_or_linked_destination_is_not_touched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); args = self.fixture(root); target = root/'out'; target.mkdir()
            (target/'keep').write_bytes(b'keep'); (root/'alias').symlink_to(target, target_is_directory=True)
            for destination in (target, root/'alias/nested'):
                with self.assertRaises(ValueError): unpack_consent_portal(*args, destination)
            self.assertEqual((target/'keep').read_bytes(), b'keep')


if __name__ == '__main__': unittest.main()
