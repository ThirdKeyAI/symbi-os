"""Bind a narrow portal-only patch and preserve every reused toolkit byte."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from image.portal.consent_inputs import (REVIEWED_FILES, IMPLEMENTATION_FILES,
                                         require_consent_bindings, require_tree,
                                         require_portal_only_install)


def sha(raw): return hashlib.sha256(raw).hexdigest()


class PortalConsentInputs(unittest.TestCase):
    def fixture(self):
        reviewed = {}
        for name in REVIEWED_FILES:
            raw = name.encode()
            reviewed[name] = {'path': 'image/portal/consent-reviewed/'+name, 'bytes': len(raw),
                              'sha256': sha(raw), 'git_blob': hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
        patches = []
        for role, path, names in (
                ('tests', '0001-no-restore-tests.patch', {'hyprland-share-picker/PickerDataTest.cpp'}),
                ('implementation', '0002-require-fresh-screen-sharing-consent.patch', IMPLEMENTATION_FILES)):
            patches.append({'role': role, 'path': 'image/portal/patches/'+path, 'bytes': 10, 'sha256': 'f'*64,
                            'files': {name: {'before': reviewed[name]['sha256'], 'after': sha((role+name).encode())} for name in names}})
        bundle = {'schema': 1, 'qualified': False, 'consent_qualified': False, 'product_installation': False,
                  'upstream_revision': 'a'*40, 'source_inputs_sha256': '1'*64, 'rpm_lock_sha256': '2'*64,
                  'parent_prefix_lock_sha256': '3'*64, 'reviewed_files': reviewed, 'patches': patches,
                  'patch_license': {'source': 'LICENSE', 'path': 'image/portal/consent-reviewed/LICENSE.symbi-os',
                                    'license': 'Apache-2.0', 'sha256': 'd'*64, 'bytes': 20,
                                    'installed_path': 'share/licenses/symbi-os-portal-patch/LICENSE'}}
        pins = {'components': [{'name': 'xdg-desktop-portal-hyprland', 'revision': 'a'*40}]}
        return bundle, pins

    def check(self, bundle, pins): require_consent_bindings(bundle, pins, '1'*64, '2'*64, '3'*64)

    def test_exact_scope_and_parent_bindings_are_accepted(self):
        self.check(*self.fixture())

    def test_changed_sources_scope_order_or_qualification_are_refused(self):
        for case in ('revision', 'source', 'packages', 'parent', 'qualification', 'order', 'scope', 'path', 'hash', 'unchanged'):
            with self.subTest(case=case):
                bundle, pins = self.fixture()
                if case == 'revision': bundle['upstream_revision'] = 'b'*40
                elif case == 'source': bundle['source_inputs_sha256'] = '4'*64
                elif case == 'packages': bundle['rpm_lock_sha256'] = '4'*64
                elif case == 'parent': bundle['parent_prefix_lock_sha256'] = '4'*64
                elif case == 'qualification': bundle['consent_qualified'] = True
                elif case == 'order': bundle['patches'].reverse()
                elif case == 'scope': bundle['patches'][1]['files']['CMakeLists.txt'] = {'before': '0'*64, 'after': '1'*64}
                elif case == 'path': next(iter(bundle['reviewed_files'].values()))['path'] = '../outside'
                elif case == 'hash': bundle['patches'][0]['sha256'] = 'bad'
                else:
                    row = next(iter(bundle['patches'][0]['files'].values())); row['after'] = row['before']
                with self.assertRaises(ValueError): self.check(bundle, pins)

    def test_changed_review_or_patch_preimage_is_refused(self):
        for case in ('missing', 'extra', 'blob', 'large', 'before', 'patch_license'):
            with self.subTest(case=case):
                bundle, pins = self.fixture(); name = 'hyprland-share-picker/PickerDataTest.cpp'
                if case == 'missing': del bundle['reviewed_files'][name]
                elif case == 'extra': bundle['reviewed_files']['../escape'] = copy.deepcopy(bundle['reviewed_files'][name])
                elif case == 'blob': bundle['reviewed_files'][name]['git_blob'] = 'bad'
                elif case == 'large': bundle['reviewed_files'][name]['bytes'] = 128*1024+1
                elif case == 'before': bundle['patches'][0]['files'][name]['before'] = 'c'*64
                else: bundle['patch_license']['license'] = 'MIT'
                with self.assertRaises(ValueError): self.check(bundle, pins)

    def test_each_patch_phase_requires_the_exact_transformed_files(self):
        bundle, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in REVIEWED_FILES:
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(name.encode())
            require_tree(root, bundle, 'upstream')
            with self.assertRaises(ValueError): require_tree(root, bundle, 'tests')
            for row in bundle['patches']:
                for name in row['files']: (root/name).write_bytes((row['role']+name).encode())
                require_tree(root, bundle, row['role'])
            with self.assertRaises(ValueError): require_tree(root, bundle, 'upstream')
            with self.assertRaises(ValueError): require_tree(root, bundle, 'unknown')

    def test_linked_or_oversized_reviewed_source_is_refused(self):
        for case in ('link', 'large'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                bundle, _ = self.fixture(); root = Path(directory)
                for name in REVIEWED_FILES:
                    path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(name.encode())
                path = root/'src/portals/Screencopy.cpp'
                if case == 'link':
                    path.unlink(); path.symlink_to(root/'LICENSE')
                else: path.write_bytes(b'x'*(128*1024+1))
                with self.assertRaises(ValueError): require_tree(root, bundle, 'upstream')

    def test_only_portal_and_picker_binaries_may_change_in_retained_prefix(self):
        file = {'sha256': 'a'*64, 'bytes': 10, 'mode': 0o755}
        before = {'files': {'bin/hyprland-share-picker': file.copy(), 'libexec/xdg-desktop-portal-hyprland': file.copy(),
                            'lib/libhyprtoolkit.so.0.6.0': file.copy(), 'share/licenses/hyprtoolkit/LICENSE': file.copy()}}
        after = copy.deepcopy(before['files'])
        for name in ('bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland'):
            after[name]['sha256'] = 'b'*64
        require_portal_only_install(before, after)
        for case in ('toolkit', 'license', 'extra', 'old_binary', 'mode', 'link'):
            with self.subTest(case=case):
                changed = copy.deepcopy(after)
                if case == 'toolkit': changed['lib/libhyprtoolkit.so.0.6.0']['sha256'] = 'c'*64
                elif case == 'license': changed['share/licenses/hyprtoolkit/LICENSE']['mode'] = 0o644
                elif case == 'extra': changed['bin/extra'] = file.copy()
                elif case == 'old_binary': changed['bin/hyprland-share-picker'] = file.copy()
                elif case == 'mode': changed['bin/hyprland-share-picker']['mode'] = 0o4755
                else: changed['bin/hyprland-share-picker'] = {'link': '../lib/unreviewed'}
                with self.assertRaises(ValueError): require_portal_only_install(before, changed)

    def test_prefix_inventory_refuses_external_links_and_special_files(self):
        from image.portal.consent_inputs import prefix_inventory
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'library').write_bytes(b'native'); (root/'library').chmod(0o755)
            (root/'link').symlink_to('library')
            self.assertEqual(prefix_inventory(root), {'library': {'bytes': 6, 'mode': 0o755, 'sha256': sha(b'native')},
                                                      'link': {'link': 'library'}})
            (root/'link').unlink(); (root/'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): prefix_inventory(root)
            (root/'link').unlink(); os.mkfifo(root/'special')
            with self.assertRaises(ValueError): prefix_inventory(root)

    def test_downstream_license_is_required_and_bound_when_supplied(self):
        file = {'sha256': 'a'*64, 'bytes': 10, 'mode': 0o755}
        before = {'files': {'bin/hyprland-share-picker': file.copy(), 'libexec/xdg-desktop-portal-hyprland': file.copy()}}
        after = {name: dict(row, sha256='b'*64) for name, row in before['files'].items()}
        license = {'installed_path': 'share/licenses/symbi-os-portal-patch/LICENSE', 'sha256': 'c'*64, 'bytes': 20}
        after[license['installed_path']] = {'sha256': license['sha256'], 'bytes': license['bytes'], 'mode': 0o644}
        require_portal_only_install(before, after, license)
        for case in ('missing', 'changed', 'mode'):
            with self.subTest(case=case):
                modified = copy.deepcopy(after)
                if case == 'missing': del modified[license['installed_path']]
                elif case == 'changed': modified[license['installed_path']]['sha256'] = 'd'*64
                else: modified[license['installed_path']]['mode'] = 0o755
                with self.assertRaises(ValueError): require_portal_only_install(before, modified, license)


if __name__ == '__main__': unittest.main()
