"""Only the retained compositor and exact portal sources may enter a native build."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from image.portal.build_inputs import (require_prefix_bindings, require_rpm_bindings,
                                       require_source_tree, require_test_report)


class PrefixBindings(unittest.TestCase):
    def fixture(self):
        sources = {'hyprland_revision': 'a'*40,
                   'libraries': [{'name': 'hyprutils', 'repo': 'hyprutils', 'owner': 'hyprwm', 'rev': 'b'*40}],
                   'glaze': {'revision': 'c'*40},
                   'submodules': [{'path': 'subprojects/udis86', 'revision': 'd'*40}]}
        rows = [{'name': name, 'url': url, 'rev': rev} for name, url, rev in [
            ('Hyprland', 'https://github.com/hyprwm/Hyprland.git', 'a'*40),
            ('hyprutils', 'https://github.com/hyprwm/hyprutils.git', 'b'*40),
            ('glaze', 'https://github.com/stephenberry/glaze.git', 'c'*40),
            ('Hyprland/subprojects/udis86', 'https://github.com/canihavesomecoffee/udis86.git', 'd'*40)]]
        manifest = {'compiled': True, 'os_qualified': False, 'source_commit': 'e'*40,
                    'base': 'registry/base@sha256:'+'f'*64, 'source_revisions': rows,
                    'rpm_lock_sha256': '1'*64, 'native_patch_sha256': '2'*64}
        return [manifest, {'tested_merge': 'e'*40}, sources, manifest['base'], '1'*64, '2'*64]

    def test_exact_prefix_sources_base_and_patch_are_reused(self):
        require_prefix_bindings(*self.fixture())

    def test_changed_source_origin_duplicate_base_patch_or_build_is_refused(self):
        for change in ('base', 'patch', 'rpm', 'build', 'compiled', 'qualified', 'revision', 'origin', 'duplicate', 'missing'):
            with self.subTest(change=change):
                args = self.fixture()
                m = args[0]
                if change == 'base':m['base'] = 'other'
                elif change == 'patch':m['native_patch_sha256'] = '3'*64
                elif change == 'rpm':m['rpm_lock_sha256'] = '3'*64
                elif change == 'build':m['source_commit'] = 'f'*40
                elif change == 'compiled':m['compiled'] = False
                elif change == 'qualified':m['os_qualified'] = True
                elif change == 'revision':m['source_revisions'][1]['rev'] = 'f'*40
                elif change == 'origin':m['source_revisions'][1]['url'] = 'https://other.invalid/library.git'
                elif change == 'duplicate':m['source_revisions'].append(copy.deepcopy(m['source_revisions'][0]))
                else:m['source_revisions'].pop()
                with self.assertRaises(ValueError):require_prefix_bindings(*args)


class RpmBindings(unittest.TestCase):
    def fixture(self):
        requirements = {'schema': 1, 'source_inputs_sha256': 'a'*64, 'packages': ['cmake']}
        key = {'fingerprint': 'B'*40, 'sha256': 'c'*64, 'path': 'image/hyprland/keys/fedora-45-primary.asc'}
        lock = {'schema': 1, 'qualified': False, 'product_installation': False,
                'base': 'registry/base@sha256:'+'d'*64, 'requirements': requirements,
                'key': key, 'source_inputs_sha256': 'a'*64}
        return [lock, copy.deepcopy(requirements), lock['base'], {'key': copy.deepcopy(key)}]

    def test_exact_signed_build_profile_is_accepted(self):
        require_rpm_bindings(*self.fixture())

    def test_stale_profile_key_base_or_product_claim_is_refused(self):
        for change in ('requirements', 'key', 'base', 'sources', 'qualified', 'product'):
            with self.subTest(change=change):
                args = self.fixture()
                lock = args[0]
                if change == 'requirements':lock['requirements']['packages'].append('curl')
                elif change == 'key':lock['key']['fingerprint'] = 'E'*40
                elif change == 'base':lock['base'] = 'registry/other:latest'
                elif change == 'sources':lock['source_inputs_sha256'] = 'e'*64
                elif change == 'qualified':lock['qualified'] = True
                else:lock['product_installation'] = True
                with self.assertRaises(ValueError):require_rpm_bindings(*args)


class SourceTree(unittest.TestCase):
    def fixture(self, root):
        component = {'name': 'hyprtoolkit', 'revision': 'a'*40, 'reviewed_files': {}}
        for name, data in [('VERSION', b'0.6.0\n'), ('CMakeLists.txt', b'project(toolkit)\n')]:
            (root/name).write_bytes(data)
            component['reviewed_files'][name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        return component

    def test_actual_checkout_files_match_reviewed_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            component = self.fixture(root)
            require_source_tree(root, component, 'a'*40)

    def test_changed_checkout_revision_bytes_links_and_path_escape_are_refused(self):
        for change in ('revision', 'bytes', 'link', 'escape', 'missing'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                component = self.fixture(root)
                rev = 'a'*40
                if change == 'revision':rev = 'b'*40
                elif change == 'bytes':(root/'VERSION').write_bytes(b'0.9.0\n')
                elif change == 'link':
                    (root/'VERSION').rename(root/'other')
                    (root/'VERSION').symlink_to('other')
                elif change == 'escape':component['reviewed_files']['../outside'] = component['reviewed_files']['VERSION']
                else:(root/'VERSION').unlink()
                with self.assertRaises(ValueError):require_source_tree(root, component, rev)


class TestReports(unittest.TestCase):
    def fixture(self):
        return b'<testsuites tests="2" failures="0" errors="0" disabled="0"><testsuite name="Input" tests="2" failures="0" errors="0" disabled="0"><testcase name="Physical" classname="Input" status="run" result="completed"/><testcase name="Synthetic" classname="Input" status="run" result="completed"/></testsuite></testsuites>'

    def test_complete_upstream_test_result_is_accepted(self):
        self.assertEqual(require_test_report(self.fixture()), ['Input.Physical', 'Input.Synthetic'])
        self.assertEqual(require_test_report(b'<testsuite tests="1" failures="0" disabled="0" skipped="0"><testcase name="hyprland-share-picker-data"/></testsuite>'), ['hyprland-share-picker-data'])

    def test_skipped_empty_failed_disabled_malformed_and_incomplete_results_are_refused(self):
        raw = self.fixture()
        cases = [raw.replace(b'tests="2"', b'tests="3"', 1),
                 raw.replace(b'failures="0"', b'failures="1"', 1),
                 raw.replace(b'errors="0"', b'errors="1"', 1),
                 raw.replace(b'disabled="0"', b'disabled="1"', 1),
                 raw.replace(b'result="completed"', b'result="skipped"', 1),
                 raw.replace(b'status="run"', b'status="notrun"', 1),
                 raw.replace(b'name="Synthetic"', b'name="Physical"'),
                 raw.replace(b'/><testcase', b'><skipped/></testcase><testcase', 1),
                 b'<testsuite tests="0"/>', b'<testcase name="one"/>',
                 b'<!DOCTYPE t [<!ENTITY e "x">]><testsuite tests="1">&e;</testsuite>',
                 raw[:-3], b'x'*(1024**2+1)]
        for index, data in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):require_test_report(data)

    def test_encoded_declaration_cannot_bypass_entity_refusal(self):
        xml = '<!DOCTYPE t [<!ENTITY e "hidden">]><testsuite tests="1"><testcase name="&e;"/></testsuite>'
        for data in (xml.encode('utf-16'), xml.encode('utf-32'),
                     b'<?xml version="1.0" encoding="iso-8859-1"?><testsuite tests="1"><testcase name="\xff"/></testsuite>'):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):require_test_report(data)


if __name__ == '__main__':
    unittest.main()
