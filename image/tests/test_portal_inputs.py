"""Portal discovery must use the compositor's exact sources and reviewed RPM scope."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from image.portal.inputs import read_pinned, require_package_selection, require_source_selection


EXTRA = ['pkgconfig(libpipewire-0.3)', 'pkgconfig(libspa-0.2)',
         'pkgconfig(sdbus-c++)', 'pkgconfig(iniparser)', 'pkgconfig(absl_flat_hash_map)']


class PortalSourceSelection(unittest.TestCase):
    def fixture(self):
        components = [{'name': name, 'lock_node': node, 'revision': rev,
                       'repository': 'https://github.com/hyprwm/'+name+'.git'}
                      for name, node, rev in [('hyprtoolkit', 'hyprtoolkit', 'b'*40),
                                              ('xdg-desktop-portal-hyprland', 'xdph', 'c'*40)]]
        pins = {'schema': 1, 'qualified': False, 'hyprland_revision': 'a'*40, 'components': components}
        flake = {'nodes': {x['lock_node']: {'locked': {'type': 'github', 'owner': 'hyprwm',
                 'repo': x['name'], 'rev': x['revision']}} for x in components}}
        compositor = {'hyprland_revision': 'a'*40}
        return pins, flake, compositor

    def test_exact_release_selected_pair_is_accepted(self):
        require_source_selection(*self.fixture())

    def test_changed_source_origin_revision_node_or_pair_is_refused(self):
        for change in ('compositor', 'revision', 'tag', 'origin', 'node', 'duplicate',
                       'extra', 'missing', 'qualified', 'lock_owner', 'lock_type'):
            with self.subTest(change=change):
                pins, flake, compositor = self.fixture()
                component = pins['components'][0]
                if change == 'compositor':compositor['hyprland_revision'] = 'd'*40
                elif change == 'revision':component['revision'] = 'd'*40
                elif change == 'tag':component['revision'] = 'v0.6.0'
                elif change == 'origin':component['repository'] = 'https://unreviewed.example/toolkit.git'
                elif change == 'node':component['lock_node'] = 'xdph'
                elif change == 'duplicate':pins['components'].append(copy.deepcopy(component))
                elif change == 'extra':pins['components'].append({'name': 'unreviewed'})
                elif change == 'missing':pins['components'].pop()
                elif change == 'qualified':pins['qualified'] = True
                elif change == 'lock_owner':flake['nodes']['hyprtoolkit']['locked']['owner'] = 'other'
                else:flake['nodes']['hyprtoolkit']['locked']['type'] = 'git'
                with self.assertRaises(ValueError):require_source_selection(pins, flake, compositor)


class PortalPackageSelection(unittest.TestCase):
    def fixture(self):
        pins = {'hyprland_revision': 'a'*40}
        base = {'schema': 1, 'hyprland_revision': 'a'*40, 'packages': ['gcc-c++', 'cmake']}
        requirements = {'schema': 1, 'source_inputs': 'image/portal/source-inputs.json',
                        'source_inputs_sha256': 'b'*64, 'hyprland_revision': 'a'*40,
                        'base_requirements': 'image/hyprland/build-requirements.json',
                        'base_requirements_sha256': 'c'*64, 'packages': base['packages']+EXTRA}
        return [requirements, pins, base, 'b'*64, 'c'*64]

    def test_reuses_reviewed_build_scope_plus_portal_requirements(self):
        require_package_selection(*self.fixture())

    def test_changed_hashes_profile_missing_or_extra_package_is_refused(self):
        for change in ('sources', 'base', 'source_path', 'base_path', 'revision',
                       'base_revision', 'missing', 'extra', 'duplicate', 'option'):
            with self.subTest(change=change):
                args = self.fixture()
                req = args[0]
                if change == 'sources':args[3] = 'd'*64
                elif change == 'base':args[4] = 'd'*64
                elif change == 'source_path':req['source_inputs'] = '../elsewhere.json'
                elif change == 'base_path':req['base_requirements'] = 'another-profile.json'
                elif change == 'revision':req['hyprland_revision'] = 'd'*40
                elif change == 'base_revision':args[2]['hyprland_revision'] = 'd'*40
                elif change == 'missing':req['packages'].pop()
                elif change == 'extra':req['packages'].append('unreviewed-package')
                elif change == 'duplicate':req['packages'].append(req['packages'][0])
                else:req['packages'].append('--nogpgcheck')
                with self.assertRaises(ValueError):require_package_selection(*args)


class ReviewedFiles(unittest.TestCase):
    def test_exact_regular_source_bytes_are_returned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            path = root/'image/portal/reviewed/hyprtoolkit/VERSION'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'0.6.0\n')
            self.assertEqual(read_pinned(root, str(path.relative_to(root)), hashlib.sha256(path.read_bytes()).hexdigest()), b'0.6.0\n')

    def test_changed_bytes_symlink_parent_escape_and_oversize_are_refused(self):
        for change in ('hash', 'link', 'parent', 'escape', 'oversize'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                path = root/'image/portal/reviewed/hyprtoolkit/VERSION'
                path.parent.mkdir(parents=True)
                path.write_bytes(b'0.6.0\n')
                expected = hashlib.sha256(path.read_bytes()).hexdigest()
                relative = str(path.relative_to(root))
                if change == 'hash':path.write_bytes(b'0.7.0\n')
                elif change == 'link':
                    outside = root/'version';path.rename(outside);path.symlink_to(outside)
                elif change == 'parent':
                    old = path.parent;target = root/'toolkit';old.rename(target);old.symlink_to(target, target_is_directory=True)
                elif change == 'escape':relative = 'image/portal/reviewed/hyprtoolkit/../../../../outside'
                else:
                    path.write_bytes(b'a'*(128*1024+1));expected = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):read_pinned(root, relative, expected)


if __name__ == '__main__':
    unittest.main()
