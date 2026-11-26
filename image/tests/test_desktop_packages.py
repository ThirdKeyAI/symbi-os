"""Desktop candidates need exact, isolated package-signing trust before review."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('desktop_package_contract',
    Path(__file__).parents[1] / 'desktop_packages/contract.py')
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)
FEDORA = '4F50A6114CD5C6976A7F1179655A4B02F577861E'
FUSION = 'E9A491A3DE247814E7E067EAE06F8ECDD651FF2E'


class DesktopPackages(unittest.TestCase):
    def verified(self, fingerprint):
        return ('candidate.rpm:\n'
                f'    Header V4 RSA/SHA256 Signature, key fingerprint: {fingerprint.lower()}: OK\n'
                '    Header SHA256 digest: OK\n'
                '    Payload SHA256 digest: OK\n')

    def test_exact_two_keyring_identities(self):
        contract.require_keyring(FEDORA + ' Fedora\n' + FUSION + ' RPM Fusion\n', [FEDORA, FUSION])
        for output in (FEDORA+' Fedora\n', FEDORA+' Fedora\n'+FEDORA+' Fedora\n',
                       FEDORA+' Fedora\n'+FUSION+' Fusion\n'+'A'*40+' unexpected\n'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                contract.require_keyring(output, [FEDORA, FUSION])

    def test_verified_payload_reports_exact_allowed_signer(self):
        for key in (FEDORA, FUSION):
            self.assertEqual(contract.verified_signer(0, self.verified(key), [FEDORA, FUSION]), key)

    def test_untrusted_incomplete_or_failed_signature_is_rejected(self):
        good = self.verified(FEDORA)
        cases = [(1, good), (0, self.verified('A'*40)),
                 (0, good.replace('Payload SHA256 digest: OK\n', 'Payload SHA256 digest: BAD\n')),
                 (0, good.replace('    Payload SHA256 digest: OK\n', '')),
                 (0, good.replace(FEDORA.lower(), FEDORA[-16:].lower())),
                 (0, 'candidate.rpm: digests OK\n'),
                 (0, good + f'    V4 RSA/SHA256 Signature, key fingerprint: {FUSION}: OK\n')]
        for status, output in cases:
            with self.subTest(output=output), self.assertRaises(ValueError):
                contract.verified_signer(status, output, [FEDORA, FUSION])

    def test_repo_policy_cannot_enable_unsigned_or_unrelated_repositories(self):
        configs = {
            'fedora': {'metalink': 'https://mirrors.fedoraproject.org/metalink?protocol=https&repo=fedora-45&arch=x86_64',
                       'key': 'file:///inputs/fedora-45-primary.asc'},
            'updates': {'metalink': 'https://mirrors.fedoraproject.org/metalink?protocol=https&repo=updates-released-f45&arch=x86_64',
                        'key': 'file:///inputs/fedora-45-primary.asc'},
            'rpmfusion-free': {'metalink': 'https://mirrors.rpmfusion.org/metalink?repo=free-fedora-45&arch=x86_64&protocol=https',
                               'key': 'file:///inputs/rpmfusion-free-2020.asc'},
            'rpmfusion-free-updates': {'metalink': 'https://mirrors.rpmfusion.org/metalink?repo=free-fedora-updates-released-45&arch=x86_64&protocol=https',
                                       'key': 'file:///inputs/rpmfusion-free-2020.asc'},
        }
        def render(values):
            return '\n'.join(f'[{name}]\nmetalink={v["metalink"]}\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\nskip_if_unavailable=0\ngpgkey={v["key"]}\n' for name,v in values.items())
        good = render(configs)
        contract.require_repositories(good)
        bad = [good.replace('gpgcheck=1', 'gpgcheck=0', 1),
               good.replace('sslverify=1', 'sslverify=0', 1),
               good.replace('https://mirrors.rpmfusion.org/', 'http://mirrors.rpmfusion.org/', 1),
               good.replace('fedora-45-primary.asc', 'unreviewed.asc', 1),
               good.replace('free-fedora-45', 'nonfree-fedora-45', 1),
               good + '\n[unreviewed]\nenabled=1\n',
               good.replace('enabled=1', 'enabled=0', 1)]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                contract.require_repositories(value)

    def test_candidate_requirements_do_not_claim_security_clearance(self):
        value = {'schema': 1, 'packages': ['kitty', 'mplayer', 'mpv'],
                 'security_review': {'kitty': {'minimum_upstream_version': '0.51.0',
                   'cves': ['CVE-2026-134823', 'CVE-2026-95835'],
                   'fixed_package_verified': False}}, 'packages_selected': False}
        contract.require_requirements(value)
        for change in ('flag', 'url', 'duplicate', 'missing_mplayer', 'selected', 'fixed'):
            bad = copy.deepcopy(value)
            if change == 'flag': bad['packages'].append('--nogpgcheck')
            elif change == 'url': bad['packages'].append('https://example.invalid/a.rpm')
            elif change == 'duplicate': bad['packages'].append('kitty')
            elif change == 'missing_mplayer': bad['packages'].remove('mplayer')
            elif change == 'selected': bad['packages_selected'] = True
            else: bad['security_review']['kitty']['fixed_package_verified'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                contract.require_requirements(bad)

    def input_fixture(self, root):
        staged=Path(__file__).parents[1]/'desktop_packages'
        # Tests run both in the full repository and in a staged namespace.
        import image.hyprland.guest_inventory as guest
        existing=Path(guest.__file__).resolve().parents[2]
        for source in staged.iterdir():
            if source.is_file():
                target=root/'image/desktop_packages'/source.name
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        for relative in ('image/hyprland/guest_inventory.py','image/hyprland/package-dnf.conf',
                         'image/hyprland/fedora-package-trust.json','image/hyprland/keys/fedora-45-primary.asc',
                         'image/launcher/probes/bounded_process.py'):
            target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(existing/relative,target)
        return json.loads((root/'image/desktop_packages/trust.json').read_text())['base']

    def test_host_inputs_bind_public_keys_and_private_repository_configuration(self):
        from image.desktop_packages.hosted import prepare_inputs
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);base=self.input_fixture(root)
            result=prepare_inputs(root,root/'inputs',base)
            self.assertEqual(result['trust']['base'],base)
            self.assertEqual(result['trust']['keys'][0]['fingerprint'],FEDORA)
            self.assertEqual(result['trust']['keys'][1]['fingerprint'],FUSION)
            self.assertEqual(set(result['bindings']),{str(p.relative_to(root/'inputs')) for p in (root/'inputs').rglob('*') if p.is_file()})
            self.assertFalse(result['requirements']['packages_selected'])

    def test_changed_linked_or_mismatched_host_inputs_are_rejected_before_staging(self):
        from image.desktop_packages.hosted import prepare_inputs
        for change in ('key','repository','link','base','repo_metadata_link'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);base=self.input_fixture(root)
                key=root/'image/desktop_packages/rpmfusion-free-2020.asc'
                if change=='key': key.write_bytes(b'changed key')
                elif change=='repository':
                    p=root/'image/desktop_packages/desktop.repo';p.write_text(p.read_text().replace('gpgcheck = 1','gpgcheck = 0'))
                elif change=='link':
                    moved=root/'outside-key';key.rename(moved);key.symlink_to(moved)
                elif change=='repo_metadata_link':
                    metadata=root/'image/desktop_packages/repository-inputs.json'
                    moved=root/'outside-metadata';metadata.rename(moved);metadata.symlink_to(moved)
                else: base='unreviewed-base'
                with self.assertRaises(ValueError): prepare_inputs(root,root/'inputs',base)
                self.assertFalse((root/'inputs').exists())

    def test_public_evidence_copy_rejects_links_directories_and_oversize(self):
        from image.desktop_packages.hosted import collect_evidence
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'evidence';source.mkdir()
            (source/'result.json').write_text('{}\n');(source/'probe-stdout.log').write_text('checked\n')
            collect_evidence(source,root/'retained')
            self.assertEqual((root/'retained/probe-stdout.log').read_text(),'checked\n')
        for change in ('link','directory','oversize','unexpected'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);source=root/'evidence';source.mkdir()
                path=source/'probe.log'
                if change=='link': path.symlink_to('/etc/passwd')
                elif change=='directory': path.mkdir()
                elif change=='oversize':
                    with path.open('wb') as stream: stream.truncate(1024**2+1)
                else: (source/'unexpected.rpm').write_bytes(b'not evidence')
                with self.assertRaises(ValueError): collect_evidence(source,root/'retained')
                self.assertFalse((root/'retained').exists())


if __name__ == '__main__':
    unittest.main()
