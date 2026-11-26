"""Refuse wrong image, installation inputs, protection state and local execution."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import unittest

from image.boot.preflight import validate_report, validate_loaded_image


class AtomicPreflight(unittest.TestCase):
    def fixture(self):
        file = {'bytes': 2048, 'sha256': 'a'*64, 'uid': 0, 'mode': 0o644}
        expected = {'os': {'ID':'secureblue','ID_LIKE':'fedora','VERSION_ID':'45',
                            'VARIANT_ID':'sericea-main-hardened','IMAGE_ID':'sericea-main-hardened'},
                    'kernel': '7.3.4-200.fc45.x86_64', 'bootc_version': '1.17.1',
                    'packages': ['bootc\t0\t1.17.1\t1.fc45\tx86_64',
                                 'kernel-core\t0\t7.3.4\t200.fc45\tx86_64'],
                    'trust': {'etc/containers/policy.json': 'b'*64,
                              'etc/containers/registries.d/symbiont.yaml': 'c'*64}}
        report = {'schema': 1, 'os_qualified': False, 'guest_booted': False,
                  'uid': 10001, 'cap_eff': '0000000000000000', 'no_new_privileges': '1',
                  'root_readonly': True, 'interfaces': ['lo'],
                  'limits': {'memory.max': '536870912', 'memory.swap.max': '0',
                             'cpu.max': '100000 100000', 'pids.max': '64'},
                  'os': expected['os'].copy(), 'selinux': {'SELINUX': 'enforcing'},
                  'packages': expected['packages'].copy(), 'bootc_version': 'bootc 1.17.1',
                  'root_fs': {'root-fs-type': 'btrfs'}, 'install_options': ['--source-imgref',
                    '--target-imgref', '--enforce-container-sigpolicy', '--generic-image', '--via-loopback', '--filesystem'],
                  'kernel': {'version': expected['kernel'], 'vmlinuz': file.copy(), 'initramfs.img': file.copy()},
                  'trust': {path: {**file, 'sha256': digest} for path,digest in expected['trust'].items()}}
        return report, expected

    def test_valid_observation_remains_unqualified(self):
        report, expected = self.fixture()
        validate_report(report, expected)
        self.assertFalse(report['os_qualified']); self.assertFalse(report['guest_booted'])

    def test_policy_package_kernel_or_selinux_drift_is_refused(self):
        report, expected = self.fixture()
        mutations = [lambda d: d['trust']['etc/containers/policy.json'].update(sha256='d'*64),
                     lambda d: d['trust']['etc/containers/registries.d/symbiont.yaml'].update(mode=0o666),
                     lambda d: d['packages'].pop(), lambda d: d['packages'].append(d['packages'][0]),
                     lambda d: d['kernel'].update(version='7.2.11'),
                     lambda d: d['kernel']['initramfs.img'].update(bytes=0),
                     lambda d: d['kernel']['vmlinuz'].update(sha256='wrong'),
                     lambda d: d['selinux'].update(SELINUX='permissive'),
                     lambda d: d.update(bootc_version='bootc 1.16.0'),
                     lambda d: d.update(os={'ID':'ubuntu','VERSION_ID':'24.04'})]
        for i, change in enumerate(mutations):
            candidate=copy.deepcopy(report); change(candidate)
            with self.subTest(i=i), self.assertRaises(ValueError): validate_report(candidate,expected)

    def test_unsafe_execution_or_false_qualification_is_refused(self):
        report,expected=self.fixture()
        for key,value in [('uid',0),('cap_eff','0000000000000001'),('no_new_privileges','0'),
                          ('root_readonly',False),('interfaces',['lo','eth0']),('guest_booted',True),
                          ('os_qualified',True),('schema',True),('install_options',[]),
                          ('root_fs',{'root-fs-type':'unknown'})]:
            candidate=copy.deepcopy(report);candidate[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): validate_report(candidate,expected)
        candidate=copy.deepcopy(report);candidate['limits']['memory.swap.max']='max'
        with self.assertRaises(ValueError): validate_report(candidate,expected)

    def test_missing_or_malformed_observations_fail_closed(self):
        report,expected=self.fixture()
        for key in report:
            for action in ('missing','wrong_type'):
                candidate=copy.deepcopy(report)
                if action=='missing': del candidate[key]
                else: candidate[key]=None
                with self.subTest(key=key,action=action),self.assertRaises(ValueError):
                    validate_report(candidate,expected)

    def test_no_installer_default_requires_explicit_filesystem_choice(self):
        report,expected=self.fixture()
        report['root_fs']['root-fs-type']=None
        requirements=validate_report(report,expected)
        self.assertEqual(requirements,{'filesystem_default':None,'filesystem_argument_required':True})
        self.assertFalse(report['os_qualified']);self.assertFalse(report['guest_booted'])
        report['root_fs']['root-fs-type']='btrfs'
        self.assertEqual(validate_report(report,expected),
                         {'filesystem_default':'btrfs','filesystem_argument_required':False})

    def test_exact_secureblue_variant_and_fedora_lineage_are_required(self):
        report,expected=self.fixture()
        for key,value in [('ID','fedora'),('ID_LIKE','debian'),('VERSION_ID','44'),
                          ('VARIANT_ID','sericea-nvidia-hardened'),('IMAGE_ID','other')]:
            candidate=copy.deepcopy(report);candidate['os'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): validate_report(candidate,expected)

    def test_only_one_exact_loaded_image_is_selected(self):
        image_id='sha256:'+'e'*64
        valid={'Id':image_id,'Digest':'sha256:'+'f'*64,'Architecture':'amd64','Os':'linux'}
        self.assertEqual(validate_loaded_image([valid],image_id),valid)
        self.assertEqual(validate_loaded_image([{**valid,'Id':'e'*64}],image_id)['Digest'],valid['Digest'])
        for candidate in ([],[valid,valid],[{**valid,'Id':'a'*64}],
                          [{**valid,'Architecture':'arm64'}],[{**valid,'Os':'windows'}],
                          [{**valid,'Digest':'latest'}],None):
            with self.subTest(candidate=candidate),self.assertRaises(ValueError):
                validate_loaded_image(candidate,image_id)

    def test_hosted_controller_and_probe_refuse_local_execution(self):
        stage=Path(__file__).resolve().parents[2]
        env=dict(os.environ);env.pop('GITHUB_ACTIONS',None);env.pop('RUNNER_ENVIRONMENT',None)
        for script in ('image/boot/hosted.py','image/boot/probe.py'):
            result=subprocess.run([sys.executable,str(stage/script)],env=env,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Use the ',result.stderr)
            self.assertNotIn('Traceback',result.stderr)


if __name__=='__main__': unittest.main()
