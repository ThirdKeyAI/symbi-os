"""Reject incomplete native runtime results before reporting a usable closure."""
import copy
import unittest

from image.portal.runtime_inputs import require_runtime_result


class PortalRuntimeEvidence(unittest.TestCase):
    def fixture(self):
        limits = {'memory.max': '2147483648', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '128'}
        return {'passed': True, 'os_qualified': False, 'consent_qualified': False,
                'all_base_packages_unchanged': True, 'base_crypto_configuration_unchanged': True,
                'negative_controls': {'missing_key_rejected': True, 'tampered_package_rejected': True},
                'base_package_count': 2178, 'added_packages': ['iniparser\t0\t4.2.6\t5.fc45\tx86_64'],
                'required_packages': ['iniparser\t0\t4.2.6\t5.fc45\tx86_64'],
                'runtime_package': {'sha256': 'a'*64},
                'probe_identity': {'uid': [10001]*4, 'gid': [10001]*4, 'groups': [],
                                   'capabilities': {name: '0000000000000000' for name in
                                                    ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')},
                                   'no_new_privileges': 1},
                'loader_probes': ['lib/libhyprtoolkit.so.0.6.0', 'bin/hyprland-share-picker',
                                  'libexec/xdg-desktop-portal-hyprland'],
                'portal_version': 'xdg-desktop-portal-hyprland v1.5.0', 'limits': limits,
                'cgroup_final': dict(limits, **{'memory.peak': '50000000',
                     'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0'})}

    def test_requires_complete_unprivileged_loader_result(self):
        result = self.fixture()
        require_runtime_result(result, result['runtime_package'], '1.5.0')

    def test_missing_probe_or_qualification_overclaim_is_refused(self):
        for case in ('failed', 'missing_loader', 'duplicate_loader', 'version', 'os', 'consent', 'base',
                     'crypto', 'missing_control', 'tamper_control', 'added', 'required', 'package', 'inventory'):
            with self.subTest(case=case):
                result = self.fixture(); package = copy.deepcopy(result['runtime_package'])
                if case == 'failed': result['passed'] = False
                elif case == 'missing_loader': result['loader_probes'].pop()
                elif case == 'duplicate_loader': result['loader_probes'][-1] = result['loader_probes'][0]
                elif case == 'version': result['portal_version'] += '-different'
                elif case == 'os': result['os_qualified'] = True
                elif case == 'consent': result['consent_qualified'] = True
                elif case == 'base': result['all_base_packages_unchanged'] = False
                elif case == 'crypto': result['base_crypto_configuration_unchanged'] = False
                elif case == 'missing_control': result['negative_controls']['missing_key_rejected'] = False
                elif case == 'tamper_control': result['negative_controls']['tampered_package_rejected'] = False
                elif case == 'added': result['added_packages'].append('unexpected\t0\t1\t1.fc45\tx86_64')
                elif case == 'required': result['required_packages'] = []
                elif case == 'package': result['runtime_package']['sha256'] = 'b'*64
                else: result['base_package_count'] = 0
                with self.assertRaises(ValueError): require_runtime_result(result, package, '1.5.0')

    def test_privileged_or_incompletely_dropped_probe_is_refused(self):
        for case in ('uid', 'gid', 'groups', 'capability', 'no_new_privileges'):
            with self.subTest(case=case):
                result = self.fixture(); identity = result['probe_identity']
                if case in ('uid', 'gid'): identity[case][-1] = 0
                elif case == 'groups': identity[case] = [0]
                elif case == 'capability': identity['capabilities']['CapEff'] = '0000000000000001'
                else: identity[case] = 0
                with self.assertRaises(ValueError): require_runtime_result(result, result['runtime_package'], '1.5.0')

    def test_missing_limits_changed_limits_or_oom_is_refused(self):
        for case in ('missing', 'raised', 'swap', 'oom', 'kill', 'group_kill'):
            with self.subTest(case=case):
                result = self.fixture(); counters = result['cgroup_final']
                if case == 'missing': del counters['memory.max']
                elif case == 'raised': counters['memory.max'] = 'max'
                elif case == 'swap': result['limits']['memory.swap.max'] = '10000000'
                else:
                    key = {'oom': 'oom', 'kill': 'oom_kill', 'group_kill': 'oom_group_kill'}[case]
                    counters['memory.events'] = counters['memory.events'].replace(key+' 0', key+' 1')
                with self.assertRaises(ValueError): require_runtime_result(result, result['runtime_package'], '1.5.0')


if __name__ == '__main__': unittest.main()
