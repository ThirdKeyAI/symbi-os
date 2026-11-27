"""Package discovery must follow the observed pinned-runtime loader failure."""
import copy
import unittest

from image.runtime_packages.hosted_discover import require_observed_inputs


class RuntimeRequirements(unittest.TestCase):
    def fixture(self):
        requirements = {'schema': 1, 'packages': ['libssl.so.3()(64bit)', 'libcrypto.so.3()(64bit)'],
                        'expected_provider': 'openssl3-libs'}
        lock = {'source_revision': 'a'*40, 'binaries': {'symbi': {'sha256': 'b'*64}}}
        observed = {'passed': False, 'os_qualified': False, 'base': 'pinned-base',
                    'upstream_revision': lock['source_revision'], 'binaries': copy.deepcopy(lock['binaries'])}
        loader = '\tlibssl.so.3 => not found\n\tlibcrypto.so.3 => not found\n\tlibc.so.6 => /lib64/libc.so.6 (0xabc)\n'
        return [requirements, observed, loader, lock, 'pinned-base']

    def test_actual_missing_sonames_bind_the_requested_providers(self):
        require_observed_inputs(*self.fixture())

    def test_changed_runtime_base_or_nonmatching_loader_evidence_is_refused(self):
        for change in ('base', 'source', 'binary', 'successful', 'missing', 'additional', 'packages'):
            with self.subTest(change=change):
                args = self.fixture()
                if change == 'base':args[1]['base'] = 'different-base'
                elif change == 'source':args[1]['upstream_revision'] = 'f'*40
                elif change == 'binary':args[1]['binaries']['symbi']['sha256'] = 'f'*64
                elif change == 'successful':args[1]['passed'] = True
                elif change == 'missing':args[2] = args[2].replace('libssl.so.3 => not found', 'libssl.so.3 => /lib64/libssl.so.3')
                elif change == 'additional':args[2] += 'libother.so => not found\n'
                else:args[0]['packages'] = ['unrelated-package']
                with self.assertRaises(ValueError):require_observed_inputs(*args)
