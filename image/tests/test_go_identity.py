"""The signed compiler must report the pinned version and selected target."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('go_identity', Path(__file__).parents[1] / 'launcher/go_identity.py')
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)


class GoIdentity(unittest.TestCase):
    def test_exact_authenticated_fedora_compiler_identity(self):
        actual = {'GOVERSION': 'go1.27.4-X:nodwarf5', 'GOOS': 'linux', 'GOARCH': 'amd64',
                  'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '1', 'GOEXPERIMENT': 'nodwarf5'}
        identity.require_compiler(actual)

    def test_other_version_target_auto_download_or_missing_field_is_refused(self):
        original = {'GOVERSION': 'go1.27.4-X:nodwarf5', 'GOOS': 'linux', 'GOARCH': 'amd64',
                    'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '1', 'GOEXPERIMENT': 'nodwarf5'}
        for key, bad in [('GOVERSION', 'go1.27.3'), ('GOVERSION', 'go1.27.4-anything'),
                         ('GOVERSION', 'go1.27.4'), ('GOVERSION', 'go1.27.4-X:systemcrypto'),
                         ('GOVERSION', 'go1.27.4-X:nodwarf5,anything'),
                         ('GOEXPERIMENT', ''), ('GOEXPERIMENT', 'systemcrypto'),
                         ('GOEXPERIMENT', 'nodwarf5,anything'), ('GOEXPERIMENT', None),
                         ('GOOS', 'windows'), ('GOARCH', 'arm64'),
                         ('GOTOOLCHAIN', 'auto'), ('CGO_ENABLED', '0'), ('GOVERSION', None)]:
            with self.subTest(key=key, bad=bad), self.assertRaisesRegex(ValueError, key):
                actual = dict(original)
                if bad is None:del actual[key]
                else:actual[key] = bad
                identity.require_compiler(actual)


if __name__ == '__main__':
    unittest.main()
