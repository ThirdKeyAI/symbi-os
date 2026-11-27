"""A retained builder must preserve exact bytes and its source/compiler bindings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('builder_artifact', Path(__file__).parents[1]/'toolchain/artifact.py')
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class BuilderArtifact(unittest.TestCase):
    def fixture(self, root):
        binary, license_file, config_file = (root/name for name in ('tool', 'LICENSE', 'config.json'))
        binary.write_bytes(b'synthetic non-executable fixture')
        license_file.write_bytes(b'original source license\n')
        config = {'schema': 1, 'repository': 'https://github.com/blue-build/cli', 'revision': '1'*40,
                  'rust': '1.100.0', 'features': ['v1_0_0'], 'profile': 'dev', 'qualified': False,
                  'patches': [{'path': 'image/toolchain/patches/validator.patch', 'sha256': '2'*64}]}
        config_file.write_text(json.dumps(config)+'\n')
        record = {'source_revision': config['revision'], 'source_clean_before_build': True,
                  'cargo_lock_sha256': '3'*64, 'applied_diff_sha256': '4'*64,
                  'rust': config['rust'], 'rustc': 'rustc 1.100.0 (fixture)',
                  'features': config['features'], 'profile': config['profile'], 'patches': config['patches'],
                  'build_passed': True, 'license_sha256': hashlib.sha256(license_file.read_bytes()).hexdigest()}
        return {'binary': binary, 'source_license': license_file, 'config_path': config_file,
                'record': record, 'tested_commit': '5'*40, 'destination': root/'payload'}

    def test_exact_bytes_license_and_build_bindings_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            arguments = self.fixture(Path(directory))
            manifest = artifact.retain_compiled_tool(**arguments)
            payload = arguments['destination']
            self.assertEqual({p.name for p in payload.iterdir()}, {'bluebuild', 'LICENSE', 'manifest.json'})
            self.assertEqual((payload/'bluebuild').read_bytes(), arguments['binary'].read_bytes())
            self.assertEqual((payload/'LICENSE').read_bytes(), arguments['source_license'].read_bytes())
            self.assertEqual((payload/'bluebuild').stat().st_mode & 0o777, 0o755)
            self.assertEqual(manifest['binary']['sha256'], hashlib.sha256(arguments['binary'].read_bytes()).hexdigest())
            self.assertEqual(manifest['tool_config_sha256'], hashlib.sha256(arguments['config_path'].read_bytes()).hexdigest())
            self.assertTrue(manifest['compiled'])
            self.assertFalse(manifest['os_qualified'])
            self.assertFalse(manifest['cli_acceptance_qualified'])
            self.assertEqual(json.loads((payload/'manifest.json').read_text()), manifest)

    def test_failed_stale_or_ambiguous_build_identity_cannot_create_payload(self):
        for field, value in (('build_passed', False), ('source_clean_before_build', False),
                             ('source_revision', '6'*40), ('rust', '1.101.0'), ('rustc', 'rustc 1.101.0'),
                             ('features', []), ('profile', 'release'), ('patches', []),
                             ('cargo_lock_sha256', 'invalid'), ('applied_diff_sha256', ''),
                             ('license_sha256', '0'*64)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                arguments = self.fixture(Path(directory))
                arguments['record'] = {**arguments['record'], field: value}
                with self.assertRaises(ValueError):artifact.retain_compiled_tool(**arguments)
                self.assertFalse(arguments['destination'].exists())

    def test_links_oversized_binary_and_existing_destination_are_refused(self):
        for mutation in ('binary-link', 'license-link', 'oversized', 'destination', 'invalid-commit'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                arguments = self.fixture(root)
                if mutation.endswith('-link'):
                    key = 'binary' if mutation == 'binary-link' else 'source_license'
                    linked = root/'linked'
                    linked.symlink_to(arguments[key])
                    arguments[key] = linked
                elif mutation == 'oversized':
                    with arguments['binary'].open('wb') as stream:stream.truncate(128*1024**2+1)
                elif mutation == 'destination':
                    arguments['destination'].mkdir()
                else:
                    arguments['tested_commit'] = 'moving-branch'
                with self.assertRaises(ValueError):artifact.retain_compiled_tool(**arguments)


if __name__ == '__main__':
    unittest.main()
