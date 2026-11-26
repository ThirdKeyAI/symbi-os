"""Exercise the CLI probe with actual small processes before the hosted build."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT/'walker'))
sys.path.insert(0, str(ROOT/'launcher/probes'))
try:
    SPEC = importlib.util.spec_from_file_location('walker_cli', ROOT/'walker/cli_guest.py')
    cli = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(cli)
finally:
    sys.path.pop(0)
    sys.path.pop(0)


class WalkerCLI(unittest.TestCase):
    def fixture(self, root, version='2.17.2', unknown_exit=1):
        path = root/'fixture.py'
        path.write_text('import sys\n'
                        'arg=sys.argv[1]\n'
                        f'if arg=="--version": print({version!r})\n'
                        'elif arg=="--help": print("Usage: walker [OPTION]\\n--version\\n--provider")\n'
                        f'else: print("Unknown option "+arg,file=sys.stderr);sys.exit({unknown_exit})\n')
        return [sys.executable, str(path)]

    def test_four_actual_process_controls_preserve_outputs_and_limited_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = cli.run_cli(self.fixture(root), root/'evidence', '2.17.2')
            self.assertTrue(record['passed'])
            self.assertFalse(record['os_qualified'])
            self.assertFalse(record['gui_qualified'])
            self.assertEqual([c['exit_code'] for c in record['cases']], [0, 0, 1, 0])
            self.assertEqual((root/'evidence/version-stdout.log').read_text(), '2.17.2\n')

    def test_wrong_version_or_nonrefusing_parser_cannot_pass(self):
        for version, unknown_exit in (('9.9.9', 1), ('2.17.2', 0)):
            with self.subTest(version=version, unknown_exit=unknown_exit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises(ValueError):
                    cli.run_cli(self.fixture(root, version, unknown_exit), root/'evidence', '2.17.2')
                record = json.loads((root/'evidence/result.json').read_text())
                self.assertFalse(record['passed'])
                self.assertFalse(record['gui_qualified'])
                self.assertIn('failure', record)


if __name__ == '__main__':
    unittest.main()
