"""Retain bounded startup evidence without nested timeout processes."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT/'launcher/probes'))
try:
    SPEC = importlib.util.spec_from_file_location('loader_diagnostic', ROOT/'launcher/loader_diagnostic.py')
    diagnostic = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(diagnostic)
finally:
    sys.path.pop(0)


class StartupDiagnostic(unittest.TestCase):
    def record(self):
        return {'diagnostic_completed': False, 'provider_loading_qualified': False,
                'upstream_tests_passed': False, 'os_qualified': False}

    def test_timed_child_is_reaped_and_partial_output_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = ('import os,time; from pathlib import Path; '
                    f'Path({str(root/"pid")!r}).write_text(str(os.getpid())); '
                    'os.write(2,b"actual startup diagnostic\\n"); time.sleep(120)')
            record = self.record()
            try:
                diagnostic.capture_startup([sys.executable, '-c', code], root, record, timeout=1)
                retained = json.loads((root/'loader-result.json').read_text())
                self.assertTrue(retained['timed_out'])
                self.assertTrue(retained['diagnostic_completed'])
                self.assertIsNone(retained['exit_code'])
                self.assertFalse(retained['provider_loading_qualified'])
                self.assertFalse(retained['os_qualified'])
                self.assertEqual((root/'loader-stderr.log').read_text(), 'actual startup diagnostic\n')
                with self.assertRaises(ProcessLookupError):os.kill(int((root/'pid').read_text()), 0)
            finally:
                if (root/'pid').exists():
                    try:os.kill(int((root/'pid').read_text()), signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_early_failure_is_recorded_without_becoming_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self.record()
            diagnostic.capture_startup([sys.executable, '-c', 'import sys; print("loader error",file=sys.stderr); sys.exit(7)'],
                                       root, record, timeout=1)
            retained = json.loads((root/'loader-result.json').read_text())
            self.assertEqual(retained['exit_code'], 7)
            self.assertFalse(retained['timed_out'])
            self.assertFalse(retained['upstream_tests_passed'])
            self.assertFalse(retained['provider_loading_qualified'])

    def test_output_failure_preserves_an_incomplete_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self.record()
            with self.assertRaises(ValueError):
                diagnostic.capture_startup([sys.executable, '-c', 'import os; os.write(1,b"x"*70000)'],
                                           root, record, timeout=1)
            retained = json.loads((root/'loader-result.json').read_text())
            self.assertFalse(retained['diagnostic_completed'])
            self.assertIn('execution_failure', retained)
            self.assertLessEqual((root/'loader-stdout.log').stat().st_size, 65536)


if __name__ == '__main__':
    unittest.main()
