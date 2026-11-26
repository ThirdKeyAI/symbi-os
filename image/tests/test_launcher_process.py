"""Exercise real child processes without starting a compiler or container."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('bounded_process', Path(__file__).parents[1] / 'launcher/probes/bounded_process.py')
process = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(process)


class LauncherProcess(unittest.TestCase):
    def test_separate_bounded_channels_and_nonzero_status_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = process.run_bounded([sys.executable, '-c', 'import sys; print("out"); print("err", file=sys.stderr); sys.exit(7)'], root/'out', root/'err')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (7, 'out\n', 'err\n'))
            self.assertEqual((root/'out').read_text(), result.stdout)
            self.assertEqual((root/'err').read_text(), result.stderr)

    def test_oversized_child_output_is_stopped_at_the_evidence_bound(self):
        for channel in ('stdout', 'stderr'):
            with self.subTest(channel=channel), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                command = [sys.executable, '-c', f'import sys; sys.{channel}.write("x"*100000)']
                with self.assertRaisesRegex(ValueError, 'output exceeded'):
                    process.run_bounded(command, root/'out', root/'err', max_bytes=4096)
                self.assertLessEqual((root/'out').stat().st_size, 4096)
                self.assertLessEqual((root/'err').stat().st_size, 4096)

    def test_timed_out_child_is_reaped_and_partial_output_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, '-c', 'import os,time; print(os.getpid(), flush=True); time.sleep(30)']
            with self.assertRaises(subprocess.TimeoutExpired):
                process.run_bounded(command, root/'out', root/'err', timeout=0.3)
            pid = int((root/'out').read_text().strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


if __name__ == '__main__':
    unittest.main()
