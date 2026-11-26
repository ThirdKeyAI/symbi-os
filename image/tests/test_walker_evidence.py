"""Guest evidence must remain small regular files inside its output directory."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT/'walker'))
sys.path.insert(0, str(ROOT/'launcher/probes'))
try:
    SPEC = importlib.util.spec_from_file_location('walker_hosted', ROOT/'walker/hosted_build.py')
    hosted = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(hosted)
finally:
    sys.path.pop(0)
    sys.path.pop(0)


class WalkerEvidence(unittest.TestCase):
    def test_nested_regular_evidence_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'source/nested').mkdir(parents=True)
            (root/'source/nested/result.json').write_text('{"passed": false}\n')
            hosted.retain_directory(root/'source', root/'retained')
            self.assertEqual((root/'retained/nested/result.json').read_text(), '{"passed": false}\n')

    def test_guest_symlinks_and_oversized_files_are_refused_before_copy(self):
        for mutation in ('file-link', 'directory-link', 'oversized'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root/'source'
                source.mkdir()
                if mutation == 'file-link':
                    (source/'escape').symlink_to(root/'outside')
                elif mutation == 'directory-link':
                    (source/'escape').symlink_to(root, target_is_directory=True)
                else:
                    with (source/'large').open('wb') as stream:stream.truncate(2*1024**2+1)
                with self.assertRaises(ValueError):hosted.retain_directory(source, root/'retained')
                self.assertFalse((root/'retained').exists())


    def test_image_id_comes_only_from_stdout_with_stderr_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = 'a'*64
            command = [sys.executable, '-c', 'import sys;print("'+identity+'");print("Copying blob sha256:'+('b'*64)+'",file=sys.stderr)']
            self.assertEqual(hosted.capture_image_id(command, root, 'commit'), 'sha256:'+identity)
            self.assertEqual((root/'commit.log').read_text(), identity+'\n')
            self.assertIn('Copying blob', (root/'commit-stderr.log').read_text())

    def test_ambiguous_stdout_and_failed_commit_cannot_supply_an_id(self):
        for output, status in (('a'*64+'\n'+'b'*64, 0), ('Copying blob\n'+'a'*64, 0), ('a'*64, 1)):
            with self.subTest(output=output, status=status), tempfile.TemporaryDirectory() as directory:
                command = [sys.executable, '-c', f'import sys;print({output!r});sys.exit({status})']
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    hosted.capture_image_id(command, Path(directory), 'commit')


if __name__ == '__main__':
    unittest.main()
