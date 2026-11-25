"""A retained compiler artifact must not escape its prefix or change binaries."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile


SPEC = importlib.util.spec_from_file_location('prefix_input', Path(__file__).parents[1] / 'hyprland/prefix_input.py')
prefix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prefix)


class PrefixInput(unittest.TestCase):
    def bundle(self, directory, extra=(), change_binary=False):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w:gz') as archive:
            for name in ['hyprland', 'hyprland/bin', 'hyprland/lib']:
                item = tarfile.TarInfo(name)
                item.type = tarfile.DIRTYPE
                item.mode = 0o777
                archive.addfile(item)
            for name, data in [('bin/Hyprland', b'changed' if change_binary else b'compositor'),
                               ('bin/hyprctl', b'controller'), ('lib/libexample.so.1', b'library')]:
                item = tarfile.TarInfo('hyprland/'+name)
                item.size, item.mode = len(data), 0o6755
                archive.addfile(item, io.BytesIO(data))
            item = tarfile.TarInfo('hyprland/lib/libexample.so')
            item.type, item.linkname = tarfile.SYMTYPE, 'libexample.so.1'
            archive.addfile(item)
            for item in extra:
                archive.addfile(item, io.BytesIO(b'x'*item.size) if item.isfile() else None)
        raw = payload.getvalue()
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False,
                    'native_loading_qualified': False, 'selected_base_qualified': False,
                    'payload_sha256': hashlib.sha256(raw).hexdigest(),
                    'binaries': {name: hashlib.sha256(data).hexdigest() for name, data in
                                 [('Hyprland', b'compositor'), ('hyprctl', b'controller')]}}
        text = (json.dumps(manifest) + '\n').encode()
        path = directory / 'artifact.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('manifest.json', text)
            archive.writestr('hyprland-prefix.tar.gz', raw)
        lock = {'artifact': {'bytes': path.stat().st_size, 'sha256': prefix.digest(path)},
                'manifest_sha256': hashlib.sha256(text).hexdigest(), 'manifest': manifest,
                'qualified': False, 'product_installation': False}
        return path, lock

    def test_exact_prefix_preserves_internal_library_links_and_normalizes_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, lock = self.bundle(root)
            target = root / 'prefix'
            prefix.unpack_prefix(archive, lock, target)
            self.assertEqual((target/'hyprland/bin/Hyprland').read_bytes(), b'compositor')
            self.assertEqual((target/'hyprland/lib/libexample.so').read_bytes(), b'library')
            self.assertEqual((target/'hyprland/bin/Hyprland').stat().st_mode & 0o7777, 0o755)
            self.assertEqual((target/'hyprland').stat().st_mode & 0o7777, 0o755)

    def test_changed_payload_or_binary_does_not_leave_a_reusable_prefix(self):
        for binary in (False, True):
            with self.subTest(binary=binary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, lock = self.bundle(root, change_binary=binary)
                if not binary:
                    with archive.open('ab') as output:
                        output.write(b'changed')
                with self.assertRaises(ValueError):
                    prefix.unpack_prefix(archive, lock, root/'prefix')
                self.assertFalse((root/'prefix').exists())

    def test_tar_path_escape_special_files_duplicate_and_link_parent_are_refused(self):
        variants = []
        for name, kind, link in [('hyprland/../escape', tarfile.REGTYPE, ''),
                                 ('/outside', tarfile.REGTYPE, ''),
                                 ('hyprland/lib/escape', tarfile.SYMTYPE, '../../../outside'),
                                 ('hyprland/lib/absolute', tarfile.SYMTYPE, '/etc/shadow'),
                                 ('hyprland/lib/device', tarfile.CHRTYPE, ''),
                                 ('hyprland/bin/hyprctl', tarfile.REGTYPE, ''),
                                 ('hyprland/lib/hardlink', tarfile.LNKTYPE, 'hyprland/bin/Hyprland'),
                                 ('hyprland/lib/libexample.so/child', tarfile.REGTYPE, '')]:
            item = tarfile.TarInfo(name)
            item.type, item.linkname = kind, link
            variants.append(item)
        for item in variants:
            with self.subTest(name=item.name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, lock = self.bundle(root, extra=[item])
                with self.assertRaises(ValueError):
                    prefix.unpack_prefix(archive, lock, root/'prefix')
                self.assertFalse((root/'prefix').exists())

    def test_development_artifact_cannot_self_assert_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, lock = self.bundle(root)
            lock['qualified'] = True
            with self.assertRaises(ValueError):
                prefix.unpack_prefix(archive, lock, root/'prefix')


if __name__ == '__main__':
    unittest.main()
