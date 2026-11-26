"""Refuse unsafe or unauthenticated candidate bundles before any installation."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class KittyBundle(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('kitty_bundle', ROOT/'image/kitty/bundle.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def tar(self, path, extras=()):
        with tarfile.open(path,'w') as archive:
            for name in ('bin/kitty','bin/kitten'):
                item=tarfile.TarInfo(name);item.size=3;item.mode=0o755
                archive.addfile(item,io.BytesIO(b'elf'))
            for name,kind,target in extras:
                item=tarfile.TarInfo(name);item.type=kind
                if kind==tarfile.REGTYPE:
                    item.size=1;archive.addfile(item,io.BytesIO(b'x'))
                else:
                    item.linkname=target;archive.addfile(item)

    def test_inspection_hashes_regular_files_without_extracting_or_executing(self):
        mod=self.module()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'bundle.tar'
            self.tar(archive,[('bin/link',tarfile.SYMTYPE,'kitty')])
            rows=mod.inspect_archive(archive)
            self.assertEqual(set(rows),{'bin/kitty','bin/kitten','bin/link'})
            self.assertEqual(rows['bin/kitty']['bytes'],3)
            self.assertEqual(rows['bin/link']['target'],'bin/kitty')
            self.assertEqual(list(root.iterdir()),[archive])

    def test_archive_rejects_escaping_duplicate_special_and_dangling_members(self):
        mod=self.module()
        bad=[('../escape',tarfile.REGTYPE,''),('/absolute',tarfile.REGTYPE,''),
             ('bin/kitty',tarfile.REGTYPE,''),('bin/link',tarfile.SYMTYPE,'../../escape'),
             ('bin/link',tarfile.SYMTYPE,'/bin/sh'),('bin/link',tarfile.SYMTYPE,'missing'),
             ('bin/pipe',tarfile.FIFOTYPE,''),('bin/hard',tarfile.LNKTYPE,'bin/kitty'),
             ('etc/profile',tarfile.REGTYPE,''),('bin/\ncontrol',tarfile.REGTYPE,'')]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bundle.tar'
            for member in bad:
                self.tar(path,[member])
                with self.subTest(member=member),self.assertRaises(ValueError):mod.inspect_archive(path)

    def test_archive_rejects_limits_and_missing_programs(self):
        mod=self.module()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bundle.tar';self.tar(path)
            with self.assertRaises(ValueError):mod.inspect_archive(path,max_bytes=5)
            with self.assertRaises(ValueError):mod.inspect_archive(path,max_members=1)
            with tarfile.open(path,'w'):pass
            with self.assertRaises(ValueError):mod.inspect_archive(path)

    def test_signature_requires_full_identity_and_modern_hash_without_failure_status(self):
        mod=self.module();fp='3CE1780F78DD88DF45194FD706BC317B515ACE7C'
        status='[GNUPG:] VALIDSIG '+fp+' 2026-11-18 1795017600 0 4 0 1 10 00 '+fp+'\n'
        mod.require_signature(0,status,fp)
        for code,text in [(1,status),(0,''),(0,status.replace(fp,'A'*40)),
                          (0,status.replace(' 1 10 00 ',' 1 2 00 ')),
                          (0,status+status),(0,status+'[GNUPG:] REVKEYSIG stale\n')]:
            with self.subTest(code=code,text=text),self.assertRaises(ValueError):mod.require_signature(code,text,fp)


if __name__=='__main__':unittest.main()
