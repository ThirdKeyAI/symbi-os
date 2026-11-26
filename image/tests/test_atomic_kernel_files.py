"""Protected kernel reads never change image permissions or execute a container."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

from image.boot.kernel_files import read_copied_kernel, validate_copy_container


class CopiedKernel(unittest.TestCase):
    def fixture(self, root):
        root.chmod(0o700)
        for name in ('vmlinuz','initramfs.img'):
            (root/name).write_bytes(b'pinned kernel input\n'); (root/name).chmod(0o600)
        return '7.3.4-300.secureblue.1.fc45.x86_64'

    def test_protected_files_are_hashed_without_permission_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();version=self.fixture(root)
            report=read_copied_kernel(root,version)
            self.assertEqual(report['version'],version)
            for name in ('vmlinuz','initramfs.img'):
                self.assertEqual(report[name]['mode'],0o600)
                self.assertEqual((root/name).stat().st_mode & 0o777,0o600)
                self.assertEqual(report[name]['bytes'],20)

    def test_links_extra_files_empty_or_world_writable_input_are_refused(self):
        for kind in ('link','extra','empty','write','linked_parent','public_parent'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                base=Path(directory).resolve();root=base/'files';root.mkdir();version=self.fixture(root)
                if kind=='link': (root/'initramfs.img').unlink();(root/'initramfs.img').symlink_to(root/'vmlinuz')
                elif kind=='extra': (root/'unexpected').write_bytes(b'x')
                elif kind=='empty': (root/'initramfs.img').write_bytes(b'')
                elif kind=='write': (root/'initramfs.img').chmod(0o666)
                elif kind=='linked_parent': (base/'alias').symlink_to(root,target_is_directory=True);root=base/'alias'
                else: root.chmod(0o755)
                with self.assertRaises(ValueError): read_copied_kernel(root,version)

    def test_copy_source_must_be_exact_and_never_started(self):
        image_id='sha256:'+'a'*64
        row={'Image':image_id, 'State':{'Status':'created','Running':False,'Pid':0}}
        validate_copy_container([row],image_id)
        for state in ({'Status':'running','Running':True,'Pid':12},
                      {'Status':'exited','Running':False,'Pid':0},
                      {'Status':'created','Running':False,'Pid':1}):
            with self.assertRaises(ValueError): validate_copy_container([{**row,'State':state}],image_id)
        for rows in ([],[row,row],[{**row,'Image':'b'*64}],None):
            with self.assertRaises(ValueError): validate_copy_container(rows,image_id)

    def test_empty_backend_marker_is_allowed_only_explicitly(self):
        stage=Path(__file__).resolve().parents[2]
        spec=importlib.util.spec_from_file_location('atomic_probe',stage/'image/boot/probe.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'marker';path.write_bytes(b'')
            with self.assertRaises(ValueError): module.regular(path)
            self.assertEqual(module.regular(path,allow_empty=True)['bytes'],0)


if __name__=='__main__': unittest.main()
