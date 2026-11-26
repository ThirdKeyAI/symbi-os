"""A boot harness must consume only the exact reviewed development image."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from image.boot.inputs import require_desktop_image, unpack_desktop_image


def sha(data): return hashlib.sha256(data).hexdigest()


class DesktopImageInput(unittest.TestCase):
    def fixture(self, root, variant='generic', mutate=None):
        payload = b'opaque development-image fixture; never executed'
        name = 'symbiont-os-'+variant+'.oci.tar.gz'
        pins = {'variants': {'generic': {'image': 'registry/generic@sha256:'+'a'*64},
                             'nvidia': {'image': 'registry/nvidia@sha256:'+'b'*64}}}
        manifest = {'schema': 1, 'built': True, 'os_qualified': False, 'source_commit': 'c'*40,
                    'base': pins['variants'][variant]['image'], 'variant': variant,
                    'preparation_sha256': 'd'*64, 'archive': {'name': name, 'bytes': len(payload),
                    'sha256': sha(payload), 'image_id': 'sha256:'+'e'*64}}
        raw = (json.dumps(manifest)+'\n').encode()
        members = [('manifest.json', raw), (name, payload)]
        if mutate: members = mutate(members)
        archive = root/'image.zip'
        with zipfile.ZipFile(archive, 'w') as bundle:
            for member, data in members: bundle.writestr(member, data)
        selected = {'tested_commit': 'c'*40, 'run_id': 1, 'manifest': manifest,
                    'manifest_sha256': sha(raw), 'artifact': {'id': 2,
                    'name': 'desktop-development-image-'+variant, 'bytes': archive.stat().st_size,
                    'sha256': sha(archive.read_bytes())}}
        lock = {'schema': 1, 'os_qualified': False, 'signature_qualified': False, 'images': {variant: selected}}
        return archive, lock, pins, variant

    def test_exact_bounded_opaque_archive_survives_for_either_variant(self):
        for variant in ('generic', 'nvidia'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); args = self.fixture(root, variant)
                manifest = unpack_desktop_image(*args, root/'out')
                self.assertEqual(manifest, args[1]['images'][variant]['manifest'])
                self.assertEqual(sha((root/'out'/manifest['archive']['name']).read_bytes()), manifest['archive']['sha256'])
                self.assertEqual((root/'out').stat().st_mode & 0o777, 0o700)

    def test_wrong_source_base_variant_flags_or_artifact_identity_is_refused(self):
        for kind in ('source', 'base', 'variant', 'built', 'qualified', 'signature', 'run', 'name', 'size', 'image-id', 'hash'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                archive, lock, pins, variant = self.fixture(Path(directory).resolve())
                selected = lock['images'][variant]; manifest = selected['manifest']
                if kind == 'source': manifest['source_commit'] = 'f'*40
                elif kind == 'base': manifest['base'] = pins['variants']['nvidia']['image']
                elif kind == 'variant': manifest['variant'] = 'nvidia'
                elif kind == 'built': manifest['built'] = 1
                elif kind == 'qualified': manifest['os_qualified'] = True
                elif kind == 'signature': lock['signature_qualified'] = True
                elif kind == 'run': selected['run_id'] = True
                elif kind == 'name': selected['artifact']['name'] = 'unrelated'
                elif kind == 'size': manifest['archive']['bytes'] = 14*1024**3
                elif kind == 'image-id': manifest['archive']['image_id'] = 'latest'
                else: selected['manifest_sha256'] = 'bad'
                with self.assertRaises(ValueError): require_desktop_image(lock, pins, variant)

    def test_corrupt_archive_manifest_or_image_leaves_no_partial_destination(self):
        for member in ('zip', 'manifest.json', 'symbiont-os-generic.oci.tar.gz'):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); args = self.fixture(root); archive, lock = args[:2]
                if member == 'zip': archive.write_bytes(archive.read_bytes()+b'changed')
                else:
                    with zipfile.ZipFile(archive) as bundle: contents = {n: bundle.read(n) for n in bundle.namelist()}
                    contents[member] = b'X'+contents[member][1:]
                    with zipfile.ZipFile(archive, 'w') as bundle:
                        for name, data in contents.items(): bundle.writestr(name, data)
                    lock['images']['generic']['artifact'].update(bytes=archive.stat().st_size, sha256=sha(archive.read_bytes()))
                with self.assertRaises(ValueError): unpack_desktop_image(*args, root/'out')
                self.assertFalse((root/'out').exists())

    def test_alias_extra_duplicate_special_and_oversized_members_are_refused(self):
        for kind in ('traversal', 'absolute', 'extra', 'duplicate', 'special', 'oversized'):
            def mutate(rows):
                if kind == 'traversal': rows[1] = ('../escape', rows[1][1])
                elif kind == 'absolute': rows[1] = ('/absolute', rows[1][1])
                elif kind == 'extra': rows.append(('extra', b'bad'))
                elif kind == 'duplicate': rows.append(rows[0])
                elif kind == 'oversized': rows[0] = (rows[0][0], b' '*65537)
                else:
                    info = zipfile.ZipInfo(rows[1][0]); info.create_system = 3; info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    rows[1] = (info, rows[1][1])
                return rows
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); args = self.fixture(root, mutate=mutate)
                with self.assertRaises(ValueError): unpack_desktop_image(*args, root/'out')
                self.assertFalse((root/'out').exists()); self.assertFalse((root/'escape').exists())

    def test_existing_destination_or_linked_source_or_parent_is_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); args = list(self.fixture(root))
            target = root/'out'; target.mkdir(); (target/'keep').write_bytes(b'keep')
            with self.assertRaises(ValueError): unpack_desktop_image(*args, target)
            (root/'alias').symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError): unpack_desktop_image(*args, root/'alias/nested')
            (root/'source-alias.zip').symlink_to(args[0]); args[0] = root/'source-alias.zip'
            with self.assertRaises(ValueError): unpack_desktop_image(*args, root/'new')
            self.assertEqual((target/'keep').read_bytes(), b'keep')

    def test_variant_must_be_explicitly_available(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(Path(directory).resolve())
            for variant in ('nvidia', '../generic', '', None):
                with self.subTest(variant=variant), self.assertRaises(ValueError): require_desktop_image(args[1], args[2], variant)


if __name__ == '__main__': unittest.main()
