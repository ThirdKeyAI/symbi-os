"""Only a complete, pinned portal prefix can be reused by the runtime checks."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from image.portal.prefix_input import require_portal_manifest, unpack_portal


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PortalPrefix(unittest.TestCase):
    def fixture(self, root, mutate=None):
        pins = {'components':[{'name':'hyprtoolkit','revision':'a'*40},
                             {'name':'xdg-desktop-portal-hyprland','revision':'b'*40}]}
        files = {'bin/hyprland-share-picker': {'data':b'picker fixture', 'mode':0o755},
                 'libexec/xdg-desktop-portal-hyprland': {'data':b'portal fixture', 'mode':0o755},
                 'lib/libhyprtoolkit.so.0.6.0': {'data':b'library fixture', 'mode':0o755},
                 'lib/libhyprtoolkit.so.6': {'link':'libhyprtoolkit.so.0.6.0'},
                 'lib/libhyprtoolkit.so': {'link':'libhyprtoolkit.so.6'},
                 'share/licenses/hyprtoolkit/LICENSE': {'data':b'toolkit license fixture', 'mode':0o644},
                 'share/licenses/xdg-desktop-portal-hyprland/LICENSE': {'data':b'portal license fixture', 'mode':0o644}}
        inventory = {name:({'link':row['link']} if 'link' in row else
                          {'sha256':sha(row['data']),'bytes':len(row['data']),'mode':row['mode']}) for name,row in files.items()}
        output = io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as tar:
            dirs = {'portal'}
            for name in files:
                dirs.update('portal/'+str(p) for p in Path(name).parents if str(p) != '.')
            for name in sorted(dirs, key=lambda n:(n.count('/'),n)):
                info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=0o755;tar.addfile(info)
            for name,row in files.items():
                info=tarfile.TarInfo('portal/'+name)
                if 'link' in row:info.type=tarfile.SYMTYPE;info.linkname=row['link'];info.mode=0o777;data=None
                else:info.mode=row['mode'];info.size=len(row['data']);data=io.BytesIO(row['data'])
                if mutate:mutate(info)
                tar.addfile(info,data)
        payload=output.getvalue()
        manifest={'schema':1,'compiled':True,'os_qualified':False,'selected_base_qualified':False,'consent_qualified':False,
                  'source_commit':'c'*40,'base':'registry/base@sha256:'+'d'*64,'source_inputs':pins,
                  'rpm_lock_sha256':'e'*64,'reused_compositor_manifest_sha256':'f'*64,
                  'compile_report_sha256':'1'*64,'payload_sha256':sha(payload),'payload_bytes':len(payload),'files':inventory,
                  'test_suites':{'toolkit-unit':{'cases':['case.'+str(n) for n in range(91)],'sha256':'2'*64},
                                 'toolkit-renderer':{'cases':['CEmbeddedRendererTest.rendersAndRestoresHostState'],'sha256':'3'*64},
                                 'portal-tests':{'cases':['hyprland-share-picker-data.hyprland-share-picker-data'],'sha256':'4'*64}}}
        raw=(json.dumps(manifest)+'\n').encode()
        archive=root/'prefix.zip'
        with zipfile.ZipFile(archive,'w') as bundle:
            bundle.writestr('manifest.json',raw);bundle.writestr('portal-prefix.tar.gz',payload)
        lock={'schema':1,'qualified':False,'product_installation':False,'consent_qualified':False,'tested_commit':'c'*40,
              'manifest':manifest,'manifest_sha256':sha(raw),'artifact':{'id':1,'bytes':archive.stat().st_size,'sha256':sha(archive.read_bytes())}}
        return archive,lock,pins,manifest['base'],'e'*64,'f'*64

    def test_exact_prefix_files_and_links_survive(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();args=self.fixture(root);destination=root/'out'
            actual=unpack_portal(*args,destination)
            self.assertEqual(actual,args[1]['manifest'])
            self.assertEqual((destination/'portal/bin/hyprland-share-picker').read_bytes(),b'picker fixture')
            self.assertEqual((destination/'portal/lib/libhyprtoolkit.so').resolve(),destination/'portal/lib/libhyprtoolkit.so.0.6.0')
            self.assertEqual((destination/'portal/bin/hyprland-share-picker').stat().st_mode & 0o777,0o755)

    def test_changed_source_base_rpm_compositor_or_qualification_is_refused(self):
        for kind in ('source','base','rpm','compositor','commit','compiled','qualified','consent','tests'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                args=list(self.fixture(Path(temp).resolve()));manifest=copy.deepcopy(args[1]['manifest'])
                if kind=='source':manifest['source_inputs']['components'][0]['revision']='9'*40
                elif kind=='base':manifest['base']='other'
                elif kind=='rpm':manifest['rpm_lock_sha256']='9'*64
                elif kind=='compositor':manifest['reused_compositor_manifest_sha256']='9'*64
                elif kind=='commit':manifest['source_commit']='9'*40
                elif kind=='compiled':manifest['compiled']=False
                elif kind=='qualified':manifest['selected_base_qualified']=True
                elif kind=='consent':manifest['consent_qualified']=True
                else:manifest['test_suites']['portal-tests']['cases']=['wrong-test']
                args[1]['manifest']=manifest
                with self.assertRaises(ValueError):require_portal_manifest(manifest,*args[1:])

    def test_archive_manifest_and_payload_corruption_are_refused(self):
        for member in ('archive','manifest.json','portal-prefix.tar.gz'):
            with self.subTest(member=member),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();args=self.fixture(root);archive,lock=args[:2]
                if member=='archive':archive.write_bytes(archive.read_bytes()+b'corrupt')
                else:
                    with zipfile.ZipFile(archive) as bundle:content={n:bundle.read(n) for n in bundle.namelist()}
                    content[member]+=b'corrupt'
                    with zipfile.ZipFile(archive,'w') as bundle:
                        for name,data in content.items():bundle.writestr(name,data)
                    lock['artifact'].update(bytes=archive.stat().st_size,sha256=sha(archive.read_bytes()))
                with self.assertRaises(ValueError):unpack_portal(*args,root/'out')
                self.assertFalse((root/'out').exists())

    def test_traversal_escaping_links_unlisted_files_and_wrong_modes_are_refused(self):
        for kind in ('traversal','absolute','link','unlisted','mode','hardlink'):
            def mutate(info):
                if info.name=='portal/bin/hyprland-share-picker':
                    if kind=='traversal':info.name='portal/../escape'
                    elif kind=='absolute':info.name='/portal/bin/hyprland-share-picker'
                    elif kind=='unlisted':info.name='portal/bin/unreviewed'
                    elif kind=='mode':info.mode=0o4755
                    elif kind=='hardlink':info.type=tarfile.LNKTYPE;info.linkname='portal/lib/libhyprtoolkit.so.0.6.0'
                if kind=='link' and info.name=='portal/lib/libhyprtoolkit.so':info.linkname='../../outside'
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();args=self.fixture(root,mutate)
                with self.assertRaises(ValueError):unpack_portal(*args,root/'out')
                self.assertFalse((root/'out').exists())

    def test_existing_or_linked_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();args=self.fixture(root);destination=root/'out';destination.mkdir()
            with self.assertRaises(ValueError):unpack_portal(*args,destination)
            (destination/'keep').write_bytes(b'keep')
            alias=root/'alias';alias.symlink_to(destination,target_is_directory=True)
            with self.assertRaises(ValueError):unpack_portal(*args,alias/'nested')
            self.assertEqual((destination/'keep').read_bytes(),b'keep')


if __name__=='__main__':unittest.main()
