"""Inert fixtures for the hosted-only Atomic disk and boot acceptance boundary."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from image.atomic.contract import (create_disk, require_disk, unpack_oci,
                                   installer_arguments, firmware_arguments,
                                   validate_report)


class AtomicBoot(unittest.TestCase):
    def fixture(self):
        config = json.dumps({'architecture':'amd64', 'os':'linux'}).encode()
        layer = b'opaque layer bytes; never an extracted root filesystem'
        blobs = {hashlib.sha256(v).hexdigest():v for v in (config, layer)}
        config_id, layer_id = [hashlib.sha256(v).hexdigest() for v in (config, layer)]
        manifest = json.dumps({'schemaVersion':2,
            'mediaType':'application/vnd.oci.image.manifest.v1+json',
            'config':{'mediaType':'application/vnd.oci.image.config.v1+json',
                      'digest':'sha256:'+config_id, 'size':len(config)},
            'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar',
                       'digest':'sha256:'+layer_id, 'size':len(layer)}]}).encode()
        manifest_id = hashlib.sha256(manifest).hexdigest()
        blobs[manifest_id] = manifest
        files = {'oci-layout':b'{"imageLayoutVersion":"1.0.0"}',
                 'index.json':json.dumps({'schemaVersion':2, 'manifests':[
                     {'mediaType':'application/vnd.oci.image.manifest.v1+json',
                      'digest':'sha256:'+manifest_id,'size':len(manifest)}]}).encode(),
                 **{'blobs/sha256/'+key:value for key,value in blobs.items()}}
        return files, 'sha256:'+manifest_id, 'sha256:'+config_id

    def archive(self, path, files, extra=None):
        with tarfile.open(path, 'w:gz') as archive:
            for name, content in files.items():
                info=tarfile.TarInfo(name);info.size=len(content)
                archive.addfile(info,io.BytesIO(content))
            if extra:
                archive.addfile(extra,io.BytesIO(b'x'*extra.size))

    def test_oci_data_blobs_are_verified_without_extracting_layers(self):
        files, manifest, config=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.archive(root/'image.gz',files)
            result=unpack_oci(root/'image.gz',root/'oci',manifest,config)
            self.assertEqual(result['manifest_digest'],manifest)
            self.assertEqual(result['config_digest'],config)
            self.assertEqual(result['blobs'],3)
            self.assertEqual({str(p.relative_to(root/'oci')) for p in (root/'oci').rglob('*') if p.is_file()},set(files))
            self.assertEqual((root/'oci').stat().st_mode & 0o777,0o700)

    def test_corrupt_wrong_or_unreferenced_oci_blob_is_refused_and_cleaned(self):
        original, manifest, config=self.fixture()
        blob=next(k for k in original if k.startswith('blobs/'))
        extra=b'unreferenced'
        cases=[]
        changed=dict(original);changed[blob]=b'x'*len(changed[blob]);cases.append((changed,manifest,config))
        changed=dict(original);changed['blobs/sha256/'+hashlib.sha256(extra).hexdigest()]=extra;cases.append((changed,manifest,config))
        cases.extend([(original,'sha256:'+'0'*64,config),(original,manifest,'sha256:'+'0'*64)])
        for files, expected_manifest, expected_config in cases:
            with self.subTest(expected_manifest=expected_manifest), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.archive(root/'image.gz',files)
                with self.assertRaises(ValueError):
                    unpack_oci(root/'image.gz',root/'oci',expected_manifest,expected_config)
                self.assertFalse((root/'oci').exists())

    def test_tar_paths_links_duplicates_and_oversize_are_refused(self):
        files,manifest,config=self.fixture()
        members=[]
        for name in ('../escaped','/absolute','unexpected','index.json'):
            member=tarfile.TarInfo(name);member.size=1;members.append(member)
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE,tarfile.FIFOTYPE):
            member=tarfile.TarInfo('blobs/sha256/'+'0'*64);member.type=kind;member.linkname='/etc/passwd';members.append(member)
        for member in members:
            with self.subTest(name=member.name,kind=member.type), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.archive(root/'image.gz',files,member)
                with self.assertRaises(ValueError): unpack_oci(root/'image.gz',root/'oci',manifest,config)
                self.assertFalse((root/'oci').exists())
                self.assertFalse((root/'escaped').exists())
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.archive(root/'image.gz',files)
            with self.assertRaises(ValueError): unpack_oci(root/'image.gz',root/'oci',manifest,config,max_bytes=64)
            self.assertFalse((root/'oci').exists())

    def test_existing_oci_destination_is_never_replaced(self):
        files,manifest,config=self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.archive(root/'image.gz',files)
            (root/'oci').mkdir();(root/'oci/keep').write_text('preserve')
            with self.assertRaises(ValueError): unpack_oci(root/'image.gz',root/'oci',manifest,config)
            self.assertEqual((root/'oci/keep').read_text(),'preserve')

    def test_only_a_new_private_regular_disk_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);identity=create_disk(root,4096);path=root/'atomic.raw'
            self.assertEqual(path.stat().st_size,4096)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            require_disk(path,identity)
            with self.assertRaises(ValueError): create_disk(root,4096)
            path.unlink();path.write_bytes(b'x'*4096);path.chmod(0o600)
            # A newly created inode must never stand in for the checked target.
            altered=dict(identity);altered['inode']=-1
            with self.assertRaises(ValueError): require_disk(path,altered)

    def test_disk_links_shared_parents_and_identity_changes_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o755)
            with self.assertRaises(ValueError): create_disk(root,4096)
            root.chmod(0o700);identity=create_disk(root,4096);path=root/'atomic.raw'
            os.link(path,root/'hardlink')
            with self.assertRaises(ValueError): require_disk(path,identity)
            (root/'hardlink').unlink();path.chmod(0o666)
            with self.assertRaises(ValueError): require_disk(path,identity)
            path.unlink();path.symlink_to('/dev/null')
            with self.assertRaises(ValueError): require_disk(path,identity)
            with self.assertRaises(ValueError): create_disk(root,4096)

    def test_installer_has_one_file_target_and_enforcing_update_policy(self):
        command=installer_arguments('sha256:'+'a'*64)
        self.assertEqual(command[:3],['/usr/bin/bootc','install','to-disk'])
        self.assertEqual(command[-1],'/output/atomic.raw')
        for flag in ('--via-loopback','--generic-image','--enforce-container-sigpolicy','--filesystem=btrfs'):
            self.assertIn(flag,command)
        self.assertIn('--source-imgref=oci:/inputs/oci',command)
        for forbidden in ('--wipe','--disable-selinux','--target-no-signature-verification','--allow-missing-verity'):
            self.assertFalse(any(v.split('=')[0]==forbidden for v in command))
        for bad in ('latest','sha256:'+'x'*64,'sha256:'+'a'*64+' --wipe'):
            with self.assertRaises(ValueError): installer_arguments(bad)

    def test_firmware_names_fit_qemu_and_do_not_add_login_credentials(self):
        args=firmware_arguments(Path('/inputs'))
        self.assertEqual(len(args),6)
        names=[args[n].split(',file=')[0].removeprefix('name=') for n in (1,3,5)]
        self.assertTrue(all(len(name.encode('ascii'))<56 for name in names))
        self.assertIn('opt/io.systemd.credentials/systemd.extra-unit.o.service',names)
        self.assertFalse(any('password' in name or 'ssh' in name for name in names))

    def test_installer_observes_live_devices_through_readonly_mounts(self):
        from image.atomic.contract import installer_mounts
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('installer-input','oci','disk','installer-tmp'):
                (root/name).mkdir(mode=0o700)
            args=installer_mounts(root)
            mounts=[dict(field.split('=',1) if '=' in field else (field,True)
                         for field in args[n].split(',')) for n in range(1,len(args),2)]
            by_target={row['dst']:row for row in mounts}
            self.assertEqual(by_target['/dev'],{'type':'bind','src':'/dev','dst':'/dev','ro':True,'bind-nonrecursive':True})
            self.assertEqual(by_target['/run/udev'],{'type':'bind','src':'/run/udev','dst':'/run/udev','ro':True,'bind-nonrecursive':True})
            self.assertEqual({p for p,row in by_target.items() if not row.get('ro')},{'/output','/var/tmp'})
            for target in ('/output','/var/tmp'):
                self.assertTrue(Path(by_target[target]['src']).is_relative_to(root))
            self.assertTrue(by_target['/inputs']['ro']);self.assertTrue(by_target['/inputs/oci']['ro'])

    def test_installer_rejects_shared_or_linked_host_input_directories(self):
        from image.atomic.contract import installer_mounts
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('installer-input','oci','disk','installer-tmp'):
                (root/name).mkdir(mode=0o700)
            (root/'disk').chmod(0o755)
            with self.assertRaises(ValueError): installer_mounts(root)
            (root/'disk').rmdir();(root/'disk').symlink_to('/dev')
            with self.assertRaises(ValueError): installer_mounts(root)

    def boot(self):
        expected={'os':{'ID':'secureblue','ID_LIKE':'fedora','VERSION_ID':'45','IMAGE_ID':'sericea-main-hardened'},
                  'kernel':'7.3.4-300.secureblue.1.fc45.x86_64','bootc_version':'1.17.1',
                  'inventory_sha256':'b'*64,'inventory_count':2184,'payload_count':102,
                  'trust':{'etc/containers/policy.json':'c'*64},
                  'manifest_digest':'sha256:'+'d'*64}
        reference={'image':'ghcr.io/thirdkeyai/symbiont-os@'+expected['manifest_digest'],
                   'transport':'registry','signature':'containerPolicy'}
        report={'schema':1,'nonce':'a'*32,'probe_sha256':'e'*64,'expected_sha256':'f'*64,
                'probe_completed':True,'guest_booted':True,'os_qualified':False,'release_qualified':False,
                'product':'Symbi-Hosted-Atomic-Probe','boot_id':'e9579818-d971-4761-b9a2-000b3f08f660',
                'kernel':expected['kernel'],'os':expected['os'],'nics':['lo'],'selinux':'Enforcing',
                'selinux_enforce':'1','usr_readonly':True,'sysroot_readonly':True,'sysroot_fstype':'btrfs',
                'bootc_version':'bootc 1.17.1','payload_count':102,'payload_verified':True,
                'inventory_sha256':expected['inventory_sha256'],'inventory_count':2184,'trust':expected['trust'],
                'bootc_status':{'apiVersion':'org.containers.bootc/v1','kind':'BootcHost',
                    'spec':{'image':reference},'status':{'type':'bootcHost','booted':{'incompatible':False,
                        'image':{'image':reference,'imageDigest':expected['manifest_digest'],'architecture':'amd64'},
                        'ostree':{'checksum':'1'*64,'stateroot':'default','deploySerial':0}}}}}
        return expected,report

    def test_exact_booted_deployment_is_checked_without_release_claim(self):
        expected,report=self.boot()
        validate_report(report,expected,'a'*32,'e'*64,'f'*64)
        self.assertFalse(report['os_qualified']);self.assertFalse(report['release_qualified'])

    def test_wrong_guest_replayed_report_and_unenforced_boot_are_refused(self):
        expected,original=self.boot()
        for key,value in [('nonce','0'*32),('probe_sha256','0'*64),('expected_sha256','0'*64),
                          ('kernel','cloud-kernel'),('boot_id','invalid'),('nics',['lo','eth0']),
                          ('selinux','Permissive'),('selinux_enforce','0'),('usr_readonly',False),
                          ('sysroot_readonly',False),('sysroot_fstype','ext4'),('guest_booted',False),
                          ('os_qualified',True),('release_qualified',True),('payload_verified',False),
                          ('inventory_count',2183),('inventory_sha256','0'*64),('trust',{})]:
            with self.subTest(key=key):
                report=copy.deepcopy(original);report[key]=value
                with self.assertRaises(ValueError): validate_report(report,expected,'a'*32,'e'*64,'f'*64)

    def test_booted_or_future_update_reference_cannot_lose_signature_policy(self):
        expected,original=self.boot()
        changes=[('digest',None),('signature','insecure'),('repo','ghcr.io/elsewhere/os'),('spec',None),('booted',None)]
        for key,value in changes:
            with self.subTest(key=key):
                report=copy.deepcopy(original);status=report['bootc_status']
                if key=='digest': status['status']['booted']['image']['imageDigest']='sha256:'+'0'*64
                elif key=='signature': status['status']['booted']['image']['image']['signature']=value
                elif key=='repo': status['status']['booted']['image']['image']['image']=value
                elif key=='spec': status['spec']['image']=value
                else: status['status']['booted']=value
                with self.assertRaises(ValueError): validate_report(report,expected,'a'*32,'e'*64,'f'*64)


if __name__=='__main__': unittest.main()
