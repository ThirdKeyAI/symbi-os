"""Validation primitives for a disposable, offline development-image boot."""
import hashlib
import base64
import copy
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import uuid


def unique_json(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError('Duplicate JSON key: '+key)
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)


def sha256(path):
    with path.open('rb') as source: return hashlib.file_digest(source,'sha256').hexdigest()


def digest_value(value):
    if not isinstance(value,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',value):
        raise ValueError('An exact SHA-256 digest is required')
    return value.removeprefix('sha256:')


def private_directory(path):
    info=path.lstat()
    if (not path.is_absolute() or path.resolve()!=path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700):
        raise ValueError('A canonical private directory owned by the controller is required')


def disk_identity(path,mode=0o600):
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid()
            or stat.S_IMODE(info.st_mode)!=mode):
        raise ValueError('Disk must be a private, singly linked regular file')
    return {'device':info.st_dev,'inode':info.st_ino,'bytes':info.st_size,
            'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'links':info.st_nlink}


def create_disk(directory,size):
    private_directory(directory)
    if type(size) is not int or not 4096<=size<=32*1024**3:
        raise ValueError('Invalid bounded disk size')
    path=directory/'atomic.raw'
    try: fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY|os.O_CLOEXEC,0o600)
    except FileExistsError as error: raise ValueError('Never replace an existing disk target') from error
    try: os.ftruncate(fd,size);os.fsync(fd)
    finally: os.close(fd)
    return disk_identity(path)


def require_disk(path,expected,*,readonly=False):
    private_directory(path.parent)
    mode=0o444 if readonly else 0o600
    if path.name!='atomic.raw' or disk_identity(path,mode)!={**expected,'mode':mode}:
        raise ValueError('The private regular disk target changed')


def unpack_oci(archive,target,manifest_digest,image_id,*,max_bytes=32*1024**3):
    """Extract only the OCI layout; layer blobs remain opaque, never unpacked."""
    digest_value(manifest_digest);digest_value(image_id)
    if target.exists() or target.is_symlink() or target.parent.resolve()!=target.parent:
        raise ValueError('OCI layout destination must be new under a canonical parent')
    if archive.is_symlink() or not archive.is_file(): raise ValueError('Expected regular OCI archive')
    if type(max_bytes) is not int or not 1<=max_bytes<=32*1024**3: raise ValueError('Invalid OCI size limit')
    target.mkdir(mode=0o700)
    names=set();blobs={};total=0
    try:
        with tarfile.open(archive,'r|gz') as stream:
            for member in stream:
                name=member.name
                if name in names or len(names)>=4096: raise ValueError('Duplicate or excessive OCI member')
                names.add(name)
                if member.isdir() and name in ('blobs','blobs/sha256'):
                    (target/name).mkdir(mode=0o700,parents=True,exist_ok=True);continue
                blob=re.fullmatch(r'blobs/sha256/([0-9a-f]{64})',name)
                if not member.isfile() or (not blob and name not in ('index.json','oci-layout')):
                    raise ValueError('Unexpected OCI member, path or file type: '+name)
                maximum=max_bytes if blob else 1024**2
                total+=member.size
                if not 0<member.size<=maximum or total>max_bytes:
                    raise ValueError('OCI data exceeds the bounded layout size')
                path=target/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                digest=hashlib.sha256();count=0
                with stream.extractfile(member) as source, path.open('xb') as output:
                    while block:=source.read(1024**2):
                        count+=len(block)
                        if count>member.size: raise ValueError('OCI member grew while reading')
                        digest.update(block);output.write(block)
                path.chmod(0o600)
                if count!=member.size or (blob and digest.hexdigest()!=blob.group(1)):
                    raise ValueError('OCI blob content does not match its name and size')
                if blob: blobs['sha256:'+blob.group(1)]={'bytes':count,'path':path}
        def document(name):
            path=target/name
            if path.stat().st_size>1024**2: raise ValueError('Oversized OCI JSON')
            return unique_json(path.read_bytes())
        def descriptor(row):
            value=row['digest'];digest_value(value)
            if type(row['size']) is not int or value not in blobs or blobs[value]['bytes']!=row['size']:
                raise ValueError('OCI descriptor does not match a verified blob')
            return value
        if document('oci-layout')!={'imageLayoutVersion':'1.0.0'}: raise ValueError('Unknown OCI layout')
        index=document('index.json')
        if index.get('schemaVersion')!=2 or len(index['manifests'])!=1:
            raise ValueError('Expected one OCI image manifest')
        item=index['manifests'][0]
        if descriptor(item)!=manifest_digest or item['mediaType']!='application/vnd.oci.image.manifest.v1+json':
            raise ValueError('OCI manifest differs from the loaded preflight image')
        manifest=document('blobs/sha256/'+digest_value(manifest_digest))
        if (manifest.get('schemaVersion')!=2
                or manifest.get('mediaType')!='application/vnd.oci.image.manifest.v1+json'
                or descriptor(manifest['config'])!=image_id
                or manifest['config']['mediaType']!='application/vnd.oci.image.config.v1+json'):
            raise ValueError('OCI manifest/config identity changed')
        config=document('blobs/sha256/'+digest_value(image_id))
        if config.get('architecture')!='amd64' or config.get('os')!='linux':
            raise ValueError('Expected Linux amd64 image configuration')
        referenced={manifest_digest,image_id}
        if not isinstance(manifest['layers'],list) or not manifest['layers']:
            raise ValueError('Missing OCI layers')
        for layer in manifest['layers']:
            if (layer.get('mediaType') not in ('application/vnd.oci.image.layer.v1.tar',
                    'application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.v1.tar+zstd')
                    or layer.get('urls')):
                raise ValueError('Unreviewed or remote OCI layer transport')
            referenced.add(descriptor(layer))
        if set(blobs)!=referenced: raise ValueError('Unreferenced OCI payload')
        return {'manifest_digest':manifest_digest,'config_digest':image_id,
                'blobs':len(blobs),'layers':len(manifest['layers']),'bytes':total,
                'root_filesystem_extracted':False}
    except Exception as error:
        shutil.rmtree(target)
        if isinstance(error,(KeyError,TypeError,IndexError,FileNotFoundError,tarfile.TarError)):
            raise ValueError('Malformed OCI layout') from error
        raise


def directory_source(oci,target,manifest_digest):
    """Re-layout verified opaque OCI blobs without recompression or copying layers."""
    private_directory(oci);private_directory(target.parent)
    hex_digest=digest_value(manifest_digest)
    manifest_path=oci/'blobs/sha256'/hex_digest
    if manifest_path.resolve()!=manifest_path or sha256(manifest_path)!=hex_digest:
        raise ValueError('OCI manifest bytes changed before source preparation')
    manifest=unique_json(manifest_path.read_bytes())
    blobs={}
    for item in [manifest['config'],*manifest['layers']]:
        name=digest_value(item['digest']);path=oci/'blobs/sha256'/name
        if (path.resolve()!=path or not path.is_file() or path.stat().st_size!=item['size']
                or sha256(path)!=name):
            raise ValueError('OCI blob bytes changed before source preparation')
        blobs[name]=path
    try: target.mkdir(mode=0o700)
    except FileExistsError as error: raise ValueError('Never replace an existing source directory') from error
    try:
        shutil.copyfile(manifest_path,target/'manifest.json')
        for name,path in blobs.items(): os.link(path,target/name,follow_symlinks=False)
        (target/'version').write_text('Directory Transport Version: 1.1\n')
        return {'manifest_digest':manifest_digest,'blobs':sorted(blobs),'recompressed':False,'root_filesystem_extracted':False}
    except Exception:
        shutil.rmtree(target)
        raise


def require_verifier_identity(version,package):
    if (version.strip()!='skopeo version 1.25.1 commit: 849f8f0f9443e56435f4302f81ccadcf6a56da21'
            or package.strip()!='skopeo\t1\t1.25.1\t2.fc45\tx86_64'):
        raise ValueError('The pinned image signature verifier identity changed')


def installer_policy(original,public_key,manifest_digest):
    """Authorize one ephemeral CI-signed local source, preserving release trust."""
    digest_value(manifest_digest)
    if (original.get('default')!=[{'type':'reject'}] or set(original.get('transports',{}))!={'docker'}
            or not isinstance(public_key,bytes) or not 1<=len(public_key)<=65536
            or 'insecureAcceptAnything' in json.dumps(original)):
        raise ValueError('Unexpected enforcing source policy or public test key')
    policy=copy.deepcopy(original)
    policy['transports']['dir']={'/inputs/signed':[{
        'type':'signedBy','keyType':'GPGKeys','keyData':base64.b64encode(public_key).decode('ascii'),
        'signedIdentity':{'type':'exactReference','dockerReference':'localhost/symbi-ci/development@'+manifest_digest}}]}
    return policy


def installer_arguments(manifest_digest):
    digest_value(manifest_digest)
    return ['/usr/bin/bootc','install','to-disk','--source-imgref=dir:/inputs/signed',
            '--target-imgref=ghcr.io/thirdkeyai/symbiont-os@'+manifest_digest,
            '--enforce-container-sigpolicy','--filesystem=btrfs','--generic-image','--via-loopback',
            '--karg=console=ttyS0,115200n8','--karg=selinux=1','--karg=enforcing=1',
            '--karg=systemd.unit=multi-user.target','--karg=systemd.wants=o.service',
            '/output/atomic.raw']


def installer_mounts(storage, *, input_name='installer-input', source_name='signed',
                     disk_name='disk', temporary_name='installer-tmp'):
    """Expose new host-created loop partitions without sharing host PID/network."""
    private_directory(storage)
    names=(input_name,source_name,disk_name,temporary_name)
    if (any(character in str(storage) for character in (',','\n','\r'))
            or any(not re.fullmatch(r'[a-z0-9-]{1,48}',name) for name in names)
            or len(set(names))!=len(names)):
        raise ValueError('Unsafe container mount specification')
    result=[]
    for name,destination,readonly in [(input_name,'/inputs',True),(source_name,'/inputs/signed',True),
                                      (disk_name,'/output',False),(temporary_name,'/var/tmp',False)]:
        source=storage/name;private_directory(source)
        result+=['--mount',f'type=bind,src={source},dst={destination}'+(',ro' if readonly else '')]
    policy=storage/input_name/'install-policy.json'
    if policy.resolve()!=policy or not policy.is_file() or policy.stat().st_size>128*1024:
        raise ValueError('Expected a bounded, unlinked installer-only policy')
    result+=['--mount',f'type=bind,src={policy},dst=/etc/containers/policy.json,ro']
    # A privileged container's initial /dev is a snapshot of device nodes. The
    # host udev daemon creates partition nodes after bootc attaches/partitions
    # its loop file. A live read-only bind makes those nodes visible, while
    # preventing the installer from creating/removing host device-directory entries.
    # Do not recursively import host /dev/shm, /dev/pts or other submounts.
    for path in ('/dev','/run/udev'):
        result+=['--mount',f'type=bind,src={path},dst={path},ro,bind-nonrecursive']
    return result


def firmware_arguments(directory):
    if directory!=Path('/inputs'): raise ValueError('Fixed read-only firmware input mount required')
    result=[]
    for name,file in [('systemd.extra-unit.o.service','o.service'),
                      ('systemd.extra-unit.s.service','s.service'),
                      ('symbi-probe.py','guest.py'),('symbi-expected.json','expected.json')]:
        name='opt/io.systemd.credentials/'+name
        if len(name.encode('ascii'))>=56: raise ValueError('QEMU firmware name is too long')
        result+=['-fw_cfg',f'name={name},file={directory/file}']
    return result


def validate_report(report,expected,nonce,probe_hash,expected_hash):
    def require(condition,reason):
        if not condition: raise ValueError(reason)
    try:
        require(type(report['schema']) is int and report['schema']==1
                and report['nonce']==nonce and report['probe_sha256']==probe_hash
                and report['expected_sha256']==expected_hash,'Unbound or replayed guest report')
        require(report['probe_completed'] is True and report['guest_booted'] is True
                and report['os_qualified'] is False and report['release_qualified'] is False
                and 'failure' not in report,'Incomplete boot observation or false release claim')
        require(report['product']=='Symbi-Hosted-Atomic-Probe','Unexpected guest identity')
        uuid.UUID(report['boot_id'])
        require(report['probe_security']=={'CapEff':'0000000000000000','CapPrm':'0000000000000000',
                                           'CapBnd':'0000000000000000','NoNewPrivs':'1'},
                'Observation probe gained privileges')
        observation=report['bootc_status_observation']
        require(observation['unit']=='s.service' and observation['service']=={
                    'Result':'success','ExecMainCode':'1','ExecMainStatus':'0','ActiveState':'active','SubState':'exited'}
                and type(observation['bytes']) is int and 0<observation['bytes']<=128*1024
                and re.fullmatch(r'[0-9a-f]{64}',observation['sha256']) is not None,
                'Incomplete or unbounded fixed status observation')
        require(report['kernel']==expected['kernel'] and report['bootc_version']=='bootc '+expected['bootc_version']
                and all(report['os'].get(k)==v for k,v in expected['os'].items()),'Wrong booted OS/kernel/installer')
        require(report['nics']==['lo'] and report['selinux']=='Enforcing' and report['selinux_enforce']=='1'
                and report['usr_readonly'] is True and report['sysroot_readonly'] is True
                and report['sysroot_fstype']=='btrfs','Booted isolation, SELinux or immutable paths changed')
        require(report['payload_verified'] is True and report['payload_count']==expected['payload_count']
                and report['inventory_count']==expected['inventory_count']
                and report['inventory_sha256']==expected['inventory_sha256']
                and report['trust']==expected['trust'],'Booted payload, package inventory or trust changed')
        status=report['bootc_status'];booted=status['status']['booted']
        reference={'image':'ghcr.io/thirdkeyai/symbiont-os@'+expected['manifest_digest'],
                   'transport':'registry','signature':'containerPolicy'}
        require(status['apiVersion']=='org.containers.bootc/v1' and status['kind']=='BootcHost'
                and status['status']['type']=='bootcHost' and status['spec']['image']==reference
                and booted['incompatible'] is False and booted['image']['image']==reference
                and booted['image']['imageDigest']==expected['manifest_digest']
                and booted['image']['architecture']=='amd64'
                and re.fullmatch(r'[0-9a-f]{64}',booted['ostree']['checksum']) is not None,
                'Booted deployment or future update verification policy changed')
    except (KeyError,TypeError,AttributeError) as error:
        raise ValueError('Malformed Atomic boot observation') from error
