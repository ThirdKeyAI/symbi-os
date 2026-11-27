"""Observe the booted Atomic image, then write bounded evidence to virtio serial."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time


def sha256(path):
    with path.open('rb') as source: return hashlib.file_digest(source,'sha256').hexdigest()


def _observe_bound_regular(root_fd,parts,owner_uid,maximum,expected_digest,label):
    """Open each component relative to held directory descriptors, never links."""
    directory_fd=os.dup(root_fd);file_fd=None
    try:
        for component in parts[:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                          dir_fd=directory_fd)
            os.close(directory_fd);directory_fd=child
            info=os.fstat(directory_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner_uid
                    or info.st_gid!=owner_uid or stat.S_IMODE(info.st_mode)&0o022):
                raise ValueError('Booted container path parent changed: '+label)
        file_fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                        dir_fd=directory_fd)
        info=os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                or info.st_uid!=owner_uid or info.st_gid!=owner_uid
                or stat.S_IMODE(info.st_mode)&0o022 or not 0<info.st_size<=maximum):
            raise ValueError('Booted container file metadata changed: '+label)
        stream=os.fdopen(file_fd,'rb');file_fd=None
        with stream:
            digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest!=expected_digest:
            raise ValueError('Booted container file content changed: '+label)
        return digest
    except OSError as error:
        raise ValueError('Booted container path is not direct: '+label) from error
    finally:
        if file_fd is not None: os.close(file_fd)
        os.close(directory_fd)


def observe_container_candidate(root, expected, owner_uid=0):
    """Observe only the contract-bound runtime bytes in a booted filesystem."""
    if (not isinstance(expected,dict)
            or set(expected)!={'contract_sha256','runsc_files','daemon_configuration_sha256'}
            or re.fullmatch(r'[0-9a-f]{64}',expected.get('contract_sha256','')) is None
            or re.fullmatch(r'[0-9a-f]{64}',expected.get('daemon_configuration_sha256','')) is None
            or type(owner_uid) is not int or owner_uid<0):
        raise ValueError('Invalid generated container contract boot binding')
    files=expected.get('runsc_files')
    if not isinstance(files,dict) or not 0<len(files)<=64:
        raise ValueError('Missing bounded runsc file bindings')
    observed={};root_fd=None
    try:
        root_fd=os.open(Path(root),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        root_info=os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=owner_uid
                or root_info.st_gid!=owner_uid or stat.S_IMODE(root_info.st_mode)&0o022):
            raise ValueError('Container observation root changed')
        for relative,digest in files.items():
            path_parts=Path(relative).parts if isinstance(relative,str) else ()
            if (not path_parts or str(Path(relative))!=relative or '\\' in relative
                    or Path(relative).is_absolute() or '..' in path_parts
                    or path_parts[0] not in ('usr','etc')
                    or re.fullmatch(r'[0-9a-f]{64}',digest or '') is None):
                raise ValueError('Unsafe runsc file binding')
            observed[relative]=_observe_bound_regular(
                root_fd,path_parts,owner_uid,256*1024**2,digest,relative)
        _observe_bound_regular(
            root_fd,('etc','docker','daemon.json'),owner_uid,128*1024,
            expected['daemon_configuration_sha256'],'etc/docker/daemon.json')
    except OSError as error:
        raise ValueError('Container observation root is not direct') from error
    finally:
        if root_fd is not None: os.close(root_fd)
    return {'contract_sha256':expected['contract_sha256'],
            'runsc_files':dict(sorted(observed.items())),
            'daemon_configuration_sha256':expected['daemon_configuration_sha256']}


def read_bootc_status(path, properties):
    required={'Result':'success','ExecMainCode':'1','ExecMainStatus':'0',
              'ActiveState':'active','SubState':'exited'}
    if properties!=required: raise ValueError('Fixed bootc status collector did not complete')
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        directory=os.fstat(parent)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=0 or directory.st_mode & 0o022:
            raise ValueError('Status parent is not a root-controlled directory')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=128*1024):
            raise ValueError('Status output is not one bounded private root-owned regular file')
        raw=source.read(128*1024+1)
        if len(raw)!=info.st_size: raise ValueError('Status output changed during observation')
    return json.loads(raw), {'unit':'s.service','service':properties,'bytes':len(raw),
                             'sha256':hashlib.sha256(raw).hexdigest()}


def collect_status_diagnostic(run):
    text=run(['/usr/bin/systemctl','show','s.service',
              '--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState'])
    properties={}
    for line in text.splitlines():
        key,value=line.split('=',1)
        if key in properties: raise ValueError('Duplicate collector service property')
        properties[key]=value
    journal=run(['/usr/bin/journalctl','--boot=0','--unit=s.service','--no-pager',
                 '--output=short-monotonic','--lines=40'],check=False)
    if len(journal.encode())>32768: raise ValueError('Collector journal exceeds observation bound')
    return {'service':properties,'journal':journal}


def main():
    product=Path('/sys/class/dmi/id/product_name').read_text().strip()
    if (os.geteuid()!=0 or product!='Symbi-Hosted-Atomic-Probe'
            or Path('/run/.containerenv').exists() or len(sys.argv)!=2):
        raise SystemExit('Use only the disposable hosted Atomic guest')
    expected_path=Path(sys.argv[1])
    if expected_path.stat().st_size>128*1024: raise ValueError('Oversized observation input')
    expected=json.loads(expected_path.read_bytes())
    if not re.fullmatch(r'[0-9a-f]{32}',expected['nonce']): raise ValueError('Missing invocation nonce')
    record={'schema':1,'nonce':expected['nonce'],'probe_sha256':sha256(Path(__file__)),
            'expected_sha256':sha256(expected_path),'probe_completed':False,'guest_booted':True,
            'os_qualified':False,'release_qualified':False,'product':product,
            'kernel':platform.release(),'os':platform.freedesktop_os_release(),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'nics':sorted(path.name for path in Path('/sys/class/net').iterdir()),
            'commands':[],'scope':'CI fixture-signed development artifact boot only; no release, desktop or containment qualification'}
    def run(command,check=True,timeout=60):
        if type(timeout) is not int or not 1<=timeout<=180:
            raise ValueError('Invalid bounded boot-observation timeout')
        result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout,
                              env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        if len(result.stdout.encode())>512*1024 or len(result.stderr.encode())>65536:
            raise ValueError('Oversized boot observation')
        record['commands'].append({'command':command,'timeout_seconds':timeout,'exit_code':result.returncode,
                                   'stderr':result.stderr,'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest()})
        if check: result.check_returncode()
        return result.stdout
    try:
        process={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)}
        record['probe_security']={k:process[k] for k in ('CapEff','CapPrm','CapBnd','NoNewPrivs')}
        if record['probe_security']!={'CapEff':'0000000000000000','CapPrm':'0000000000000000',
                                      'CapBnd':'0000000000000000','NoNewPrivs':'1'}:
            raise ValueError('Observation probe gained privileges')
        record['selinux']=run(['/usr/sbin/getenforce']).strip()
        record['selinux_enforce']=Path('/sys/fs/selinux/enforce').read_text().strip()
        record['usr_readonly']=bool(os.statvfs('/usr').f_flag & os.ST_RDONLY)
        record['sysroot_readonly']=bool(os.statvfs('/sysroot').f_flag & os.ST_RDONLY)
        record['sysroot_fstype']=run(['/usr/bin/findmnt','-n','-o','FSTYPE','--target','/sysroot']).strip()
        record['cmdline']=Path('/proc/cmdline').read_text().strip()
        record['bootc_version']=run(['/usr/bin/bootc','--version']).strip()
        record['bootc_status_diagnostic']=collect_status_diagnostic(run)
        record['bootc_status'],record['bootc_status_observation']=read_bootc_status(
            Path('/run/symbi-atomic-status.json'),record['bootc_status_diagnostic']['service'])
        fmt='%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        inventory=run(['/usr/bin/rpm','-qa','--qf',fmt],timeout=180).splitlines()
        if len(set(inventory))!=len(inventory): raise ValueError('Duplicate installed package identity')
        record['inventory_count']=len(inventory)
        record['inventory_sha256']=hashlib.sha256(('\n'.join(sorted(inventory))+'\n').encode()).hexdigest()
        record['payload_verified']=False;record['payload_count']=0;record['trust']={}
        for relative,item in expected['payload'].items():
            if not relative.startswith(('usr/','etc/')) or '..' in Path(relative).parts:
                raise ValueError('Invalid observed payload path')
            path=Path('/')/relative;info=path.lstat()
            if info.st_uid!=0 or (not path.is_symlink() and info.st_mode & 0o022):
                raise ValueError('Booted file ownership/permissions changed: '+relative)
            if 'link' in item:
                if not path.is_symlink() or os.readlink(path)!=item['link'] or not path.resolve(strict=True).is_file():
                    raise ValueError('Booted payload link changed: '+relative)
            else:
                if (not stat.S_ISREG(info.st_mode) or info.st_size!=item['bytes']
                        or stat.S_IMODE(info.st_mode)!=item['mode'] or sha256(path)!=item['sha256']):
                    raise ValueError('Booted payload content changed: '+relative)
            record['payload_count']+=1
        for relative in expected['trust']:
            record['trust'][relative]=sha256(Path('/')/relative)
        if 'container_candidate' in expected:
            record['container_candidate']=observe_container_candidate(
                Path('/'),expected['container_candidate'])
        record['payload_verified']=True
        record['probe_completed']=True
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
    raw=(json.dumps(record,sort_keys=True)+'\n').encode()
    if len(raw)>128*1024: raise ValueError('Guest report exceeds its bound')
    channel=Path('/dev/virtio-ports/org.symbi.atomic')
    deadline=time.monotonic()+15
    while not channel.exists() and time.monotonic()<deadline: time.sleep(0.1)
    # QEMU's file chardev has no input source; no shell or host filesystem share.
    with channel.open('wb',buffering=0) as output:
        offset=0
        while offset<len(raw):
            written=output.write(raw[offset:])
            if not written: raise RuntimeError('Guest report channel stopped accepting data')
            offset+=written


if __name__=='__main__': main()
