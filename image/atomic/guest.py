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
            'commands':[],'scope':'Unsigned development artifact boot only; no release, desktop or containment qualification'}
    def run(command):
        result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=60,
                              env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        if len(result.stdout.encode())>512*1024 or len(result.stderr.encode())>65536:
            raise ValueError('Oversized boot observation')
        record['commands'].append({'command':command,'exit_code':result.returncode,
                                   'stderr':result.stderr,'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest()})
        result.check_returncode()
        return result.stdout
    try:
        record['selinux']=run(['/usr/sbin/getenforce']).strip()
        record['selinux_enforce']=Path('/sys/fs/selinux/enforce').read_text().strip()
        record['usr_readonly']=bool(os.statvfs('/usr').f_flag & os.ST_RDONLY)
        record['sysroot_readonly']=bool(os.statvfs('/sysroot').f_flag & os.ST_RDONLY)
        record['sysroot_fstype']=run(['/usr/bin/findmnt','-n','-o','FSTYPE','--target','/sysroot']).strip()
        record['cmdline']=Path('/proc/cmdline').read_text().strip()
        record['bootc_version']=run(['/usr/bin/bootc','--version']).strip()
        record['bootc_status']=json.loads(run(['/usr/bin/bootc','status','--json']))
        fmt='%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        inventory=run(['/usr/bin/rpm','-qa','--qf',fmt]).splitlines()
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
