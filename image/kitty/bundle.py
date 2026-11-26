"""Authenticate and inventory a public Kitty bundle without extracting or running it."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import time
import urllib.request


def digest(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def require_signature(code, status, fingerprint):
    valid=[line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    bad=('BADSIG','ERRSIG','EXPKEYSIG','EXPSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED')
    if (code!=0 or len(valid)!=1 or len(valid[0])<11 or valid[0][2]!=fingerprint
            or valid[0][9] not in ('8','9','10') or any(x in status for x in bad)):
        raise ValueError('Bundle lacks one valid current signature by the pinned primary identity')


def inspect_archive(path, max_bytes=512*1024**2, max_members=8192):
    rows={};expanded=0;count=0
    with tarfile.open(path,'r|*') as archive:
        for item in archive:
            count+=1;expanded+=item.size
            if count>max_members or expanded>max_bytes or item.size>128*1024**2:
                raise ValueError('Bundle exceeds inventory limits')
            name=item.name.removeprefix('./')
            if name in ('','.'):
                if item.isdir():continue
                raise ValueError('Unexpected root payload')
            parts=name.split('/')
            if (name.startswith('/') or len(name)>1024 or any(x in ('','.','..') for x in parts)
                    or any(ord(x)<32 or ord(x)==127 for x in name) or name in rows
                    or parts[0] not in ('bin','lib','lib64','share') or item.mode & 0o6000
                    or item.issparse()):
                raise ValueError('Unsafe or duplicate archive path/mode: '+repr(name))
            row={'mode':item.mode,'uid':item.uid,'gid':item.gid}
            if item.isfile():
                hasher=hashlib.sha256();size=0
                source=archive.extractfile(item)
                if source is None:raise ValueError('Missing regular member bytes')
                with source:
                    while block:=source.read(65536):
                        size+=len(block)
                        if size>item.size:raise ValueError('Archive member exceeded its declared size')
                        hasher.update(block)
                if size!=item.size:raise ValueError('Truncated archive member')
                row.update(kind='regular',bytes=size,sha256=hasher.hexdigest())
            elif item.isdir():row.update(kind='directory')
            elif item.issym():
                link=item.linkname
                if not link or link.startswith('/') or any(ord(x)<32 or ord(x)==127 for x in link):
                    raise ValueError('Unsafe symlink target')
                target=list(PurePosixPath(name).parent.parts)
                for part in link.split('/'):
                    if part in ('','.'):continue
                    if part=='..':
                        if not target:raise ValueError('Symlink escapes the archive root')
                        target.pop()
                    else:target.append(part)
                row.update(kind='symlink',link=link,target='/'.join(target))
            else:raise ValueError('Special or hard-linked archive member')
            rows[name]=row
    for name,row in rows.items():
        if row['kind']!='symlink':continue
        target=row['target'];seen={name}
        for _ in range(32):
            if target not in rows or target in seen:raise ValueError('Dangling or cyclic archive link')
            seen.add(target);next_row=rows[target]
            if next_row['kind']!='symlink':break
            target=next_row['target']
        else:raise ValueError('Excessive archive link chain')
    for required in ('bin/kitty','bin/kitten'):
        row=rows.get(required,{})
        if row.get('kind')!='regular' or not row.get('mode',0)&0o111:
            raise ValueError('Missing executable bundle entry: '+required)
    return dict(sorted(rows.items()))


def main():
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.geteuid()==0):raise SystemExit('Use the unprivileged disposable hosted inspection unit')
    root=Path.cwd().resolve()
    group=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    if not group.name.startswith('symbi-kitty-bundle-') or not group.name.endswith('.service'):
        raise ValueError('Unexpected bundle inspection resource group')
    limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    if limits!={'memory.max':'536870912','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'32'}:
        raise ValueError('Unexpected bundle inspection resource limits')
    process=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(process[x].strip()!='0000000000000000' for x in ('CapEff','CapPrm','CapBnd')) or process['NoNewPrivs'].strip()!='1':
        raise ValueError('Bundle inspector must have no capabilities and no new privileges')
    evidence=root/'.cache/kitty-bundle-evidence';evidence.mkdir(exist_ok=True)
    private=root/'.cache/kitty-bundle-input';private.mkdir(mode=0o700)
    record={'schema':1,'passed':False,'selected':False,'security_qualified':False,'os_qualified':False,
            'scope':'Signature and archive inventory only; no extraction, candidate execution, installation or release claim',
            'source_commit':os.environ['GITHUB_SHA'],'limits':limits,'commands':[],'downloads':[]}
    def save():(evidence/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    def run(name,command):
        result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=60,
                              env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        if len(result.stdout.encode())+len(result.stderr.encode())>65536:raise ValueError('Excessive verifier output')
        (evidence/(name+'-stdout.log')).write_text(result.stdout)
        (evidence/(name+'-stderr.log')).write_text(result.stderr)
        record['commands'].append({'name':name,'exit_code':result.returncode});save()
        return result
    try:
        pins_path=root/'image/kitty/bundle-inputs.json'
        pins=json.loads(pins_path.read_bytes())
        if (pins['schema']!=1 or pins['selected'] is not False or pins['security_qualified'] is not False
                or pins['version']!='0.51.0' or pins['revision']!='c83027daa9b031541193c19dbc518a4a42a5c9f5'
                or pins['publisher_fingerprint']!='3CE1780F78DD88DF45194FD706BC317B515ACE7C'
                or pins['public_key']['file']!='image/kitty/kovid.gpg'):
            raise ValueError('Unexpected candidate or publisher selection')
        key=root/pins['public_key']['file']
        if key.resolve()!=key or not key.is_file() or key.stat().st_size>65536 or digest(key)!=pins['public_key']['sha256']:
            raise ValueError('Pinned public verification key changed')
        expected_names=['kitty-0.51.0-x86_64.txz','kitty-0.51.0-x86_64.txz.sig']
        if [x['name'] for x in pins['assets']]!=expected_names:raise ValueError('Unexpected bundle asset set')
        record.update(inputs_sha256=digest(pins_path),public_key_sha256=digest(key),publisher=pins['publisher_fingerprint'])
        for item in pins['assets']:
            if (item['url']!='https://github.com/kovidgoyal/kitty/releases/download/v0.51.0/'+item['name']
                    or not re.fullmatch(r'[0-9a-f]{64}',item['sha256']) or not 0<item['bytes']<=64*1024**2):
                raise ValueError('Unexpected public asset pin')
            dest=private/item['name'];start=time.monotonic();size=0;hasher=hashlib.sha256()
            request=urllib.request.Request(item['url'],headers={'User-Agent':'SymbiOS-P0-public-bundle-inspection/1','Accept-Encoding':'identity'})
            with urllib.request.urlopen(request,timeout=30) as response,dest.open('xb') as output:
                if response.status!=200 or not response.url.startswith('https://'):raise ValueError('Unexpected asset response')
                while block:=response.read(65536):
                    size+=len(block)
                    if size>item['bytes'] or time.monotonic()-start>180:raise ValueError('Asset exceeded size/time bound')
                    hasher.update(block);output.write(block)
            if size!=item['bytes'] or hasher.hexdigest()!=item['sha256']:raise ValueError('Public asset bytes changed')
            record['downloads'].append(item);save()
        verify_home=private/'public-verification';verify_home.mkdir(mode=0o700)
        version=run('gpgv-version',['/usr/bin/gpgv','--version']);version.check_returncode()
        record['verifier']={'version':version.stdout.splitlines()[0],'sha256':digest(Path('/usr/bin/gpgv'))}
        archive,signature=(private/x for x in expected_names)
        def verify(name,data,keyring):
            return run(name,['/usr/bin/gpgv','--homedir',str(verify_home),'--status-fd=1','--keyring',str(keyring),str(signature),str(data)])
        positive=verify('valid-bundle',archive,key)
        require_signature(positive.returncode,positive.stdout,pins['publisher_fingerprint'])
        empty=private/'empty-keyring.gpg';empty.touch()
        if verify('missing-key',archive,empty).returncode==0:raise ValueError('Missing-key negative control passed unexpectedly')
        altered=private/'altered.txz';shutil.copyfile(archive,altered)
        with altered.open('r+b') as output:
            output.seek(archive.stat().st_size//2);byte=output.read(1)
            output.seek(-1,1);output.write(bytes([byte[0]^1]))
        if verify('altered-bundle',altered,key).returncode==0:raise ValueError('Altered-archive negative control passed unexpectedly')
        record['signature_controls']={'valid_bundle':True,'missing_key_rejected':True,'altered_bundle_rejected':True}
        if digest(archive)!=pins['assets'][0]['sha256']:raise ValueError('Authenticated source changed before inventory')
        rows=inspect_archive(archive)
        raw=(json.dumps(rows,indent=2)+'\n').encode()
        if len(raw)>4*1024**2:raise ValueError('Inventory exceeds evidence limit')
        (evidence/'inventory.json').write_bytes(raw)
        record.update(passed=True,members=len(rows),regular_bytes=sum(x.get('bytes',0) for x in rows.values()),
                      inventory_sha256=hashlib.sha256(raw).hexdigest(),candidate_executed=False,archive_extracted=False)
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        shutil.rmtree(private)
        record['private_downloads_removed']=not private.exists()
        record['cgroup_final']={name:(group/name).read_text().strip() for name in (*limits,'memory.peak','memory.events','cpu.stat')}
        if not record['private_downloads_removed']:record['passed']=False
        save()


if __name__=='__main__':main()
