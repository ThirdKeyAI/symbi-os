"""Resolve desktop candidate RPMs on bounded disposable hosted infrastructure."""
import json
import os
from pathlib import Path
import shutil

from image.desktop_packages.contract import FEDORA, FUSION, require_repositories, require_requirements
from image.toolchain.reuse import digest, unique_json


def prepare_inputs(root, inputs, base):
    for relative in ('image/desktop_packages/trust.json','image/hyprland/fedora-package-trust.json',
                     'image/desktop_packages/requirements.json','image/desktop_packages/repository-inputs.json'):
        source=root/relative
        if source.resolve()!=source or not source.is_file() or source.stat().st_size>256*1024:
            raise ValueError('Unexpected or linked desktop discovery metadata: '+relative)
    trust=unique_json((root/'image/desktop_packages/trust.json').read_bytes())
    fedora=unique_json((root/'image/hyprland/fedora-package-trust.json').read_bytes())
    requirements=unique_json((root/'image/desktop_packages/requirements.json').read_bytes())
    require_requirements(requirements)
    if (trust.get('schema')!=1 or trust.get('release')!='45' or trust.get('architecture')!='x86_64'
            or trust.get('base')!=base or fedora['source']['image']!=base
            or [key['fingerprint'] for key in trust['keys']]!=[FEDORA,FUSION]
            or [key['file'] for key in trust['keys']]!=['fedora-45-primary.asc','rpmfusion-free-2020.asc']
            or any(trust['keys'][0][name]!=fedora['key'][name] for name in ('fingerprint','sha256','identity'))):
        raise ValueError('Desktop discovery public trust differs from reviewed base/key inputs')
    paths={
        'resolve.py':'image/desktop_packages/resolve.py',
        'contract.py':'image/desktop_packages/contract.py',
        'bounded_process.py':'image/launcher/probes/bounded_process.py',
        'guest_inventory.py':'image/hyprland/guest_inventory.py',
        'requirements.json':'image/desktop_packages/requirements.json',
        'trust.json':'image/desktop_packages/trust.json',
        'fedora-45-primary.asc':'image/hyprland/keys/fedora-45-primary.asc',
        'rpmfusion-free-2020.asc':'image/desktop_packages/rpmfusion-free-2020.asc',
        'dnf.conf':'image/hyprland/package-dnf.conf',
        'repos/desktop.repo':'image/desktop_packages/desktop.repo',
    }
    bindings={}
    for name,relative in paths.items():
        source=root/relative
        if source.resolve()!=source or not source.is_file() or source.stat().st_size>256*1024:
            raise ValueError('Unexpected or linked desktop discovery input: '+relative)
        bindings[name]=digest(source)
    for key in trust['keys']:
        if bindings[key['file']]!=key['sha256']: raise ValueError('Pinned public package key changed')
    repositories=unique_json((root/'image/desktop_packages/repository-inputs.json').read_bytes())
    if bindings['repos/desktop.repo']!=repositories['selected_configuration_sha256']:
        raise ValueError('Reviewed repository configuration bytes changed')
    require_repositories((root/paths['repos/desktop.repo']).read_text())
    inputs.mkdir(mode=0o755)
    try:
        for name,relative in paths.items():
            target=inputs/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/relative,target);target.chmod(0o644)
            if digest(target)!=bindings[name]: raise ValueError('Discovery input changed during staging')
    except Exception:
        shutil.rmtree(inputs)
        raise
    return {'trust':trust,'requirements':requirements,'bindings':bindings,'repository_inputs':repositories}


def collect_evidence(source,target):
    if source.resolve()!=source or not source.is_dir():
        raise ValueError('Unexpected guest evidence directory')
    files=list(source.iterdir())
    if len(files)>1100:
        raise ValueError('Excessive guest evidence file count')
    total=0
    for path in files:
        if (path.resolve()!=path or not path.is_file() or path.stat().st_size>1024**2
                or not (path.name=='result.json' or path.name.endswith('.log'))):
            raise ValueError('Unexpected guest evidence file')
        total+=path.stat().st_size
    if total>16*1024**2: raise ValueError('Excessive public guest evidence bytes')
    target.mkdir(mode=0o755)
    for path in files: shutil.copyfile(path,target/path.name)


def main():
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.geteuid()!=0):
        raise SystemExit('Use the disposable hosted desktop package unit')
    from image.hyprland.inventory import require_subject
    from image.launcher.probes.bounded_process import run_bounded
    from image.recipe import render
    from image.toolchain.bootstrap_cosign import bootstrap
    root=Path.cwd().resolve()
    process=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    group=process.parent
    if (process.name!='supervisor' or not group.name.startswith('symbi-desktop-rpms-')
            or not group.name.endswith('.service') or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected desktop package supervisor')
    limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    if limits!={'memory.max':'3221225472','memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'256'}:
        raise ValueError('Unexpected desktop package resource limits')
    required={'cpu','memory','pids'}
    if not required.issubset((group/'cgroup.controllers').read_text().split()): raise ValueError('Missing cgroup delegation')
    (group/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    if not required.issubset((group/'cgroup.subtree_control').read_text().split()): raise ValueError('Delegation failed')
    evidence=root/'.cache/desktop-package-evidence';evidence.mkdir(parents=True,exist_ok=True)
    output=root/'.cache/desktop-package-output';output.mkdir(mode=0o755)
    inputs=root/'.cache/desktop-package-inputs'
    storage=root/'.cache/desktop-package-storage';storage.mkdir(mode=0o700)
    runroot=Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot))>50: raise ValueError('Private Podman runroot path is too long')
    runroot.mkdir(mode=0o700)
    podman=['podman','--cgroup-manager=cgroupfs','--root',str(storage/'root'),'--runroot',str(runroot)]
    record={'schema':1,'passed':False,'os_qualified':False,'security_qualified':False,'packages_selected':False,
            'source_commit':os.environ['GITHUB_SHA'],'limits':limits,'commands':[],
            'scope':'Authenticated public candidates only; no package transaction, program execution or release acceptance'}
    container=None;pulled=False;base=None
    def save(): (evidence/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    def run(name,command,timeout=60,check=True):
        record['active_command']={'name':name,'command':command};save()
        result=run_bounded(command,evidence/(name+'-stdout.log'),evidence/(name+'-stderr.log'),timeout,1024**2)
        record['commands'].append({'name':name,'exit_code':result.returncode});del record['active_command'];save()
        if check: result.check_returncode()
        return result
    try:
        pins=unique_json((root/'image/base-images.json').read_bytes());render(pins,'generic',root)
        base=pins['variants']['generic']
        bound=prepare_inputs(root,inputs,base['image']);record.update(base=base['image'],inputs=bound)
        cosign=bootstrap(root,evidence)
        signature=run('base-signature',[str(cosign),'verify','--key',str(root/base['public_key']),
                                       '--output','json',base['image']],180)
        require_subject(unique_json(signature.stdout),base['image'])
        auth=storage/'auth.json';auth.write_text('{"auths": {}}\n')
        run('pull',podman+['pull','--authfile',str(auth),base['image']],1200);pulled=True
        container='symbi-desktop-package-discovery'
        run('discover',podman+['run','--rm','--name='+container,'--pull=never','--user=0','--read-only',
            '--network=bridge','--pid=private','--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
            '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=2g','--memory-swap=2g','--cpus=1',
            '--mount',f'type=bind,src={inputs},dst=/inputs,ro','--mount',f'type=bind,src={output},dst=/output',
            '--env=PYTHONDONTWRITEBYTECODE=1','--env=LANG=C.UTF-8','--entrypoint=/usr/bin/python3',base['image'],'/inputs/resolve.py'],2700)
        result=unique_json((output/'evidence/result.json').read_bytes())
        controls={key:{'missing_key_rejected':True,'wrong_key_rejected':True,'tampered_package_rejected':True} for key in (FEDORA,FUSION)}
        if (result.get('passed') is not True or result.get('installed_packages_unchanged') is not True
                or any(result.get(name) is not False for name in ('os_qualified','security_qualified','packages_selected'))
                or result.get('requirements')!=bound['requirements'] or result.get('trust')!=bound['trust']
                or result.get('negative_controls')!=controls):
            raise ValueError('Desktop candidate acceptance incomplete')
        files=set()
        for row in result['packages']:
            name=row['filename']
            if (Path(name).name!=name or not name.endswith('.rpm') or name in files
                    or row.get('signature_verified') is not True or row.get('key_fingerprint') not in (FEDORA,FUSION)):
                raise ValueError('Unexpected signed package record')
            path=output/'rpms'/name
            if path.resolve()!=path or not path.is_file() or path.stat().st_size!=row['bytes'] or digest(path)!=row['sha256']:
                raise ValueError('Authenticated candidate bytes changed')
            files.add(name)
        if files!={path.name for path in (output/'rpms').iterdir()}:
            raise ValueError('Unrecorded package payload')
        record.update(passed=True,packages=len(files),candidate_manifest_sha256=digest(output/'evidence/result.json'))
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        stopped=True
        if container:
            removed=run('cleanup-container',podman+['rm','--force','--ignore',container],check=False)
            absent=run('container-absent',podman+['container','exists',container],check=False)
            stopped=removed.returncode==0 and absent.returncode==1
            record['container_absent']=stopped
            if not stopped: record['passed']=False
        if (output/'evidence').is_dir():
            try: collect_evidence(output/'evidence',evidence/'guest')
            except Exception as error:
                record['passed']=False
                record['evidence_failure']=type(error).__name__+': '+str(error)
        if pulled:
            removed=run('remove-image',podman+['image','rm','--force',base['image']],300,check=False)
            absent=run('image-absent',podman+['image','exists',base['image']],check=False)
            record['image_removed']=removed.returncode==0 and absent.returncode==1
            if not record['image_removed']: record['passed']=False
        if stopped:
            shutil.rmtree(storage);shutil.rmtree(runroot)
            record['private_storage_removed']=not storage.exists() and not runroot.exists()
        final={name:(group/name).read_text().strip() for name in (*limits,'memory.peak','memory.events','cpu.stat')}
        record['cgroup_final']=final
        events=dict(line.split() for line in final['memory.events'].splitlines())
        if (any(final[name]!=value for name,value in limits.items())
                or any(events.get(name)!='0' for name in ('oom','oom_kill','oom_group_kill'))): record['passed']=False
        save()
    if not record['passed']: raise RuntimeError('Desktop discovery, resource or cleanup checks failed')


if __name__=='__main__': main()
