"""Consume and inspect a saved development image on a disposable hosted runner only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('Use the disposable hosted Atomic image preflight units')
    if sys.argv[1:] not in (['prepare'], ['inspect']): raise SystemExit('Select prepare or inspect')
    from image.boot.inputs import require_desktop_image, unpack_desktop_image
    from image.boot.kernel_files import read_copied_kernel, validate_copy_container
    from image.boot.preflight import expected_inputs, validate_loaded_image, validate_report
    from image.launcher.probes.bounded_process import run_bounded
    from image.toolchain.reuse import digest, unique_json
    root = Path.cwd().resolve()
    phase = sys.argv[1]
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent if phase == 'inspect' else process
    if (not group.name.startswith('symbi-atomic-'+phase+'-') or not group.name.endswith('.service')
            or (phase == 'prepare' and os.geteuid() == 0)
            or (phase == 'inspect' and (os.geteuid() != 0 or process.name != 'supervisor'
                                      or (group/'cgroup.procs').read_text().strip()))):
        raise ValueError('Unexpected hosted preflight identity or resource group')
    limits = {name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    expected_limits = {'memory.max':'1073741824' if phase == 'prepare' else '4294967296',
                       'memory.swap.max':'0', 'cpu.max':'100000 100000' if phase == 'prepare' else '200000 100000',
                       'pids.max':'64' if phase == 'prepare' else '256'}
    if limits != expected_limits: raise ValueError('Unexpected hosted preflight resource limits')
    variant = os.environ['SYMBI_IMAGE_VARIANT']
    lock = unique_json((root/'image/desktop-images.lock.json').read_bytes())
    pins = unique_json((root/'image/base-images.json').read_bytes())
    manifest = require_desktop_image(lock,pins,variant)
    selected = lock['images'][variant]
    evidence = root/'.cache/atomic-image-evidence'
    evidence.mkdir(parents=True,exist_ok=True)
    inputs = root/'.cache/atomic-image-inputs'
    record = {'schema':1,'passed':False,'os_qualified':False,'guest_booted':False,'installation_attempted':False,
              'source_commit':os.environ['GITHUB_SHA'],'image_source_commit':selected['tested_commit'],
              'variant':variant,'phase':phase,'base':manifest['base'],'limits':limits,'commands':[],
              'lock_sha256':digest(root/'image/desktop-images.lock.json'),
              'scope':'Read-only saved development image preflight; no disk, installation, boot or release qualification'}
    target=evidence/(phase+'.json')
    def save(): target.write_text(json.dumps(record,indent=2)+'\n')
    def run(name,command,timeout=60,check=True):
        record['active_command']={'name':name,'command':command};save()
        result=run_bounded(command,evidence/(name+'-stdout.log'),evidence/(name+'-stderr.log'),timeout,1024**2)
        record['commands'].append({'name':name,'exit_code':result.returncode})
        del record['active_command'];save()
        if check: result.check_returncode()
        return result
    podman=None; image_id=manifest['archive']['image_id']; containers=[]; kernel_output=None
    try:
        expected=expected_inputs(root,lock,pins,variant)
        record['expected_inputs']=expected
        if phase=='prepare':
            metadata=unique_json((root/'.cache/atomic-image-artifact.json').read_bytes())
            artifact=selected['artifact']
            if (metadata['id']!=artifact['id'] or metadata['name']!=artifact['name']
                    or metadata['size_in_bytes']!=artifact['bytes'] or metadata['digest']!='sha256:'+artifact['sha256']
                    or metadata['expired'] is not False or metadata['workflow_run']['id']!=selected['run_id']
                    or metadata['workflow_run']['head_sha']!=selected['tested_commit']):
                raise ValueError('Hosted image artifact metadata differs from the reviewed lock')
            record['artifact']=metadata
            if shutil.disk_usage(root/'.cache').free < 20*1024**3:
                raise ValueError('Need at least 20 GiB free after downloading the saved image')
            unpack_desktop_image(root/'.cache/atomic-development-image.zip',lock,pins,variant,inputs)
            (evidence/'image-manifest.json').write_bytes((inputs/'manifest.json').read_bytes())
            # Only this run's verified original ZIP is removed; the verified OCI stays private.
            (root/'.cache/atomic-development-image.zip').unlink()
            record['verified_archive']=manifest['archive']
            record['passed']=True
        else:
            prepared=unique_json((evidence/'prepare.json').read_bytes())
            if (prepared['passed'] is not True or prepared['source_commit']!=record['source_commit']
                    or prepared['variant']!=variant or prepared['expected_inputs']!=expected
                    or prepared['lock_sha256']!=record['lock_sha256'] or inputs.resolve()!=inputs):
                raise ValueError('Exact current image preparation has not passed')
            archive=inputs/manifest['archive']['name']
            if (archive.is_symlink() or not archive.is_file()
                    or archive.stat().st_size!=manifest['archive']['bytes'] or digest(archive)!=manifest['archive']['sha256']):
                raise ValueError('Verified OCI archive changed before loading')
            required={'cpu','memory','pids'}
            if not required.issubset((group/'cgroup.controllers').read_text().split()):
                raise ValueError('Hosted parent lacks delegated resource controllers')
            (group/'cgroup.subtree_control').write_text('+cpu +memory +pids')
            if not required.issubset((group/'cgroup.subtree_control').read_text().split()):
                raise ValueError('Hosted parent did not enable delegated controllers')
            storage=root/'.cache/atomic-image-storage';storage.mkdir(mode=0o700)
            runroot=Path('/run')/group.name.removesuffix('.service')
            if len(os.fsencode(runroot))>50: raise ValueError('Container runtime path too long')
            runroot.mkdir(mode=0o700)
            podman=['podman','--cgroup-manager=cgroupfs','--root',str(storage/'root'),'--runroot',str(runroot)]
            record['disk_free_before_load']=shutil.disk_usage(storage).free
            if record['disk_free_before_load']<20*1024**3: raise ValueError('Need 20 GiB free for private image loading')
            print('Atomic preflight: loading the exact retained OCI image into private storage',flush=True)
            run('load-image',podman+['load','--input',str(archive)],1800)
            rows=unique_json(run('inspect-image',podman+['image','inspect',image_id]).stdout)
            observed=validate_loaded_image(rows,image_id)
            record['loaded_image']={key:observed[key] for key in ('Id','Digest','Architecture','Os')}
            # Preserve the source's root-only permissions. No code runs as root
            # in a container: Podman reads only two paths from a stopped image.
            copy_source='symbi-atomic-kernel-copy';containers.append(copy_source)
            run('create-kernel-copy',podman+['create','--name='+copy_source,'--pull=never',
                '--read-only','--network=none','--user=10001:10001','--cap-drop=ALL',
                '--security-opt=no-new-privileges','--memory=512m','--memory-swap=512m',
                '--cpus=1','--pids-limit=64','--entrypoint=/usr/bin/false',image_id])
            before=unique_json(run('kernel-copy-before',podman+['container','inspect',copy_source]).stdout)
            validate_copy_container(before,image_id)
            kernel_output=storage/'kernel-files';kernel_output.mkdir(mode=0o700)
            for filename in ('vmlinuz','initramfs.img'):
                run('copy-'+filename,podman+['cp','--archive=true',
                    copy_source+':/usr/lib/modules/'+expected['kernel']+'/'+filename,
                    str(kernel_output/filename)],120)
            kernel=read_copied_kernel(kernel_output,expected['kernel'])
            after=unique_json(run('kernel-copy-after',podman+['container','inspect',copy_source]).stdout)
            validate_copy_container(after,image_id)
            record['kernel_copy']={'source_container':copy_source,'never_started':True,'kernel':kernel}
            shutil.rmtree(kernel_output);kernel_output=None
            record['kernel_copy']['private_payload_removed']=True
            qualification=storage/'qualification';qualification.mkdir(mode=0o755)
            (qualification/'kernel.json').write_text(json.dumps(kernel,sort_keys=True)+'\n')
            (qualification/'kernel.json').chmod(0o644)
            record['kernel_copy']['observation_sha256']=digest(qualification/'kernel.json')
            (qualification/'expected.json').write_text(json.dumps(expected)+'\n')
            (qualification/'expected.json').chmod(0o644)
            for source,name in [(root/'image/boot/probe.py','probe.py'),
                                (root/'image/desktop/verify.py','verify.py'),
                                (root/'image/fonts/verify.py','font_verify.py'),
                                (root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])/'preparation.json','preparation.json'),
                                (root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])/'install/installed-after-stdout.log','installed-after-stdout.log')]:
                shutil.copyfile(source,qualification/name);(qualification/name).chmod(0o644)
            record['probe_hashes']={name:digest(qualification/name)
                                    for name in ('probe.py','verify.py','font_verify.py','expected.json')}
            for name,script in [('installed-files','verify.py'),('boot-inputs','probe.py')]:
                container='symbi-atomic-'+name;containers.append(container)
                command=podman+['run','--rm','--name='+container,'--pull=never','--read-only','--network=none',
                    '--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
                    '--memory=512m','--memory-swap=512m','--cpus=1','--pids-limit=64',
                    '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                    '--mount',f'type=bind,src={qualification},dst=/qualification,ro',
                    '--env=PATH=/usr/bin:/bin','--env=LANG=C.UTF-8','--env=PYTHONDONTWRITEBYTECODE=1',
                    '--entrypoint=/usr/bin/python3',image_id,'/qualification/'+script]
                result=unique_json(run(name,command,300).stdout)
                if name=='installed-files':
                    if result.get('passed') is not True or result.get('os_qualified') is not False:
                        raise ValueError('Installed payload re-verification failed')
                    record['installed_files']=result
                else:
                    record['install_requirements']=validate_report(result,expected)
                    if (result['kernel']!=kernel
                            or result.get('kernel_source_sha256')!=record['kernel_copy']['observation_sha256']):
                        raise ValueError('Unprivileged report changed its bound kernel observation')
                    record['boot_inputs']=result
            record['passed']=True
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        if kernel_output is not None: shutil.rmtree(kernel_output)
        if podman is not None:
            record['cleanup']={}
            for name in containers:
                removed=run('cleanup-'+name,podman+['rm','--force','--ignore',name],check=False)
                absent=run('absent-'+name,podman+['container','exists',name],check=False)
                record['cleanup'][name]={'removed':removed.returncode==0,'absent':absent.returncode==1}
                if removed.returncode!=0 or absent.returncode!=1: record['passed']=False
            removed=run('remove-image',podman+['image','rm','--force',image_id],300,check=False)
            absent=run('image-absent',podman+['image','exists',image_id],check=False)
            record['image_removed']=removed.returncode==0 and absent.returncode==1
            if not record['image_removed']: record['passed']=False
        record['cgroup_final']={name:(group/name).read_text().strip() for name in (*limits,'memory.peak','memory.events','cpu.stat')}
        events=dict(line.split() for line in record['cgroup_final']['memory.events'].splitlines())
        if (any(record['cgroup_final'][name]!=value for name,value in limits.items())
                or any(events.get(name)!='0' for name in ('oom','oom_kill','oom_group_kill'))):
            record['passed']=False
        save()
    if not record['passed']: raise RuntimeError('Atomic preflight or cleanup did not pass')


if __name__=='__main__': main()
