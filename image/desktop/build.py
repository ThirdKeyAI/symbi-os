"""Build and retain the real desktop OCI image in a capped disposable runner."""
import json
import os
from pathlib import Path
import re
import shutil

from image.desktop.prepare import inventory
from image.desktop.recipe import review_containerfile
from image.hyprland.inventory import require_subject
from image.launcher.probes.bounded_process import run_bounded
from image.recipe import render
from image.toolchain.bootstrap_cosign import bootstrap
from image.toolchain.reuse import digest, unique_json


def main():
    if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('Use the disposable hosted desktop image build unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if process.name != 'supervisor' or not group.name.startswith('symbi-desktop-build-') or (group/'cgroup.procs').read_text().strip():
        raise ValueError('Unexpected image build parent cgroup')
    limits = {n:(group/n).read_text().strip() for n in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    if limits != {'memory.max':'4294967296', 'memory.swap.max':'0', 'cpu.max':'200000 100000', 'pids.max':'256'}:
        raise ValueError('Unexpected image build parent limits')
    evidence = root/'.cache/desktop-image-evidence'
    prepared = unique_json((evidence/'preparation.json').read_bytes())
    if prepared.get('passed') is not True or prepared['source_commit'] != os.environ['GITHUB_SHA']:
        raise ValueError('Exact desktop preparation has not passed')
    variant = prepared['variant']
    storage = root/'.cache/desktop-image-storage'
    storage.mkdir(mode=0o700)
    install_output = storage/'install-evidence'
    install_output.mkdir()
    outputs = root/'.cache/desktop-image-output'
    outputs.mkdir()
    context = root/'.cache/desktop-image-inputs/context'
    if inventory(context) != prepared['context']: raise ValueError('Prepared build context changed')
    recipe = unique_json((context/'recipe.json').read_bytes())
    pins = unique_json((root/'image/base-images.json').read_bytes())
    render(pins, variant, root)
    base = pins['variants'][variant]
    if base['image'] != prepared['base']: raise ValueError('Prepared base changed')
    review_containerfile((context/'Containerfile').read_text(), recipe, base['image'])
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50: raise ValueError('Container runtime path is too long')
    runroot.mkdir(mode=0o700)
    podman = ['podman','--cgroup-manager=cgroupfs','--root',str(storage/'root'),'--runroot',str(runroot)]
    auth = storage/'auth.json'; auth.write_text('{"auths":{}}\n')
    build_group = group/'image-build'
    build_group.mkdir()
    for name, value in {'memory.max':'2147483648','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'128'}.items():
        (build_group/name).write_text(value)
    (build_group/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    (build_group/'supervisor').mkdir()
    record = {'passed':False, 'image_built':False, 'os_qualified':False, 'source_commit':os.environ['GITHUB_SHA'],
              'variant':variant, 'base':base['image'], 'limits':limits, 'commands':[], 'checks':[], 'containers':{},
              'scope':'Actual desktop OCI assembly and installed-input checks; boot, graphics, TLS, containment and signed-release acceptance remain open'}

    def save(): (evidence/'build.json').write_text(json.dumps(record,indent=2)+'\n')

    def run(name, command, timeout=60, check=True):
        record['active_command']={'name':name,'command':command}; save()
        result=run_bounded(command,evidence/(name+'-stdout.log'),evidence/(name+'-stderr.log'),timeout,1024**2)
        record['commands'].append({'name':name,'exit_code':result.returncode})
        del record['active_command']; save()
        if check: result.check_returncode()
        return result

    try:
        free=shutil.disk_usage(storage).free
        record['disk_free_before_pull']=free
        if free < 18*1024**3: raise ValueError('At least 18 GiB free disk is required for image assembly and export')
        cosign=bootstrap(root,evidence)
        signature=run('base-signature',[str(cosign),'verify','--key',str(root/base['public_key']),'--output','json',base['image']],180)
        require_subject(unique_json(signature.stdout),base['image'])
        record['signature_verified_before_pull']=True
        run('pull-base',podman+['pull','--authfile',str(auth),base['image']],1200)
        run('podman-version',podman+['version','--format=json'])
        preflight_name='symbi-desktop-base-check'
        preflight='set -eu; for x in bash jq curl grep ls bootc python3 dnf5 rpm; do command -v "$x"; done; for x in /usr/bin/Hyprland /usr/bin/hyprctl /usr/bin/elephant /usr/bin/walker /usr/bin/symbi /usr/bin/symbi-sandbox-supervisor /usr/lib/symbi; do test ! -e "$x"; test ! -L "$x"; done'
        try:
            run('base-prerequisites',podman+['run','--rm','--name='+preflight_name,'--pull=never','--read-only','--network=none',
                '--user=10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--memory-swap=128m',
                '--cpus=1','--pids-limit=32','--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                '--entrypoint=/usr/bin/bash',base['image'],'-c',preflight])
        finally:
            remove=run('base-check-cleanup',podman+['rm','--force','--ignore',preflight_name],check=False)
            exists=run('base-check-absent',podman+['container','exists',preflight_name],check=False)
            record['containers'][preflight_name]={'removed':remove.returncode==0,'absent':exists.returncode==1}
            if remove.returncode!=0 or exists.returncode!=1: raise ValueError('Base preflight cleanup failed')
        iid=storage/'image-id'
        command=['/usr/bin/python3','-m','image.desktop.enter_build',*podman,'build','--authfile',str(auth),
                 '--pull=never','--network=none','--isolation=oci','--jobs=1','--layers=false','--force-rm',
                 '--memory=2g','--memory-swap=2g','--cpu-period=100000','--cpu-quota=100000',
                 '--cgroup-parent=/'+str(build_group.relative_to('/sys/fs/cgroup')),
                 '--cap-drop=ALL','--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP',
                 '--security-opt=no-new-privileges','--volume',str(install_output)+':/symbi-build-evidence:rw',
                 '--iidfile',str(iid),'--file',str(context/'Containerfile'),str(context)]
        try:
            run('build-image',command,1800)
        finally:
            record['image_build_cgroup_final']={n:(build_group/n).read_text().strip() for n in (*limits,'memory.peak','memory.events','cpu.stat')}
            (build_group/'cgroup.kill').write_text('1')
        image_id=iid.read_text().strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image_id) or image_id=='sha256:'+'0'*64:
            raise ValueError('Missing exact built image ID')
        record.update(image_built=True,image_id=image_id)
        installed=unique_json((install_output/'result.json').read_bytes())
        if (installed.get('passed') is not True or installed.get('all_base_packages_unchanged') is not True
                or installed.get('base_crypto_configuration_unchanged') is not True):
            raise ValueError('Image package installation did not preserve the base')
        record['installation']=installed
        # Retain a successful assembly before later runtime checks, so a probe
        # correction can reuse the image instead of repeating the build.
        archive=outputs/('symbiont-os-'+variant+'.oci.tar')
        run('save-image',podman+['save','--format=oci-archive','--output',str(archive),image_id],1200)
        run('compress-image',['gzip','--no-name','-1',str(archive)],1200)
        archive=archive.with_suffix('.tar.gz')
        record['image_archive']={'name':archive.name,'bytes':archive.stat().st_size,'sha256':digest(archive),'image_id':image_id}
        (outputs/'manifest.json').write_text(json.dumps({'schema':1,'built':True,'os_qualified':False,
            'source_commit':record['source_commit'],'base':base['image'],'variant':variant,'archive':record['image_archive'],
            'preparation_sha256':digest(evidence/'preparation.json')},indent=2)+'\n')
        qualification=storage/'qualification'
        qualification.mkdir(mode=0o755)
        for source, name in [(evidence/'preparation.json','preparation.json'),
                             (install_output/'installed-after-stdout.log','installed-after-stdout.log'),
                             (root/'image/desktop/verify.py','verify.py'),
                             (root/'image/hyprland/guest_inventory.py','guest_inventory.py'),
                             (root/'image/hyprland/tests/qualify_session_defaults.py','qualify_session_defaults.py')]:
            shutil.copyfile(source,qualification/name); (qualification/name).chmod(0o644)

        def guest(name, executable, arguments, uid='10001:10001', timeout=120):
            container='symbi-desktop-'+name
            home=storage/('home-'+name);home.mkdir(mode=0o700);os.chown(home,10001,10001)
            for folder in ('config','cache','runtime'):
                (home/folder).mkdir(mode=0o700);os.chown(home/folder,10001,10001)
            command=podman+['run','--rm','--name='+container,'--pull=never','--read-only','--network=none','--user='+uid,
                '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=512m','--memory-swap=512m','--cpus=1','--pids-limit=64',
                '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                '--mount',f'type=bind,src={qualification},dst=/qualification,ro',
                '--mount',f'type=bind,src={home},dst=/output','--workdir=/output',
                '--env=HOME=/output','--env=XDG_CONFIG_HOME=/output/config','--env=XDG_CACHE_HOME=/output/cache',
                '--env=XDG_RUNTIME_DIR=/output/runtime','--env=PATH=/usr/bin:/bin','--env=LANG=C.UTF-8',
                '--env=PYTHONDONTWRITEBYTECODE=1','--env=RAYON_NUM_THREADS=1','--env=TOKIO_WORKER_THREADS=1','--env=GOMAXPROCS=1',
                '--entrypoint='+executable,image_id,*arguments]
            try: return run(name,command,timeout,check=False)
            finally:
                removed=run('cleanup-'+name,podman+['rm','--force','--ignore',container],check=False)
                exists=run('absent-'+name,podman+['container','exists',container],check=False)
                record['containers'][container]={'removed':removed.returncode==0,'absent':exists.returncode==1};save()
                if removed.returncode!=0 or exists.returncode!=1: raise ValueError('Installed-image probe cleanup failed')

        result=guest('installed-files','/usr/bin/python3',['/qualification/verify.py'])
        result.check_returncode(); record['installed_files']=unique_json(result.stdout)
        if record['installed_files'].get('passed') is not True: raise ValueError('Installed file verification failed')
        for name in ('Hyprland','hyprctl','elephant','walker','symbi','symbi-sandbox-supervisor'):
            result=guest('ldd-'+name,'/usr/bin/ldd',['/usr/bin/'+name])
            passed=result.returncode==0 and 'not found' not in result.stdout+result.stderr
            record['checks'].append({'name':'ldd-'+name,'passed':passed,'exit_code':result.returncode})
        for name,executable,args,expected in [
                ('symbi-version','/usr/bin/symbi',['--version'],'symbi 3.0.0'),
                ('walker-version','/usr/bin/walker',['--version'],'2.17.2'),
                ('elephant-provider','/usr/bin/elephant',['listproviders'],'desktopapplications')]:
            result=guest(name,executable,args)
            record['checks'].append({'name':name,'passed':result.returncode==0 and result.stdout.strip()==expected,'exit_code':result.returncode})
        result=guest('session-defaults','/usr/bin/python3',['/qualification/qualify_session_defaults.py',
            '--hyprland','/usr/bin/Hyprland','--defaults','/usr/share/symbiont/defaults/hypr',
            '--work-dir','/output/s','--report','/output/session-result.json'])
        report=storage/'home-session-defaults/session-result.json'
        if report.is_file() and not report.is_symlink() and report.stat().st_size<1024**2:
            shutil.copyfile(report,evidence/'session-result.json')
        record['checks'].append({'name':'session-defaults','passed':result.returncode==0 and report.is_file() and unique_json(report.read_bytes()).get('passed') is True,'exit_code':result.returncode})
        result=guest('bootc-lint','/usr/bin/bootc',['container','lint'],uid='0',timeout=300)
        record['checks'].append({'name':'bootc-lint','passed':result.returncode==0,'exit_code':result.returncode})
        save()
        if not all(row['passed'] for row in record['checks']): raise ValueError('Installed desktop image acceptance failed')
        record['passed']=True
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        for path in install_output.iterdir():
            if path.is_file() and not path.is_symlink() and path.suffix in ('.json','.log','.cnf') and path.stat().st_size<=1024**2:
                target=evidence/'install'/path.name;target.parent.mkdir(exist_ok=True);shutil.copyfile(path,target)
        # Only this run's private storage is inspected/cleaned. Force removal
        # also handles Buildah containers, including failed RUN stages.
        try:
            pending=run('remaining-build-containers',podman+['ps','--all','--external','--quiet','--no-trunc'],check=False)
            ids=pending.stdout.splitlines()
            if pending.returncode or any(not re.fullmatch(r'[0-9a-f]{64}',value) for value in ids):
                raise ValueError('Could not inspect private container storage')
            if ids: run('cleanup-build-containers',podman+['rm','--force',*ids])
            final=run('all-containers-absent',podman+['ps','--all','--external','--quiet'],check=False)
            record['all_containers_absent']=final.returncode==0 and not final.stdout.strip()
            if not record['all_containers_absent']: record['passed']=False
        finally:
            record['cgroup_final']={n:(group/n).read_text().strip() for n in (*limits,'memory.peak','memory.events','cpu.stat')}
            save()
        if not record.get('all_containers_absent'): raise ValueError('Private image build containers remain')


if __name__ == '__main__': main()
