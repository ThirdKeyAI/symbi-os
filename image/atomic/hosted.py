"""Install and boot an exact retained image, exclusively on disposable hosted CI."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import re

from image.atomic.contract import (create_disk,require_disk,sha256,unique_json,
                                   unpack_oci,validate_report,installer_mounts,
                                   directory_source,installer_policy)
from image.boot.inputs import require_desktop_image
from image.boot.preflight import expected_inputs,validate_loaded_image,validate_report as validate_preflight
from image.launcher.probes.bounded_process import run_bounded
from image.qualification.hosted_process import (TIMEOUT_SECONDS as LANDLOCK_TIMEOUT_SECONDS,
                                                run_landlock_controller)


LANDLOCK_PARENT_LIMITS = {'memory.high':'4294967296','memory.max':'5368709120',
                          'memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'256'}
DEFAULT_PARENT_LIMITS = {'memory.high':'max','memory.max':'4294967296',
                         'memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'256'}


def run_hosted_command(qualification,name,command,stdout_path,stderr_path,timeout,
                       expected_cgroup_parent=None,expected_image=None):
    """Select the one command allowed beyond the shared process deadline."""
    if name=='landlock-qualification':
        if qualification!='landlock' or timeout!=LANDLOCK_TIMEOUT_SECONDS:
            raise ValueError('Invalid hosted Landlock controller deadline')
        return run_landlock_controller(command,stdout_path,stderr_path,
                                       expected_cgroup_parent,expected_image)
    return run_bounded(command,stdout_path,stderr_path,timeout,1024**2)


def main():
    qualification=os.environ.get('SYMBI_QUALIFICATION','')
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'
            or os.environ.get('SYMBI_IMAGE_VARIANT')!='generic' or qualification not in ('','landlock','update','containers')
            or os.geteuid()!=0):
        raise SystemExit('Use the disposable hosted generic Atomic install/boot unit')
    root=Path.cwd().resolve()
    process=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    group=process.parent
    unit_prefix={'landlock':'symbi-landlock-','containers':'symbi-container-'}.get(
        qualification,'symbi-atomic-disk-')
    if (process.name!='supervisor' or not group.name.startswith(unit_prefix)
            or not group.name.endswith('.service') or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected delegated installer controller')
    limits={n:(group/n).read_text().strip() for n in
            ('memory.high','memory.max','memory.swap.max','cpu.max','pids.max')}
    expected_limits=LANDLOCK_PARENT_LIMITS if qualification=='landlock' else DEFAULT_PARENT_LIMITS
    if limits!=expected_limits:
        raise ValueError('Hosted Atomic resource limits changed')
    required={'cpu','memory','pids'}
    if not required.issubset((group/'cgroup.controllers').read_text().split()): raise ValueError('Missing delegation')
    (group/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    if not required.issubset((group/'cgroup.subtree_control').read_text().split()): raise ValueError('Delegation failed')
    evidence=root/'.cache/atomic-disk-evidence';evidence.mkdir(parents=True,exist_ok=True)
    lock=unique_json((root/'image/desktop-images.lock.json').read_bytes())
    pins=unique_json((root/'image/base-images.json').read_bytes())
    manifest=require_desktop_image(lock,pins,'generic');selected=lock['images']['generic']
    expected=expected_inputs(root,lock,pins,'generic')
    record={'schema':1,'passed':False,'installation_attempted':False,'guest_booted':False,
            'os_qualified':False,'release_qualified':False,'source_commit':os.environ['GITHUB_SHA'],
            'image_source_commit':selected['tested_commit'],'image_id':manifest['archive']['image_id'],
            'limits':limits,'commands':[],'qualification':qualification or None,
            'scope':'Offline development artifact authenticated with an ephemeral CI fixture key; no product/release qualification'}
    def save(): (evidence/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    def run(name,command,timeout=60,check=True):
        record['active_command']={'name':name,'command':command};save()
        result=run_hosted_command(qualification,name,command,evidence/(name+'-stdout.log'),
                                  evidence/(name+'-stderr.log'),timeout,
                                  '/'+str(group.relative_to('/sys/fs/cgroup')),
                                  record['image_id'])
        record['commands'].append({'name':name,'exit_code':result.returncode});del record['active_command'];save()
        if check: result.check_returncode()
        return result
    podman=None;containers=[];storage=None;disk=None;identity=None;boot_output=None;runroot=None;disk_readonly=False;signing_output=None
    try:
        readiness=unique_json((root/'image/atomic/preflight.lock.json').read_bytes())
        if readiness['schema']!=1 or readiness['variant']!='generic' or type(readiness['preflight_run']) is not int:
            raise ValueError('Unknown preflight readiness binding')
        previous=root/'docs/security/reports/P0-03-atomic-preflight'/str(readiness['preflight_run'])
        if previous.resolve()!=previous: raise ValueError('Linked preflight evidence')
        reports={}
        for phase in ('inspect','prepare'):
            path=previous/(phase+'.json')
            if sha256(path)!=readiness[phase+'_sha256']: raise ValueError('Preflight evidence bytes changed')
            item=unique_json(path.read_bytes());reports[phase]=item
            if (item['passed'] is not True or item['source_commit']!=readiness['source_commit']
                    or item['image_source_commit']!=selected['tested_commit'] or item['variant']!='generic'
                    or item['expected_inputs']!=expected or item['guest_booted'] is not False
                    or item['os_qualified'] is not False or item['installation_attempted'] is not False
                    or item['lock_sha256']!=sha256(root/'image/desktop-images.lock.json')):
                raise ValueError('Exact saved-image preflight has not passed')
        validate_preflight(reports['inspect']['boot_inputs'],expected)
        if (reports['inspect']['loaded_image']['Digest']!=readiness['manifest_digest']
                or reports['prepare']['verified_archive']!=manifest['archive']):
            raise ValueError('Preflight describes a different OCI image')
        record['preflight']=readiness
        # The existing bounded prepare phase verifies the current GitHub artifact
        # metadata and streams its complete ZIP/manifest/OCI hashes again.
        prepared=unique_json((root/'.cache/atomic-image-evidence/prepare.json').read_bytes())
        if (prepared['passed'] is not True or prepared['source_commit']!=record['source_commit']
                or prepared['expected_inputs']!=expected or prepared['variant']!='generic'
                or prepared['lock_sha256']!=sha256(root/'image/desktop-images.lock.json')):
            raise ValueError('Current hosted image intake has not passed')
        if qualification=='containers':
            from image.qualification.container_hosted import run_container_preflight
            record['container_preflight']=run_container_preflight(
                root,record['source_commit'],record['image_source_commit'])
            save()
            blockers=record['container_preflight']['blockers']
            raise ValueError('Fedora container qualification remains fail closed: '+','.join(blockers))
        archive=root/'.cache/atomic-image-inputs'/manifest['archive']['name']
        if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size!=manifest['archive']['bytes']
                or sha256(archive)!=manifest['archive']['sha256']):
            raise ValueError('Verified development archive changed')
        storage=root/'.cache/atomic-disk-storage';storage.mkdir(mode=0o700)
        record['disk_free_before_load']=shutil.disk_usage(storage).free
        if record['disk_free_before_load']<60*1024**3: raise ValueError('Need 60 GiB free for isolated install and boot')
        runroot=Path('/run')/group.name.removesuffix('.service');runroot.mkdir(mode=0o700)
        if len(os.fsencode(runroot))>50: raise ValueError('Runtime path is too long')
        podman=['podman','--cgroup-manager=cgroupfs','--root',str(storage/'root'),'--runroot',str(runroot)]
        image_id=record['image_id']
        print('Atomic install: loading the exact saved image into private CI storage',flush=True)
        run('load-image',podman+['load','--input',str(archive)],1800)
        loaded=validate_loaded_image(unique_json(run('inspect-image',podman+['image','inspect',image_id]).stdout),image_id)
        if loaded['Digest']!=readiness['manifest_digest']: raise ValueError('Loaded OCI manifest changed')
        record['loaded_image']={k:loaded[k] for k in ('Id','Digest','Architecture','Os')}
        print('Atomic install: verifying opaque OCI layout blobs',flush=True)
        record['oci']=unpack_oci(archive,storage/'oci',readiness['manifest_digest'],image_id)
        record['directory_source']=directory_source(storage/'oci',storage/'signed',readiness['manifest_digest'])
        signer_input=storage/'signer-input';signer_input.mkdir(mode=0o755)
        for name in ('sign.py','contract.py'):
            shutil.copyfile(root/'image/atomic'/name,signer_input/name);(signer_input/name).chmod(0o644)
        shutil.copyfile(root/'image/launcher/probes/bounded_process.py',signer_input/'bounded_process.py')
        shutil.copyfile(storage/'signed/manifest.json',signer_input/'manifest.json')
        (signer_input/'sign.json').write_text(json.dumps({'manifest_digest':readiness['manifest_digest']})+'\n')
        signing_output=storage/'signer-output';signing_output.mkdir(mode=0o700);os.chown(signing_output,10001,10001)
        container='symbi-atomic-signer';containers.append(container)
        common=['--pull=never','--network=none','--pid=private',
                '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                '--env=LANG=C.UTF-8','--env=PYTHONDONTWRITEBYTECODE=1']
        print('Atomic install: authenticating a local source with an ephemeral offline CI test key',flush=True)
        run('sign-source',podman+['run','--rm','--name='+container,*common,'--read-only','--user=10001:10001',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=1g','--memory-swap=1g','--cpus=1','--pids-limit=64',
            '--mount',f'type=bind,src={signer_input},dst=/inputs,ro',
            '--mount',f'type=bind,src={signing_output},dst=/output',
            '--env=HOME=/output','--entrypoint=/usr/bin/python3',image_id,'/inputs/sign.py'],480)
        signed=unique_json((signing_output/'evidence/result.json').read_bytes())
        if (signed.get('passed') is not True or signed.get('release_qualified') is not False
                or signed.get('source_manifest_digest')!=readiness['manifest_digest']
                or signed.get('private_keys_removed') is not True or signed.get('positive_policy_control') is not True
                or signed.get('negative_controls')!={case:True for case in ('unsigned','wrong-key','wrong-reference','altered-signature')}
                or sha256(signing_output/'good-public.asc')!=signed.get('public_key_sha256')
                or sha256(signing_output/'signature-1')!=signed.get('signature_sha256')):
            raise ValueError('Ephemeral source authentication acceptance incomplete')
        shutil.copyfile(signing_output/'signature-1',storage/'signed/signature-1')
        record['source_authentication']=signed
        from image.signing import render as render_trust
        policy=render_trust(unique_json((root/'image/release-trust.json').read_bytes()),pins,root)['policy']
        policy_bytes=(json.dumps(policy,indent=2)+'\n').encode()
        if hashlib.sha256(policy_bytes).hexdigest()!=expected['trust']['etc/containers/policy.json']:
            raise ValueError('The immutable release policy binding changed')
        local_policy=installer_policy(policy,(signing_output/'good-public.asc').read_bytes(),readiness['manifest_digest'])
        if qualification=='update':
            from image.atomic.update_hosted import run_update
            print('Atomic update: installing the exact predecessor for a signed switch and booted rollback',flush=True)
            record['update']=run_update(root,group,podman,image_id,storage,containers,run,pins,
                                        lock,readiness['manifest_digest'],storage/'signed',
                                        signing_output,signed,policy,policy_bytes)
            record['guest_booted']=record['update']['guest_booted'] is True
            record['update_qualified']=record['update']['passed'] is True
            record['passed']=record['guest_booted'] and record['update_qualified']
            return
        disk_dir=storage/'disk';disk_dir.mkdir(mode=0o700)
        identity=create_disk(disk_dir,24*1024**3);disk=disk_dir/'atomic.raw'
        record['disk']=identity
        installer_input=storage/'installer-input';installer_input.mkdir(mode=0o700)
        (installer_input/'signed').mkdir(mode=0o700)
        for name in ('install.py','contract.py'):
            shutil.copyfile(root/'image/atomic'/name,installer_input/name)
        (installer_input/'original-policy.json').write_bytes(policy_bytes)
        shutil.copyfile(signing_output/'good-public.asc',installer_input/'test-public.asc')
        (installer_input/'install-policy.json').write_text(json.dumps(local_policy,indent=2)+'\n')
        (installer_input/'install.json').write_text(json.dumps({'disk':identity,'manifest_digest':readiness['manifest_digest'],
            'original_policy_sha256':expected['trust']['etc/containers/policy.json'],
            'installer_policy_sha256':sha256(installer_input/'install-policy.json'),
            'test_public_key_sha256':signed['public_key_sha256'],'signature_sha256':signed['signature_sha256']})+'\n')
        temporary=storage/'installer-tmp';temporary.mkdir(mode=0o700)
        if not Path('/run/udev').is_dir(): raise ValueError('Hosted udev state is unavailable')
        container='symbi-atomic-installer';containers.append(container)
        command=podman+['run','--rm','--name='+container,*common,'--privileged',
                       '--memory=2g','--memory-swap=2g','--cpus=1','--pids-limit=128',
                       *installer_mounts(storage),
                       '--entrypoint=/usr/bin/python3',image_id,'/inputs/install.py']
        require_disk(disk,identity);record['installation_attempted']=True;save()
        print('Atomic install: bootc is writing only the new private 24 GiB regular file',flush=True)
        run('install',command,2400)
        require_disk(disk,identity)
        loops=unique_json(run('disk-loops-after-install',['losetup','--json','--list','--output','NAME,BACK-FILE','--associated',str(disk)]).stdout)
        if loops.get('loopdevices') not in (None,[]): raise ValueError('Installer left attached loop devices')
        record['installation_completed']=True;record['disk_sha256']=sha256(disk);save()
        expected['manifest_digest']=readiness['manifest_digest']
        payload=unique_json((root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])/'preparation.json').read_bytes())
        expected['payload']={**payload['payload'],**payload['overlay']}
        expected['payload_count']=len(expected['payload'])
        inventory=(root/'docs/security/reports/P0-03-desktop'/str(selected['run_id'])/'install/installed-after-stdout.log').read_text().splitlines()
        if len(set(inventory))!=len(inventory): raise ValueError('Duplicate retained package identity')
        expected['inventory_count']=len(inventory)
        expected['inventory_sha256']=hashlib.sha256(('\n'.join(sorted(inventory))+'\n').encode()).hexdigest()
        expected['nonce']=secrets.token_hex(16)
        boot_input=storage/'boot-input';boot_input.mkdir(mode=0o755)
        for name in ('boot.py','contract.py','guest.py','o.service','s.service'):
            shutil.copyfile(root/'image/atomic'/name,boot_input/name);(boot_input/name).chmod(0o644)
        (boot_input/'atomic.raw').touch(mode=0o644)
        raw=(json.dumps(expected,sort_keys=True)+'\n').encode()
        if len(raw)>128*1024: raise ValueError('Boot observation input is too large')
        (boot_input/'expected.json').write_bytes(raw);(boot_input/'expected.json').chmod(0o644)
        boot_output=storage/'boot-output';boot_output.mkdir(mode=0o700)
        os.chown(boot_output,10001,10001)
        # The source disk becomes read-only; QEMU writes only a new qcow2 overlay.
        os.chmod(disk,0o444,follow_symlinks=False);disk_readonly=True
        container='symbi-atomic-qemu';containers.append(container)
        command=podman+['run','--rm','--name='+container,*common,'--read-only','--user=10001:10001',
                       '--cap-drop=ALL','--security-opt=no-new-privileges',
                       '--memory=3g','--memory-swap=3g','--cpus=2','--pids-limit=64',
                       '--mount',f'type=bind,src={boot_input},dst=/inputs,ro',
                       '--mount',f'type=bind,src={disk},dst=/inputs/atomic.raw,ro',
                       '--mount',f'type=bind,src={boot_output},dst=/output',
                       '--entrypoint=/usr/bin/python3',image_id,'/inputs/boot.py']
        record['boot_inputs']={name:sha256(boot_input/name) for name in ('boot.py','contract.py','guest.py','o.service','s.service','expected.json')}
        print('Atomic boot: starting the offline VM under unprivileged QEMU/TCG',flush=True)
        run('boot',command,960)
        result=unique_json((boot_output/'result.json').read_bytes())
        report=unique_json((boot_output/'report.json').read_bytes())
        validate_report(report,expected,expected['nonce'],record['boot_inputs']['guest.py'],record['boot_inputs']['expected.json'])
        if result['passed'] is not True or result['guest_booted'] is not True:
            raise ValueError('Hosted QEMU observation did not pass')
        if sha256(disk)!=record['disk_sha256']: raise ValueError('Read-only source disk changed during boot')
        record['guest_booted']=True;record['boot_id']=report['boot_id']
        if qualification=='landlock':
            from image.qualification.hosted import run_landlock
            print('Landlock qualification: starting the second offline installed-image boot',flush=True)
            record['landlock']=run_landlock(root,group,podman,image_id,disk,storage,containers,
                                            run,expected,record)
            record['landlock_qualified']=record['landlock']['qualified'] is True
        record['passed']=True
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        record['cleanup']={}
        if podman is not None:
            for name in containers:
                removed=run('cleanup-'+name,podman+['rm','--force','--ignore',name],check=False)
                absent=run('absent-'+name,podman+['container','exists',name],check=False)
                record['cleanup'][name]={'removed':removed.returncode==0,'absent':absent.returncode==1}
                if removed.returncode!=0 or absent.returncode!=1: record['passed']=False
        if boot_output is not None:
            for name in ('result.json','report.json','prepare.log','serial.log','qemu.log'):
                path=boot_output/name
                if path.is_file() and not path.is_symlink() and path.stat().st_size<=2*1024**2:
                    shutil.copyfile(path,evidence/('guest-'+name))
        if signing_output is not None:
            # Only public evidence is retained. The generated private keyring is
            # deleted inside the stopped signer and is never an upload input.
            if (signing_output/'evidence').is_dir():
                shutil.copytree(signing_output/'evidence',evidence/'source-authentication')
            for name in ('good-public.asc','signature-1'):
                path=signing_output/name
                if path.is_file() and not path.is_symlink() and path.stat().st_size<=65536:
                    shutil.copyfile(path,evidence/('source-'+name))
        stopped=all(v['removed'] and v['absent'] for v in record['cleanup'].values())
        if disk is not None and stopped:
            # Cleanup may detach only devices still associated with this exact new
            # file, after every installer/VM container has stopped. Never use -D.
            require_disk(disk,identity,readonly=disk_readonly)
            result=run('disk-loops-cleanup',['losetup','--json','--list','--output','NAME,BACK-FILE','--associated',str(disk)],check=False)
            if result.returncode!=0: record['passed']=False
            else:
                rows=unique_json(result.stdout).get('loopdevices') or []
                for index,row in enumerate(rows):
                    if row.get('back-file')!=str(disk) or not re.fullmatch(r'/dev/loop[0-9]+',row.get('name','')):
                        raise ValueError('Unexpected loop device in targeted cleanup')
                    run('detach-owned-loop-'+str(index),['losetup','--detach',row['name']])
                check=unique_json(run('disk-loops-absent',['losetup','--json','--list','--output','NAME,BACK-FILE','--associated',str(disk)]).stdout)
                record['loops_absent']=not check.get('loopdevices')
                if not record['loops_absent']: record['passed']=False
        if podman is not None:
            removed=run('remove-image',podman+['image','rm','--force',record['image_id']],300,check=False)
            absent=run('image-absent',podman+['image','exists',record['image_id']],check=False)
            record['image_removed']=removed.returncode==0 and absent.returncode==1
            if not record['image_removed']: record['passed']=False
        # Large private artifacts are never uploaded; only the bounded evidence is.
        if storage is not None and stopped:
            if disk is None or record.get('loops_absent'):
                shutil.rmtree(storage);record['private_storage_removed']=not storage.exists()
                if runroot is not None:
                    shutil.rmtree(runroot);record['private_runroot_removed']=not runroot.exists()
        record['cgroup_final']={n:(group/n).read_text().strip() for n in (*limits,'memory.peak','memory.events','cpu.stat')}
        events=dict(line.split() for line in record['cgroup_final']['memory.events'].splitlines())
        if (any(record['cgroup_final'][n]!=v for n,v in limits.items())
                or any(events.get(n)!='0' for n in ('oom','oom_kill','oom_group_kill'))): record['passed']=False
        save()
    if not record['passed']: raise RuntimeError('Atomic install/boot or cleanup did not pass')


if __name__=='__main__': main()
