"""Check retained development runtime loading on the authenticated Fedora base."""
import json
import os
from pathlib import Path
import re
import shutil

from image.assembly.inputs import require_runtime, unpack_runtime
from image.assembly.runtime_install import require_runtime_rpms
from image.hyprland.build_inputs import unpack_rpms
from image.hyprland.inventory import require_subject
from image.launcher.probes.bounded_process import run_bounded
from image.recipe import render
from image.toolchain.bootstrap_cosign import bootstrap
from image.toolchain.reuse import unique_json

GUEST_METADATA = '''import json, os
from pathlib import Path
p = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
s = dict(row.split(':',1) for row in Path('/proc/self/status').read_text().splitlines() if ':' in row)
print(json.dumps({'uid': os.geteuid(), 'kernel': os.uname().release,
 'limits': {n:(p/n).read_text().strip() for n in ('memory.max','memory.swap.max','cpu.max','pids.max')},
 'cap_effective': s['CapEff'].strip(), 'no_new_privileges': s['NoNewPrivs'].strip(),
 'root_readonly': bool(os.statvfs('/').f_flag & os.ST_RDONLY),
 'network_devices': sorted(x.name for x in Path('/sys/class/net').iterdir())}))
'''


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Use the disposable hosted runtime compatibility unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if (process.name != 'supervisor' or not group.name.startswith('symbi-runtime-reuse-')
            or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected hosted supervisor cgroup')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '4294967296', 'memory.swap.max': '0',
                  'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected hosted runtime-reuse limits')
    evidence = root/'.cache/assembly-input-evidence/runtime'
    evidence.mkdir(parents=True)
    storage = root/'.cache/assembly-runtime-reuse'
    storage.mkdir(mode=0o700)
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50:
        raise ValueError('Container runtime path exceeds the checked bound')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'source_commit': os.environ['GITHUB_SHA'],
              'limits': limits, 'commands': [], 'checks': [], 'containers': {},
              'scope': 'Offline additive compatibility library and actual retained runtime CLI; no product installation, containment or OS qualification'}
    install_output = storage/'install-output'

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60, check=True):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        if check:
            result.check_returncode()
        return result

    try:
        lock = unique_json((root/'image/assembly/runtime-development.lock.json').read_bytes())
        source_pin, build_result = root/'upstream/symbiont.toml', root/'image/assembly/runtime-build-result.json'
        source = require_runtime(lock, source_pin, build_result)
        unpack_runtime(root/'.cache/symbiont-runtime.zip', lock, source_pin, build_result, storage/'binaries')
        record.update(artifact=lock['artifact'], binaries=lock['binaries'], upstream_revision=source['revision'],
                      original_build_run=lock['validation_run'], original_build_checked_merge=lock['validation_checked_merge'])
        pins = unique_json((root/'image/base-images.json').read_bytes())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        cosign = bootstrap(root, evidence)
        signature = run('base-signature', [str(cosign), 'verify', '--key', str(root/base['public_key']),
                                          '--output', 'json', base['image']], 180)
        require_subject(unique_json(signature.stdout), base['image'])
        record.update(base=base['image'], signature_verified_before_pull=True)
        rpm_lock = unique_json((root/'image/assembly/runtime-rpms.lock.json').read_bytes())
        requirements = unique_json((root/'image/runtime_packages/requirements.json').read_bytes())
        trust = unique_json((root/'image/hyprland/fedora-package-trust.json').read_bytes())
        require_runtime_rpms(rpm_lock, base['image'], requirements, trust)
        install_inputs = storage/'install-inputs'
        install_inputs.mkdir()
        unpack_rpms(root/'.cache/symbiont-runtime-rpms.zip', rpm_lock, install_inputs/'packages')
        files = {'runtime-rpms.lock.json': 'image/assembly/runtime-rpms.lock.json',
                 'runtime_install.py': 'image/assembly/runtime_install.py',
                 'requirements.json': 'image/runtime_packages/requirements.json',
                 'fedora-package-trust.json': 'image/hyprland/fedora-package-trust.json',
                 'fedora-45-primary.asc': trust['key']['path'],
                 'guest_inventory.py': 'image/hyprland/guest_inventory.py',
                 'resolve_packages.py': 'image/hyprland/resolve_packages.py',
                 'package_identity.py': 'image/walker/inputs.py',
                 'bounded_process.py': 'image/launcher/probes/bounded_process.py'}
        for name, relative in files.items():shutil.copyfile(root/relative, install_inputs/name)
        install_output.mkdir()
        record['compatibility_rpm_artifact'] = rpm_lock['artifact']
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull-base', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        install_container = 'symbi-runtime-offline-install'
        install_command = podman+['run', '--name='+install_container, '--pull=never', '--network=none', '--user=0',
                                 '--cap-drop=ALL', '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP',
                                 '--security-opt=no-new-privileges', '--memory=2g', '--memory-swap=2g', '--cpus=1',
                                 '--pids-limit=128', '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                                 '--mount', f'type=bind,src={install_inputs},dst=/inputs,ro',
                                 '--mount', f'type=bind,src={install_output},dst=/output',
                                 '--env=GITHUB_ACTIONS=true', '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8',
                                 '--entrypoint=/usr/bin/python3', base['image'], '/inputs/runtime_install.py']
        try:
            run('offline-install', install_command, 600)
            installed = unique_json((install_output/'install-evidence/result.json').read_bytes())
            if (installed.get('passed') is not True or installed.get('os_qualified') is not False
                    or installed.get('all_base_packages_unchanged') is not True
                    or installed.get('base_crypto_configuration_unchanged') is not True):
                raise ValueError('Offline compatibility installation failed its additive checks')
            committed = run('commit-compatibility-image', podman+['commit', install_container], 300)
            match = re.fullmatch(r'(?:sha256:)?([a-f0-9]{64})', committed.stdout.strip())
            if not match or match[1] == '0'*64:raise ValueError('Invalid committed compatibility image ID')
            runtime_image = 'sha256:'+match[1]
            record['runtime_stage_image_id'] = runtime_image
            record['installation'] = installed
        finally:
            removed = run('install-cleanup', podman+['rm', '--force', '--ignore', install_container], check=False)
            exists = run('install-exists', podman+['container', 'exists', install_container], check=False)
            record['containers'][install_container] = {'removed': removed.returncode == 0, 'absent': exists.returncode == 1}
            if removed.returncode != 0 or exists.returncode != 1:
                raise RuntimeError('Offline installation container cleanup failed')

        def guest(name, executable, arguments):
            container = 'symbi-runtime-'+name
            home = storage/name
            home.mkdir(mode=0o700)
            os.chown(home, 10001, 10001)
            command = podman+['run', '--rm', '--name='+container, '--pull=never', '--read-only', '--network=none',
                             '--user=10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                             '--memory=512m', '--memory-swap=512m', '--cpus=1', '--pids-limit=64',
                             '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                             '--mount', f'type=bind,src={storage / "binaries"},dst=/inputs,ro',
                             '--mount', f'type=bind,src={home},dst=/output', '--workdir=/output',
                             '--env=HOME=/output', '--env=PATH=/usr/bin:/bin', '--env=LANG=C.UTF-8',
                             '--env=PYTHONDONTWRITEBYTECODE=1', '--env=TOKIO_WORKER_THREADS=1',
                             '--env=RAYON_NUM_THREADS=1', '--entrypoint='+executable, runtime_image, *arguments]
            try:
                return run(name, command, check=False)
            finally:
                removed = run('cleanup-'+name, podman+['rm', '--force', '--ignore', container], check=False)
                exists = run('exists-'+name, podman+['container', 'exists', container], check=False)
                record['containers'][container] = {'removed': removed.returncode == 0, 'absent': exists.returncode == 1}
                save()
                if removed.returncode != 0 or exists.returncode != 1:
                    raise RuntimeError('Runtime compatibility container cleanup failed: '+name)

        metadata_process = guest('metadata', '/usr/bin/python3', ['-c', GUEST_METADATA])
        metadata_process.check_returncode()
        metadata = unique_json(metadata_process.stdout)
        if (metadata.get('uid') != 10001 or metadata.get('root_readonly') is not True
                or metadata.get('cap_effective') != '0000000000000000' or metadata.get('no_new_privileges') != '1'
                or metadata.get('network_devices') != ['lo'] or metadata.get('limits') != {
                    'memory.max': '536870912', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '64'}):
            raise ValueError('Unexpected runtime guest isolation or limits')
        record['guest_metadata'] = metadata
        guest('openssl-packages', '/usr/bin/rpm', ['-q', 'openssl', 'openssl-libs', 'openssl3-libs']).check_returncode()
        for name in lock['binaries']:
            result = guest('ldd-'+name, '/usr/bin/ldd', ['/inputs/'+name])
            passed = result.returncode == 0 and 'not found' not in result.stdout+result.stderr
            record['checks'].append({'name': 'ldd-'+name, 'exit_code': result.returncode, 'passed': passed})
        for name, argument in (('version', '--version'), ('help', '--help'),
                               ('unknown-option', '--symbi-unknown-qualification-option'), ('repeated-version', '--version')):
            result = guest(name, '/inputs/symbi', [argument])
            if argument == '--version':
                passed = result.returncode == 0 and result.stdout.strip() == 'symbi '+source['version'] and not result.stderr.strip()
            elif argument == '--help':
                passed = result.returncode == 0 and all(value in result.stdout for value in ('Usage:', 'symbi', 'doctor', '--version'))
            else:
                passed = result.returncode == 2 and 'unexpected argument' in result.stderr and argument in result.stderr
            record['checks'].append({'name': name, 'argument': argument, 'exit_code': result.returncode, 'passed': passed})
            save()
        if not all(row['passed'] for row in record['checks']):
            raise ValueError('Retained runtime is not compatible with the original base plus signed compatibility library')
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        retained = install_output/'install-evidence'
        if retained.is_dir():
            paths = list(retained.rglob('*'))
            if (len(paths) > 256 or any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths)
                    or sum(path.stat().st_size for path in paths if path.is_file()) > 16*1024**2):
                raise ValueError('Unexpected offline installation evidence')
            shutil.copytree(retained, evidence/'install')
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
