#!/usr/bin/env python3
"""Source-build Walker and test its CLI on a separate original-base stage."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from inputs import digest, require_source

sys.path.insert(0, str(Path(__file__).parents[1]/'launcher/probes'))
try:
    from bounded_process import run_bounded
finally:
    sys.path.pop(0)


def retain_directory(source, destination):
    """Copy bounded regular evidence without following guest-created links."""
    if not source.exists():
        return
    if source.is_symlink() or not source.is_dir() or destination.exists():
        raise ValueError('Unexpected evidence directory')
    files, total = [], 0
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError('Linked guest evidence is forbidden')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_size > 2*1024**2:
            raise ValueError('Invalid or oversized guest evidence')
        total += path.stat().st_size
        files.append(path)
    if len(files) > 512 or total > 8*1024**2:
        raise ValueError('Guest evidence exceeds its bound')
    destination.mkdir()
    for path in files:
        target = destination/path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def capture_image_id(command, evidence, name):
    result = run_bounded(command, evidence/(name+'.log'), evidence/(name+'-stderr.log'),
                         timeout=300, max_bytes=1024**2)
    result.check_returncode()
    match = re.fullmatch(r'(?:sha256:)?([0-9a-f]{64})', result.stdout.strip())
    if not match:
        raise ValueError('Unexpected committed image identity')
    return 'sha256:'+match[1]


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Walker builds require the disposable hosted resource unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if process.name != 'supervisor' or not group.name.startswith('symbi-walker-') or (group/'cgroup.procs').read_text().strip():
        raise ValueError('Unexpected hosted supervisor cgroup')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '4294967296', 'memory.swap.max': '0',
                  'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected hosted resource limits')
    evidence = root/'.cache/walker-build-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    storage = root/'.cache/walker-build-storage'
    storage.mkdir(mode=0o700)
    inputs, build, runtime, cli = (storage/name for name in ('inputs', 'build', 'runtime', 'cli'))
    for path in (inputs, build, runtime, cli):
        path.mkdir(mode=0o755)
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50:
        raise ValueError('Container runtime path exceeds its bound')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'gui_qualified': False,
              'upstream_tests_passed': False, 'source_commit': os.environ['GITHUB_SHA'],
              'limits': limits, 'commands': [], 'containers': {},
              'scope': 'Exact Walker source build, upstream tests and original-base CLI compatibility only'}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=300, check=True):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence/(name+'.log')).open('xb') as log:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        if check:
            result.check_returncode()
        return result

    def container(name, image, output, arguments, flags, timeout, commit=False, check=True):
        identifier = 'symbi-walker-'+name
        command = podman+['run', '--name='+identifier, '--pull=never', '--security-opt=no-new-privileges',
                          '--cap-drop=ALL', '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                          '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                          '--mount', f'type=bind,src={output},dst=/output', '--env=PYTHONDONTWRITEBYTECODE=1',
                          '--env=GITHUB_ACTIONS=true', '--entrypoint=/usr/bin/python3', *flags, image, *arguments]
        image_id = None
        try:
            completed = run(name, command, timeout, check=False)
            if completed.returncode == 0 and commit:
                commit_command = podman+['commit', identifier]
                record['active_command'] = {'name': name+'-commit', 'command': commit_command}
                save()
                image_id = capture_image_id(commit_command, evidence, name+'-commit')
                record['commands'].append({'name': name+'-commit', 'exit_code': 0})
                del record['active_command']
                save()
            if check:
                completed.check_returncode()
            return completed, image_id
        finally:
            removed = run(name+'-cleanup', podman+['rm', '--force', '--ignore', identifier], 30, check=False)
            exists = run(name+'-exists', podman+['container', 'exists', identifier], 30, check=False)
            record['containers'][name] = {'remove_exit': removed.returncode, 'exists_exit': exists.returncode,
                                          'absent': removed.returncode == 0 and exists.returncode == 1}
            save()
            if not record['containers'][name]['absent']:
                raise RuntimeError('Failed to remove and verify the disposable container: '+name)

    try:
        sys.path.insert(0, str(root/'image/toolchain'))
        from bootstrap_cosign import bootstrap
        sys.path.insert(0, str(root/'image'))
        from recipe import render
        sys.path.insert(0, str(root/'image/hyprland'))
        from inventory import require_subject
        from build_inputs import unpack_rpms, require_current_requirements
        pins = json.loads((root/'image/base-images.json').read_text())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        cosign = bootstrap(root, evidence)
        signature = subprocess.check_output([str(cosign), 'verify', '--key', str(root/base['public_key']),
                                             '--output', 'json', base['image']], text=True, timeout=180)
        require_subject(json.loads(signature), base['image'])
        (evidence/'base-signature.json').write_text(signature)
        record['base'] = base['image']
        for mode, lock_name, requirement in (('build', 'walker-build-rpms.lock.json', 'walker-build-requirements.json'),
                                             ('runtime', 'runtime-rpms.lock.json', 'runtime-requirements.json')):
            lock = json.loads((root/'image/launcher'/lock_name).read_text())
            require_current_requirements(lock, json.loads((root/'image/launcher'/requirement).read_text()))
            if lock['base'] != base['image']:
                raise ValueError('RPM inputs target a different base')
            unpack_rpms(root/f'.cache/walker-{mode}-rpms.zip', lock, inputs/(mode+'-rpms'))
            shutil.copyfile(root/'image/launcher'/lock_name, inputs/lock_name)
            key = root/lock['key']['path']
            if digest(key) != lock['key']['sha256']:
                raise ValueError('Fedora verification key changed')
            if (inputs/'fedora-45-primary.asc').exists() and digest(inputs/'fedora-45-primary.asc') != digest(key):
                raise ValueError('Compiler and runtime RPM keys differ')
            shutil.copyfile(key, inputs/'fedora-45-primary.asc')
        for name in ('inputs.py', 'install_guest.py', 'build_guest.py', 'cli_guest.py'):
            shutil.copyfile(root/'image/walker'/name, inputs/name)
        for name in ('guest_inventory.py', 'resolve_packages.py'):
            shutil.copyfile(root/'image/hyprland'/name, inputs/name)
        shutil.copyfile(root/'image/launcher/probes/bounded_process.py', inputs/'bounded_process.py')
        shutil.copyfile(root/'image/launcher/walker-source.json', inputs/'walker-source.json')
        source_pins = json.loads((inputs/'walker-source.json').read_text())
        if (source_pins['repository'] != 'https://github.com/abenz1267/walker'
                or not re.fullmatch(r'[0-9a-f]{40}', source_pins['revision'])):
            raise ValueError('Unexpected pinned Walker repository')
        source = inputs/'source'
        source.mkdir()
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never',
               '-c', 'protocol.ext.allow=never', '-C', str(source)]
        run('source-init', git+['init'], 30)
        run('source-fetch', git+['fetch', '--depth=1', '--no-tags', source_pins['repository'], source_pins['revision']])
        run('source-checkout', git+['checkout', '--detach', 'FETCH_HEAD'], 30)
        if subprocess.check_output(git+['rev-parse', 'HEAD'], text=True).strip() != source_pins['revision']:
            raise ValueError('Unexpected checked-out revision')
        modes = subprocess.check_output(git+['ls-tree', '-r', 'HEAD'], text=True).splitlines()
        if not modes or not all(row.startswith(('100644 ', '100755 ')) for row in modes):
            raise ValueError('Only regular tracked source files are permitted')
        record['source_graph'] = require_source(source, source_pins)
        record['upstream_revision'] = source_pins['revision']
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull-base', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        installer = ['--user=0', '--network=none', '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP',
                     '--memory=2g', '--memory-swap=2g', '--cpus=1', '--pids-limit=128']
        _, compiler = container('compiler', base['image'], build, ['/inputs/install_guest.py', 'build'], installer, 900, commit=True)
        retain_directory(build/'install-evidence', evidence/'toolchain')
        installed = json.loads((evidence/'toolchain/result.json').read_text())
        if installed.get('passed') is not True or installed.get('all_base_packages_unchanged') is not True:
            raise ValueError('Compiler installation evidence is incomplete')
        record['compiler_image_id'] = compiler
        os.chown(build, 10001, 10001)
        for mode in ('download', 'compile'):
            flags = ['--read-only', '--user=10001:10001', '--network=bridge' if mode == 'download' else '--network=none',
                     '--memory=3g', '--memory-swap=3g', '--cpus=2', '--pids-limit=128']
            completion, _ = container(mode, compiler, build, ['/inputs/build_guest.py', mode], flags,
                                      1800 if mode == 'download' else 7200, check=mode == 'download')
            retain_directory(build/(mode+'-evidence'), evidence/mode)
        built = json.loads((evidence/'compile/result.json').read_text())
        binary = build/'binaries/walker'
        if (built.get('compiled') is not True or binary.is_symlink() or not binary.is_file()
                or binary.stat().st_size != built['binary_bytes'] or digest(binary) != built['binary_sha256']):
            raise ValueError('No authenticated complete Walker compilation was retained')
        payload = root/'.cache/walker-build-payload'
        payload.mkdir()
        shutil.copyfile(binary, payload/'walker')
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False, 'gui_qualified': False,
                    'base': base['image'], 'source_commit': record['source_commit'], 'upstream_revision': source_pins['revision'],
                    'version': source_pins['version'], 'binary_sha256': built['binary_sha256'], 'binary_bytes': built['binary_bytes'],
                    'cargo_toml_sha256': source_pins['cargo_toml_sha256'], 'cargo_lock_sha256': source_pins['cargo_lock_sha256'],
                    'build_rs_sha256': source_pins['build_rs_sha256'],
                    'build_rpm_lock_sha256': digest(inputs/'walker-build-rpms.lock.json')}
        (payload/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        shutil.copyfile(payload/'manifest.json', evidence/'compiled-manifest.json')
        completion.check_returncode()
        if built.get('passed') is not True or built.get('source_locks_unchanged') is not True:
            raise ValueError('Upstream suite or final source binding failed')
        record['upstream_tests_passed'] = True
        # Runtime installation starts again from the original base, never the compiler image.
        _, runtime_image = container('runtime-install', base['image'], runtime, ['/inputs/install_guest.py', 'runtime'], installer, 900, commit=True)
        retain_directory(runtime/'install-evidence', evidence/'runtime-install')
        runtime_result = json.loads((evidence/'runtime-install/result.json').read_text())
        if runtime_result.get('passed') is not True or runtime_result.get('all_base_packages_unchanged') is not True:
            raise ValueError('Original-base runtime installation failed')
        record['runtime_image_id'] = runtime_image
        shutil.copyfile(binary, inputs/'walker')
        (inputs/'walker').chmod(0o755)
        shutil.copyfile(payload/'manifest.json', inputs/'compiled-manifest.json')
        os.chown(cli, 10001, 10001)
        container('cli', runtime_image, cli, ['/inputs/cli_guest.py'],
                  ['--read-only', '--user=10001:10001', '--network=none', '--memory=512m', '--memory-swap=512m',
                   '--cpus=1', '--pids-limit=64'], 180)
        retain_directory(cli, evidence/'runtime')
        tested = json.loads((evidence/'runtime/result.json').read_text())
        if tested.get('passed') is not True or tested.get('os_qualified') is not False or tested.get('gui_qualified') is not False:
            raise ValueError('Runtime CLI evidence did not pass with its limited scope')
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        for source, name in ((build/'install-evidence', 'toolchain'), (build/'download-evidence', 'download'),
                             (build/'compile-evidence', 'compile'), (runtime/'install-evidence', 'runtime-install'), (cli, 'runtime')):
            if source.exists() and not (evidence/name).exists():
                try:
                    retain_directory(source, evidence/name)
                except Exception as error:
                    record.setdefault('evidence_failures', {})[name] = type(error).__name__+': '+str(error)
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
