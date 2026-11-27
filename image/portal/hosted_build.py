"""Reuse authenticated compositor output; build only the portal and toolkit."""
import json
import os
from pathlib import Path
import shutil


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Portal compilation requires the disposable hosted resource unit')
    from image.desktop.files import inventory, release_file_cache
    from image.hyprland.build_inputs import unpack_rpms
    from image.hyprland.inventory import require_subject
    from image.hyprland.prefix_input import unpack_prefix
    from image.launcher.probes.bounded_process import run_bounded
    from image.portal.build_inputs import require_prefix_bindings, require_rpm_bindings, require_source_tree
    from image.portal.inputs import load_inputs
    from image.recipe import render
    from image.toolchain.bootstrap_cosign import bootstrap
    from image.toolchain.reuse import digest, unique_json
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(memory['MemTotal'].split()[0])*1024 < 14*1024**3 or int(memory['MemAvailable'].split()[0])*1024 < 10*1024**3:
        raise SystemExit('Hosted runner lacks measured headroom for the 8 GiB portal build unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if (process.name != 'supervisor' or not group.name.startswith('symbi-portal-build-')
            or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected portal build supervisor group')
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group/name).read_text().strip() for name in names}
    if limits != {'memory.max': '8589934592', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected portal build resource limits')
    evidence = root/'.cache/portal-build-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    output, inputs, storage, payload = (root/'.cache'/name for name in
                                        ('portal-build-output', 'portal-build-inputs', 'portal-build-storage', 'portal-build-payload'))
    for path in (output, inputs, storage, payload):path.mkdir(mode=0o755)
    (output/'portal').mkdir()
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50:raise ValueError('Runtime storage path too long')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'source_commit': os.environ['GITHUB_SHA'],
              'limits': limits, 'commands': [], 'compositor_recompiled': False,
              'scope': 'Offline portal/toolkit development build and unchanged-base loader probes; no desktop consent qualification'}

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
        if check:result.check_returncode()
        return result

    def remove(container):
        removed = run(container+'-cleanup', podman+['rm', '--force', '--ignore', container], check=False)
        absent = run(container+'-exists', podman+['container', 'exists', container], check=False)
        if removed.returncode != 0 or absent.returncode != 1:raise RuntimeError('Portal container cleanup failed')

    try:
        base_pins = unique_json((root/'image/base-images.json').read_bytes())
        render(base_pins, 'generic', root)
        base = base_pins['variants']['generic']
        pins, requirements, bindings = load_inputs(root)
        trust = unique_json((root/'image/hyprland/fedora-package-trust.json').read_bytes())
        lock = unique_json((root/'image/portal/build-rpms.lock.json').read_bytes())
        require_rpm_bindings(lock, requirements, base['image'], trust)
        unpack_rpms(root/'.cache/portal-build-rpms.zip', lock, inputs/'packages')
        release_file_cache(inputs/'packages')
        hypr_lock = unique_json((root/'image/hyprland/development-prefix.lock.json').read_bytes())
        record['prefix_link_rewrites'] = []
        hypr = unpack_prefix(root/'.cache/hyprland-development-prefix.zip', hypr_lock,
                             inputs/'prefix', record['prefix_link_rewrites'])
        release_file_cache(inputs/'prefix')
        sources = unique_json((root/'image/hyprland/candidate-inputs.json').read_bytes())
        require_prefix_bindings(hypr, hypr_lock, sources, base['image'],
                                digest(root/'image/hyprland/build-rpms.lock.json'),
                                digest(root/'image/hyprland/patches/0001-disable-native-loading.patch'))
        record.update(base=base['image'], source_inputs=pins, reviewed_source_bindings=bindings,
                      rpm_lock_sha256=digest(root/'image/portal/build-rpms.lock.json'),
                      reused_compositor_manifest_sha256=hypr_lock['manifest_sha256'])
        files = {'build-rpms.lock.json': 'image/portal/build-rpms.lock.json',
                 'source-inputs.json': 'image/portal/source-inputs.json',
                 'build_guest.py': 'image/portal/build_guest.py', 'compile.py': 'image/portal/compile.py',
                 'build_inputs.py': 'image/portal/build_inputs.py',
                 'bounded_process.py': 'image/launcher/probes/bounded_process.py',
                 'resolve_packages.py': 'image/hyprland/resolve_packages.py',
                 'guest_inventory.py': 'image/hyprland/guest_inventory.py',
                 'reuse.py': 'image/toolchain/reuse.py', 'fedora-45-primary.asc': trust['key']['path']}
        record['input_bindings'] = {}
        for name, relative in files.items():
            source = root/relative
            if source.is_symlink() or not source.is_file() or source.resolve() != source:
                raise ValueError('Expected regular portal build input')
            shutil.copyfile(source, inputs/name)
            record['input_bindings'][name] = digest(inputs/name)
        for index, component in enumerate(pins['components']):
            destination = inputs/'sources'/component['name']
            destination.mkdir(parents=True)
            git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false',
                   '-c', 'credential.helper=', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
                   '-c', 'http.followRedirects=false', '-C', str(destination)]
            run(f'source-{index}-init', git+['init'])
            run(f'source-{index}-fetch', git+['fetch', '--depth=1', '--no-tags', component['repository'], component['revision']], 300)
            run(f'source-{index}-checkout', git+['checkout', '--detach', 'FETCH_HEAD'])
            revision = run(f'source-{index}-revision', git+['rev-parse', 'HEAD']).stdout.strip()
            require_source_tree(destination, component, revision)
        cosign = bootstrap(root, evidence)
        signature = run('base-signature', [str(cosign), 'verify', '--key', str(root/base['public_key']),
                                          '--output', 'json', base['image']], 180)
        require_subject(unique_json(signature.stdout), base['image'])
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        common = ['--pull=never', '--network=none', '--security-opt=no-new-privileges',
                  '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                  '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                  '--mount', f'type=bind,src={inputs / "prefix/hyprland"},dst=/usr/lib/symbi/hyprland,ro',
                  '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8']
        container = 'symbi-portal-compile'
        try:
            run('offline-build', podman+['run', '--name='+container, '--user=0', '--cap-drop=ALL',
                '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP',
                '--memory=6g', '--memory-swap=6g', '--cpus=2', '--pids-limit=128', *common,
                '--mount', f'type=bind,src={output},dst=/output',
                '--mount', f'type=bind,src={output / "portal"},dst=/usr/lib/symbi/portal',
                '--entrypoint=/usr/bin/python3', base['image'], '/inputs/build_guest.py'], 3600)
        finally:
            remove(container)
        compiled = unique_json((output/'evidence/compile.json').read_bytes())
        installed = unique_json((output/'evidence/install.json').read_bytes())
        if (compiled['passed'] is not True or installed['passed'] is not True
                or compiled['os_qualified'] is not False or installed['os_qualified'] is not False
                or compiled['source_revisions'] != pins['components']):
            raise ValueError('Native portal build acceptance incomplete')
        guest_counters = unique_json((output/'evidence/build-cgroup-final.json').read_bytes())
        events = dict(line.split() for line in guest_counters['memory.events'].splitlines())
        if any(events[name] != '0' for name in ('oom', 'oom_kill', 'oom_group_kill')):
            raise ValueError('Native build recorded an OOM event')
        run('archive-prefix', ['tar', '-C', str(output), '-czf', str(payload/'portal-prefix.tar.gz'), 'portal'], 180)
        manifest = {'schema': 1, 'compiled': True, 'os_qualified': False, 'selected_base_qualified': False,
                    'consent_qualified': False, 'source_commit': record['source_commit'], 'base': base['image'],
                    'source_inputs': pins, 'rpm_lock_sha256': record['rpm_lock_sha256'],
                    'reused_compositor_manifest_sha256': record['reused_compositor_manifest_sha256'],
                    'compile_report_sha256': digest(output/'evidence/compile.json'),
                    'test_suites': compiled['test_suites'], 'files': inventory(output/'portal'),
                    'payload_sha256': digest(payload/'portal-prefix.tar.gz'), 'payload_bytes': (payload/'portal-prefix.tar.gz').stat().st_size,
                    'scope': 'Unqualified development prefix; Debug toolkit tests do not certify the separate Release toolkit binary'}
        (payload/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        shutil.copyfile(payload/'manifest.json', evidence/'development-prefix.json')
        record['compiled_prefix_retained'] = True
        # Retain the compiled prefix before probing the unchanged product base.
        # Missing runtime packages require a separately authenticated additive layer.
        for index, relative in enumerate(('lib/libhyprtoolkit.so.0.6.0', 'bin/hyprland-share-picker', 'libexec/xdg-desktop-portal-hyprland')):
            container = 'symbi-portal-base-'+str(index)
            try:
                checked = run('base-loader-'+str(index), podman+['run', '--name='+container, '--read-only',
                    '--user=10001:10001', '--cap-drop=ALL', '--memory=1g', '--memory-swap=1g', '--cpus=1',
                    '--pids-limit=64', *common,
                    '--mount', f'type=bind,src={output / "portal"},dst=/usr/lib/symbi/portal,ro',
                    '--entrypoint=/usr/bin/ldd', base['image'], '/usr/lib/symbi/portal/'+relative])
                if 'not found' in checked.stdout+checked.stderr:raise ValueError('Selected base lacks a portal runtime dependency')
            finally:
                remove(container)
        record['selected_base_loader_checks_passed'] = True
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        if (output/'evidence').is_dir():
            target = evidence/'guest'
            target.mkdir()
            for path in (output/'evidence').iterdir():
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
                    raise ValueError('Unexpected native build evidence member')
                shutil.copyfile(path, target/path.name)
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        events = dict(line.split() for line in record['cgroup_final']['memory.events'].splitlines())
        if (any(record['cgroup_final'][name] != limits[name] for name in names)
                or any(events[name] != '0' for name in ('oom', 'oom_kill', 'oom_group_kill'))):
            record['passed'] = False
            record['resource_failure'] = 'Resource limits changed or an OOM event occurred'
            save()
            raise RuntimeError(record['resource_failure'])
        save()


if __name__ == '__main__':
    main()
