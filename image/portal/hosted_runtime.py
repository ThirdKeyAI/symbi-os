"""Reuse the portal build and verify its minimal runtime closure on the base."""
import json
import os
from pathlib import Path
import shutil


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Portal runtime checks require the disposable hosted resource unit')
    from image.desktop.files import release_file_cache
    from image.hyprland.build_inputs import unpack_rpms
    from image.hyprland.inventory import require_subject
    from image.hyprland.prefix_input import unpack_prefix
    from image.launcher.probes.bounded_process import run_bounded
    from image.portal.build_inputs import require_prefix_bindings, require_rpm_bindings
    from image.portal.inputs import load_inputs
    from image.portal.prefix_input import unpack_portal
    from image.portal.runtime_inputs import require_runtime_result, select_runtime_package
    from image.recipe import render
    from image.toolchain.bootstrap_cosign import bootstrap
    from image.toolchain.reuse import digest, unique_json
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(memory['MemTotal'].split()[0])*1024 < 10*1024**3 or int(memory['MemAvailable'].split()[0])*1024 < 6*1024**3:
        raise SystemExit('Hosted runner lacks measured headroom for the 4 GiB runtime unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if (process.name != 'supervisor' or not group.name.startswith('symbi-portal-runtime-')
            or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected portal runtime supervisor group')
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group/name).read_text().strip() for name in names}
    if limits != {'memory.max': '4294967296', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected hosted portal runtime limits')
    evidence = root/'.cache/portal-runtime-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    output, inputs, storage = (root/'.cache'/name for name in
                               ('portal-runtime-output', 'portal-runtime-inputs', 'portal-runtime-storage'))
    for path in (output, inputs, storage): path.mkdir(mode=0o755)
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50: raise ValueError('Runtime storage path too long')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'consent_qualified': False,
              'source_commit': os.environ['GITHUB_SHA'], 'limits': limits, 'commands': [],
              'native_components_recompiled': False, 'product_installation': False,
              'scope': 'Retained binaries with one authenticated additive library on the disposable generic base; no GUI or consent qualification'}

    def save(): (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60, check=True):
        record['active_command'] = {'name': name, 'command': command}; save()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']; save()
        if check: result.check_returncode()
        return result

    try:
        base_pins = unique_json((root/'image/base-images.json').read_bytes())
        render(base_pins, 'generic', root)
        base = base_pins['variants']['generic']
        pins, requirements, bindings = load_inputs(root)
        trust = unique_json((root/'image/hyprland/fedora-package-trust.json').read_bytes())
        lock = unique_json((root/'image/portal/build-rpms.lock.json').read_bytes())
        require_rpm_bindings(lock, requirements, base['image'], trust)
        package = select_runtime_package(lock)
        unpack_rpms(root/'.cache/portal-build-rpms.zip', lock, inputs/'packages')
        release_file_cache(inputs/'packages')
        (inputs/'rpms').mkdir()
        shutil.copyfile(inputs/'packages/rpms'/package['filename'], inputs/'rpms'/package['filename'])
        shutil.rmtree(inputs/'packages')
        hypr_lock = unique_json((root/'image/hyprland/development-prefix.lock.json').read_bytes())
        record['prefix_link_rewrites'] = []
        hypr = unpack_prefix(root/'.cache/hyprland-development-prefix.zip', hypr_lock,
                             inputs/'hyprland-prefix', record['prefix_link_rewrites'])
        release_file_cache(inputs/'hyprland-prefix')
        sources = unique_json((root/'image/hyprland/candidate-inputs.json').read_bytes())
        require_prefix_bindings(hypr, hypr_lock, sources, base['image'],
                                digest(root/'image/hyprland/build-rpms.lock.json'),
                                digest(root/'image/hyprland/patches/0001-disable-native-loading.patch'))
        portal_lock = unique_json((root/'image/portal/development-prefix.lock.json').read_bytes())
        portal = unpack_portal(root/'.cache/portal-development-prefix.zip', portal_lock, pins, base['image'],
                               digest(root/'image/portal/build-rpms.lock.json'), hypr_lock['manifest_sha256'],
                               inputs/'portal-prefix')
        release_file_cache(inputs/'portal-prefix')
        record.update(base=base['image'], source_inputs=pins, reviewed_source_bindings=bindings,
                      runtime_package=package, rpm_lock_sha256=digest(root/'image/portal/build-rpms.lock.json'),
                      portal_manifest_sha256=portal_lock['manifest_sha256'],
                      reused_compositor_manifest_sha256=hypr_lock['manifest_sha256'])
        (evidence/'portal-prefix.json').write_text(json.dumps(portal, indent=2)+'\n')
        files = {'build-rpms.lock.json': 'image/portal/build-rpms.lock.json',
                 'source-inputs.json': 'image/portal/source-inputs.json',
                 'runtime_guest.py': 'image/portal/runtime_guest.py', 'runtime_inputs.py': 'image/portal/runtime_inputs.py',
                 'desktop_inputs.py': 'image/desktop/inputs.py', 'runtime_install.py': 'image/assembly/runtime_install.py',
                 'package_identity.py': 'image/walker/inputs.py',
                 'bounded_process.py': 'image/launcher/probes/bounded_process.py',
                 'resolve_packages.py': 'image/hyprland/resolve_packages.py',
                 'guest_inventory.py': 'image/hyprland/guest_inventory.py',
                 'reuse.py': 'image/toolchain/reuse.py', 'fedora-45-primary.asc': trust['key']['path']}
        record['input_bindings'] = {}
        for name, relative in files.items():
            source = root/relative
            if source.is_symlink() or not source.is_file() or source.resolve() != source:
                raise ValueError('Expected regular portal runtime input')
            shutil.copyfile(source, inputs/name)
            record['input_bindings'][name] = digest(inputs/name)
        cosign = bootstrap(root, evidence)
        signature = run('base-signature', [str(cosign), 'verify', '--key', str(root/base['public_key']),
                                          '--output', 'json', base['image']], 180)
        require_subject(unique_json(signature.stdout), base['image'])
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull', podman+['pull', '--authfile', str(auth), base['image']], 900)
        container = 'symbi-portal-runtime'
        try:
            run('offline-runtime', podman+['run', '--name='+container, '--user=0', '--cap-drop=ALL',
                '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP', '--pull=never',
                '--network=none', '--security-opt=no-new-privileges',
                '--memory=2g', '--memory-swap=2g', '--cpus=1', '--pids-limit=128',
                '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                '--mount', f'type=bind,src={inputs / "hyprland-prefix/hyprland"},dst=/usr/lib/symbi/hyprland,ro',
                '--mount', f'type=bind,src={inputs / "portal-prefix/portal"},dst=/usr/lib/symbi/portal,ro',
                '--mount', f'type=bind,src={output},dst=/output',
                '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8', '--env=GITHUB_ACTIONS=true',
                '--entrypoint=/usr/bin/python3', base['image'], '/inputs/runtime_guest.py'], 600)
        finally:
            removed = run('container-cleanup', podman+['rm', '--force', '--ignore', container], check=False)
            absent = run('container-exists', podman+['container', 'exists', container], check=False)
            if removed.returncode != 0 or absent.returncode != 1: raise RuntimeError('Portal runtime container cleanup failed')
        result = unique_json((output/'evidence/result.json').read_bytes())
        version = next(row['version'] for row in pins['components'] if row['name'] == 'xdg-desktop-portal-hyprland')
        require_runtime_result(result, package, version)
        record['runtime_report_sha256'] = digest(output/'evidence/result.json')
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        if (output/'evidence').is_dir():
            target = evidence/'guest'
            target.mkdir()
            members = list((output/'evidence').iterdir())
            if len(members) > 100: raise ValueError('Excessive runtime evidence')
            for path in members:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
                    raise ValueError('Unexpected portal runtime evidence member')
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


if __name__ == '__main__': main()
