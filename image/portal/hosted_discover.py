"""Resolve signed portal build RPMs on a bounded disposable hosted runner."""
import json
import os
from pathlib import Path
import shutil


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0):
        raise SystemExit('Portal build package discovery requires the disposable hosted resource unit')
    from image.portal.inputs import load_inputs
    from image.hyprland.inventory import require_subject
    from image.launcher.probes.bounded_process import run_bounded
    from image.recipe import render
    from image.toolchain.bootstrap_cosign import bootstrap
    from image.toolchain.reuse import digest, unique_json
    root = Path.cwd()
    process = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    if (process.name != 'supervisor' or not group.name.startswith('symbi-portal-rpms-')
            or (group/'cgroup.procs').read_text().strip()):
        raise ValueError('Unexpected portal RPM supervisor group')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '3221225472', 'memory.swap.max': '0',
                  'cpu.max': '200000 100000', 'pids.max': '256'}:
        raise ValueError('Unexpected portal package discovery limits')
    evidence = root/'.cache/portal-package-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    output, inputs, storage = (root/'.cache'/name for name in
                               ('portal-package-output', 'portal-package-inputs', 'portal-package-storage'))
    for path in (output, inputs, storage):path.mkdir(mode=0o755)
    runroot = Path('/run')/group.name.removesuffix('.service')
    if len(os.fsencode(runroot)) > 50:raise ValueError('Runtime storage path too long')
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage/'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'source_commit': os.environ['GITHUB_SHA'], 'limits': limits,
              'scope': 'Signed build candidate discovery only; no package installation, compilation or OS qualification', 'commands': []}

    def run(name, command, timeout=60, check=True):
        record['active_command'] = {'name': name, 'command': command}
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        if check:result.check_returncode()
        return result

    try:
        pins = unique_json((root/'image/base-images.json').read_bytes())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        source_pins, requirements, source_bindings = load_inputs(root)
        trust = unique_json((root/'image/hyprland/fedora-package-trust.json').read_bytes())
        if trust['source']['image'] != base['image']:raise ValueError('Package trust base changed')
        paths = {'resolve_packages.py': 'image/hyprland/resolve_packages.py',
                 'guest_inventory.py': 'image/hyprland/guest_inventory.py',
                 'build-requirements.json': 'image/portal/build-requirements.json',
                 'fedora-package-trust.json': 'image/hyprland/fedora-package-trust.json',
                 'fedora-45-primary.asc': trust['key']['path'],
                 'dnf.conf': 'image/hyprland/package-dnf.conf',
                 'repos/fedora-build.repo': 'image/hyprland/fedora-build.repo'}
        bindings = {}
        for name, relative in paths.items():
            source, target = root/relative, inputs/name
            allowed = root/('image/portal' if name == 'build-requirements.json' else 'image/hyprland')
            if source.is_symlink() or source.resolve() != source or not source.is_relative_to(allowed):
                raise ValueError('Unexpected package input path')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            bindings[name] = digest(target)
        repo_pin = unique_json((root/'image/hyprland/package-repository-inputs.json').read_bytes())
        if (bindings['fedora-45-primary.asc'] != trust['key']['sha256']
                or bindings['repos/fedora-build.repo'] != repo_pin['selected_configuration_sha256']):
            raise ValueError('Package key/repository inputs changed')
        record.update(base=base['image'], requirements=requirements, input_bindings=bindings,
                      source_inputs=source_pins, reviewed_source_bindings=source_bindings)
        cosign = bootstrap(root, evidence)
        signature = run('base-signature', [str(cosign), 'verify', '--key', str(root/base['public_key']),
                                          '--output', 'json', base['image']], 180)
        require_subject(unique_json(signature.stdout), base['image'])
        auth = storage/'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull', podman+['pull', '--authfile', str(auth), base['image']], 1200)
        container = 'symbi-portal-package-discovery'
        command = podman+['run', '--rm', '--name='+container, '--pull=never', '--user=0', '--read-only', '--network=bridge',
                         '--cgroup-parent=/'+str(group.relative_to('/sys/fs/cgroup')),
                         '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
                         '--memory=2g', '--memory-swap=2g', '--cpus=1',
                         '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                         '--mount', f'type=bind,src={output},dst=/output', '--env=PYTHONDONTWRITEBYTECODE=1',
                         '--env=LANG=C.UTF-8', '--entrypoint=/usr/bin/python3', base['image'], '/inputs/resolve_packages.py']
        try:
            run('discovery', command, 1500)
        finally:
            removed = run('cleanup', podman+['rm', '--force', '--ignore', container], check=False)
            exists = run('exists', podman+['container', 'exists', container], check=False)
            record['container_absent'] = removed.returncode == 0 and exists.returncode == 1
            if not record['container_absent']:raise RuntimeError('Portal build package discovery cleanup failed')
        result = unique_json((output/'evidence/result.json').read_bytes())
        if (result.get('passed') is not True or result.get('installed_packages_unchanged') is not True
                or result.get('os_qualified') is not False or result.get('requirements') != requirements
                or result.get('base') != base['image'] or result.get('key') != trust['key']
                or result.get('negative_controls') != {'missing_key_rejected': True, 'tampered_package_rejected': True}):
            raise ValueError('Signed discovery acceptance incomplete')
        for row in result['packages']:
            if (Path(row['filename']).name != row['filename'] or not row['filename'].endswith('.rpm')
                    or row.get('signature_verified') is not True
                    or row.get('key_fingerprint') != trust['key']['fingerprint']):
                raise ValueError('Unexpected RPM identity/signature record')
            path = output/'rpms'/row['filename']
            if (path.is_symlink() or path.stat().st_size != row['bytes'] or digest(path) != row['sha256']):
                raise ValueError('RPM payload changed after discovery')
        record.update(passed=True, packages=len(result['packages']), rpm_manifest_sha256=digest(output/'evidence/result.json'))
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        if (output/'evidence').is_dir():shutil.copytree(output/'evidence', evidence/'guest')
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
