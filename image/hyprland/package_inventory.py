#!/usr/bin/env python3
"""Resolve candidate RPMs in the authenticated base on a hosted runner only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def requirements_input(root, profile):
    profiles = {'hyprland': 'image/hyprland/build-requirements.json',
                'hyprland-runtime': 'image/hyprland/runtime-requirements.json',
                'launcher': 'image/launcher/runtime-requirements.json',
                'elephant-build': 'image/launcher/elephant-build-requirements.json',
                'walker-build': 'image/launcher/walker-build-requirements.json'}
    if profile not in profiles:
        raise ValueError('Unknown package discovery profile')
    relative = profiles[profile]
    path = root / relative
    if not path.is_file() or path.is_symlink() or path.resolve() != path:
        raise ValueError('Package requirements must be a regular reviewed file without linked parents')
    return relative


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0:
        raise SystemExit('Package discovery requires the disposable hosted resource unit')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('hyprland', 'hyprland-runtime', 'launcher', 'elephant-build', 'walker-build'), default='hyprland')
    args = parser.parse_args()
    root = Path.cwd()
    selected_requirements = requirements_input(root, args.profile)
    sys.path.insert(0, str(root / 'image/toolchain'))
    from bootstrap_cosign import bootstrap
    sys.path.insert(0, str(root / 'image'))
    from recipe import render
    from inventory import require_subject
    evidence = root / '.cache/fedora-package-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    process_group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    assert process_group.name == 'supervisor'
    group = process_group.parent
    assert group.name.startswith('symbi-fedora-packages-') and group.name.endswith('.service')
    assert not (group / 'cgroup.procs').read_text().strip()
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group / name).read_text().strip() for name in names}
    (evidence / 'cgroup-limits.json').write_text(json.dumps(limits, indent=2) + '\n')
    assert limits == {'memory.max': '3221225472', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}
    output = root / '.cache/fedora-package-output'
    try:
        pins = json.loads((root / 'image/base-images.json').read_text())
        render(pins, 'generic', root)
        pin = pins['variants']['generic']
        trust = json.loads((root / 'image/hyprland/fedora-package-trust.json').read_text())
        assert trust['source']['image'] == pin['image']
        cosign = bootstrap(root, evidence)
        verified = subprocess.check_output([str(cosign), 'verify', '--key', str(root / pin['public_key']),
                                            '--output', 'json', pin['image']], text=True, timeout=180)
        require_subject(json.loads(verified), pin['image'])
        (evidence / 'base-signature.json').write_text(verified)
        inputs = root / '.cache/fedora-package-inputs'
        inputs.mkdir()
        paths = {
            'resolve_packages.py': 'image/hyprland/resolve_packages.py',
            'guest_inventory.py': 'image/hyprland/guest_inventory.py',
            'build-requirements.json': selected_requirements,
            'fedora-package-trust.json': 'image/hyprland/fedora-package-trust.json',
            'fedora-45-primary.asc': trust['key']['path'],
            'dnf.conf': 'image/hyprland/package-dnf.conf',
            'repos/fedora-build.repo': 'image/hyprland/fedora-build.repo',
        }
        bindings = {}
        for name, path in paths.items():
            source = (root / path).resolve(strict=True)
            allowed_root = root / 'image/launcher' if name == 'build-requirements.json' and args.profile in ('launcher', 'elephant-build', 'walker-build') else root / 'image/hyprland'
            assert source.is_relative_to(allowed_root)
            target = inputs / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            bindings[name] = digest(target)
        assert bindings['fedora-45-primary.asc'] == trust['key']['sha256']
        repo_pin = json.loads((root / 'image/hyprland/package-repository-inputs.json').read_text())
        assert bindings['repos/fedora-build.repo'] == repo_pin['selected_configuration_sha256']
        (evidence / 'input-bindings.json').write_text(json.dumps({'source_commit': os.environ['GITHUB_SHA'], 'profile': args.profile,
                                                                'requirements_source': selected_requirements, 'files': bindings}, indent=2) + '\n')
        output.mkdir()
        storage = root / '.cache/fedora-package-storage'
        storage.mkdir()
        auth = storage / 'auth.json'
        auth.write_text('{"auths": {}}\n')
        podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage / 'root'), '--runroot', str(storage / 'run')]
        with (evidence / 'pull.log').open('w') as log:
            subprocess.run(podman + ['pull', '--authfile', str(auth), pin['image']], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        command = podman + ['run', '--rm', '--pull=never', '--user=0', '--read-only', '--network=bridge',
                            '--cgroup-parent=/' + str(group.relative_to('/sys/fs/cgroup')),
                            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
                            '--memory=2g', '--memory-swap=2g', '--cpus=1',
                            '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                            '--mount', f'type=bind,src={output},dst=/output',
                            '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8',
                            '--entrypoint=/usr/bin/python3', pin['image'], '/inputs/resolve_packages.py']
        subprocess.run(command, check=True, timeout=1500)
        result = json.loads((output / 'evidence/result.json').read_text())
        assert result['passed'] and result['installed_packages_unchanged'] and not result['os_qualified']
        for row in result['packages']:
            name = row['filename']
            assert Path(name).name == name and name.endswith('.rpm')
            package = output / 'rpms' / name
            assert not package.is_symlink() and digest(package) == row['sha256']
        (evidence / 'result.json').write_text(json.dumps({'passed': True, 'base': pin['image'], 'source_commit': os.environ['GITHUB_SHA'],
                                                        'profile': args.profile,
                                                        'packages': len(result['packages']), 'rpm_manifest_sha256': digest(output / 'evidence/result.json'),
                                                        'os_qualified': False, 'scope': 'Candidate signed build inputs, not installed or compiled'}, indent=2) + '\n')
    finally:
        if (output / 'evidence').is_dir():
            shutil.copytree(output / 'evidence', evidence / 'guest')
        final = {name: (group / name).read_text().strip() for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence / 'cgroup-final.json').write_text(json.dumps(final, indent=2) + '\n')
        assert all(final[name] == value for name, value in limits.items())


if __name__ == '__main__':
    main()
