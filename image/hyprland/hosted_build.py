#!/usr/bin/env python3
"""Build and probe Hyprland only on a disposable capped hosted runner."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from build_inputs import digest, require_current_requirements, unpack_rpms


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.getuid() != 0:
        raise SystemExit('Hyprland compilation requires the disposable hosted resource unit')
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(memory['MemTotal'].split()[0]) * 1024 < 14 * 1024**3 or int(memory['MemAvailable'].split()[0]) * 1024 < 10 * 1024**3:
        raise SystemExit('The hosted runner lacks the measured headroom for an 8 GiB build unit')
    root = Path.cwd()
    sys.path.insert(0, str(root / 'image/toolchain'))
    from bootstrap_cosign import bootstrap
    sys.path.insert(0, str(root / 'image'))
    from recipe import render
    from inventory import require_subject
    evidence = root / '.cache/hyprland-build-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    process_group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    assert process_group.name == 'supervisor'
    group = process_group.parent
    assert group.name.startswith('symbi-hyprland-build-') and group.name.endswith('.service')
    assert not (group / 'cgroup.procs').read_text().strip()
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group / name).read_text().strip() for name in names}
    assert limits == {'memory.max': '8589934592', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}
    (evidence / 'cgroup-limits.json').write_text(json.dumps(limits, indent=2) + '\n')
    output = root / '.cache/hyprland-build-output'
    record = {'passed': False, 'os_qualified': False, 'commands': [], 'source_commit': os.environ['GITHUB_SHA'],
              'scope': 'Offline compilation and headless native-loading probe in a disposable Fedora build stage'}

    def save():
        (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, timeout=600, cwd=None):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence / (name + '.log')).open('w') as log:
            result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'command': command, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()

    try:
        pins = json.loads((root / 'image/base-images.json').read_text())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        lock = json.loads((root / 'image/hyprland/build-rpms.lock.json').read_text())
        require_current_requirements(lock, json.loads((root / 'image/hyprland/build-requirements.json').read_text()))
        assert lock['base'] == base['image']
        record['base'] = base['image']
        cosign = bootstrap(root, evidence)
        signature = subprocess.check_output([str(cosign), 'verify', '--key', str(root / base['public_key']),
                                             '--output', 'json', base['image']], text=True, timeout=180)
        require_subject(json.loads(signature), base['image'])
        (evidence / 'base-signature.json').write_text(signature)
        inputs = root / '.cache/hyprland-build-inputs'
        inputs.mkdir()
        unpack_rpms(root / '.cache/hyprland-rpms.zip', lock, inputs / 'packages')
        files = {
            'build-rpms.lock.json': 'build-rpms.lock.json', 'build_guest.py': 'build_guest.py',
            'compile.py': 'compile.py', 'resolve_packages.py': 'resolve_packages.py',
            'guest_inventory.py': 'guest_inventory.py', 'patch-inputs.json': 'patch-inputs.json',
            'native-loading.patch': 'patches/0001-disable-native-loading.patch',
            'fedora-45-primary.asc': 'keys/fedora-45-primary.asc',
            'tests/qualify_native_loading.py': 'tests/qualify_native_loading.py',
            'tests/native_probe.c': 'tests/native_probe.c'}
        for destination, source in files.items():
            target = inputs / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / 'image/hyprland' / source, target)
        source_pins = json.loads((root / 'image/hyprland/candidate-inputs.json').read_text())
        sources = [{'name': 'Hyprland', 'url': 'https://github.com/hyprwm/Hyprland.git',
                    'rev': source_pins['hyprland_revision']}]
        for library in source_pins['libraries']:
            assert library['owner'] == 'hyprwm' and library['name'] == library['repo']
            assert re.fullmatch(r'[a-z][a-z0-9-]+', library['repo'])
            sources.append({'name': library['name'], 'url': f"https://github.com/hyprwm/{library['repo']}.git", 'rev': library['rev']})
        sources += [{'name': 'glaze', 'url': 'https://github.com/stephenberry/glaze.git', 'rev': source_pins['glaze']['revision']},
                    {'name': 'Hyprland/subprojects/udis86', 'url': 'https://github.com/canihavesomecoffee/udis86.git',
                     'rev': next(item['revision'] for item in source_pins['submodules'] if item['path'] == 'subprojects/udis86')}]
        for index, source in enumerate(sources):
            assert re.fullmatch(r'[a-f0-9]{40}', source['rev'])
            destination = inputs / 'sources' / source['name']
            destination.mkdir(parents=True, exist_ok=True)
            git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-C', str(destination)]
            run(f'source-{index}-init', git + ['init'], 30)
            run(f'source-{index}-fetch', git + ['fetch', '--depth=1', '--no-tags', source['url'], source['rev']], 300)
            run(f'source-{index}-checkout', git + ['checkout', '--detach', 'FETCH_HEAD'], 60)
            assert subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == source['rev']
        (inputs / 'source-revisions.json').write_text(json.dumps(sources, indent=2) + '\n')
        shutil.copyfile(inputs / 'source-revisions.json', evidence / 'source-revisions.json')
        output.mkdir()
        storage = root / '.cache/hyprland-build-storage'
        storage.mkdir()
        auth = storage / 'auth.json'
        auth.write_text('{"auths": {}}\n')
        podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage / 'root'), '--runroot', str(storage / 'run')]
        run('pull', podman + ['pull', '--authfile', str(auth), base['image']], 1200)
        common = ['--pull=never', '--network=none', '--security-opt=no-new-privileges',
                  '--cgroup-parent=/' + str(group.relative_to('/sys/fs/cgroup')),
                  '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                  '--mount', f'type=bind,src={output},dst=/output',
                  '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8']
        build = podman + ['run', '--name=symbi-hyprland-build', '--user=0', '--cap-drop=ALL',
                          '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP',
                          '--memory=6g', '--memory-swap=6g', '--cpus=2', '--pids-limit=128', *common,
                          '--entrypoint=/usr/bin/python3', base['image'], '/inputs/build_guest.py']
        run('offline-build', build, 7200)
        committed = subprocess.check_output(podman + ['commit', 'symbi-hyprland-build'], text=True, timeout=300).strip()
        match = re.fullmatch(r'(?:sha256:)?([a-f0-9]{64})', committed)
        assert match, 'Podman must return an immutable image identifier'
        image_id = 'sha256:' + match[1]
        record['development_image_id'] = image_id
        probe = podman + ['run', '--rm', '--read-only', '--user=10001:10001', '--cap-drop=ALL',
                          '--memory=2g', '--memory-swap=2g', '--cpus=1', '--pids-limit=64', *common,
                          '--entrypoint=/usr/bin/python3', image_id, '/inputs/tests/qualify_native_loading.py',
                          '--hyprland', '/usr/lib/symbi/hyprland/bin/Hyprland',
                          '--hyprctl', '/usr/lib/symbi/hyprland/bin/hyprctl',
                          '--work-dir', '/output/native-work', '--report', '/output/native-result.json']
        run('native-loading-probe', probe, 180)
        native = json.loads((output / 'native-result.json').read_text())
        assert native['passed'] is True and native['os_qualified'] is False
        payload = root / '.cache/hyprland-build-payload'
        payload.mkdir()
        run('copy-prefix', podman + ['cp', 'symbi-hyprland-build:/usr/lib/symbi/hyprland', str(payload)], 60)
        run('archive-prefix', ['tar', '-C', str(payload), '-czf', str(payload / 'hyprland-prefix.tar.gz'), 'hyprland'], 180)
        record['payload_sha256'] = digest(payload / 'hyprland-prefix.tar.gz')
        record['passed'] = True
    finally:
        save()
        if (output / 'evidence').is_dir():
            shutil.copytree(output / 'evidence', evidence / 'guest')
        for source, target in [('native-result.json', 'native-result.json'), ('native-work/compositor.log', 'compositor.log')]:
            path = output / source
            if path.is_file() and not path.is_symlink():
                shutil.copyfile(path, evidence / target)
        final = {name: (group / name).read_text().strip() for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence / 'cgroup-final.json').write_text(json.dumps(final, indent=2) + '\n')
        assert all(final[name] == value for name, value in limits.items())


if __name__ == '__main__':
    main()
