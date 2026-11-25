#!/usr/bin/env python3
"""Check retained Hyprland binaries on the base plus only signed runtime libraries."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0:
        raise SystemExit('Runtime packaging requires the disposable hosted resource unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    assert process.name == 'supervisor' and group.name.startswith('symbi-hypr-runtime-')
    assert not (group / 'cgroup.procs').read_text().strip()
    limits = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    assert limits == {'memory.max': '4294967296', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '256'}
    evidence = root / '.cache/hyprland-runtime-evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    storage = root / '.cache/hyprland-runtime-storage'
    storage.mkdir(mode=0o700)
    inputs, output = storage / 'inputs', storage / 'output'
    inputs.mkdir(mode=0o755)
    output.mkdir(mode=0o755)
    runroot = Path('/run') / group.name.removesuffix('.service')
    assert len(os.fsencode(runroot)) <= 50
    runroot.mkdir(mode=0o700)
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage / 'root'), '--runroot', str(runroot)]
    record = {'passed': False, 'os_qualified': False, 'source_commit': os.environ['GITHUB_SHA'],
              'limits': limits, 'commands': [],
              'scope': 'Original base plus only reviewed runtime libraries and retained compiler prefix; no boot/native acceptance'}

    def save():
        (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, timeout=120):
        record['active_command'] = {'name': name, 'command': command}
        save()
        with (evidence / (name + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()

    try:
        sys.path.insert(0, str(root / 'image/toolchain'))
        from bootstrap_cosign import bootstrap
        sys.path.insert(0, str(root / 'image'))
        from recipe import render
        from inventory import require_subject
        from build_inputs import unpack_rpms, require_current_requirements
        from prefix_input import unpack_prefix
        pins = json.loads((root / 'image/base-images.json').read_text())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        cosign = bootstrap(root, evidence)
        signature = subprocess.check_output([str(cosign), 'verify', '--key', str(root / base['public_key']),
                                             '--output', 'json', base['image']], text=True, timeout=180)
        require_subject(json.loads(signature), base['image'])
        (evidence / 'base-signature.json').write_text(signature)
        record['base'] = base['image']
        lock = json.loads((root / 'image/hyprland/runtime-rpms.lock.json').read_text())
        require_current_requirements(lock, json.loads((root / 'image/hyprland/runtime-requirements.json').read_text()))
        assert lock['base'] == base['image']
        unpack_rpms(root / '.cache/hyprland-runtime-rpms.zip', lock, inputs / 'packages')
        prefix_lock = json.loads((root / 'image/hyprland/development-prefix.lock.json').read_text())
        manifest = unpack_prefix(root / '.cache/hyprland-development-prefix.zip', prefix_lock, inputs / 'prefix')
        assert manifest['base'] == base['image']
        assert manifest['rpm_lock_sha256'] == digest(root / 'image/hyprland/build-rpms.lock.json')
        assert manifest['native_patch_sha256'] == digest(root / 'image/hyprland/patches/0001-disable-native-loading.patch')
        sources = json.loads((root / 'image/hyprland/candidate-inputs.json').read_text())
        expected = {library['name']: library['rev'] for library in sources['libraries']}
        expected.update(Hyprland=sources['hyprland_revision'], glaze=sources['glaze']['revision'])
        expected['Hyprland/subprojects/udis86'] = next(row['revision'] for row in sources['submodules'] if row['path'] == 'subprojects/udis86')
        assert len(manifest['source_revisions']) == len(expected)
        assert {row['name']: row['rev'] for row in manifest['source_revisions']} == expected
        (inputs / 'prefix-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        (evidence / 'prefix-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        for name in ('runtime-rpms.lock.json', 'runtime_guest.py', 'guest_inventory.py', 'resolve_packages.py'):
            shutil.copyfile(root / 'image/hyprland' / name, inputs / name)
        shutil.copyfile(root / lock['key']['path'], inputs / 'fedora-45-primary.asc')
        (inputs / 'tests').mkdir()
        shutil.copyfile(root / 'image/hyprland/tests/qualify_session_defaults.py', inputs / 'tests/qualify_session_defaults.py')
        shutil.copytree(root / 'image/overlay/usr/share/symbiont/defaults/hypr', inputs / 'session-defaults')
        auth = storage / 'auth.json'
        auth.write_text('{"auths": {}}\n')
        run('pull', podman + ['pull', '--authfile', str(auth), base['image']], 1200)
        common = ['--pull=never', '--network=none', '--security-opt=no-new-privileges',
                  '--cgroup-parent=/' + str(group.relative_to('/sys/fs/cgroup')),
                  '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                  '--mount', f'type=bind,src={output},dst=/output',
                  '--env=PYTHONDONTWRITEBYTECODE=1', '--env=LANG=C.UTF-8',
                  '--memory=2g', '--memory-swap=2g', '--cpus=1']
        run('add-runtime-packages', podman + ['run', '--name=symbi-hyprland-runtime', '--user=0',
            '--cap-drop=ALL', '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,SETFCAP', '--pids-limit=128',
            *common, '--entrypoint=/usr/bin/python3', base['image'], '/inputs/runtime_guest.py'], 600)
        installed = json.loads((output / 'install-evidence/result.json').read_text())
        assert installed['passed'] and installed['all_base_packages_unchanged'] and not installed['os_qualified']
        assert installed['binary_hashes'] == manifest['binaries']
        image_id = subprocess.check_output(podman + ['commit', 'symbi-hyprland-runtime'], text=True, timeout=300).strip()
        match = re.fullmatch(r'(?:sha256:)?([a-f0-9]{64})', image_id)
        assert match
        image_id = 'sha256:' + match[1]
        record['runtime_stage_image_id'] = image_id
        # Keep root-produced installation evidence outside the user-writable probe output.
        shutil.copytree(output / 'install-evidence', evidence / 'install')
        os.chown(output, 10001, 10001)
        run('session-defaults', podman + ['run', '--rm', '--read-only', '--user=10001:10001',
            '--cap-drop=ALL', '--pids-limit=64', *common, '--entrypoint=/usr/bin/python3', image_id,
            '/inputs/tests/qualify_session_defaults.py', '--hyprland', '/usr/lib/symbi/hyprland/bin/Hyprland',
            '--defaults', '/inputs/session-defaults', '--work-dir', '/output/s', '--report', '/output/session-result.json'])
        session = json.loads((output / 'session-result.json').read_text())
        assert session['passed'] and not session['os_qualified'] and session['hyprland_sha256'] == manifest['binaries']['Hyprland']
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        if (output / 'install-evidence').is_dir() and not (evidence / 'install').exists():
            shutil.copytree(output / 'install-evidence', evidence / 'install')
        report = output / 'session-result.json'
        if report.is_file() and not report.is_symlink() and report.stat().st_size < 1024**2:
            shutil.copyfile(report, evidence / 'session-result.json')
        record['cgroup_final'] = {name: (group / name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
