#!/usr/bin/env python3
"""Initialize a virtual GPU using hosted software GL, without booting a guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or os.geteuid() != 0:
        raise SystemExit('Graphics preflight requires the disposable hosted resource unit')
    root = Path.cwd()
    process = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    group = process.parent
    assert process.name == 'supervisor' and group.name.startswith('symbi-graphics-') and group.name.endswith('.service')
    assert not (group / 'cgroup.procs').read_text().strip()
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group / name).read_text().strip() for name in names}
    assert limits == {'memory.max': '2147483648', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '256'}
    evidence = root / '.cache/hyprland-graphics-evidence'
    storage = root / '.cache/hyprland-graphics-storage'
    inputs = storage / 'inputs'
    output = storage / 'output'
    # Ubuntu 24.04's Podman limits runroot to 50 characters. Keep image layers
    # in the workspace, but use a fresh root-owned per-unit runtime directory.
    runroot = Path('/run') / group.name.removesuffix('.service')
    assert len(os.fsencode(runroot)) <= 50
    podman = ['podman', '--cgroup-manager=cgroupfs', '--root', str(storage / 'root'), '--runroot', str(runroot)]

    if sys.argv[1:] == ['--inside-xvfb']:
        # xvfb-run created a fresh cookie; it is never part of retained evidence.
        display = os.environ['DISPLAY']
        assert re.fullmatch(r':[0-9]+', display)
        x_socket = Path('/tmp/.X11-unix') / ('X' + display[1:])
        assert x_socket.is_socket() and not x_socket.is_symlink()
        authority = Path(os.environ['XAUTHORITY'])
        assert authority.is_file() and not authority.is_symlink() and authority.stat().st_size <= 4096
        shutil.copyfile(authority, inputs / 'xauthority')
        os.chmod(inputs / 'xauthority', 0o600)
        os.chown(inputs / 'xauthority', 10001, 10001)
        base = json.loads((evidence / 'selected-base.json').read_text())['image']
        command = podman + ['run', '--rm', '--pull=never', '--read-only', '--network=none',
                            '--user=10001:10001', '--hostname=' + socket.gethostname(),
                            '--cap-drop=ALL', '--security-opt=no-new-privileges',
                            '--memory=1g', '--memory-swap=1g', '--cpus=1', '--pids-limit=64',
                            '--cgroup-parent=/' + str(group.relative_to('/sys/fs/cgroup')),
                            '--mount', f'type=bind,src={inputs},dst=/inputs,ro',
                            '--mount', f'type=bind,src={output},dst=/output',
                            '--mount', f'type=bind,src={x_socket},dst={x_socket}',
                            '--env=DISPLAY=' + display, '--env=PYTHONDONTWRITEBYTECODE=1',
                            '--entrypoint=/usr/bin/python3', base, '/inputs/guest.py']
        subprocess.run(command, check=True, timeout=120)
        return
    if sys.argv[1:]:
        raise SystemExit('Unexpected argument')

    evidence.mkdir(parents=True, exist_ok=True)
    record = {'passed': False, 'os_qualified': False, 'guest_booted': False,
              'source_commit': os.environ['GITHUB_SHA'], 'limits': limits,
              'scope': 'Hosted graphics feasibility only; no compositor or OS boot qualification'}
    try:
        # Use only the runner's existing display tools. No mutable package install.
        for name in ('Xvfb', 'xvfb-run', 'xauth'):
            tool = shutil.which(name)
            assert tool, 'Runner lacks required display tool: ' + name
            with Path(tool).open('rb') as stream:
                record.setdefault('host_tools', {})[name] = {'path': tool, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
        record['host_tool_packages'] = subprocess.check_output(
            ['dpkg-query', '-W', '-f=${Package}\t${Version}\n', 'xvfb', 'xauth'], text=True, timeout=15)
        sys.path.insert(0, str(root / 'image/toolchain'))
        from bootstrap_cosign import bootstrap
        sys.path.insert(0, str(root / 'image'))
        from recipe import render
        sys.path.insert(0, str(root / 'image/hyprland'))
        from inventory import require_subject
        pins = json.loads((root / 'image/base-images.json').read_text())
        render(pins, 'generic', root)
        base = pins['variants']['generic']
        cosign = bootstrap(root, evidence)
        signature = subprocess.check_output([str(cosign), 'verify', '--key', str(root / base['public_key']),
                                             '--output', 'json', base['image']], text=True, timeout=180)
        require_subject(json.loads(signature), base['image'])
        (evidence / 'base-signature.json').write_text(signature)
        (evidence / 'selected-base.json').write_text(json.dumps(base, indent=2) + '\n')
        record['base'] = base['image']
        storage.mkdir(mode=0o700)
        runroot.mkdir(mode=0o700)
        for path in (inputs, output):
            path.mkdir(mode=0o700)
            os.chown(path, 10001, 10001)
        shutil.copyfile(root / 'image/hyprland/graphics/guest.py', inputs / 'guest.py')
        record['guest_probe_sha256'] = hashlib.sha256((inputs / 'guest.py').read_bytes()).hexdigest()
        auth = storage / 'auth.json'
        auth.write_text('{"auths": {}}\n')
        with (evidence / 'pull.log').open('w') as log:
            subprocess.run(podman + ['pull', '--authfile', str(auth), base['image']],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        with (evidence / 'probe.log').open('w') as log:
            subprocess.run(['xvfb-run', '--auto-servernum', '--error-file=' + str(evidence / 'xvfb.log'),
                            '--server-args=-screen 0 640x480x24 -nolisten tcp', sys.executable,
                            str(Path(__file__).resolve()), '--inside-xvfb'],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        guest = json.loads((output / 'result.json').read_text())
        assert guest['passed'] and not guest['os_qualified'] and not guest['guest_booted']
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        for name in ('result.json', 'qemu.log', 'without-gl.log'):
            path = output / name
            if path.is_file() and not path.is_symlink():
                shutil.copyfile(path, evidence / ('guest-' + name))
        (inputs / 'xauthority').unlink(missing_ok=True)
        record['cgroup_final'] = {name: (group / name).read_text().strip()
                                  for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        assert all(record['cgroup_final'][name] == value for name, value in limits.items())
        (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
