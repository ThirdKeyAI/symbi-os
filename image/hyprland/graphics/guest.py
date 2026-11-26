#!/usr/bin/env python3
"""Probe virtual graphics initialization, without a guest disk or guest boot."""
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import time


def message(stream):
    line = stream.readline(16385)
    if not line or len(line) > 16384:
        raise ValueError('Missing or oversized QMP response')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('QMP response must be an object')
    return value


def request(stream, name, arguments=None):
    command = {'execute': name, 'id': name}
    if arguments is not None:
        command['arguments'] = arguments
    stream.write(json.dumps(command).encode() + b'\n')
    stream.flush()
    for _ in range(20):
        result = message(stream)
        if 'event' in result:
            continue
        if result.get('id') != name or 'error' in result or 'return' not in result:
            raise ValueError('Unexpected QMP response: ' + repr(result))
        return result['return']
    raise ValueError('QMP response exceeded event bound')


def main():
    if os.geteuid() == 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Run only in the disposable unprivileged Fedora container')
    fields = platform.freedesktop_os_release()
    if fields.get('ID') != 'secureblue' or 'fedora' not in fields.get('ID_LIKE', '').split():
        raise SystemExit('Selected secureblue base required')
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max')}
    assert limits == {'memory.max': '1073741824', 'memory.swap.max': '0', 'cpu.max': '100000 100000'}
    output = Path('/output')
    binary = Path('/usr/bin/qemu-system-x86_64')
    with binary.open('rb') as stream:
        binary_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    result = {'passed': False, 'os_qualified': False, 'guest_booted': False,
              'scope': 'QEMU GL device and private X11 display initialization only; guest rendering remains untested',
              'qemu_sha256': binary_hash, 'limits': limits, 'commands': []}

    def save():
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    env = {'PATH': '/usr/bin:/bin', 'HOME': '/output', 'XDG_RUNTIME_DIR': '/output/runtime',
           'DISPLAY': os.environ['DISPLAY'], 'XAUTHORITY': '/inputs/xauthority',
           'SDL_VIDEODRIVER': 'x11', 'LIBGL_ALWAYS_SOFTWARE': '1',
           'GALLIUM_DRIVER': 'llvmpipe', 'LP_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1',
           'LANG': 'C.UTF-8'}
    Path(env['XDG_RUNTIME_DIR']).mkdir(mode=0o700)
    common = [str(binary), '-machine', 'q35,accel=tcg', '-m', '256M', '-smp', '1',
              '-nodefaults', '-no-user-config', '-S', '-device', 'virtio-vga-gl,id=symbi-gpu',
              '-monitor', 'none', '-serial', 'none', '-net', 'none']
    child = None
    try:
        result['qemu_version'] = subprocess.check_output([str(binary), '--version'], text=True, timeout=15)
        packages = subprocess.check_output(['rpm', '-q', 'qemu-system-x86-core', 'qemu-ui-sdl',
                                           'qemu-ui-opengl', 'qemu-device-display-virtio-vga-gl',
                                           'virglrenderer', 'mesa-dri-drivers'], text=True, timeout=15)
        result['graphics_packages'] = packages.splitlines()
        negative = subprocess.run(common + ['-display', 'none'], env=env, cwd=output,
                                  capture_output=True, text=True, timeout=20)
        (output / 'without-gl.log').write_text(negative.stdout + negative.stderr)
        result['negative_control'] = {'exit_code': negative.returncode,
                                      'passed': negative.returncode != 0 and 'opengl' in negative.stderr.lower()}
        save()
        assert result['negative_control']['passed'], 'GL device must refuse a display without OpenGL'
        command = common + ['-display', 'sdl,gl=on', '-qmp', 'unix:/output/qmp.sock,server=on,wait=off']
        result['commands'].append(command)
        with (output / 'qemu.log').open('w') as log:
            child = subprocess.Popen(command, cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT)
            end = time.monotonic() + 30
            while not (output / 'qmp.sock').is_socket():
                if child.poll() is not None or time.monotonic() >= end:
                    raise RuntimeError('QEMU GL initialization failed; inspect qemu.log')
                time.sleep(0.1)
            with socket.socket(socket.AF_UNIX) as channel:
                channel.settimeout(10)
                channel.connect('/output/qmp.sock')
                with channel.makefile('rwb') as stream:
                    greeting = message(stream)
                    assert 'QMP' in greeting
                    result['greeting'] = greeting
                    request(stream, 'qmp_capabilities')
                    result['status'] = request(stream, 'query-status')
                    result['device_realized'] = request(stream, 'qom-get',
                        {'path': '/machine/peripheral/symbi-gpu', 'property': 'realized'})
                    assert result['status']['running'] is False and result['device_realized'] is True
                    request(stream, 'quit')
            child.wait(timeout=10)
            assert child.returncode == 0
        result['passed'] = True
    except Exception as error:
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        if child is not None and child.poll() is None:
            try:
                child.terminate()
                child.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as error:
                result['cleanup_error'] = type(error).__name__ + ': ' + str(error)
                result['passed'] = False
        result['cgroup_final'] = {name: (group / name).read_text().strip()
                                  for name in ('memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
