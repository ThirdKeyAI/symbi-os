#!/usr/bin/env python3
"""Compile reviewed compositor sources without network or root privileges."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


PREFIX = Path('/usr/lib/symbi/hyprland')


def main():
    if os.getuid() != 10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the disposable unprivileged Fedora build account')
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output / 'evidence'
    sources = output / 'sources'
    shutil.copytree(inputs / 'sources', sources)
    record = {'passed': False, 'os_qualified': False, 'checks': [],
              'scope': 'Offline source compilation in a disposable Fedora development stage',
              'prefix': str(PREFIX), 'source_revisions': json.loads((inputs / 'source-revisions.json').read_text())}

    def save():
        (evidence / 'compile.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, cwd=None, timeout=3600):
        record['active_check'] = {'name': name, 'command': command}
        save()
        started = time.monotonic()
        with (evidence / (name + '.log')).open('w') as log:
            result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        record['checks'].append({'name': name, 'command': command, 'exit_code': result.returncode,
                                 'elapsed_seconds': time.monotonic() - started})
        del record['active_check']
        save()
        result.check_returncode()

    pin = json.loads((inputs / 'patch-inputs.json').read_text())
    patch = inputs / 'native-loading.patch'
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == pin['patch_sha256']
    hyprland = sources / 'Hyprland'
    for name, hashes in pin['files'].items():
        assert hashlib.sha256((hyprland / name).read_bytes()).hexdigest() == hashes['source_sha256']
    run('apply-check', ['git', 'apply', '--check', str(patch)], hyprland, 30)
    run('apply-patch', ['git', 'apply', str(patch)], hyprland, 30)
    for name, hashes in pin['files'].items():
        assert hashlib.sha256((hyprland / name).read_bytes()).hexdigest() == hashes['patched_sha256']
    common = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(PREFIX),
              '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_INSTALL_RPATH=' + str(PREFIX / 'lib'),
              '-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON', '-DCMAKE_PREFIX_PATH=' + str(PREFIX),
              '-DFETCHCONTENT_FULLY_DISCONNECTED=ON', '-DFETCHCONTENT_UPDATES_DISCONNECTED=ON',
              '-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG -g0', '-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG -g0']
    order = ['glaze', 'hyprutils', 'hyprwayland-scanner', 'hyprland-protocols',
             'hyprlang', 'hyprcursor', 'hyprgraphics', 'aquamarine', 'Hyprland']
    try:
        for name in order:
            source, build = sources / name, output / 'build' / name
            options = []
            if name == 'glaze':
                options = ['-Dglaze_DEVELOPER_MODE=OFF', '-Dglaze_BUILD_EXAMPLES=OFF']
            if name == 'Hyprland':
                options = ['-DNO_HYPRPM=ON', '-DUSE_TRACY=OFF', '-DNO_UWSM=ON',
                           '-Dglaze_DIR=' + str(PREFIX / 'lib/cmake/glaze')]
            run(name + '-configure', ['cmake', '-S', str(source), '-B', str(build), *common, *options], timeout=300)
            run(name + '-build', ['cmake', '--build', str(build), '--parallel', '1'], timeout=5400)
            run(name + '-install', ['cmake', '--install', str(build)], timeout=300)
        assert not (PREFIX / 'bin/hyprpm').exists()
        for name in ('Hyprland', 'hyprctl'):
            path = PREFIX / 'bin' / name
            assert path.is_file() and not path.is_symlink()
            run(name + '-needed-libraries', ['ldd', str(path)], timeout=30)
            assert 'not found' not in (evidence / (name + '-needed-libraries.log')).read_text()
        record['passed'] = True
    finally:
        save()


if __name__ == '__main__':
    main()
