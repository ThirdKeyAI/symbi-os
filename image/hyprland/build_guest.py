#!/usr/bin/env python3
"""Install exact signed build RPMs offline, then drop root for compilation."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if os.getuid() != 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the disposable Fedora build container')
    from guest_inventory import require_fedora_family
    from resolve_packages import require_keyring, require_verified_rpm
    require_fedora_family(platform.freedesktop_os_release())
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output / 'evidence'
    evidence.mkdir()
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group / name).read_text().strip() for name in names}
    assert limits == {'memory.max': '6442450944', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '128'}
    lock = json.loads((inputs / 'build-rpms.lock.json').read_text())
    key = inputs / 'fedora-45-primary.asc'
    assert digest(key) == lock['key']['sha256']
    record = {'passed': False, 'os_qualified': False, 'limits': limits, 'commands': [],
              'scope': 'Disposable build stage only; its package transaction is not a product layer'}

    def save():
        (evidence / 'install.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, timeout=60):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        (evidence / (name + '.log')).write_text(result.stdout + result.stderr)
        record['commands'].append({'name': name, 'command': command, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()
        return result

    try:
        rpm_query = ['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']
        run('installed-before', rpm_query)
        for name in ('keyring', 'rpmdb', 'empty-repos'):
            (output / name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
                   '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        run('import-key', rpmkeys + ['--import', str(key)])
        require_keyring(run('keyring', rpmkeys + ['--list']).stdout, lock['key']['fingerprint'])
        packages = []
        for index, row in enumerate(lock['packages']):
            name = row['filename']
            assert Path(name).name == name and name.endswith('.rpm')
            path = inputs / 'packages/rpms' / name
            assert not path.is_symlink() and path.stat().st_size == row['bytes'] and digest(path) == row['sha256']
            checked = run(f'rpm-{index:03}-signature', rpmkeys + ['--checksig', '--verbose', str(path)])
            require_verified_rpm(checked.returncode, checked.stdout, lock['key']['fingerprint'])
            packages.append(str(path))
        # This container has --network=none and no product output mount. DNF is
        # allowed to change its disposable build filesystem only.
        assert not any((output / 'empty-repos').iterdir())
        run('offline-install', ['dnf5', '--assumeyes', '--disable-plugin=*',
                                '--setopt=reposdir=/output/empty-repos', '--setopt=localpkg_gpgcheck=True',
                                '--setopt=install_weak_deps=False', '--setopt=tsflags=nodocs',
                                'install', '--', *packages], timeout=600)
        run('installed-after', rpm_query)
        run('create-build-account', ['useradd', '--uid', '10001', '--user-group', '--no-create-home',
                                    '--home-dir', '/output/home', '--shell', '/bin/bash', 'symbi-build'])
        prefix = Path('/usr/lib/symbi/hyprland')
        prefix.mkdir(parents=True)
        os.chown(prefix, 10001, 10001)
        (output / 'home').mkdir(mode=0o700)
        for path in [output, *output.rglob('*')]:
            assert not path.is_symlink()
            os.chown(path, 10001, 10001)
        command = ['runuser', '-u', 'symbi-build', '--', 'env', '-i',
                   'HOME=/output/home', 'PATH=/usr/lib/symbi/hyprland/bin:/usr/bin:/bin',
                   'LANG=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1', 'CMAKE_BUILD_PARALLEL_LEVEL=1',
                   'PKG_CONFIG_PATH=/usr/lib/symbi/hyprland/lib/pkgconfig:/usr/lib/symbi/hyprland/share/pkgconfig',
                   'OMP_NUM_THREADS=1', 'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                   'python3', '/inputs/compile.py']
        run('compile-driver', command, timeout=6600)
        record['passed'] = True
    finally:
        save()
        counters = {name: (group / name).read_text().strip() for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence / 'build-cgroup-final.json').write_text(json.dumps(counters, indent=2) + '\n')


if __name__ == '__main__':
    main()
