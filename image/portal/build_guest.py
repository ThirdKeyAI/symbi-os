"""Verify and install signed build RPMs offline, then compile without root."""
import json
import os
from pathlib import Path
import platform


def main():
    if os.getuid() != 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the disposable Fedora portal build container')
    from bounded_process import run_bounded
    from guest_inventory import require_fedora_family
    from resolve_packages import require_keyring, require_verified_rpm
    from reuse import digest, unique_json
    require_fedora_family(platform.freedesktop_os_release())
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output/'evidence'
    evidence.mkdir()
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    names = ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')
    limits = {name: (group/name).read_text().strip() for name in names}
    if limits != {'memory.max': '6442450944', 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '128'}:
        raise ValueError('Unexpected portal build container resource limits')
    lock = unique_json((inputs/'build-rpms.lock.json').read_bytes())
    key = inputs/'fedora-45-primary.asc'
    if digest(key) != lock['key']['sha256']:raise ValueError('Fedora signing key changed')
    record = {'passed': False, 'os_qualified': False, 'limits': limits, 'commands': [],
              'scope': 'Offline disposable compiler filesystem; its RPM transaction is not a product layer'}

    def save():
        (evidence/'install.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()
        return result

    try:
        query = ['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']
        run('installed-before', query)
        for name in ('keyring', 'rpmdb', 'empty-repos'):(output/name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
                   '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        run('import-key', rpmkeys+['--import', str(key)])
        require_keyring(run('keyring', rpmkeys+['--list']).stdout, lock['key']['fingerprint'])
        packages = []
        for index, row in enumerate(lock['packages']):
            name = row['filename']
            if Path(name).name != name or not name.endswith('.rpm'):raise ValueError('Unexpected RPM name')
            path = inputs/'packages/rpms'/name
            if path.is_symlink() or path.stat().st_size != row['bytes'] or digest(path) != row['sha256']:
                raise ValueError('Build package bytes changed')
            checked = run(f'rpm-{index:03}-signature', rpmkeys+['--checksig', '--verbose', str(path)])
            require_verified_rpm(checked.returncode, checked.stdout, lock['key']['fingerprint'])
            packages.append(str(path))
        if any((output/'empty-repos').iterdir()):raise ValueError('Offline repository directory must be empty')
        run('offline-install', ['dnf5', '--assumeyes', '--disable-plugin=*', '--setopt=reposdir=/output/empty-repos',
                               '--setopt=localpkg_gpgcheck=True', '--setopt=install_weak_deps=False',
                               '--setopt=tsflags=nodocs', 'install', '--', *packages], 600)
        run('installed-after', query)
        run('create-build-account', ['useradd', '--uid', '10001', '--user-group', '--no-create-home',
                                    '--home-dir', '/output/home', '--shell', '/bin/bash', 'symbi-build'])
        (output/'home').mkdir(mode=0o700)
        (output/'runtime').mkdir(mode=0o700)
        for path in [output, *output.rglob('*')]:
            if path.is_symlink():raise ValueError('Unexpected pre-build output link')
            os.chown(path, 10001, 10001)
        command = ['runuser', '-u', 'symbi-build', '--', 'env', '-i', 'HOME=/output/home',
                   'PATH=/usr/lib/symbi/portal/bin:/usr/lib/symbi/hyprland/bin:/usr/bin:/bin',
                   'LANG=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1', 'CMAKE_BUILD_PARALLEL_LEVEL=1',
                   'PKG_CONFIG_PATH=/usr/lib/symbi/portal/lib/pkgconfig:/usr/lib/symbi/hyprland/lib/pkgconfig:/usr/lib/symbi/hyprland/share/pkgconfig',
                   'OMP_NUM_THREADS=1', 'LP_NUM_THREADS=1', 'LIBGL_ALWAYS_SOFTWARE=1', 'EGL_PLATFORM=surfaceless',
                   'XDG_RUNTIME_DIR=/output/runtime',
                   'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null', 'python3', '/inputs/compile.py']
        run('compile-driver', command, 3600)
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        save()
        counters = {name: (group/name).read_text().strip() for name in (*names, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence/'build-cgroup-final.json').write_text(json.dumps(counters, indent=2)+'\n')


if __name__ == '__main__':
    main()
