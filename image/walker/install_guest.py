#!/usr/bin/env python3
"""Install the reviewed compiler or runtime RPM set in a disposable stage."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from inputs import digest, require_additive, require_package_identity, require_rust_identity


def main():
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    if mode not in ('build', 'runtime') or os.geteuid() != 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the isolated authenticated Fedora package stage')
    from guest_inventory import require_fedora_family
    from resolve_packages import require_keyring, require_verified_rpm
    require_fedora_family(platform.freedesktop_os_release())
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output/'install-evidence'
    evidence.mkdir()
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '2147483648', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '128'}:
        raise ValueError('Unexpected signed-package installation limits')
    lock_name = 'walker-build-rpms.lock.json' if mode == 'build' else 'runtime-rpms.lock.json'
    lock = json.loads((inputs/lock_name).read_text())
    key = inputs/'fedora-45-primary.asc'
    if digest(key) != lock['key']['sha256'] or lock.get('qualified') is not False:
        raise ValueError('Unexpected key or qualification scope')
    record = {'passed': False, 'os_qualified': False, 'mode': mode, 'limits': limits, 'commands': [],
              'scope': 'Disposable signed package installation only; no product installation'}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
                                env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'})
        (evidence/(name+'.log')).write_text(result.stdout+result.stderr)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']
        save()
        result.check_returncode()
        return result.stdout

    try:
        fmt = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        before = sorted(run('installed-before', ['rpm', '-qa', '--qf', fmt]).splitlines())
        for name in ('keyring', 'rpmdb', 'empty-repos'):
            (output/name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
                   '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        run('import-key', rpmkeys+['--import', str(key)])
        require_keyring(run('keyring', rpmkeys+['--list']), lock['key']['fingerprint'])
        packages, expected = [], []
        for index, row in enumerate(lock['packages']):
            path = inputs/(mode+'-rpms/rpms')/row['filename']
            if (path.name != row['filename'] or path.is_symlink() or not path.is_file()
                    or path.stat().st_size != row['bytes'] or digest(path) != row['sha256']):
                raise ValueError('Signed package bytes changed')
            raw = run(f'rpm-{index:03}-signature', rpmkeys+['--checksig', '--verbose', str(path)])
            require_verified_rpm(0, raw, lock['key']['fingerprint'])
            identities = run(f'rpm-{index:03}-identity', ['rpm', '-qp', '--qf', fmt, str(path)]).splitlines()
            if len(identities) != 1 or len(identities[0].split('\t')) != 5:
                raise ValueError('Ambiguous RPM identity')
            require_package_identity(identities[0], row['nevra'])
            expected += identities
            packages.append(str(path))
        if len(packages) != (91 if mode == 'build' else 1) or any((output/'empty-repos').iterdir()):
            raise ValueError('Unexpected package count or enabled repository')
        require_additive(before, before+expected, expected)
        run('offline-install', ['dnf5', '--assumeyes', '--disable-plugin=*', '--setopt=reposdir=/output/empty-repos',
                               '--setopt=localpkg_gpgcheck=True', '--setopt=install_weak_deps=False',
                               '--setopt=tsflags=nodocs', 'install', '--', *packages], 600)
        after = sorted(run('installed-after', ['rpm', '-qa', '--qf', fmt]).splitlines())
        require_additive(before, after, expected)
        record['added_packages'] = expected
        record['all_base_packages_unchanged'] = True
        if mode == 'build':
            record['toolchain'] = {}
            for name in ('rustc', 'cargo'):
                raw = run(name+'-version', ['/usr/bin/'+name, '--version', '--verbose'])
                record['toolchain'][name] = {'identity': require_rust_identity(raw, name),
                                              'binary_sha256': digest(Path('/usr/bin')/name)}
            protoc = run('protoc-version', ['/usr/bin/protoc', '--version']).strip()
            if protoc != 'libprotoc 33.5':
                raise ValueError('Expected the signed protoc 33.5 compiler')
            record['protoc'] = {'version': protoc, 'binary_sha256': digest(Path('/usr/bin/protoc'))}
            native = {'gtk4': '4.12', 'gio-2.0': '2.80', 'gtk4-layer-shell-0': '1.0',
                      'poppler-glib': None, 'cairo': None, 'gdk-pixbuf-2.0': None, 'wayland-client': None}
            record['native_versions'] = {}
            for index, (name, minimum) in enumerate(native.items()):
                record['native_versions'][name] = run(f'native-{index}-version', ['/usr/bin/pkg-config', '--modversion', name]).strip()
                if minimum:
                    run(f'native-{index}-minimum', ['/usr/bin/pkg-config', '--atleast-version='+minimum, name])
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
