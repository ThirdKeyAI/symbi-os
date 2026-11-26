#!/usr/bin/env python3
"""Install only the signed Go compiler in a disposable Fedora build stage."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_additive(before, after, expected):
    if any(len(rows) != len(set(rows)) for rows in (before, after, expected)):
        raise ValueError('Ambiguous duplicate package identity')
    if not set(before).issubset(after) or set(after) - set(before) != set(expected):
        raise ValueError('Runtime transaction must preserve the base and add only reviewed packages')


def main():
    if os.geteuid() != 0 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the disposable authenticated Fedora runtime container')
    from guest_inventory import require_fedora_family
    from resolve_packages import require_keyring, require_verified_rpm
    from go_identity import require_compiler
    require_fedora_family(platform.freedesktop_os_release())
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output / 'toolchain-evidence'
    evidence.mkdir()
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    assert limits == {'memory.max': '2147483648', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128'}
    lock = json.loads((inputs / 'build-rpms.lock.json').read_text())
    key = inputs / 'fedora-45-primary.asc'
    assert digest(key) == lock['key']['sha256']
    record = {'passed': False, 'os_qualified': False, 'limits': limits, 'commands': [],
              'scope': 'Disposable signed Go compiler installation only; no product installation or acceptance'}

    def save():
        (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')

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
        format_string = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        query = ['rpm', '-qa', '--qf', format_string]
        before = sorted(run('installed-before', query).stdout.splitlines())
        for name in ('keyring', 'rpmdb', 'empty-repos'):
            (output / name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
                   '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        run('import-key', rpmkeys + ['--import', str(key)])
        require_keyring(run('keyring', rpmkeys + ['--list']).stdout, lock['key']['fingerprint'])
        packages, expected = [], []
        for index, row in enumerate(lock['packages']):
            path = inputs / 'packages/rpms' / row['filename']
            assert path.name == row['filename'] and path.is_file() and not path.is_symlink()
            assert path.stat().st_size == row['bytes'] and digest(path) == row['sha256']
            response = run(f'rpm-{index:03}-signature', rpmkeys + ['--checksig', '--verbose', str(path)])
            require_verified_rpm(response.returncode, response.stdout, lock['key']['fingerprint'])
            identities = run(f'rpm-{index:03}-identity', ['rpm', '-qp', '--qf', format_string, str(path)]).stdout.splitlines()
            assert len(identities) == 1 and identities[0] not in before
            expected += identities
            packages.append(str(path))
        assert len(packages) == 5 and not any((output / 'empty-repos').iterdir())
        assert {row['nevra'].rsplit('-', 2)[0] for row in lock['packages']} == {
            'go-filesystem', 'golang', 'golang-bin', 'golang-src', 'tesseract'}
        run('offline-runtime-install', ['dnf5', '--assumeyes', '--disable-plugin=*',
                                       '--setopt=reposdir=/output/empty-repos', '--setopt=localpkg_gpgcheck=True',
                                       '--setopt=install_weak_deps=False', '--setopt=tsflags=nodocs',
                                       'install', '--', *packages], timeout=300)
        after = sorted(run('installed-after', query).stdout.splitlines())
        require_additive(before, after, expected)
        record['added_packages'] = sorted(expected)
        record['all_base_packages_unchanged'] = True
        compiler_env = ['env', 'GOTOOLCHAIN=local', 'GOENV=off', 'GOPROXY=off', 'CGO_ENABLED=1']
        version = run('go-version', compiler_env+['go', 'version']).stdout.strip()
        record['go_version'] = version
        identity = json.loads(run('go-identity', compiler_env+['go', 'env', '-json',
                                  'GOVERSION', 'GOOS', 'GOARCH', 'GOTOOLCHAIN', 'CGO_ENABLED', 'GOEXPERIMENT']).stdout)
        record['go_identity'] = identity
        require_compiler(identity)
        record['ocr_tool_version'] = run('ocr-tool-version', ['/usr/bin/tesseract', '--version']).stdout.strip()
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group / name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
