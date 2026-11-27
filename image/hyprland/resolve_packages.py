#!/usr/bin/env python3
"""Discover and authenticate candidate build RPMs without installing any package."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_keyring(output, fingerprint):
    rows = [line.split() for line in output.splitlines() if line.strip()]
    if len(rows) != 1 or rows[0][0].upper() != fingerprint:
        raise ValueError('RPM keyring must contain only the pinned Fedora key')


def require_verified_rpm(status, output, fingerprint):
    if status != 0:
        raise ValueError('RPM verification command failed')
    elements = [line.strip() for line in output.splitlines() if line.startswith((' ', '\t'))]
    if not elements or any(not line.endswith(': OK') for line in elements):
        raise ValueError('RPM contains failed or unrecognized verification elements')
    signatures = [line for line in elements if ' signature,' in line.lower()]
    if not signatures or not any(line.startswith('Payload ') and ' digest: OK' in line for line in elements):
        raise ValueError('RPM needs a verified signature and payload digest, not digest-only success')
    for line in signatures:
        match = re.search(r'key fingerprint: ([0-9a-fA-F]{40}): OK$', line)
        if not match or fingerprint != match[1].upper():
            raise ValueError('Unexpected RPM signing key')


def package_specs(requirements):
    """Return the reviewed package specs accepted by the shared DNF workflow."""
    packages = requirements.get('packages')
    if (not isinstance(packages, list) or not packages
            or any(not isinstance(spec, str) or not spec or spec.startswith('-')
                   for spec in packages)):
        raise ValueError('Package requirements are invalid')
    return packages


def container_package_names(requirements):
    """Return strict package names suitable for installed-root RPM queries."""
    packages = package_specs(requirements)
    if (len(packages) != len(set(packages))
            or any(any(character.isspace() for character in name) for name in packages)):
        raise ValueError('Container runtime requirements must be duplicate-free package names')
    return packages


def validate_installed_roots(requirements, roots):
    """Bind candidate roots to the exact NEVRAs already in the selected base."""
    packages = container_package_names(requirements)
    if not isinstance(roots, dict) or list(roots) != packages:
        raise ValueError('Installed package roots are incomplete or reordered')
    for name, nevra in roots.items():
        if (not isinstance(nevra, str) or not nevra.startswith(name + '-')
                or any(character.isspace() for character in nevra)):
            raise ValueError('Installed package root is not an exact NEVRA')
    return roots


def requires_offline_closure(requirements):
    """Select the stricter retained-closure path only for the runtime profile."""
    return requirements.get('profile') == 'container-runtime'


def resolve_command(requirements, installed_roots=None):
    """Return the fixed no-transaction command for one reviewed package profile."""
    packages = package_specs(requirements)
    command = ['dnf5', '--config=/inputs/dnf.conf', '--releasever=45', '--assumeyes',
               '--disable-plugin=*']
    if requires_offline_closure(requirements):
        # The selected Secureblue base already contains the engine packages.
        # `install --downloadonly` therefore resolves an empty transaction.
        # DNF5's download command with --alldeps intentionally retains the
        # complete repository closure even when those packages are installed.
        roots = validate_installed_roots(requirements, installed_roots)
        return command + ['download', '--resolve', '--alldeps',
                          '--destdir', '/output/rpms', '--', *roots.values()]
    return command + ['install', '--downloadonly', '--', *packages]


def require_downloaded_roots(installed_roots, downloaded_nevras):
    """Require every exact installed root in the signed downloaded set."""
    expected = set(installed_roots.values())
    observed = set(downloaded_nevras)
    if not expected.issubset(observed):
        raise ValueError('Downloaded RPM roots differ from the selected base')
    return sorted(expected)


def main():
    if not Path('/run/.containerenv').exists() or os.geteuid() != 0:
        raise SystemExit('Use the disposable hosted Fedora discovery container')
    from guest_inventory import require_fedora_family
    require_fedora_family(platform.freedesktop_os_release())
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    assert limits == {'memory.max': '2147483648', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128'}
    inputs, output = Path('/inputs'), Path('/output')
    trust = json.loads((inputs / 'fedora-package-trust.json').read_text())
    requirements = json.loads((inputs / 'build-requirements.json').read_text())
    assert trust['release'] == platform.freedesktop_os_release()['VERSION_ID'] == '45'
    assert trust['architecture'] == platform.machine() == 'x86_64'
    key = inputs / 'fedora-45-primary.asc'
    assert digest(key) == trust['key']['sha256']
    fingerprint = trust['key']['fingerprint']
    evidence = output / 'evidence'
    evidence.mkdir()
    rpms = output / 'rpms'
    rpms.mkdir()
    record = {'schema': 1, 'scope': 'Candidate RPM download and signature verification; no package install or build',
              'base': trust['source']['image'], 'key': trust['key'], 'requirements': requirements,
              'limits': limits, 'commands': [], 'packages': [], 'passed': False, 'os_qualified': False}

    def save():
        (evidence / 'result.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, timeout=30, check=True):
        record['active_command'] = {'name': name, 'command': command}
        save()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        (evidence / (name + '.log')).write_text(result.stdout + result.stderr)
        record['commands'].append({'name': name, 'command': command, 'exit_code': result.returncode})
        del record['active_command']
        save()
        if check:
            result.check_returncode()
        return result

    rpm_query = ['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']
    before = sorted(run('installed-before', rpm_query).stdout.splitlines())
    for name in ('keyring', 'empty-keyring', 'rpmdb', 'gnupg'):
        (output / name).mkdir(mode=0o700)
    gpg = run('public-key', ['gpg', '--homedir', str(output / 'gnupg'), '--batch', '--no-options',
                             '--with-colons', '--show-keys', str(key)])
    assert [line.split(':')[9] for line in gpg.stdout.splitlines() if line.startswith('fpr:')] == [fingerprint]
    rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
               '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
    try:
        run('import-key', rpmkeys + ['--import', str(key)])
        require_keyring(run('keyring', rpmkeys + ['--list']).stdout, fingerprint)
        container_runtime = requires_offline_closure(requirements)
        installed_roots = None
        if container_runtime:
            installed_roots = {}
            for index, name in enumerate(container_package_names(requirements)):
                query = run(f'installed-root-{index:03}',
                            ['rpm', '-q', '--qf', '%{NEVRA}\n', '--', name])
                rows = [line.strip() for line in query.stdout.splitlines() if line.strip()]
                if len(rows) != 1:
                    raise ValueError('Selected base does not contain exactly one requested root')
                installed_roots[name] = rows[0]
            validate_installed_roots(requirements, installed_roots)
            record['installed_root_nevras'] = installed_roots
            save()
        # The root filesystem is read-only. DNF gets only the two reviewed Fedora
        # repos and private cache/log/state paths. Both command forms only download.
        command = resolve_command(requirements, installed_roots)
        run('resolve-download', command, timeout=1200)
        packages = sorted(rpms.glob('*.rpm'))
        if not packages or len(packages) > 512 or sum(p.stat().st_size for p in packages) > 2 * 1024**3:
            raise ValueError('Unexpected empty or excessive candidate package set')
        downloaded_nevras = []
        for index, package in enumerate(packages):
            assert package.is_file() and not package.is_symlink()
            verified = run(f'rpm-{index:03}-signature', rpmkeys + ['--checksig', '--verbose', str(package)], check=False)
            require_verified_rpm(verified.returncode, verified.stdout, fingerprint)
            query = run(f'rpm-{index:03}-identity', ['rpm', '-qp', '--qf', '%{NEVRA}\t%{VENDOR}\t%{LICENSE}\n', str(package)])
            nevra, vendor, license_name = query.stdout.strip().split('\t')
            if nevra in downloaded_nevras:
                raise ValueError('Candidate closure contains a duplicate NEVRA')
            downloaded_nevras.append(nevra)
            record['packages'].append({'filename': package.name, 'bytes': package.stat().st_size,
                                       'sha256': digest(package), 'nevra': nevra, 'vendor': vendor,
                                       'license': license_name, 'signature_verified': True,
                                       'key_fingerprint': fingerprint})
            save()
        if container_runtime:
            record['downloaded_root_nevras'] = require_downloaded_roots(
                installed_roots, downloaded_nevras)
            closure_root = output / 'closure-root'
            closure_root.mkdir(mode=0o700)
            run('closure-rpmdb-init', ['rpm', '--root', str(closure_root),
                                      '--dbpath', '/var/lib/rpm', '--initdb'])
            closure_before = run(
                'closure-installed-before',
                ['rpm', '--root', str(closure_root), '--dbpath', '/var/lib/rpm',
                 '-qa', '--qf', '%{NEVRA}\n']).stdout
            if closure_before:
                raise ValueError('Offline closure root is not empty')
            run('offline-closure-test',
                ['rpm', '--root', str(closure_root), '--dbpath', '/var/lib/rpm',
                 '--test', '--noscripts', '--notriggers', '--nosignature', '-Uvh',
                 *[str(package) for package in packages]], timeout=1200)
            closure_after = run(
                'closure-installed-after',
                ['rpm', '--root', str(closure_root), '--dbpath', '/var/lib/rpm',
                 '-qa', '--qf', '%{NEVRA}\n']).stdout
            if closure_after:
                raise ValueError('Offline closure test installed packages')
            for package, row in zip(packages, record['packages'], strict=True):
                if package.stat().st_size != row['bytes'] or digest(package) != row['sha256']:
                    raise ValueError('Candidate RPM changed after closure verification')
            record['offline_closure_verified'] = True
            record['closure_package_count'] = len(packages)
            save()
        probe = max(packages, key=lambda p: p.stat().st_size)
        empty = rpmkeys.copy()
        empty[empty.index('_keyringpath /output/keyring')] = '_keyringpath /output/empty-keyring'
        missing = run('missing-key-control', empty + ['--checksig', '--verbose', str(probe)], check=False)
        assert missing.returncode != 0, 'An untrusted key must fail real RPM verification'
        tampered = output / 'tampered.rpm'
        shutil.copyfile(probe, tampered)
        with tampered.open('r+b') as stream:
            stream.seek(tampered.stat().st_size // 2)
            byte = stream.read(1)
            stream.seek(-1, 1)
            stream.write(bytes([byte[0] ^ 1]))
        invalid = run('tampered-package-control', rpmkeys + ['--checksig', '--verbose', str(tampered)], check=False)
        assert invalid.returncode != 0, 'Changed package bytes must fail real RPM verification'
        tampered.unlink()
        after = sorted(run('installed-after', rpm_query).stdout.splitlines())
        assert before == after, 'Discovery must not change installed packages'
        record['installed_packages_unchanged'] = True
        record['negative_controls'] = {'missing_key_rejected': True, 'tampered_package_rejected': True}
        record['passed'] = True
        save()
    except BaseException as error:
        record['failure'] = str(error)
        save()
        raise
    finally:
        final = {name: (group / name).read_text().strip() for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        (evidence / 'cgroup-final.json').write_text(json.dumps(final, indent=2) + '\n')
        assert all(final[name] == value for name, value in limits.items())


if __name__ == '__main__':
    main()
