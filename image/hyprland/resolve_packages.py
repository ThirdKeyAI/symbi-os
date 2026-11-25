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
    signatures = [line for line in elements if 'Signature' in line]
    if not signatures or not any(line.startswith('Payload ') and ' digest: OK' in line for line in elements):
        raise ValueError('RPM needs a verified signature and payload digest, not digest-only success')
    for line in signatures:
        match = re.search(r'key ID ([0-9a-fA-F]{8,40}): OK$', line)
        if not match or not fingerprint.endswith(match[1].upper()):
            raise ValueError('Unexpected RPM signing key')


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
        # The root filesystem is read-only. DNF gets only the two reviewed Fedora
        # repos and private cache/log/state paths. --downloadonly runs no RPM transaction.
        command = ['dnf5', '--config=/inputs/dnf.conf', '--releasever=45', '--assumeyes',
                   '--disable-plugin=*', 'install', '--downloadonly', '--', *requirements['packages']]
        run('resolve-download', command, timeout=1200)
        packages = sorted(rpms.glob('*.rpm'))
        if not packages or len(packages) > 512 or sum(p.stat().st_size for p in packages) > 2 * 1024**3:
            raise ValueError('Unexpected empty or excessive candidate package set')
        for index, package in enumerate(packages):
            assert package.is_file() and not package.is_symlink()
            verified = run(f'rpm-{index:03}-signature', rpmkeys + ['--checksig', '--verbose', str(package)], check=False)
            require_verified_rpm(verified.returncode, verified.stdout, fingerprint)
            query = run(f'rpm-{index:03}-identity', ['rpm', '-qp', '--qf', '%{NEVRA}\t%{VENDOR}\t%{LICENSE}\n', str(package)])
            nevra, vendor, license_name = query.stdout.strip().split('\t')
            record['packages'].append({'filename': package.name, 'bytes': package.stat().st_size,
                                       'sha256': digest(package), 'nevra': nevra, 'vendor': vendor,
                                       'license': license_name, 'signature_verified': True,
                                       'key_fingerprint': fingerprint})
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
