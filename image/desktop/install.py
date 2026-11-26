"""Verify and install the five signed runtime libraries inside the image build."""
import json
import os
from pathlib import Path
import platform

from inputs import required_package_delta, require_transaction
from package_identity import require_package_identity
from runtime_install import digest, snapshot_crypto_configuration
from resolve_packages import require_keyring, require_verified_rpm
from guest_inventory import require_fedora_family
from bounded_process import run_bounded


def main():
    inputs, output = Path('/symbi-build-inputs'), Path('/symbi-build-evidence')
    if (os.geteuid() != 0 or not (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists())
            or not inputs.is_dir() or not output.is_mount()):
        raise SystemExit('Use the isolated image build with its private evidence mount')
    release = platform.freedesktop_os_release()
    require_fedora_family(release)
    if release['VERSION_ID'] != '45': raise ValueError('Runtime packages require Fedora 45')
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {n: (group/n).read_text().strip() for n in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if any(limits[n] != value for n, value in {'memory.max':'2147483648', 'memory.swap.max':'0', 'cpu.max':'100000 100000'}.items()):
        raise ValueError('Image RUN memory/CPU/swap limits differ from the reviewed build')
    # The hosted controller separately records the enclosing 128-task cgroup.
    # Buildah does not expose a pids-limit build flag on the selected host.
    if sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']:
        raise ValueError('Offline image assembly must have only loopback')
    lock = json.loads((inputs/'combined-lock.json').read_text())
    if lock.get('schema') != 1 or lock.get('qualified') is not False or len(lock.get('packages', [])) != 5:
        raise ValueError('Expected the reviewed five-package runtime selection')
    key = inputs/'fedora-45-primary.asc'
    if digest(key) != lock['key']['sha256']: raise ValueError('Fedora key changed')
    record = {'passed': False, 'os_qualified': False, 'crypto_policy_qualified': False,
              'limits': limits, 'commands': [], 'target_base': lock['target_base'],
              'scope': 'Actual image package installation; dynamic TLS and boot/containment acceptance remain separate'}

    def save(): (output/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60):
        record['active_command'] = {'name': name, 'command': command}; save()
        result = run_bounded(command, output/(name+'-stdout.log'), output/(name+'-stderr.log'), timeout, 1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']; save(); result.check_returncode()
        return result

    try:
        before_config = snapshot_crypto_configuration(Path('/'))
        (output/'crypto-before.json').write_text(json.dumps(before_config, indent=2)+'\n')
        fmt = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        before = sorted(run('installed-before', ['rpm', '-qa', '--qf', fmt]).stdout.splitlines())
        for name in ('keyring', 'rpmdb', 'empty-repos', 'dnf-cache'): (output/name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath '+str(output/'keyring'),
                   '--dbpath', str(output/'rpmdb'), '--define', '_pkgverify_level all']
        run('import-key', rpmkeys+['--import', str(key)])
        require_keyring(run('keyring', rpmkeys+['--list']).stdout, lock['key']['fingerprint'])
        identities, packages = [], {}
        for index, row in enumerate(lock['packages']):
            path = inputs/'rpms'/row['filename']
            if (path.name != row['filename'] or path.is_symlink() or not path.is_file()
                    or path.stat().st_size != row['bytes'] or digest(path) != row['sha256']
                    or row.get('signature_verified') is not True or row['key_fingerprint'] != lock['key']['fingerprint']):
                raise ValueError('Runtime package bytes or signing identity changed')
            signature = run(f'rpm-{index}-signature', rpmkeys+['--checksig', '--verbose', str(path)])
            require_verified_rpm(signature.returncode, signature.stdout, lock['key']['fingerprint'])
            rows = run(f'rpm-{index}-identity', ['rpm', '-qp', '--qf', fmt, str(path)]).stdout.splitlines()
            if len(rows) != 1: raise ValueError('Ambiguous package identity')
            require_package_identity(rows[0], row['nevra'])
            identities.append(rows[0]); packages[rows[0]] = str(path)
        if {row.split('\t')[0] for row in identities} != {'libeis', 'muParser', 'tomlplusplus', 'gtk4-layer-shell', 'openssl3-libs'}:
            raise ValueError('Unexpected runtime package provider')
        delta = required_package_delta(before, identities)
        if delta:
            run('offline-install', ['dnf5', '--assumeyes', '--disable-plugin=*', '--setopt=reposdir='+str(output/'empty-repos'),
                                   '--setopt=cachedir='+str(output/'dnf-cache'), '--setopt=localpkg_gpgcheck=True',
                                   '--setopt=install_weak_deps=False', '--setopt=tsflags=nodocs',
                                   'install', '--', *[packages[row] for row in delta]], 600)
        after = sorted(run('installed-after', ['rpm', '-qa', '--qf', fmt]).stdout.splitlines())
        require_transaction(before, after, identities)
        after_config = snapshot_crypto_configuration(Path('/'))
        (output/'crypto-after.json').write_text(json.dumps(after_config, indent=2)+'\n')
        if any(after_config.get(k) != v for k, v in before_config.items()):
            raise ValueError('Original base crypto configuration changed')
        compatibility = Path('/etc/pki/tls/openssl3.cnf')
        if compatibility.is_symlink() or not compatibility.is_file() or compatibility.stat().st_size > 65536:
            raise ValueError('Expected bounded compatibility configuration')
        (output/'openssl3.cnf').write_bytes(compatibility.read_bytes())
        record.update(base_package_count=len(before), required_packages=identities, added_packages=delta,
                      all_base_packages_unchanged=True, base_crypto_configuration_unchanged=True,
                      compatibility_configuration_sha256=digest(compatibility), passed=True)
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {n: (group/n).read_text().strip() for n in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__': main()
