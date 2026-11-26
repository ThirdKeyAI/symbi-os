"""Install the reviewed compatibility RPM offline, preserving original inputs."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require_runtime_rpms(lock, base, requirements, trust):
    if (lock.get('schema') != 1 or lock.get('qualified') is not False
            or lock.get('product_installation') is not False or lock.get('base') != base
            or trust['source']['image'] != base or lock.get('key') != trust['key']
            or lock.get('requirements') != requirements
            or requirements.get('expected_provider') != 'openssl3-libs'
            or requirements.get('packages') != ['libssl.so.3()(64bit)', 'libcrypto.so.3()(64bit)']
            or not isinstance(lock.get('packages'), list) or len(lock['packages']) != 1):
        raise ValueError('Runtime RPM inputs differ from the reviewed additive compatibility input')
    row = lock['packages'][0]
    if (row.get('signature_verified') is not True or row.get('key_fingerprint') != trust['key']['fingerprint']
            or not re.fullmatch(r'openssl3-libs-[0-9][A-Za-z0-9.+:~_-]*\.fc45\.x86_64', row.get('nevra', ''))
            or not re.fullmatch(r'openssl3-libs-[0-9][A-Za-z0-9.+~_-]*\.fc45\.x86_64\.rpm', row.get('filename', ''))
            or type(row.get('bytes')) is not int or not 0 < row['bytes'] <= 16*1024**2
            or not re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', ''))):
        raise ValueError('Expected exactly the signed Fedora OpenSSL 3 compatibility library')


def snapshot_crypto_configuration(root):
    selected = set()
    for directory in ('etc', 'usr/etc', 'usr/share/factory/etc', 'usr/share/secureblue/etc'):
        selected.update((directory+'/crypto-policies/config', directory+'/crypto-policies/state/CURRENT.pol',
                         directory+'/crypto-policies/back-ends/opensslcnf.config', directory+'/pki/tls/openssl.cnf'))
        crypto = root/directory/'crypto-policies'
        if crypto.is_dir():
            for path in crypto.rglob('*'):
                if path.suffix in ('.config', '.pol', '.pmod', '.txt') or path.name == 'config':
                    selected.add(path.relative_to(root).as_posix())
    if len(selected) > 1024:raise ValueError('Excessive base crypto configuration')
    result = {}
    for relative in sorted(selected):
        path = root/relative
        if not path.exists() and not path.is_symlink():
            result[relative] = None
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(root):raise ValueError('Crypto configuration link escapes the image root')
        link = os.readlink(path) if path.is_symlink() else None
        if not resolved.exists():
            result[relative] = {'link': link, 'sha256': None}
            continue
        if not resolved.is_file() or resolved.stat().st_size > 65536:
            raise ValueError('Expected bounded regular crypto configuration')
        result[relative] = {'link': link, 'sha256': digest(resolved), 'mode': stat.S_IMODE(resolved.stat().st_mode)}
    return result


def main():
    if (os.geteuid() != 0 or not Path('/run/.containerenv').exists()
            or os.environ.get('GITHUB_ACTIONS') != 'true'):
        raise SystemExit('Use the disposable hosted offline runtime-install stage')
    from bounded_process import run_bounded
    from guest_inventory import require_fedora_family
    from package_identity import require_additive, require_package_identity
    from resolve_packages import require_keyring, require_verified_rpm
    import platform
    require_fedora_family(platform.freedesktop_os_release())
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '2147483648', 'memory.swap.max': '0',
                  'cpu.max': '100000 100000', 'pids.max': '128'}:
        raise ValueError('Unexpected offline-install resource limits')
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output/'install-evidence'
    evidence.mkdir()
    lock = json.loads((inputs/'runtime-rpms.lock.json').read_text())
    trust = json.loads((inputs/'fedora-package-trust.json').read_text())
    requirements = json.loads((inputs/'requirements.json').read_text())
    require_runtime_rpms(lock, trust['source']['image'], requirements, trust)
    record = {'passed': False, 'os_qualified': False, 'crypto_policy_qualified': False,
              'limits': limits, 'commands': [], 'scope': 'Offline additive library installation and configuration evidence; no boot, TLS policy or containment qualification'}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

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
        key = inputs/'fedora-45-primary.asc'
        if key.is_symlink() or digest(key) != trust['key']['sha256']:raise ValueError('Fedora verification key changed')
        format_string = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        query = ['rpm', '-qa', '--qf', format_string]
        before = sorted(run('installed-before', query).stdout.splitlines())
        crypto_before = snapshot_crypto_configuration(Path('/'))
        (evidence/'crypto-configuration-before.json').write_text(json.dumps(crypto_before, indent=2)+'\n')
        for name in ('keyring', 'rpmdb', 'empty-repos'):(output/name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
                   '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        run('import-key', rpmkeys+['--import', str(key)])
        require_keyring(run('keyring', rpmkeys+['--list']).stdout, trust['key']['fingerprint'])
        row = lock['packages'][0]
        package = inputs/'packages/rpms'/row['filename']
        if package.is_symlink() or package.stat().st_size != row['bytes'] or digest(package) != row['sha256']:
            raise ValueError('Compatibility RPM bytes changed')
        signature = run('rpm-signature', rpmkeys+['--checksig', '--verbose', str(package)])
        require_verified_rpm(signature.returncode, signature.stdout, trust['key']['fingerprint'])
        identities = run('rpm-identity', ['rpm', '-qp', '--qf', format_string, str(package)]).stdout.splitlines()
        if len(identities) != 1:raise ValueError('Ambiguous runtime RPM identity')
        require_package_identity(identities[0], row['nevra'])
        if any(value.split('\t')[0] == 'openssl3-libs' for value in before):
            raise ValueError('Compatibility transaction must be additive')
        run('offline-install', ['dnf5', '--assumeyes', '--disable-plugin=*',
                               '--setopt=reposdir=/output/empty-repos', '--setopt=localpkg_gpgcheck=True',
                               '--setopt=install_weak_deps=False', '--setopt=tsflags=nodocs',
                               'install', '--', str(package)], 300)
        after = sorted(run('installed-after', query).stdout.splitlines())
        require_additive(before, after, identities)
        crypto_after = snapshot_crypto_configuration(Path('/'))
        (evidence/'crypto-configuration-after.json').write_text(json.dumps(crypto_after, indent=2)+'\n')
        if any(crypto_after.get(name) != value for name, value in crypto_before.items()):
            raise ValueError('Compatibility installation changed an original crypto configuration')
        paths = run('compatibility-owned-files', ['rpm', '-ql', 'openssl3-libs']).stdout.splitlines()
        configs = {}
        for name in paths:
            path = Path(name)
            if path.suffix != '.cnf':continue
            if not path.is_absolute() or '..' in path.parts or not path.is_file() or path.stat().st_size > 65536:
                raise ValueError('Unexpected compatibility configuration path')
            data = path.read_bytes()
            if b'PRIVATE KEY-----' in data:raise ValueError('Unexpected private material in package configuration')
            destination = evidence/'compatibility-configs'/path.relative_to('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            configs[name] = digest(path)
        record.update(added_packages=identities, base_package_count=len(before),
                      all_base_packages_unchanged=True, base_crypto_configuration_unchanged=True,
                      compatibility_configuration_sha256=configs, passed=True)
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__':
    main()
