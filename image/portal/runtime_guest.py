"""Install one authenticated runtime library and probe the retained portal."""
import json
import os
from pathlib import Path
import platform
import shutil


def main():
    if (os.geteuid() != 0 or not Path('/run/.containerenv').exists()
            or os.environ.get('GITHUB_ACTIONS') != 'true'):
        raise SystemExit('Use the disposable hosted offline portal runtime stage')
    from bounded_process import run_bounded
    from desktop_inputs import required_package_delta, require_transaction
    from guest_inventory import require_fedora_family
    from package_identity import require_package_identity
    from resolve_packages import require_keyring, require_verified_rpm
    from runtime_inputs import GUEST_LIMITS, LOADER_PROBES, require_runtime_result, select_runtime_package
    from runtime_install import digest, snapshot_crypto_configuration
    from reuse import unique_json
    release = platform.freedesktop_os_release()
    require_fedora_family(release)
    if release['VERSION_ID'] != '45': raise ValueError('Portal runtime requires Fedora 45')
    if sorted(path.name for path in Path('/sys/class/net').iterdir()) != ['lo']:
        raise ValueError('Portal runtime must have only loopback')
    group = Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip() for name in GUEST_LIMITS}
    if limits != GUEST_LIMITS: raise ValueError('Unexpected portal runtime resource limits')
    inputs, output = Path('/inputs'), Path('/output')
    evidence = output/'evidence'
    evidence.mkdir()
    lock = unique_json((inputs/'build-rpms.lock.json').read_bytes())
    package = select_runtime_package(lock)
    pins = unique_json((inputs/'source-inputs.json').read_bytes())
    version = next(row['version'] for row in pins['components'] if row['name'] == 'xdg-desktop-portal-hyprland')
    record = {'passed': False, 'os_qualified': False, 'consent_qualified': False,
              'limits': limits, 'commands': [], 'runtime_package': package,
              'loader_probes': [], 'scope': 'Additive runtime library and unprivileged loader/CLI checks; no GUI or consent qualification'}

    def save(): (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60, check=True):
        record['active_command'] = {'name': name, 'command': command}; save()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'),
                             timeout=timeout, max_bytes=1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']; save()
        if check: result.check_returncode()
        return result

    try:
        key = inputs/'fedora-45-primary.asc'
        if key.is_symlink() or not key.is_file() or digest(key) != lock['key']['sha256']:
            raise ValueError('Fedora verification key changed')
        path = inputs/'rpms'/package['filename']
        if (path.is_symlink() or not path.is_file() or path.stat().st_size != package['bytes']
                or digest(path) != package['sha256']):
            raise ValueError('Portal runtime RPM bytes changed')
        fmt = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
        before = sorted(run('installed-before', ['rpm', '-qa', '--qf', fmt]).stdout.splitlines())
        crypto_before = snapshot_crypto_configuration(Path('/'))
        (evidence/'crypto-before.json').write_text(json.dumps(crypto_before, indent=2)+'\n')
        for name in ('keyring', 'empty-keyring', 'rpmdb', 'empty-repos', 'dnf-cache'):
            (output/name).mkdir(mode=0o700)
        rpmkeys = ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/keyring',
                   '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        run('import-key', rpmkeys+['--import', str(key)])
        require_keyring(run('keyring', rpmkeys+['--list']).stdout, lock['key']['fingerprint'])
        signature = run('rpm-signature', rpmkeys+['--checksig', '--verbose', str(path)])
        require_verified_rpm(signature.returncode, signature.stdout, lock['key']['fingerprint'])
        missing_key = rpmkeys.copy()
        missing_key[missing_key.index('_keyringpath /output/keyring')] = '_keyringpath /output/empty-keyring'
        missing = run('missing-key-control', missing_key+['--checksig', '--verbose', str(path)], check=False)
        if missing.returncode == 0: raise ValueError('Real RPM verification accepted the missing key')
        tampered = output/'tampered.rpm'
        try:
            shutil.copyfile(path, tampered)
            with tampered.open('r+b') as stream:
                stream.seek(tampered.stat().st_size//2)
                byte = stream.read(1); stream.seek(-1, 1); stream.write(bytes([byte[0]^1]))
            invalid = run('tampered-package-control', rpmkeys+['--checksig', '--verbose', str(tampered)], check=False)
            if invalid.returncode == 0: raise ValueError('Real RPM verification accepted changed bytes')
        finally:
            tampered.unlink(missing_ok=True)
        record['negative_controls'] = {'missing_key_rejected': True, 'tampered_package_rejected': True}
        identities = run('rpm-identity', ['rpm', '-qp', '--qf', fmt, str(path)]).stdout.splitlines()
        if len(identities) != 1: raise ValueError('Ambiguous portal runtime package identity')
        require_package_identity(identities[0], package['nevra'])
        delta = required_package_delta(before, identities)
        if delta:
            run('offline-install', ['dnf5', '--assumeyes', '--disable-plugin=*',
                '--setopt=reposdir=/output/empty-repos', '--setopt=cachedir=/output/dnf-cache',
                '--setopt=localpkg_gpgcheck=True', '--setopt=install_weak_deps=False', '--setopt=tsflags=nodocs',
                'install', '--', str(path)], timeout=300)
        after = sorted(run('installed-after', ['rpm', '-qa', '--qf', fmt]).stdout.splitlines())
        require_transaction(before, after, identities)
        crypto_after = snapshot_crypto_configuration(Path('/'))
        (evidence/'crypto-after.json').write_text(json.dumps(crypto_after, indent=2)+'\n')
        if crypto_after != crypto_before: raise ValueError('Original base crypto configuration changed')
        record.update(base_package_count=len(before), required_packages=identities, added_packages=delta,
                      all_base_packages_unchanged=True, base_crypto_configuration_unchanged=True)
        unprivileged = ['/usr/bin/setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--no-new-privs',
                        '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'HOME=/nonexistent']
        identity_code = (
            "import json;from pathlib import Path;"
            "s=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines());"
            "print(json.dumps({'uid':list(map(int,s['Uid'].split())),'gid':list(map(int,s['Gid'].split())),"
            "'groups':list(map(int,s['Groups'].split())),"
            "'capabilities':{k:s[k].strip() for k in ('CapInh','CapPrm','CapEff','CapAmb')},"
            "'no_new_privileges':int(s['NoNewPrivs'])}))")
        record['probe_identity'] = unique_json(run('probe-identity', unprivileged+['/usr/bin/python3', '-c', identity_code]).stdout)
        expected_identity = {'uid': [10001]*4, 'gid': [10001]*4, 'groups': [],
                             'capabilities': {name: '0000000000000000' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')},
                             'no_new_privileges': 1}
        if record['probe_identity'] != expected_identity: raise ValueError('Native probe identity is not unprivileged')
        for index, relative in enumerate(LOADER_PROBES):
            result = run('loader-'+str(index), unprivileged+['/usr/bin/ldd', '/usr/lib/symbi/portal/'+relative])
            if 'not found' in result.stdout+result.stderr: raise ValueError('Missing portal runtime library')
            record['loader_probes'].append(relative)
        record['portal_version'] = run('portal-version', unprivileged+[
            '/usr/lib/symbi/portal/libexec/xdg-desktop-portal-hyprland', '--version']).stdout.strip()
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        record['passed'] = True
        require_runtime_result(record, package, version)
    except Exception as error:
        record['passed'] = False
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        record['cgroup_final'] = {name: (group/name).read_text().strip()
                                  for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        save()


if __name__ == '__main__': main()
