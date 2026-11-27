"""Download public desktop candidates in a read-only disposable Fedora container."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil

from bounded_process import run_bounded
from contract import FEDORA, FUSION, require_keyring, require_repositories, require_requirements, verified_signer
from guest_inventory import require_fedora_family


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if not Path('/run/.containerenv').exists() or os.geteuid() != 0:
        raise SystemExit('Use the disposable hosted desktop discovery container')
    release = platform.freedesktop_os_release()
    require_fedora_family(release)
    if release['VERSION_ID'] != '45' or platform.machine() != 'x86_64':
        raise ValueError('Unexpected discovery distribution or architecture')
    group = Path('/sys/fs/cgroup') / Path(Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]).relative_to('/')
    limits = {name: (group/name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    if limits != {'memory.max': '2147483648', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '128'}:
        raise ValueError('Unexpected discovery resource limits')
    inputs, output = Path('/inputs'), Path('/output')
    trust = json.loads((inputs/'trust.json').read_text())
    requirements = json.loads((inputs/'requirements.json').read_text())
    require_requirements(requirements)
    require_repositories((inputs/'repos/desktop.repo').read_text())
    if trust['schema'] != 1 or [key['fingerprint'] for key in trust['keys']] != [FEDORA, FUSION]:
        raise ValueError('Unexpected isolated discovery trust anchors')
    evidence, rpms = output/'evidence', output/'rpms'
    evidence.mkdir(); rpms.mkdir()
    record = {'schema': 1, 'passed': False, 'os_qualified': False, 'packages_selected': False,
              'security_qualified': False, 'requirements': requirements, 'trust': trust,
              'limits': limits, 'commands': [], 'packages': [], 'negative_controls': {},
              'scope': 'Signed candidate discovery only; no package transaction or candidate program execution'}

    def save():
        (evidence/'result.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, command, timeout=60, check=True):
        record['active_command'] = {'name': name, 'command': command}; save()
        result = run_bounded(command, evidence/(name+'-stdout.log'), evidence/(name+'-stderr.log'), timeout, 1024**2)
        record['commands'].append({'name': name, 'exit_code': result.returncode})
        del record['active_command']; save()
        if check: result.check_returncode()
        return result

    try:
        query = ['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']
        before = sorted(run('installed-before', query).stdout.splitlines())
        for name in ('keyring', 'empty-keyring', 'fedora-keyring', 'fusion-keyring', 'rpmdb', 'gnupg'):
            (output/name).mkdir(mode=0o700)
        def rpmkeys(ring='keyring'):
            return ['rpmkeys', '--define', '_keyring fs', '--define', '_keyringpath /output/'+ring,
                    '--dbpath', '/output/rpmdb', '--define', '_pkgverify_level all']
        for index, key in enumerate(trust['keys']):
            path = inputs/key['file']
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536 or digest(path) != key['sha256']:
                raise ValueError('Public signing key bytes changed')
            shown = run('public-key-'+str(index), ['gpg', '--homedir', '/output/gnupg', '--batch', '--no-options',
                        '--with-colons', '--show-keys', str(path)])
            if [line.split(':')[9] for line in shown.stdout.splitlines() if line.startswith('fpr:')] != [key['fingerprint']]:
                raise ValueError('Public signing key identity changed')
            for ring in ('keyring', 'fedora-keyring' if index == 0 else 'fusion-keyring'):
                run('import-'+ring+'-'+str(index), rpmkeys(ring)+['--import', str(path)])
        for ring, keys in [('keyring', [FEDORA, FUSION]), ('fedora-keyring', [FEDORA]), ('fusion-keyring', [FUSION])]:
            require_keyring(run('list-'+ring, rpmkeys(ring)+['--list']).stdout, keys)
        dnf = ['dnf5', '--config=/inputs/dnf.conf', '--releasever=45', '--assumeyes', '--disable-plugin=*']
        # Query unresolved prompt/tooling names without accepting an unofficial
        # installer or executing a fetched script when a Fedora package is absent.
        run('unresolved-tooling', dnf+['repoquery', '--available', '--latest-limit=1',
            '--queryformat=%{name}\t%{evr}\t%{arch}\t%{repoid}\n', '--', 'starship', 'mise', 'gum'], 1200)
        run('resolve-download', dnf+['install', '--downloadonly', '--', *requirements['packages']], 1200)
        packages = sorted(rpms.glob('*.rpm'))
        if not packages or len(packages) > 512 or sum(path.stat().st_size for path in packages) > 2*1024**3:
            raise ValueError('Unexpected empty or excessive candidate closure')
        probes = {}
        for index, path in enumerate(packages):
            if not path.is_file() or path.is_symlink() or path.resolve() != path:
                raise ValueError('Unsafe candidate RPM path')
            verified = run(f'rpm-{index:03}-signature', rpmkeys()+['--checksig', '--verbose', str(path)], check=False)
            signer = verified_signer(verified.returncode, verified.stdout, [FEDORA, FUSION])
            identity = run(f'rpm-{index:03}-identity', ['rpm', '-qp', '--qf',
                '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\t%{VENDOR}\t%{LICENSE}\t%{SOURCERPM}\n', str(path)])
            fields = identity.stdout.strip().split('\t')
            if len(fields) != 9 or fields[4] not in ('x86_64', 'noarch'):
                raise ValueError('Unexpected RPM identity or architecture')
            row = dict(zip(('name', 'epoch', 'version', 'release', 'arch', 'nevra', 'vendor', 'license', 'source_rpm'), fields))
            row.update(filename=path.name, bytes=path.stat().st_size, sha256=digest(path),
                       signature_verified=True, key_fingerprint=signer)
            record['packages'].append(row)
            probes.setdefault(signer, path)
            save()
        if set(probes) != {FEDORA, FUSION}:
            raise ValueError('Expected separately signed Fedora and RPM Fusion candidates')
        for index, (signer, probe) in enumerate(probes.items()):
            for control, ring in [('missing-key', 'empty-keyring'),
                                  ('wrong-key', 'fusion-keyring' if signer == FEDORA else 'fedora-keyring')]:
                result = run(f'{control}-{index}', rpmkeys(ring)+['--checksig', '--verbose', str(probe)], check=False)
                if result.returncode == 0:
                    raise ValueError(control+' accepted an untrusted package')
            changed = output/f'tampered-{index}.rpm'
            shutil.copyfile(probe, changed)
            with changed.open('r+b') as stream:
                stream.seek(changed.stat().st_size//2)
                byte = stream.read(1); stream.seek(-1, 1); stream.write(bytes([byte[0]^1]))
            invalid = run('tampered-'+str(index), rpmkeys()+['--checksig', '--verbose', str(changed)], check=False)
            if invalid.returncode == 0:
                raise ValueError('Changed RPM bytes were accepted')
            changed.unlink()
            record['negative_controls'][signer] = {'missing_key_rejected': True, 'wrong_key_rejected': True,
                                                  'tampered_package_rejected': True}
        after = sorted(run('installed-after', query).stdout.splitlines())
        if before != after:
            raise ValueError('Candidate discovery changed installed packages')
        record['installed_packages_unchanged'] = True
        record['installed_inventory_sha256'] = hashlib.sha256(('\n'.join(before)+'\n').encode()).hexdigest()
        record['passed'] = True
    except Exception as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        final = {name: (group/name).read_text().strip() for name in (*limits, 'memory.peak', 'memory.events', 'cpu.stat')}
        record['cgroup_final'] = final
        events = dict(line.split() for line in final['memory.events'].splitlines())
        if (any(final[name] != value for name, value in limits.items())
                or any(events.get(name) != '0' for name in ('oom', 'oom_kill', 'oom_group_kill'))):
            record['passed'] = False
        save()
    if not record['passed']:
        raise RuntimeError('Desktop discovery or resource checks did not pass')


if __name__ == '__main__':
    main()
